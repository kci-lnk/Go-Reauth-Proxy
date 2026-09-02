package proxy

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go-reauth-proxy/pkg/models"
	proxywaf "go-reauth-proxy/pkg/waf"
)

func configureWAFBlockBehaviorTest(t *testing.T, handler *Handler, behavior string, upstreamURL string) {
	t.Helper()
	if err := handler.SetRules([]models.Rule{{
		Path:    "/app",
		Target:  upstreamURL,
		UseAuth: false,
	}}); err != nil {
		t.Fatalf("set path rule: %v", err)
	}

	rulesDir := t.TempDir()
	customDir := filepath.Join(rulesDir, "custom")
	if err := os.MkdirAll(customDir, 0o755); err != nil {
		t.Fatalf("create custom WAF directory: %v", err)
	}
	rule := `SecRule ARGS:test "@streq attack" "id:1903001,phase:2,deny,status:403,msg:'block behavior test',log"`
	if err := os.WriteFile(filepath.Join(customDir, "block-behavior-test.conf"), []byte(rule+"\n"), 0o644); err != nil {
		t.Fatalf("write custom WAF rule: %v", err)
	}
	wafConfig := models.WAFConfig{
		Enabled:           true,
		Mode:              proxywaf.ModeBlocking,
		RulesDir:          rulesDir,
		RequestBodyAccess: true,
		BlockBehavior:     behavior,
	}
	wafRuntime := proxywaf.NewRuntime(wafConfig, rulesDir)
	status, err := wafRuntime.Reload(wafConfig, "", "")
	if err != nil || !status.Loaded {
		t.Fatalf("load WAF: status=%#v err=%v", status, err)
	}
	handler.WAFConfig = wafRuntime.Config()
	handler.wafRuntime = wafRuntime
}

func TestWAFBlockBehaviorPersistsAcrossRestart(t *testing.T) {
	handler, manager := newAdditionalProxyTestHandler(t)
	next := handler.GetWAFConfig()
	next.BlockBehavior = models.WAFBlockBehaviorResetConnection
	if _, err := handler.SetWAFConfig(next); err != nil {
		t.Fatalf("set WAF block behavior: %v", err)
	}

	persisted, err := manager.Load()
	if err != nil {
		t.Fatalf("reload persisted config: %v", err)
	}
	if persisted.WAF.BlockBehavior != models.WAFBlockBehaviorResetConnection {
		t.Fatalf("persisted block behavior = %q", persisted.WAF.BlockBehavior)
	}

	restarted := NewHandler(7996, 7999, manager, persisted, filepath.Join(t.TempDir(), "restart-logs"), nil)
	t.Cleanup(restarted.gatewayLogManager.Close)
	if behavior := restarted.GetWAFConfig().BlockBehavior; behavior != models.WAFBlockBehaviorResetConnection {
		t.Fatalf("restarted block behavior = %q", behavior)
	}
}

func TestWAFBlockBehaviorRollsBackWhenPersistenceFails(t *testing.T) {
	handler, manager := newAdditionalProxyTestHandler(t)
	before := handler.GetWAFConfig()
	next := before
	next.BlockBehavior = models.WAFBlockBehaviorResetConnection
	breakConfigPersistence(t, manager)

	if _, err := handler.SetWAFConfig(next); err == nil {
		t.Fatal("SetWAFConfig returned nil error")
	}
	if behavior := handler.GetWAFConfig().BlockBehavior; behavior != before.BlockBehavior {
		t.Fatalf("configured block behavior after failure = %q, want %q", behavior, before.BlockBehavior)
	}
	if behavior := handler.wafRuntime.Config().BlockBehavior; behavior != before.BlockBehavior {
		t.Fatalf("runtime block behavior after failure = %q, want %q", behavior, before.BlockBehavior)
	}
}

func TestWAFResetConnectionHTTP1ClosesWithoutResponseAndKeepsEvent(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	handler, _ := newAdditionalProxyTestHandler(t)
	configureWAFBlockBehaviorTest(t, handler, models.WAFBlockBehaviorResetConnection, upstream.URL)
	if _, err := handler.SetLoggingConfig(models.LoggingConfig{
		Enabled:         true,
		RecordLocalhost: true,
		MaxDays:         1,
	}); err != nil {
		t.Fatalf("enable gateway logging: %v", err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}
	conn, err := net.DialTimeout("tcp", serverURL.Host, 2*time.Second)
	if err != nil {
		t.Fatalf("dial server: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.WriteString(conn, "GET /app?test=attack HTTP/1.1\r\nHost: gateway.example.test\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatalf("write request: %v", err)
	}
	data, readErr := bufio.NewReader(conn).ReadBytes('\n')
	if len(data) != 0 {
		t.Fatalf("received HTTP response before reset: %q", data)
	}
	if !isConnectionResetError(readErr) {
		t.Fatalf("read error = %v, want connection reset", readErr)
	}

	drained := handler.DrainWAFEvents(10)
	if len(drained.Events) != 1 || drained.Events[0].TraceID == "" || drained.Events[0].Status != http.StatusForbidden {
		t.Fatalf("WAF event after reset = %#v", drained.Events)
	}

	logs, err := handler.QueryLogEntries("", 1, 20, "waf_blocked", "", "", "", "", "page")
	if err != nil {
		t.Fatalf("query WAF access log: %v", err)
	}
	if len(logs.Items) != 1 {
		t.Fatalf("WAF access log count = %d, want 1", len(logs.Items))
	}
	entry := logs.Items[0]
	if entry.Status != 499 || !entry.WAFBlocked || entry.WAFTraceID == "" || entry.AuthDecision != "waf_blocked" {
		t.Fatalf("WAF reset access log = %#v", entry)
	}
	if len(entry.WAFRuleIDs) != 1 || entry.WAFRuleIDs[0] != 1903001 {
		t.Fatalf("WAF reset rule IDs = %#v", entry.WAFRuleIDs)
	}
}

func TestWAFErrorPageBehaviorKeepsExistingResponseProtocol(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	handler, _ := newAdditionalProxyTestHandler(t)
	configureWAFBlockBehaviorTest(t, handler, "", upstream.URL)
	req := httptest.NewRequest(http.MethodGet, "http://gateway.example.test/app?test=attack", nil)
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if rec.Header().Get("X-Fn-Knock-WAF-Blocked") != "1" {
		t.Fatal("missing WAF blocked response header")
	}
	if values := rec.Header().Values("X-Fn-Knock-WAF-Trace-ID"); len(values) != 0 {
		t.Fatalf("WAF trace response headers = %q, want none", values)
	}
	if contentType := rec.Header().Get("Content-Type"); contentType != "application/json" {
		t.Fatalf("content type = %q", contentType)
	}
}

func TestWAFResetConnectionHTTP2AbortsOnlyBlockedStream(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	handler, _ := newAdditionalProxyTestHandler(t)
	configureWAFBlockBehaviorTest(t, handler, models.WAFBlockBehaviorResetConnection, upstream.URL)
	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	client := server.Client()

	blocked, err := http.NewRequest(http.MethodGet, server.URL+"/app?test=attack", nil)
	if err != nil {
		t.Fatalf("build blocked request: %v", err)
	}
	if response, err := client.Do(blocked); err == nil {
		response.Body.Close()
		t.Fatal("blocked HTTP/2 stream unexpectedly returned a response")
	}

	var gotConnInfo httptrace.GotConnInfo
	allowed, err := http.NewRequest(http.MethodGet, server.URL+"/app", nil)
	if err != nil {
		t.Fatalf("build allowed request: %v", err)
	}
	allowed = allowed.WithContext(httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			gotConnInfo = info
		},
	}))
	response, err := client.Do(allowed)
	if err != nil {
		t.Fatalf("allowed HTTP/2 stream failed after block: %v", err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, response.Body)
	if response.StatusCode != http.StatusNoContent || response.ProtoMajor != 2 {
		t.Fatalf("allowed response = %s over %s", response.Status, response.Proto)
	}
	if !gotConnInfo.Reused {
		t.Fatal("HTTP/2 connection was not reused after aborting the blocked stream")
	}
}
