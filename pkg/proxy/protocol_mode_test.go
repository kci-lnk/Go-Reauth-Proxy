package proxy

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	"go-reauth-proxy/pkg/config"
	"go-reauth-proxy/pkg/grpc/pb"
	"go-reauth-proxy/pkg/models"
)

func TestSetHostRulesNormalizesProtocolModeAndPublishesSnapshot(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	var hookCalls atomic.Int32
	var hookHosts [][]string
	handler.SetHostProtocolModeChangeHook(func(hosts []string) {
		hookCalls.Add(1)
		hookHosts = append(hookHosts, append([]string(nil), hosts...))
	})

	if err := handler.SetHostRules([]models.HostRule{{
		Host:         "APP.EXAMPLE.TEST",
		Target:       "http://127.0.0.1:8080",
		ProtocolMode: " HTTP1 ",
	}}); err != nil {
		t.Fatalf("SetHostRules() returned error: %v", err)
	}

	rules := handler.GetHostRules()
	if len(rules) != 1 || rules[0].ProtocolMode != models.HostProtocolModeHTTP1 {
		t.Fatalf("normalized host rules = %#v", rules)
	}
	if got := handler.GetHostProtocolMode("APP.EXAMPLE.TEST"); got != models.HostProtocolModeHTTP1 {
		t.Fatalf("GetHostProtocolMode() = %q, want http1", got)
	}
	snapshot := handler.snapshotForRequest()
	if got := snapshot.hostRulesByHost["app.example.test"].ProtocolMode; got != models.HostProtocolModeHTTP1 {
		t.Fatalf("snapshot protocol mode = %q, want http1", got)
	}

	if err := handler.SetHostRules([]models.HostRule{{
		Host:         "app.example.test",
		Target:       "http://127.0.0.1:8080",
		ProtocolMode: "not-a-protocol",
	}}); err != nil {
		t.Fatalf("SetHostRules(invalid mode) returned error: %v", err)
	}
	if got := handler.GetHostRules()[0].ProtocolMode; got != models.HostProtocolModeAuto {
		t.Fatalf("invalid protocol mode normalized to %q, want auto", got)
	}
	if got := hookCalls.Load(); got != 2 {
		t.Fatalf("protocol change hook calls = %d, want 2", got)
	}
	for i, hosts := range hookHosts {
		if len(hosts) != 1 || hosts[0] != "app.example.test" {
			t.Fatalf("hook %d hosts = %#v, want app.example.test", i, hosts)
		}
	}
	if err := handler.SetHostRules([]models.HostRule{{
		Host:         "app.example.test",
		Target:       "http://127.0.0.1:8080",
		ProtocolMode: models.HostProtocolModeAuto,
		Title:        "metadata-only update",
	}}); err != nil {
		t.Fatalf("SetHostRules(metadata update) returned error: %v", err)
	}
	if got := hookCalls.Load(); got != 2 {
		t.Fatalf("metadata-only update called protocol hook: calls = %d", got)
	}
}

func TestChangedHostProtocolModesReturnsSortedAffectedHosts(t *testing.T) {
	before := []models.HostRule{
		{Host: "c.example.test", ProtocolMode: models.HostProtocolModeHTTP2},
		{Host: "a.example.test", ProtocolMode: models.HostProtocolModeHTTP1},
		{Host: "unchanged.example.test", ProtocolMode: models.HostProtocolModeHTTP1},
	}
	after := []models.HostRule{
		{Host: "b.example.test", ProtocolMode: models.HostProtocolModeHTTP1},
		{Host: "a.example.test", ProtocolMode: models.HostProtocolModeHTTP2},
		{Host: "unchanged.example.test", ProtocolMode: models.HostProtocolModeHTTP1},
	}
	want := []string{"a.example.test", "b.example.test", "c.example.test"}
	if got := changedHostProtocolModes(before, after); !reflect.DeepEqual(got, want) {
		t.Fatalf("changed hosts = %#v, want %#v", got, want)
	}
}

func TestDefaultHostProtocolModeAppliesOnlyToExactSNI(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	if err := handler.SetHostRules([]models.HostRule{{
		Host:         "default.example.test",
		Target:       "http://127.0.0.1:8080",
		ProtocolMode: models.HostProtocolModeHTTP1,
		IsDefault:    true,
	}}); err != nil {
		t.Fatalf("set default host rule: %v", err)
	}
	if got := handler.GetHostProtocolMode("default.example.test"); got != models.HostProtocolModeHTTP1 {
		t.Fatalf("exact default-host SNI mode = %q, want http1", got)
	}
	if got := handler.GetHostProtocolMode("unknown.example.test"); got != models.HostProtocolModeAuto {
		t.Fatalf("unknown SNI inherited default-host mode %q, want auto", got)
	}
}

func TestSetHostRulesPreservesExistingModeWhenLegacyUpdateOmitsField(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	var hookCalls atomic.Int32
	handler.SetHostProtocolModeChangeHook(func([]string) {
		hookCalls.Add(1)
	})

	if err := handler.SetHostRules([]models.HostRule{{
		Host:         "video.example.test",
		Target:       "http://127.0.0.1:8080",
		ProtocolMode: models.HostProtocolModeHTTP1,
	}}); err != nil {
		t.Fatalf("set initial rules: %v", err)
	}
	if err := handler.SetHostRules([]models.HostRule{
		{Host: "video.example.test", Target: "http://127.0.0.1:8080", Title: "legacy metadata update"},
		{Host: "new.example.test", Target: "http://127.0.0.1:8081"},
	}); err != nil {
		t.Fatalf("set legacy rules: %v", err)
	}
	rules := handler.GetHostRules()
	if len(rules) != 2 || rules[0].ProtocolMode != models.HostProtocolModeHTTP1 {
		t.Fatalf("existing rule mode was not preserved: %#v", rules)
	}
	if rules[1].ProtocolMode != models.HostProtocolModeAuto {
		t.Fatalf("new rule mode = %q, want auto", rules[1].ProtocolMode)
	}
	if got := hookCalls.Load(); got != 1 {
		t.Fatalf("legacy metadata update changed protocol policy: hook calls = %d", got)
	}

	if err := handler.SetHostRules([]models.HostRule{{
		Host:         "video.example.test",
		Target:       "http://127.0.0.1:8080",
		ProtocolMode: models.HostProtocolModeAuto,
	}}); err != nil {
		t.Fatalf("explicit auto reset: %v", err)
	}
	if got := handler.GetHostRules()[0].ProtocolMode; got != models.HostProtocolModeAuto {
		t.Fatalf("explicit auto reset mode = %q", got)
	}
	if got := hookCalls.Load(); got != 2 {
		t.Fatalf("explicit auto reset hook calls = %d, want 2", got)
	}
}

func TestAddHostRulePreservesExistingModeWhenLegacyUpdateOmitsField(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	if err := handler.SetHostRules([]models.HostRule{{
		Host:         "video.example.test",
		Target:       "http://127.0.0.1:8080",
		ProtocolMode: models.HostProtocolModeHTTP1,
	}}); err != nil {
		t.Fatalf("set initial rules: %v", err)
	}

	var hookCalls atomic.Int32
	handler.SetHostProtocolModeChangeHook(func([]string) {
		hookCalls.Add(1)
	})
	if err := handler.AddHostRule(models.HostRule{
		Host:   "VIDEO.EXAMPLE.TEST",
		Target: "http://127.0.0.1:8081",
		Title:  "legacy metadata update",
	}); err != nil {
		t.Fatalf("legacy AddHostRule: %v", err)
	}
	rules := handler.GetHostRules()
	if len(rules) != 1 || rules[0].ProtocolMode != models.HostProtocolModeHTTP1 {
		t.Fatalf("existing rule mode was not preserved: %#v", rules)
	}
	if got := hookCalls.Load(); got != 0 {
		t.Fatalf("legacy AddHostRule changed protocol policy: hook calls = %d", got)
	}

	if err := handler.AddHostRule(models.HostRule{
		Host:         "video.example.test",
		Target:       "http://127.0.0.1:8081",
		ProtocolMode: models.HostProtocolModeAuto,
	}); err != nil {
		t.Fatalf("explicit auto AddHostRule: %v", err)
	}
	if got := handler.GetHostRules()[0].ProtocolMode; got != models.HostProtocolModeAuto {
		t.Fatalf("explicit auto reset mode = %q", got)
	}
	if got := hookCalls.Load(); got != 1 {
		t.Fatalf("explicit auto AddHostRule hook calls = %d, want 1", got)
	}
}

func TestHostRulePersistenceFailureDoesNotPublishOrRunProtocolHook(t *testing.T) {
	tests := []struct {
		name  string
		apply func(*Handler) error
	}{
		{
			name: "add",
			apply: func(handler *Handler) error {
				return handler.AddHostRule(models.HostRule{
					Host:         "new.example.test",
					Target:       "http://127.0.0.1:8081",
					ProtocolMode: models.HostProtocolModeHTTP2,
				})
			},
		},
		{
			name: "set",
			apply: func(handler *Handler) error {
				return handler.SetHostRules([]models.HostRule{{
					Host:         "video.example.test",
					Target:       "http://127.0.0.1:8080",
					ProtocolMode: models.HostProtocolModeHTTP2,
				}})
			},
		},
		{name: "flush", apply: func(handler *Handler) error { return handler.FlushHostRules() }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, manager := newAdditionalProxyTestHandler(t)
			defer handler.Close()
			var hookCalls atomic.Int32
			handler.SetHostProtocolModeChangeHook(func([]string) {
				hookCalls.Add(1)
			})
			if err := handler.SetHostRules([]models.HostRule{{
				Host:         "video.example.test",
				Target:       "http://127.0.0.1:8080",
				ProtocolMode: models.HostProtocolModeHTTP1,
			}}); err != nil {
				t.Fatalf("set baseline: %v", err)
			}
			beforeRules := handler.GetHostRules()
			beforeHookCalls := hookCalls.Load()
			breakConfigPersistence(t, manager)

			if err := tt.apply(handler); err == nil {
				t.Fatal("host rule mutation succeeded, want persistence error")
			}
			if got := handler.GetHostRules(); !reflect.DeepEqual(got, beforeRules) {
				t.Fatalf("runtime rules changed after save failure: got %#v want %#v", got, beforeRules)
			}
			if got := handler.GetHostProtocolMode("video.example.test"); got != models.HostProtocolModeHTTP1 {
				t.Fatalf("snapshot mode after save failure = %q, want http1", got)
			}
			if got := hookCalls.Load(); got != beforeHookCalls {
				t.Fatalf("protocol hook ran after save failure: before=%d after=%d", beforeHookCalls, got)
			}
		})
	}
}

func TestHostRulePersistencePreservesConcurrentManagerFields(t *testing.T) {
	handler, manager := newAdditionalProxyTestHandler(t)
	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make(chan error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		errs <- manager.Update(func(cfg *config.AppConfig) error {
			cfg.IptablesChainName = "FN_KNOCK_TEST"
			return nil
		})
	}()
	go func() {
		defer wg.Done()
		<-start
		errs <- handler.SetHostRules([]models.HostRule{{
			Host:         "video.example.test",
			Target:       "http://127.0.0.1:8080",
			ProtocolMode: models.HostProtocolModeHTTP1,
		}})
	}()
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent config update: %v", err)
		}
	}

	cfg, err := manager.Load()
	if err != nil {
		t.Fatalf("reload config: %v", err)
	}
	if cfg.IptablesChainName != "FN_KNOCK_TEST" {
		t.Fatalf("iptables chain = %q", cfg.IptablesChainName)
	}
	if len(cfg.HostRules) != 1 || cfg.HostRules[0].ProtocolMode != models.HostProtocolModeHTTP1 {
		t.Fatalf("persisted host rules = %#v", cfg.HostRules)
	}
}

func breakConfigPersistence(t *testing.T, manager *config.Manager) {
	t.Helper()
	runtimeDir := manager.RuntimeDir()
	if err := os.RemoveAll(runtimeDir); err != nil {
		t.Fatalf("remove config runtime dir: %v", err)
	}
	if err := os.WriteFile(runtimeDir, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("replace config runtime dir with file: %v", err)
	}
}

func TestHTTP1OnlyHostRejectsCoalescedHTTP2Request(t *testing.T) {
	var upstreamRequests atomic.Int32
	var authorizeRequests atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamRequests.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	handler, _ := newAdditionalProxyTestHandler(t)
	setTestAuthBridge(t, handler, testAuthBridge{
		supports: true,
		authorize: func(context.Context, *pb.AuthorizeHttpRequest) (*pb.AuthorizeHttpResponse, error) {
			authorizeRequests.Add(1)
			return &pb.AuthorizeHttpResponse{}, nil
		},
	})
	if err := handler.SetHostRules([]models.HostRule{{
		Host:         "video.example.test",
		Target:       upstream.URL,
		ProtocolMode: models.HostProtocolModeHTTP1,
		UseAuth:      true,
	}}); err != nil {
		t.Fatalf("SetHostRules() returned error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "https://video.example.test/movie.mp4", nil)
	req.Host = "video.example.test"
	req.Proto = "HTTP/2.0"
	req.ProtoMajor = 2
	req.ProtoMinor = 0
	req.TLS = &tls.ConnectionState{
		ServerName:         "other.example.test",
		NegotiatedProtocol: "h2",
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusMisdirectedRequest {
		t.Fatalf("status = %d, want 421", rec.Code)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
	if got := rec.Header().Get("Connection"); got != "" {
		t.Fatalf("HTTP/2 response included forbidden Connection header %q", got)
	}
	if got := upstreamRequests.Load(); got != 0 {
		t.Fatalf("upstream requests = %d, want 0", got)
	}
	if got := authorizeRequests.Load(); got != 0 {
		t.Fatalf("auth requests = %d, want 0", got)
	}
}

func TestProtocolMismatchHonorsBlacklistAndVisibilityBefore421(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*testing.T, *Handler)
	}{
		{
			name: "general blacklist",
			setup: func(t *testing.T, handler *Handler) {
				t.Helper()
				if _, err := handler.AddGeneralBlacklist(
					[]string{"203.0.113.8"},
					models.GeneralBlacklistSourceManual,
					"protocol ordering test",
				); err != nil {
					t.Fatalf("add blacklist: %v", err)
				}
			},
		},
		{
			name: "gateway visibility",
			setup: func(t *testing.T, handler *Handler) {
				t.Helper()
				if err := handler.SetGatewayVisibility(models.GatewayVisibilityConfig{
					Enabled: true,
					CIDRs:   []string{"198.51.100.0/24"},
				}); err != nil {
					t.Fatalf("set visibility: %v", err)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var upstreamRequests atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				upstreamRequests.Add(1)
				w.WriteHeader(http.StatusOK)
			}))
			defer upstream.Close()

			handler, _ := newAdditionalProxyTestHandler(t)
			if err := handler.SetHostRules([]models.HostRule{{
				Host:         "video.example.test",
				Target:       upstream.URL,
				ProtocolMode: models.HostProtocolModeHTTP1,
			}}); err != nil {
				t.Fatalf("set host rules: %v", err)
			}
			tt.setup(t, handler)

			req := protocolMismatchRequest("203.0.113.8:4567")
			rec := newHijackableResponseRecorder()
			defer rec.Close()
			handler.ServeHTTP(rec, req)

			if rec.client == nil {
				t.Fatal("request was not terminated by IP security policy")
			}
			if got := rec.Header().Get("Cache-Control"); got != "" {
				t.Fatalf("request reached 421 handler, Cache-Control = %q", got)
			}
			if got := upstreamRequests.Load(); got != 0 {
				t.Fatalf("upstream requests = %d, want 0", got)
			}
		})
	}
}

func TestProtocolMismatchIsThrottledBefore421(t *testing.T) {
	var upstreamRequests atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamRequests.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	handler, _ := newAdditionalProxyTestHandler(t)
	if err := handler.SetHostRules([]models.HostRule{{
		Host:         "video.example.test",
		Target:       upstream.URL,
		ProtocolMode: models.HostProtocolModeHTTP1,
	}}); err != nil {
		t.Fatalf("set host rules: %v", err)
	}
	if err := handler.SetReverseProxyThrottle(models.ReverseProxyThrottleConfig{
		Enabled:           true,
		RequestsPerSecond: 1,
		Burst:             1,
		BlockSeconds:      30,
	}); err != nil {
		t.Fatalf("set throttle: %v", err)
	}

	first := httptest.NewRecorder()
	handler.ServeHTTP(first, protocolMismatchRequest("198.51.100.20:4567"))
	if first.Code != http.StatusMisdirectedRequest {
		t.Fatalf("first status = %d, want 421", first.Code)
	}

	second := newHijackableResponseRecorder()
	defer second.Close()
	handler.ServeHTTP(second, protocolMismatchRequest("198.51.100.20:4568"))
	if second.client == nil {
		t.Fatal("second mismatch request was not terminated by throttle")
	}
	if got := second.Header().Get("Cache-Control"); got != "" {
		t.Fatalf("throttled request reached 421 handler, Cache-Control = %q", got)
	}

	otherIP := httptest.NewRecorder()
	handler.ServeHTTP(otherIP, protocolMismatchRequest("198.51.100.21:4567"))
	if otherIP.Code != http.StatusMisdirectedRequest {
		t.Fatalf("independent IP status = %d, want 421", otherIP.Code)
	}
	if got := upstreamRequests.Load(); got != 0 {
		t.Fatalf("upstream requests = %d, want 0", got)
	}
}

func protocolMismatchRequest(remoteAddr string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "https://video.example.test/movie.mp4", nil)
	req.Host = "video.example.test"
	req.RemoteAddr = remoteAddr
	req.Proto = "HTTP/2.0"
	req.ProtoMajor = 2
	req.ProtoMinor = 0
	req.TLS = &tls.ConnectionState{
		ServerName:         "other.example.test",
		NegotiatedProtocol: "h2",
	}
	return req
}

func TestHTTP2OnlyHostClosesHTTP1ConnectionAfterHotUpdate(t *testing.T) {
	var upstreamRequests atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamRequests.Add(1)
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	handler, _ := newAdditionalProxyTestHandler(t)
	setMode := func(mode string) {
		t.Helper()
		if err := handler.SetHostRules([]models.HostRule{{
			Host:         "video.example.test",
			Target:       upstream.URL,
			ProtocolMode: mode,
		}}); err != nil {
			t.Fatalf("SetHostRules(%q) returned error: %v", mode, err)
		}
	}
	setMode(models.HostProtocolModeAuto)

	var newConnections atomic.Int32
	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = false
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			newConnections.Add(1)
		}
	}
	server.StartTLS()
	defer server.Close()

	client := server.Client()
	doRequest := func() *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, server.URL+"/movie.mp4", nil)
		if err != nil {
			t.Fatalf("create request: %v", err)
		}
		req.Host = "video.example.test"
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return resp
	}

	if resp := doRequest(); resp.StatusCode != http.StatusOK {
		t.Fatalf("initial status = %d, want 200", resp.StatusCode)
	}
	if got := newConnections.Load(); got != 1 {
		t.Fatalf("initial TLS connections = %d, want 1", got)
	}

	// Simulate a hot update while the HTTP/1.1 TLS connection is idle. Production
	// marks affected-SNI connections as retiring and closes them only after the
	// next Active→Idle transition; this server omits the tracker so the request
	// guard is exercised directly as the safety net.
	setMode(models.HostProtocolModeHTTP2)
	if resp := doRequest(); resp.StatusCode != http.StatusMisdirectedRequest || !resp.Close {
		t.Fatalf("post-update response = status %d close=%t, want 421 close=true", resp.StatusCode, resp.Close)
	}
	if got := newConnections.Load(); got != 1 {
		t.Fatalf("stale request did not reuse original connection: connections = %d", got)
	}

	// The next request cannot reuse the stale connection and therefore opens a
	// new one. This test server still negotiates h1, so it is rejected again.
	if resp := doRequest(); resp.StatusCode != http.StatusMisdirectedRequest || !resp.Close {
		t.Fatalf("replacement response = status %d close=%t, want 421 close=true", resp.StatusCode, resp.Close)
	}
	if got := newConnections.Load(); got != 2 {
		t.Fatalf("TLS connections after close = %d, want 2", got)
	}
	if got := upstreamRequests.Load(); got != 1 {
		t.Fatalf("upstream requests = %d, want only the pre-update request", got)
	}
}

func TestHTTP1ProtocolModePreservesRangeProxyResponse(t *testing.T) {
	payload := []byte("0123456789abcdefghijklmnopqrstuvwxyz")
	const rangeHeader = "bytes=10-19"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Range"); got != rangeHeader {
			t.Errorf("upstream Range = %q, want %q", got, rangeHeader)
		}
		part := payload[10:20]
		w.Header().Set("Accept-Ranges", "bytes")
		w.Header().Set("Content-Range", "bytes 10-19/"+strconv.Itoa(len(payload)))
		w.Header().Set("Content-Length", strconv.Itoa(len(part)))
		w.WriteHeader(http.StatusPartialContent)
		_, _ = w.Write(part)
	}))
	defer upstream.Close()

	handler, _ := newAdditionalProxyTestHandler(t)
	if err := handler.SetHostRules([]models.HostRule{{
		Host:         "video.example.test",
		Target:       upstream.URL,
		ProtocolMode: models.HostProtocolModeHTTP1,
	}}); err != nil {
		t.Fatalf("SetHostRules() returned error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "https://video.example.test/movie.mp4", nil)
	req.Host = "video.example.test"
	req.Header.Set("Range", rangeHeader)
	req.Proto = "HTTP/1.1"
	req.ProtoMajor = 1
	req.ProtoMinor = 1
	req.TLS = &tls.ConnectionState{
		ServerName:         "video.example.test",
		NegotiatedProtocol: "http/1.1",
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	result := rec.Result()
	defer result.Body.Close()
	body, err := io.ReadAll(result.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if result.StatusCode != http.StatusPartialContent {
		t.Fatalf("status = %d, want 206", result.StatusCode)
	}
	if got := result.Header.Get("Content-Range"); got != "bytes 10-19/36" {
		t.Fatalf("Content-Range = %q", got)
	}
	if got := result.Header.Get("Content-Length"); got != "10" {
		t.Fatalf("Content-Length = %q", got)
	}
	if got, want := string(body), string(payload[10:20]); got != want {
		t.Fatalf("body = %q, want %q", got, want)
	}
}
