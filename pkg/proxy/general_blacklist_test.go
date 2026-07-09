package proxy

import (
	"bufio"
	"bytes"
	"go-reauth-proxy/pkg/config"
	"go-reauth-proxy/pkg/gatewaylog"
	"go-reauth-proxy/pkg/models"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGeneralBlacklistRuntimeNormalizesAddsListsAndRemoves(t *testing.T) {
	runtime := newGeneralBlacklistRuntime(models.GeneralBlacklistConfig{
		Items: []models.GeneralBlacklistRecord{
			{IP: "203.0.113.10", Source: "unknown", Comment: "first", CreatedAt: "2026-01-01T00:00:00Z"},
			{IP: "203.0.113.10", Source: models.GeneralBlacklistSourceActiveIP, Comment: "latest", CreatedAt: "2026-01-02T00:00:00Z"},
			{IP: "127.0.0.1", Source: models.GeneralBlacklistSourceManual},
			{IP: "not-an-ip", Source: models.GeneralBlacklistSourceManual},
		},
	})

	list := runtime.list(1, 20, "")
	if list.Total != 1 {
		t.Fatalf("total = %d, want 1", list.Total)
	}
	if got := list.Items[0].Source; got != models.GeneralBlacklistSourceActiveIP {
		t.Fatalf("source = %q, want active_ip", got)
	}

	fixedNow := time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)
	_, result, err := runtime.addMany(
		[]string{"192.168.1.20", "[2001:db8::5]", "192.168.1.20"},
		models.GeneralBlacklistSourceWAFLog,
		"manual review",
		fixedNow,
	)
	if err != nil {
		t.Fatalf("addMany failed: %v", err)
	}
	if result.Added != 2 || result.Updated != 0 {
		t.Fatalf("mutation = added %d updated %d, want 2/0", result.Added, result.Updated)
	}

	if _, _, err := runtime.addMany([]string{"127.0.0.1"}, "", "", fixedNow); err == nil {
		t.Fatal("expected loopback IP to be rejected")
	}
	if _, _, err := runtime.addMany([]string{"0.0.0.0"}, "", "", fixedNow); err == nil {
		t.Fatal("expected unspecified IP to be rejected")
	}
	if _, _, err := runtime.addMany([]string{"not-an-ip"}, "", "", fixedNow); err == nil {
		t.Fatal("expected invalid IP to be rejected")
	}

	if _, ok := runtime.contains("192.168.1.20"); !ok {
		t.Fatal("expected private exact IP to be blockable")
	}
	if _, ok := runtime.contains("2001:db8::5"); !ok {
		t.Fatal("expected IPv6 exact IP to be blockable")
	}

	status, err := runtime.status([]string{"192.168.1.20:8443", "bad-ip", "127.0.0.1", "198.51.100.8", "[2001:db8::5]"})
	if err != nil {
		t.Fatalf("status failed: %v", err)
	}
	if len(status.Records) != 2 {
		t.Fatalf("status records = %d, want 2", len(status.Records))
	}
	if got := status.Records["192.168.1.20"].Source; got != models.GeneralBlacklistSourceWAFLog {
		t.Fatalf("status source = %q, want waf_log", got)
	}
	if emptyStatus, err := runtime.status([]string{"bad-ip", "127.0.0.1", "0.0.0.0"}); err != nil || len(emptyStatus.Records) != 0 {
		t.Fatalf("invalid-only status = %#v, err = %v; want empty success", emptyStatus, err)
	}

	list = runtime.list(1, 20, "MANUAL REVIEW")
	if list.Total != 2 {
		t.Fatalf("search total = %d, want 2", list.Total)
	}

	_, removed, err := runtime.removeMany([]string{"192.168.1.20"})
	if err != nil {
		t.Fatalf("removeMany failed: %v", err)
	}
	if removed.Removed != 1 {
		t.Fatalf("removed = %d, want 1", removed.Removed)
	}
	if _, ok := runtime.contains("192.168.1.20"); ok {
		t.Fatal("expected removed IP to stop matching")
	}
}

func TestGeneralBlacklistSearchMatchesNonASCIICase(t *testing.T) {
	runtime := newGeneralBlacklistRuntime(models.GeneralBlacklistConfig{
		Items: []models.GeneralBlacklistRecord{
			{IP: "198.51.100.20", Source: models.GeneralBlacklistSourceManual, Comment: "Resume required"},
			{IP: "198.51.100.21", Source: models.GeneralBlacklistSourceManual, Comment: "Résumé required"},
		},
	})

	list := runtime.list(1, 20, "résumé")
	if list.Total != 1 {
		t.Fatalf("search total = %d, want 1", list.Total)
	}
	if got := list.Items[0].IP; got != "198.51.100.21" {
		t.Fatalf("matched IP = %q, want 198.51.100.21", got)
	}
}

func TestGeneralBlacklistPersistsThroughConfigManager(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.json")
	cfgManager := config.NewManager(configPath)
	initialCfg, err := cfgManager.Load()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	handler := NewHandler(7996, 7999, cfgManager, initialCfg, filepath.Join(t.TempDir(), "logs"), nil)
	if _, err := handler.AddGeneralBlacklist([]string{"203.0.113.22"}, models.GeneralBlacklistSourceManual, "persist me"); err != nil {
		t.Fatalf("AddGeneralBlacklist failed: %v", err)
	}

	loaded, err := cfgManager.Load()
	if err != nil {
		t.Fatalf("reload config: %v", err)
	}
	if len(loaded.GeneralBlacklist.Items) != 1 {
		t.Fatalf("persisted items = %d, want 1", len(loaded.GeneralBlacklist.Items))
	}
	if got := loaded.GeneralBlacklist.Items[0].IP; got != "203.0.113.22" {
		t.Fatalf("persisted IP = %q, want 203.0.113.22", got)
	}
}

func TestGeneralBlacklistBlockedRequestIsLogged(t *testing.T) {
	logsDir := t.TempDir()
	handler := &Handler{
		gatewayLogManager: gatewaylog.NewManager(logsDir, models.LoggingConfig{
			Enabled: true,
			MaxDays: 1,
		}),
		generalBlacklist: newGeneralBlacklistRuntime(models.GeneralBlacklistConfig{
			Items: []models.GeneralBlacklistRecord{
				{
					IP:        "203.0.113.88",
					Source:    models.GeneralBlacklistSourceManual,
					CreatedAt: "2026-01-01T00:00:00Z",
					UpdatedAt: "2026-01-01T00:00:00Z",
				},
			},
		}),
	}
	handler.publishRequestSnapshotLocked()

	req := httptest.NewRequest(http.MethodGet, "http://app.example.com/private?q=1", nil)
	req.RemoteAddr = "203.0.113.88:4567"
	rec := newHijackableResponseRecorder()
	defer rec.Close()

	handler.ServeHTTP(rec, req)

	result, err := handler.QueryLogEntries("", 1, 20, "general_blacklist_blocked", "", "", "", "", "page")
	if err != nil {
		t.Fatalf("QueryLogEntries failed: %v", err)
	}
	if len(result.Items) != 1 {
		t.Fatalf("logged items = %d, want 1", len(result.Items))
	}
	entry := result.Items[0]
	if entry.Status != 499 {
		t.Fatalf("status = %d, want 499", entry.Status)
	}
	if entry.RouteType != "general_blacklist" {
		t.Fatalf("route_type = %q, want general_blacklist", entry.RouteType)
	}
	if entry.RouteKey != "203.0.113.88" {
		t.Fatalf("route_key = %q, want blocked IP", entry.RouteKey)
	}
	if entry.AuthDecision != "general_blacklist_blocked" {
		t.Fatalf("auth_decision = %q, want general_blacklist_blocked", entry.AuthDecision)
	}
	if !entry.GeneralBlacklistBlocked {
		t.Fatal("general_blacklist_blocked flag was not logged")
	}
}

func BenchmarkGeneralBlacklistRecordMatches(b *testing.B) {
	record := models.GeneralBlacklistRecord{
		IP:      "192.168.1.20",
		Source:  models.GeneralBlacklistSourceWAFLog,
		Comment: "Manual Review Required",
	}

	b.ReportAllocs()
	for b.Loop() {
		benchmarkBoolSink = generalBlacklistRecordMatches(record, "review")
	}
}

func BenchmarkGeneralBlacklistRecordMatchesOld(b *testing.B) {
	record := models.GeneralBlacklistRecord{
		IP:      "192.168.1.20",
		Source:  models.GeneralBlacklistSourceWAFLog,
		Comment: "Manual Review Required",
	}

	b.ReportAllocs()
	for b.Loop() {
		benchmarkBoolSink = strings.Contains(strings.ToLower(record.IP), "review") ||
			strings.Contains(strings.ToLower(record.Source), "review") ||
			strings.Contains(strings.ToLower(record.Comment), "review")
	}
}

type hijackableResponseRecorder struct {
	header http.Header
	code   int
	body   bytes.Buffer
	client net.Conn
}

func newHijackableResponseRecorder() *hijackableResponseRecorder {
	return &hijackableResponseRecorder{
		header: http.Header{},
		code:   http.StatusOK,
	}
}

func (r *hijackableResponseRecorder) Header() http.Header {
	return r.header
}

func (r *hijackableResponseRecorder) WriteHeader(statusCode int) {
	r.code = statusCode
}

func (r *hijackableResponseRecorder) Write(p []byte) (int, error) {
	return r.body.Write(p)
}

func (r *hijackableResponseRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	server, client := net.Pipe()
	r.client = client
	rw := bufio.NewReadWriter(bufio.NewReader(server), bufio.NewWriter(server))
	return server, rw, nil
}

func (r *hijackableResponseRecorder) Close() {
	if r.client != nil {
		_ = r.client.Close()
	}
}
