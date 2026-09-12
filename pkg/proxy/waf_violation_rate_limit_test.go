package proxy

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"go-reauth-proxy/pkg/models"
	proxywaf "go-reauth-proxy/pkg/waf"
)

func blockedViolation() proxywaf.Decision {
	return proxywaf.Decision{ViolationRateLimitEnabled: true, Enabled: true, Allowed: false, TraceID: "violation-test", RuleIDs: []int{1, 2}}
}

func enableViolationLimiter(h *Handler) {
	h.WAFConfig.Enabled = true
	h.WAFConfig.Mode = proxywaf.ModeBlocking
	h.WAFConfig.ViolationRateLimitEnabled = true
	h.WAFConfig.ViolationRateLimitCapacity = 5
	h.WAFConfig.ViolationRateLimitRefillSeconds = 60
}

func TestWAFViolationTokenBucket(t *testing.T) {
	now := time.Now()
	l := newWAFViolationLimiter()
	for i := 0; i < 5; i++ {
		if l.exceeded("a", now, 5, 60) {
			t.Fatal("early ban")
		}
	}
	if l.exceeded("b", now, 5, 60) {
		t.Fatal("IP isolation")
	}
	if !l.exceeded("a", now, 5, 60) {
		t.Fatal("sixth violation must ban")
	}
	if l.exceeded("a", now.Add(4*time.Second), 5, 60) {
		t.Fatal("retry too early")
	}
	if !l.exceeded("a", now.Add(5*time.Second), 5, 60) {
		t.Fatal("retry missing")
	}
	l = newWAFViolationLimiter()
	for i := 0; i < 5; i++ {
		l.exceeded("a", now, 5, 60)
	}
	if l.exceeded("a", now.Add(time.Minute), 5, 60) {
		t.Fatal("one token should refill")
	}
	if !l.exceeded("a", now.Add(time.Minute), 5, 60) {
		t.Fatal("only one token should refill")
	}
	l = newWAFViolationLimiter()
	l.exceeded("a", now, 5, 60)
	for i := 0; i < 5; i++ {
		if l.exceeded("a", now.Add(time.Hour), 5, 60) {
			t.Fatal("full refill")
		}
	}
	if !l.exceeded("a", now.Add(time.Hour), 5, 60) {
		t.Fatal("refill exceeded capacity")
	}
}

func TestWAFViolationBucketEviction(t *testing.T) {
	now := time.Now()
	l := newWAFViolationLimiter()
	for i := 0; i < maxWAFViolationBuckets; i++ {
		l.exceeded(fmt.Sprint(i), now, 5, 60)
	}
	l.exceeded("0", now, 5, 60)
	if l.exceeded("new", now, 5, 60) {
		t.Fatal("capacity pressure must not ban")
	}
	if len(l.buckets) != maxWAFViolationBuckets || l.buckets["1"] != nil || l.buckets["0"] == nil {
		t.Fatal("LRU eviction")
	}
	l.exceeded("after-idle", now.Add(time.Hour), 5, 60)
	if len(l.buckets) != 1 {
		t.Fatalf("idle buckets retained: %d", len(l.buckets))
	}
}

func TestWAFViolationConcurrentPersistenceAndRemoval(t *testing.T) {
	h, m := newAdditionalProxyTestHandler(t)
	enableViolationLimiter(h)
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Go(func() { h.recordWAFViolation("203.0.113.90", blockedViolation(), h.wafViolationEpoch.Load()) })
	}
	wg.Wait()
	records := h.GetGeneralBlacklist().Items
	if len(records) != 1 || records[0].Source != models.GeneralBlacklistSourceWAFRateLimit || !strings.Contains(records[0].Comment, "violation-test") {
		t.Fatalf("records: %#v", records)
	}
	first := records[0]
	h.recordWAFViolation("203.0.113.90", blockedViolation(), h.wafViolationEpoch.Load())
	if h.GetGeneralBlacklist().Items[0] != first {
		t.Fatal("existing entry overwritten")
	}
	persisted, err := m.Load()
	if err != nil {
		t.Fatal(err)
	}
	restarted := NewHandler(7996, 7999, m, persisted, filepath.Join(t.TempDir(), "logs"), nil)
	t.Cleanup(restarted.gatewayLogManager.Close)
	if len(restarted.GetGeneralBlacklist().Items) != 1 {
		t.Fatal("ban lost after restart")
	}
	if _, err := h.RemoveGeneralBlacklist([]string{"203.0.113.90"}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		h.recordWAFViolation("203.0.113.90", blockedViolation(), h.wafViolationEpoch.Load())
	}
	if len(h.GetGeneralBlacklist().Items) != 0 {
		t.Fatal("removal did not reset allowance")
	}
	if _, err := h.AddGeneralBlacklist([]string{"203.0.113.90"}, "manual", "keep me"); err != nil {
		t.Fatal(err)
	}
	h.recordWAFViolation("203.0.113.90", blockedViolation(), h.wafViolationEpoch.Load())
	if h.GetGeneralBlacklist().Items[0].Comment != "keep me" {
		t.Fatal("manual comment overwritten")
	}
}

func TestWAFViolationIgnoresNonViolations(t *testing.T) {
	h, _ := newAdditionalProxyTestHandler(t)
	d := blockedViolation()
	for i := 0; i < 10; i++ {
		h.recordWAFViolation("203.0.113.90", d, h.wafViolationEpoch.Load())
	}
	if h.wafViolationLimiter != nil {
		t.Fatal("default must be disabled")
	}
	enableViolationLimiter(h)
	for _, change := range []func(*proxywaf.Decision){func(d *proxywaf.Decision) { d.Enabled = false }, func(d *proxywaf.Decision) { d.Allowed = true }, func(d *proxywaf.Decision) { d.DetectionOnly = true }, func(d *proxywaf.Decision) { d.Err = errors.New("read error") }} {
		d := blockedViolation()
		change(&d)
		for i := 0; i < 10; i++ {
			h.recordWAFViolation("203.0.113.90", d, h.wafViolationEpoch.Load())
		}
	}
	for _, ip := range []string{"invalid", "127.0.0.1", "0.0.0.0"} {
		h.recordWAFViolation(ip, blockedViolation(), h.wafViolationEpoch.Load())
	}
	if h.wafViolationLimiter != nil {
		t.Fatal("nonviolations allocated a bucket")
	}
}

func TestWAFViolationFailureAndConfigRollback(t *testing.T) {
	h, m := newAdditionalProxyTestHandler(t)
	enableViolationLimiter(h)
	breakConfigPersistence(t, m)
	for i := 0; i < 6; i++ {
		h.recordWAFViolation("203.0.113.90", blockedViolation(), h.wafViolationEpoch.Load())
	}
	if len(h.GetGeneralBlacklist().Items) != 0 {
		t.Fatal("failed persistence reported a ban")
	}
	bucket := h.wafViolationLimiter.buckets["203.0.113.90"].Value.(*wafViolationBucket)
	if !bucket.pending {
		t.Fatal("retry state missing")
	}
	retry := bucket.retryAt
	h.recordWAFViolation("203.0.113.90", blockedViolation(), h.wafViolationEpoch.Load())
	if bucket.retryAt != retry {
		t.Fatal("retry was not throttled")
	}
	before := h.wafViolationLimiter
	cfg := h.GetWAFConfig()
	cfg.Enabled = false
	if _, err := h.SetWAFConfig(cfg); err == nil {
		t.Fatal("expected save failure")
	}
	if h.wafViolationLimiter != before {
		t.Fatal("failed config reset bucket")
	}
	if err := os.Remove(m.RuntimeDir()); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(m.RuntimeDir(), 0700); err != nil {
		t.Fatal(err)
	}
	bucket.retryAt = time.Now().Add(-time.Second)
	h.recordWAFViolation("203.0.113.90", blockedViolation(), h.wafViolationEpoch.Load())
	if len(h.GetGeneralBlacklist().Items) != 1 {
		t.Fatal("retry after storage recovery did not persist ban")
	}
	cfg = h.GetWAFConfig()
	cfg.Enabled = false
	if _, err := h.SetWAFConfig(cfg); err != nil {
		t.Fatal(err)
	}
	if len(h.GetGeneralBlacklist().Items) != 1 {
		t.Fatal("disabling WAF removed ban")
	}

}

func TestWAFViolationSettingsResetAndOrdinaryUpdatesPreserve(t *testing.T) {
	h, _ := newAdditionalProxyTestHandler(t)
	// Runtime is kept disabled so tests don't require a rules bundle.
	cfg := h.GetWAFConfig()
	cfg.ViolationRateLimitEnabled = true
	if _, err := h.SetWAFConfig(cfg); err != nil {
		t.Fatal(err)
	}
	h.wafViolationLimiter = newWAFViolationLimiter()
	h.wafViolationLimiter.exceeded("203.0.113.90", time.Now(), 5, 60)
	before := h.wafViolationLimiter
	cfg = h.GetWAFConfig()
	cfg.BlockBehavior = models.WAFBlockBehaviorResetConnection
	if _, err := h.SetWAFConfig(cfg); err != nil {
		t.Fatal(err)
	}
	if h.wafViolationLimiter != before {
		t.Fatal("ordinary settings reset bucket")
	}
	cfg.ViolationRateLimitCapacity = 10
	if _, err := h.SetWAFConfig(cfg); err != nil {
		t.Fatal(err)
	}
	if h.wafViolationLimiter != nil {
		t.Fatal("new limit did not reset bucket")
	}
}

func TestWAFViolationHTTPAcrossHosts(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer upstream.Close()
	h, _ := newAdditionalProxyTestHandler(t)
	configureWAFBlockBehaviorTest(t, h, models.WAFBlockBehaviorErrorPage, upstream.URL)
	enableViolationLimiter(h)
	if _, err := h.wafRuntime.SetConfig(h.WAFConfig); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest("GET", "http://host.test/app/?test=normal", nil)
		req.RemoteAddr = "203.0.113.90:1234"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != 204 {
			t.Fatalf("normal request status=%d", w.Code)
		}
	}
	if h.wafViolationLimiter != nil {
		t.Fatal("normal requests consumed tokens")
	}
	for i := 0; i < 6; i++ {
		req := httptest.NewRequest("GET", fmt.Sprintf("http://host%d.test/app?test=attack", i%2), nil)
		req.RemoteAddr = "203.0.113.90:1234"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != 403 {
			t.Fatalf("request %d status=%d", i, w.Code)
		}
		expected := 0
		if i == 5 {
			expected = 1
		}
		if len(h.GetGeneralBlacklist().Items) != expected {
			t.Fatalf("request %d blacklist wrong", i)
		}
	}
	if h.wafRuntime.Drain(100).Drained != 6 {
		t.Fatal("WAF events not retained")
	}
}

func TestWAFViolationHTTPExclusions(t *testing.T) {
	for _, kind := range []string{"private", "host", "path", "detect", "disabled"} {
		t.Run(kind, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
			defer upstream.Close()
			h, _ := newAdditionalProxyTestHandler(t)
			configureWAFBlockBehaviorTest(t, h, models.WAFBlockBehaviorErrorPage, upstream.URL)
			cfg := h.GetWAFConfig()
			cfg.ViolationRateLimitEnabled = true
			ip := "203.0.113.90:1234"
			switch kind {
			case "private":
				cfg.PrivateIPExemptEnabled = true
				ip = "192.168.1.10:1234"
			case "host":
				cfg.DisabledHosts = []string{"host.test"}
			case "path":
				cfg.DisabledPathPrefixes = []string{"/app"}
			case "detect":
				cfg.Mode = proxywaf.ModeDetection
			case "disabled":
				cfg.Enabled = false
			}
			if _, err := h.SetWAFConfig(cfg); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 10; i++ {
				req := httptest.NewRequest("GET", "http://host.test/app?test=attack", nil)
				req.RemoteAddr = ip
				h.ServeHTTP(httptest.NewRecorder(), req)
			}
			if h.wafViolationLimiter != nil || len(h.GetGeneralBlacklist().Items) != 0 {
				t.Fatal("excluded request counted")
			}
		})
	}
}

func TestWAFViolationIgnoresRequestsFromBeforeAdministrativeReset(t *testing.T) {
	for _, change := range []string{"remove", "settings", "disable-reenable"} {
		t.Run(change, func(t *testing.T) {
			h, _ := newAdditionalProxyTestHandler(t)
			enableViolationLimiter(h)
			epoch := h.wafViolationEpoch.Load()
			switch change {
			case "remove":
				if _, err := h.RemoveGeneralBlacklist([]string{"203.0.113.90"}); err != nil {
					t.Fatal(err)
				}
			case "settings":
				cfg := h.GetWAFConfig()
				cfg.ViolationRateLimitCapacity = 1
				if _, err := h.SetWAFConfig(cfg); err != nil {
					t.Fatal(err)
				}
			case "disable-reenable":
				cfg := h.GetWAFConfig()
				cfg.ViolationRateLimitEnabled = false
				if _, err := h.SetWAFConfig(cfg); err != nil {
					t.Fatal(err)
				}
				cfg.ViolationRateLimitEnabled = true
				if _, err := h.SetWAFConfig(cfg); err != nil {
					t.Fatal(err)
				}
			}
			for i := 0; i < 10; i++ {
				h.recordWAFViolation("203.0.113.90", blockedViolation(), epoch)
			}
			if h.wafViolationLimiter != nil || len(h.GetGeneralBlacklist().Items) != 0 {
				t.Fatal("stale evaluations consumed the new allowance")
			}
			h.recordWAFViolation("203.0.113.90", blockedViolation(), h.wafViolationEpoch.Load())
			if h.wafViolationLimiter == nil {
				t.Fatal("new evaluation was not counted")
			}
		})
	}
}

func TestWAFViolationDisabledEvaluationDoesNotAcquireMutationLock(t *testing.T) {
	h, _ := newAdditionalProxyTestHandler(t)
	enableViolationLimiter(h)
	decision := blockedViolation()
	decision.ViolationRateLimitEnabled = false
	h.mu.Lock()
	done := make(chan struct{})
	go func() { h.recordWAFViolation("203.0.113.90", decision, h.wafViolationEpoch.Load()); close(done) }()
	select {
	case <-done:
		h.mu.Unlock()
	case <-time.After(time.Second):
		h.mu.Unlock()
		<-done
		t.Fatal("disabled evaluation waited for global mutation lock")
	}
	if h.wafViolationLimiter != nil {
		t.Fatal("evaluation made while disabled was counted")
	}
}
