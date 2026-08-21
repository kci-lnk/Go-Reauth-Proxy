package proxy

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"go-reauth-proxy/pkg/deepmonitor"
	"go-reauth-proxy/pkg/gatewaylog"
	"go-reauth-proxy/pkg/models"
)

func newCertificateDeployTestHandler(t *testing.T, upstream *httptest.Server) *Handler {
	t.Helper()
	handler := &Handler{
		AuthConfig: models.AuthConfig{
			AuthHost: "auth.example.com",
			AuthPort: testServerPort(t, upstream.URL),
		},
		authCache:      newAuthStateCache(),
		preflightCache: newPreflightStateCache(),
	}
	handler.publishRequestSnapshotLocked()
	return handler
}

func TestCertificateDeployRouteForwardsOnlyExactAuthHostAndSanitizesHeaders(t *testing.T) {
	var hits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Method != http.MethodPut || r.URL.Path != "/__certificates__/binding-1" {
			t.Fatalf("unexpected upstream request %s %s", r.Method, r.URL.Path)
		}
		if r.Host != "auth.example.com" {
			t.Fatalf("Host = %q, want auth.example.com", r.Host)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer fnk_cert_secret" {
			t.Fatalf("Authorization = %q", got)
		}
		if got := r.Header.Get("X-Signature"); got != "" {
			t.Fatalf("client supplied internal signature leaked upstream: %q", got)
		}
		if got := r.Header.Get("Forwarded"); got != "" {
			t.Fatalf("client supplied Forwarded leaked upstream: %q", got)
		}
		if got := r.Header.Get("X-Forwarded-For"); got != "192.0.2.1" {
			t.Fatalf("X-Forwarded-For = %q, want resolved client IP", got)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil || string(body) != `{"cert":"pem","key":"key"}` {
			t.Fatalf("body = %q, err = %v", body, err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"success":true}`)
	}))
	defer upstream.Close()

	handler := newCertificateDeployTestHandler(t, upstream)
	req := httptest.NewRequest(
		http.MethodPut,
		"https://auth.example.com/__certificates__/binding-1",
		strings.NewReader(`{"cert":"pem","key":"key"}`),
	)
	req.Header.Set("Authorization", "Bearer fnk_cert_secret")
	req.Header.Set("X-Signature", "forged")
	req.Header.Set("Forwarded", "for=203.0.113.8")
	req.Header.Set("X-Forwarded-For", "203.0.113.8")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if hits.Load() != 1 {
		t.Fatalf("upstream hits = %d, want 1", hits.Load())
	}
	assertAuthResponseNoStore(t, recorder.Header())

	wrongHost := httptest.NewRequest(
		http.MethodPut,
		"https://app.example.com/__certificates__/binding-1",
		strings.NewReader(`{}`),
	)
	wrongHostRecorder := httptest.NewRecorder()
	handler.ServeHTTP(wrongHostRecorder, wrongHost)
	if wrongHostRecorder.Code != http.StatusNotFound {
		t.Fatalf("wrong host status = %d, want 404", wrongHostRecorder.Code)
	}
	if hits.Load() != 1 {
		t.Fatalf("wrong host reached certificate upstream")
	}
}

func TestCertificateDeployRouteRejectsInvalidMethodPathAndOversizedBody(t *testing.T) {
	var hits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	handler := newCertificateDeployTestHandler(t, upstream)

	tests := []struct {
		name   string
		method string
		path   string
		body   []byte
		status int
	}{
		{name: "method", method: http.MethodPost, path: "/__certificates__/binding-1", status: http.StatusMethodNotAllowed},
		{name: "missing id", method: http.MethodPut, path: "/__certificates__", status: http.StatusNotFound},
		{name: "extra segment", method: http.MethodPut, path: "/__certificates__/binding-1/extra", status: http.StatusNotFound},
		{name: "non canonical", method: http.MethodPut, path: "/__certificates__//binding-1", status: http.StatusNotFound},
		{name: "invalid id", method: http.MethodPut, path: "/__certificates__/binding.1", status: http.StatusNotFound},
		{name: "query rejected", method: http.MethodPut, path: "/__certificates__/binding-1?token=secret", status: http.StatusNotFound},
		{name: "oversized", method: http.MethodPut, path: "/__certificates__/binding-1", body: bytes.Repeat([]byte("x"), int(certificateDeployBodyLimit)+1), status: http.StatusRequestEntityTooLarge},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(test.method, "https://auth.example.com"+test.path, bytes.NewReader(test.body))
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, req)
			if recorder.Code != test.status {
				t.Fatalf("status = %d, want %d; body = %s", recorder.Code, test.status, recorder.Body.String())
			}
			if test.name == "query rejected" && req.URL.RawQuery != "" {
				t.Fatalf("certificate deployment query remained available to logging: %q", req.URL.RawQuery)
			}
			assertAuthResponseNoStore(t, recorder.Header())
		})
	}
	if hits.Load() != 0 {
		t.Fatalf("rejected requests reached upstream %d times", hits.Load())
	}
}

func TestCertificateDeployBindingIDValidation(t *testing.T) {
	for _, valid := range []string{"abc", "binding-1", "binding_1", "A1"} {
		if got, ok := certificateDeployBindingID(certificateDeployPathPrefix + "/" + valid); !ok || got != valid {
			t.Fatalf("valid binding id %q rejected", valid)
		}
	}
	for _, invalid := range []string{"", "a/b", "a.b", "a%2Fb", strings.Repeat("a", maxCertificateBindingIDLen+1)} {
		if _, ok := certificateDeployBindingID(certificateDeployPathPrefix + "/" + invalid); ok {
			t.Fatalf("invalid binding id %q accepted", invalid)
		}
	}
}

func TestCertificateDeployLoggingOmitsFreeFormSensitiveValues(t *testing.T) {
	req := httptest.NewRequest(http.MethodPut, "https://auth.example.com/__certificates__/binding-1", nil)
	req.Header.Set("Authorization", "Bearer fnk_cert_secret")
	req.Header.Set("Referer", "https://example.test/?value=private-key")
	req.Header.Set("X-Forwarded-For", "fnk_cert_secret")
	field, value := requestDebugHeaders(true, req.Header)
	if field != "header_names" {
		t.Fatalf("debug header field = %q, want header_names", field)
	}
	if names, ok := value.([]string); !ok || strings.Contains(strings.Join(names, ","), "fnk_cert_secret") {
		t.Fatalf("debug header metadata retained a sensitive value: %#v", value)
	}
	if xff, real, ali, eo := requestDebugClientHeaders(true, req); xff != "" || real != "" || ali != "" || eo != "" {
		t.Fatalf("debug client headers were retained: %q %q %q %q", xff, real, ali, eo)
	}
	entry := gatewaylog.Entry{
		UserAgent: "private-key", Referer: "fnk_cert_secret", XForwardedFor: "fnk_cert_secret",
	}
	redactCertificateDeployAccessEntry(&entry)
	if entry.UserAgent != "" || entry.Referer != "" || entry.XForwardedFor != "" {
		t.Fatalf("access entry retained sensitive values: %#v", entry)
	}
}

func TestCertificateDeployRouteUsesActualHostForGatewayPolicies(t *testing.T) {
	var hits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	handler := &Handler{
		HostRules: []models.HostRule{
			{Host: "auth.example.com", Target: upstream.URL, Disabled: true},
			{Host: "less-restricted.example.com", Target: upstream.URL},
		},
		AuthConfig: models.AuthConfig{
			AuthHost: "auth.example.com",
			AuthPort: testServerPort(t, upstream.URL),
		},
		authCache:      newAuthStateCache(),
		preflightCache: newPreflightStateCache(),
	}
	handler.publishRequestSnapshotLocked()

	req := httptest.NewRequest(
		http.MethodPut,
		"https://auth.example.com/__certificates__/binding-1",
		strings.NewReader(`{"cert":"pem","key":"key"}`),
	)
	req.Header.Set("X-Forwarded-Host", "less-restricted.example.com")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body = %s", recorder.Code, recorder.Body.String())
	}
	if hits.Load() != 0 {
		t.Fatalf("forged X-Forwarded-Host bypassed auth-host policy")
	}
	if got := req.Header.Get("X-Forwarded-Host"); got != "" {
		t.Fatalf("forged X-Forwarded-Host remained after routing: %q", got)
	}
}

func TestCertificateDeployRouteIsExcludedFromDeepMonitor(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	handler := newCertificateDeployTestHandler(t, upstream)
	manager, err := deepmonitor.NewManager(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	handler.deepMonitorManager = manager
	session, err := manager.Start("auth.example.com", deepmonitor.MinDuration)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(
		http.MethodPut,
		"https://auth.example.com/__certificates__/binding-1",
		strings.NewReader(`{"cert":"private-certificate","key":"private-key"}`),
	)
	req.Header.Set("Authorization", "Bearer fnk_cert_must_not_be_captured")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	malformed := httptest.NewRequest(
		http.MethodPut,
		"https://auth.example.com/safe/../__certificates__/binding-1?token=must-not-be-captured",
		strings.NewReader(`{"cert":"private-certificate","key":"private-key"}`),
	)
	malformed.Header.Set("Authorization", "Bearer fnk_cert_must_not_be_captured")
	malformedRecorder := httptest.NewRecorder()
	handler.ServeHTTP(malformedRecorder, malformed)
	if malformedRecorder.Code != http.StatusNotFound {
		t.Fatalf(
			"malformed status = %d, want 404; body = %s",
			malformedRecorder.Code,
			malformedRecorder.Body.String(),
		)
	}

	items, _, _, err := manager.Query(session.Id, "", 20, "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 {
		t.Fatalf("certificate deployment produced deep-monitor events: %#v", items)
	}
}

func TestLANCertificateDeployRequiresConfiguredHTTPSHostAndTransportPrivateClient(t *testing.T) {
	var hits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if got := r.Header.Get("X-Forwarded-For"); got != "192.168.31.50" {
			t.Fatalf("forwarded client = %q, want transport client", got)
		}
		if got := r.Header.Get("X-Forwarded-Proto"); got != "https" {
			t.Fatalf("forwarded proto = %q, want authoritative TLS scheme", got)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	handler := newCertificateDeployTestHandler(t, upstream)
	cert, key := makeTestCertificatePEM(t, []string{"gateway.example.test"}, nil)
	bundle, err := newSSLRuntimeBundle(models.SSLConfig{
		Certificates: []models.SSLDeployedCertificate{{Cert: cert, Key: key, IsDefault: true}},
		LANDeployment: models.SSLLANDeployment{
			Enabled: true, Addresses: []string{"192.168.31.98"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	handler.sslBundle.Store(bundle)

	request := httptest.NewRequest(http.MethodPut, "https://192.168.31.98/__certificates__/binding-1", strings.NewReader(`{}`))
	request.RemoteAddr = "192.168.31.50:41234"
	request.Header.Set("X-Forwarded-For", "203.0.113.9")
	request.Header.Set("X-Forwarded-Proto", "http")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || hits.Load() != 1 {
		t.Fatalf("LAN request status=%d hits=%d body=%s", recorder.Code, hits.Load(), recorder.Body.String())
	}
	// A configured LAN IP must not become a public route if AuthHost is also
	// (mis)configured to the same IP.
	handler.AuthConfig.AuthHost = "192.168.31.98"
	handler.publishRequestSnapshotLocked()

	for _, candidate := range []struct {
		name       string
		url        string
		remoteAddr string
		forwarded  string
	}{
		{name: "http", url: "http://192.168.31.98/__certificates__/binding-1", remoteAddr: "192.168.31.50:41234"},
		{name: "unconfigured host", url: "https://192.168.31.99/__certificates__/binding-1", remoteAddr: "192.168.31.50:41234"},
		{name: "public transport", url: "https://192.168.31.98/__certificates__/binding-1", remoteAddr: "203.0.113.9:41234", forwarded: "192.168.31.50"},
	} {
		t.Run(candidate.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPut, candidate.url, strings.NewReader(`{}`))
			req.RemoteAddr = candidate.remoteAddr
			req.Header.Set("X-Forwarded-For", candidate.forwarded)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusNotFound {
				t.Fatalf("status=%d, want 404", rec.Code)
			}
		})
	}
	if hits.Load() != 1 {
		t.Fatalf("rejected LAN requests reached upstream: %d hits", hits.Load())
	}
}
