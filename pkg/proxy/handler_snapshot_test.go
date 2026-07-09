package proxy

import (
	"bytes"
	"fmt"
	"go-reauth-proxy/pkg/models"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

var (
	benchmarkRuleSink          *models.Rule
	benchmarkTargetRuntimeSink reverseProxyTargetRuntime
	benchmarkBytesSink         []byte
	benchmarkHostSink          string
	benchmarkURLSink           *url.URL
)

func TestNewInternalTransportUsesHighIdleConnectionLimits(t *testing.T) {
	transport := newInternalTransport()
	if got, want := transport.MaxIdleConns, 2048; got != want {
		t.Fatalf("MaxIdleConns = %d, want %d", got, want)
	}
	if got, want := transport.MaxIdleConnsPerHost, 2048; got != want {
		t.Fatalf("MaxIdleConnsPerHost = %d, want %d", got, want)
	}
}

func TestShouldRunPreflightForRouteKeepsLegacyDefault(t *testing.T) {
	if !shouldRunPreflightForRoute(false, false, nil, nil) {
		t.Fatalf("unmatched requests should keep the legacy preflight path")
	}
	if !shouldRunPreflightForRoute(true, false, nil, nil) {
		t.Fatalf("select route should run preflight")
	}
	if !shouldRunPreflightForRoute(false, true, nil, nil) {
		t.Fatalf("auth route should run preflight")
	}
	if shouldRunPreflightForRoute(false, false, &models.HostRule{UseAuth: false}, nil) {
		t.Fatalf("host rule with use_auth=false should skip preflight")
	}
	if !shouldRunPreflightForRoute(false, false, &models.HostRule{UseAuth: true}, nil) {
		t.Fatalf("host rule with use_auth=true should run preflight")
	}
	if shouldRunPreflightForRoute(false, false, nil, &models.Rule{UseAuth: false}) {
		t.Fatalf("path rule with use_auth=false should skip preflight")
	}
	if !shouldRunPreflightForRoute(false, false, nil, &models.Rule{UseAuth: true}) {
		t.Fatalf("path rule with use_auth=true should run preflight")
	}
}

func TestNormalizeRequestHostMatchesLegacyBehavior(t *testing.T) {
	cases := []string{
		"",
		" App.Example.COM ",
		"App.Example.COM:443",
		"app.example.com:",
		":8080",
		"app.example.com:abc",
		"2001:db8::1",
		"[2001:db8::1]:443",
		"[2001:db8::1]",
		"[2001:db8::1]trailing",
		"[2001:db8::1",
		"app.example.com:443:extra",
	}

	for _, tc := range cases {
		if got, want := normalizeRequestHost(tc), legacyNormalizeRequestHost(tc); got != want {
			t.Fatalf("normalizeRequestHost(%q) = %q, want legacy %q", tc, got, want)
		}
	}
}

func TestLocalServiceURLMatchesLegacyFormat(t *testing.T) {
	tests := []struct {
		port int
		path string
	}{
		{port: 7999, path: "/auth/check"},
		{port: 7999, path: "auth/check"},
		{port: 1, path: "/"},
		{port: 65535, path: ""},
	}

	for _, tt := range tests {
		if got, want := localServiceURL(tt.port, tt.path), fmt.Sprintf("http://127.0.0.1:%d%s", tt.port, ensureLeadingSlash(tt.path)); got != want {
			t.Fatalf("localServiceURL(%d, %q) = %q, want %q", tt.port, tt.path, got, want)
		}
		if got, want := localServiceBaseURL(tt.port), fmt.Sprintf("http://127.0.0.1:%d", tt.port); got != want {
			t.Fatalf("localServiceBaseURL(%d) = %q, want %q", tt.port, got, want)
		}
		targetURL := localServiceTargetURL(tt.port)
		legacyURL, err := url.Parse(localServiceBaseURL(tt.port))
		if err != nil {
			t.Fatalf("parse legacy local service base URL: %v", err)
		}
		if targetURL.String() != legacyURL.String() || targetURL.Scheme != legacyURL.Scheme || targetURL.Host != legacyURL.Host {
			t.Fatalf("localServiceTargetURL(%d) = %#v, want legacy %#v", tt.port, targetURL, legacyURL)
		}
	}
}

func TestRequestSnapshotIsPublishedImmutableCopy(t *testing.T) {
	handler := &Handler{
		Rules: []models.Rule{
			{Path: "/app", Target: "http://127.0.0.1:8080"},
		},
		HostRules: []models.HostRule{
			{Host: "app.example.com", Target: "http://127.0.0.1:8080"},
		},
		DefaultRoute: "/app",
	}
	handler.publishRequestSnapshotLocked()

	handler.Rules[0].Path = "/mutated"
	handler.HostRules[0].Host = "mutated.example.com"

	snapshot := handler.snapshotForRequest()
	if got := snapshot.rules[0].Path; got != "/app" {
		t.Fatalf("snapshot rule path = %q, want /app", got)
	}
	if got := snapshot.hostRules[0].Host; got != "app.example.com" {
		t.Fatalf("snapshot host rule = %q, want app.example.com", got)
	}
}

func TestGatewayThrottleDedupeKeyMatchesLegacyFormat(t *testing.T) {
	blockedUntil := time.Unix(1760000000, 0)
	ip := "2001:db8::1"
	if got, want := gatewayThrottleDedupeKey(ip, blockedUntil), fmt.Sprintf("gateway-throttle:%s:%d", ip, blockedUntil.Unix()); got != want {
		t.Fatalf("gatewayThrottleDedupeKey() = %q, want %q", got, want)
	}
}

func legacyNormalizeRequestHost(host string) string {
	value := strings.TrimSpace(strings.ToLower(host))
	if value == "" {
		return ""
	}

	if strings.HasPrefix(value, "[") {
		if idx := strings.LastIndex(value, "]"); idx != -1 {
			return value[:idx+1]
		}
	}

	if parsedHost, _, err := net.SplitHostPort(value); err == nil {
		return strings.TrimSpace(strings.ToLower(parsedHost))
	}

	return value
}

func TestMatchHostRuleUsesPublishedHostMap(t *testing.T) {
	handler := &Handler{
		HostRules: []models.HostRule{
			{Host: "app.example.com", Target: "http://127.0.0.1:8080"},
		},
	}
	handler.publishRequestSnapshotLocked()

	req := httptest.NewRequest("GET", "http://fallback.example.com/", nil)
	req.Header.Set("X-Forwarded-Host", "App.Example.COM:443")

	rule := matchHostRule(req, handler.snapshotForRequest())
	if rule == nil {
		t.Fatal("expected host rule match")
	}
	if got := rule.Target; got != "http://127.0.0.1:8080" {
		t.Fatalf("target = %q, want http://127.0.0.1:8080", got)
	}
}

func TestDefaultHostRuleRedirectsUnmatchedHost(t *testing.T) {
	handler := &Handler{
		HostRules: []models.HostRule{
			{
				Host:      "app.example.com",
				Target:    "http://127.0.0.1:8080",
				IsDefault: true,
			},
		},
		DefaultRoute: "/__select__",
	}
	handler.publishRequestSnapshotLocked()

	req := httptest.NewRequest(http.MethodGet, "http://root.example.com:7999/path?q=1", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if got, want := rec.Header().Get("Location"), "http://app.example.com:7999/path?q=1"; got != want {
		t.Fatalf("Location = %q, want %q", got, want)
	}
}

func TestDefaultHostRuleRedirectPreservesMethodForNonGet(t *testing.T) {
	handler := &Handler{
		HostRules: []models.HostRule{
			{
				Host:      "app.example.com",
				Target:    "http://127.0.0.1:8080",
				IsDefault: true,
			},
		},
		DefaultRoute: "/__select__",
	}
	handler.publishRequestSnapshotLocked()

	req := httptest.NewRequest(http.MethodPost, "https://root.example.com/form", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTemporaryRedirect {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if got, want := rec.Header().Get("Location"), "https://app.example.com/form"; got != want {
		t.Fatalf("Location = %q, want %q", got, want)
	}
}

func TestDefaultHostRuleDoesNotRedirectSpecialRoutesOrDefaultHost(t *testing.T) {
	handler := &Handler{
		HostRules: []models.HostRule{
			{
				Host:      "app.example.com",
				Target:    "http://127.0.0.1:8080",
				IsDefault: true,
			},
		},
		DefaultRoute: "/__select__",
	}
	handler.publishRequestSnapshotLocked()

	for _, tc := range []struct {
		name string
		url  string
	}{
		{name: "select", url: "http://root.example.com/__select__"},
		{name: "auth", url: "http://root.example.com/__auth__/login"},
		{name: "default-host", url: "http://app.example.com/missing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.url, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if got := rec.Header().Get("Location"); strings.Contains(got, "app.example.com") {
				t.Fatalf("Location = %q, should not redirect to default host", got)
			}
		})
	}
}

func TestMatchRuleUsesCompiledLongestPrefix(t *testing.T) {
	handler := &Handler{
		Rules: []models.Rule{
			{Path: "/app", Target: "http://127.0.0.1:8080"},
			{Path: "/app/api", Target: "http://127.0.0.1:8081"},
		},
	}
	handler.publishRequestSnapshotLocked()

	req := httptest.NewRequest(http.MethodGet, "http://example.com/app/api/users", nil)
	rule, redirect := matchRule(req, handler.snapshotForRequest())
	if redirect != "" {
		t.Fatalf("redirect = %q, want empty", redirect)
	}
	if rule == nil {
		t.Fatal("expected path rule match")
	}
	if got := rule.Path; got != "/app/api" {
		t.Fatalf("path = %q, want /app/api", got)
	}
}

func TestMatchRulePreservesNonBoundaryPrefixBehavior(t *testing.T) {
	handler := &Handler{
		Rules: []models.Rule{
			{Path: "/app", Target: "http://127.0.0.1:8080"},
			{Path: "/app-001", Target: "http://127.0.0.1:8081"},
		},
	}
	handler.publishRequestSnapshotLocked()

	req := httptest.NewRequest(http.MethodGet, "http://example.com/app-001-assets/main.js", nil)
	rule, redirect := matchRule(req, handler.snapshotForRequest())
	if redirect != "" {
		t.Fatalf("redirect = %q, want empty", redirect)
	}
	if rule == nil {
		t.Fatal("expected path rule match")
	}
	if got := rule.Path; got != "/app-001" {
		t.Fatalf("path = %q, want /app-001", got)
	}
}

func TestMatchRuleUsesCompiledSlashRedirect(t *testing.T) {
	handler := &Handler{
		Rules: []models.Rule{
			{Path: "/app/", Target: "http://127.0.0.1:8080"},
		},
	}
	handler.publishRequestSnapshotLocked()

	req := httptest.NewRequest(http.MethodGet, "http://example.com/app", nil)
	rule, redirect := matchRule(req, handler.snapshotForRequest())
	if rule != nil {
		t.Fatalf("rule = %#v, want nil while redirecting", rule)
	}
	if redirect != "/app/" {
		t.Fatalf("redirect = %q, want /app/", redirect)
	}
}

func TestRequestSnapshotCachesReverseProxyTargets(t *testing.T) {
	handler := &Handler{
		Rules: []models.Rule{
			{Path: "/web", Target: "http://127.0.0.1:8088"},
			{Path: "/app", Target: "ws://127.0.0.1:8080/socket"},
			{Path: "/broken", Target: "ftp://127.0.0.1:21"},
		},
		HostRules: []models.HostRule{
			{
				Host:   "app.example.com",
				Target: "https://127.0.0.1:9443",
				Locations: []models.HostLocation{
					{Path: "/api", Match: models.HostLocationMatchPrefix, Action: models.HostLocationActionProxy, Target: "wss://127.0.0.1:9444/ws"},
					{Path: "/healthz", Match: models.HostLocationMatchExact, Action: models.HostLocationActionResponse},
				},
			},
			{Host: "socket.example.com", Target: "wss://127.0.0.1:9445/ws"},
		},
	}
	handler.publishRequestSnapshotLocked()

	snapshot := handler.snapshotForRequest()
	pathRuntime := reverseProxyTargetRuntimeFor(snapshot, "ws://127.0.0.1:8080/socket")
	if pathRuntime.err != nil {
		t.Fatalf("path target runtime error = %v", pathRuntime.err)
	}
	if got := pathRuntime.transportURL.Scheme; got != "http" {
		t.Fatalf("path transport scheme = %q, want http", got)
	}
	if pathRuntime.supportsHTMLFeatures {
		t.Fatalf("websocket target should not support HTML features")
	}

	hostRuntime := reverseProxyTargetRuntimeFor(snapshot, "https://127.0.0.1:9443")
	if hostRuntime.err != nil {
		t.Fatalf("host target runtime error = %v", hostRuntime.err)
	}
	if !hostRuntime.supportsHTMLFeatures {
		t.Fatalf("https target should support HTML features")
	}

	locationRuntime := reverseProxyTargetRuntimeFor(snapshot, "wss://127.0.0.1:9444/ws")
	if locationRuntime.err != nil {
		t.Fatalf("location target runtime error = %v", locationRuntime.err)
	}
	if got := locationRuntime.transportURL.Scheme; got != "https" {
		t.Fatalf("location transport scheme = %q, want https", got)
	}

	invalidRuntime := reverseProxyTargetRuntimeFor(snapshot, "ftp://127.0.0.1:21")
	if invalidRuntime.err == nil {
		t.Fatalf("invalid target runtime error = nil, want error")
	}
	if len(snapshot.toolbarRules) != 1 || snapshot.toolbarRules[0].Path != "/web" {
		t.Fatalf("toolbar path rules = %#v, want only /web", snapshot.toolbarRules)
	}
	if len(snapshot.toolbarHostRules) != 1 || snapshot.toolbarHostRules[0].Host != "app.example.com" {
		t.Fatalf("toolbar host rules = %#v, want only app.example.com", snapshot.toolbarHostRules)
	}
}

func TestAddProxyPathCookieIfChangedSkipsCurrentCookie(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/app/", nil)
	req.AddCookie(&http.Cookie{Name: proxyPathCookieName, Value: "/app"})
	resp := &http.Response{Header: http.Header{}}

	addProxyPathCookieIfChanged(resp, req, "/app")

	if values := resp.Header.Values("Set-Cookie"); len(values) != 0 {
		t.Fatalf("Set-Cookie values = %#v, want none", values)
	}
}

func TestAddProxyPathCookieIfChangedAddsMissingCookie(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/app/", nil)
	resp := &http.Response{Header: http.Header{}}

	addProxyPathCookieIfChanged(resp, req, "/app")

	values := resp.Header.Values("Set-Cookie")
	if len(values) != 1 {
		t.Fatalf("Set-Cookie count = %d, want 1: %#v", len(values), values)
	}
	if !strings.Contains(values[0], proxyPathCookieName+"=/app") {
		t.Fatalf("Set-Cookie = %q, want proxy path cookie", values[0])
	}
}

func TestAddProxyPathCookieIfChangedStripsUpstreamProxyPathCookie(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/app/", nil)
	req.AddCookie(&http.Cookie{Name: proxyPathCookieName, Value: "/app"})
	resp := &http.Response{Header: http.Header{}}
	resp.Header.Add("Set-Cookie", "session_id=abc; Path=/; HttpOnly")
	resp.Header.Add("Set-Cookie", proxyPathCookieName+"=/other; Path=/")

	addProxyPathCookieIfChanged(resp, req, "/app")

	values := resp.Header.Values("Set-Cookie")
	if len(values) != 1 {
		t.Fatalf("Set-Cookie count = %d, want only upstream session cookie: %#v", len(values), values)
	}
	if values[0] != "session_id=abc; Path=/; HttpOnly" {
		t.Fatalf("Set-Cookie = %#v, want only upstream session cookie", values)
	}
}

func TestAddProxyPathCookieIfChangedReplacesUpstreamProxyPathCookie(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/app/", nil)
	resp := &http.Response{Header: http.Header{}}
	resp.Header.Add("Set-Cookie", "session_id=abc; Path=/; HttpOnly")
	resp.Header.Add("Set-Cookie", proxyPathCookieName+"=/other; Path=/")

	addProxyPathCookieIfChanged(resp, req, "/app")

	values := resp.Header.Values("Set-Cookie")
	if len(values) != 2 {
		t.Fatalf("Set-Cookie count = %d, want session plus proxy path cookie: %#v", len(values), values)
	}
	if values[0] != "session_id=abc; Path=/; HttpOnly" {
		t.Fatalf("first Set-Cookie = %q, want upstream session cookie", values[0])
	}
	if !strings.Contains(values[1], proxyPathCookieName+"=/app") {
		t.Fatalf("second Set-Cookie = %q, want canonical proxy path cookie", values[1])
	}
}

func TestRewriteHTMLAbsolutePathsUsesBytes(t *testing.T) {
	body := []byte(`<html><a href="/home"><img src="/logo.png"><form action="/save"><base href="/"></form></html>`)

	got := string(rewriteHTMLAbsolutePaths(body, "/app"))

	for _, want := range []string{
		`href="/app/home"`,
		`src="/app/logo.png"`,
		`action="/app/save"`,
		`<base href="/app/">`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("rewritten HTML %q does not contain %q", got, want)
		}
	}
}

func TestRewriteHTMLAbsolutePathsReturnsOriginalWhenUnchanged(t *testing.T) {
	body := []byte(`<html><a href="relative">relative</a></html>`)
	got := rewriteHTMLAbsolutePaths(body, "/app")

	if len(got) == 0 || &got[0] != &body[0] {
		t.Fatalf("rewrite returned a copied slice when no absolute paths changed")
	}
}

func TestInjectToolbarIntoHTMLBytesFindsBodyCaseInsensitively(t *testing.T) {
	body := []byte(`<HTML><BODY>content</BODY></HTML>`)

	got := string(injectToolbarIntoHTMLBytes(body, `<script>toolbar()</script>`))

	if !strings.Contains(got, `content<script>toolbar()</script></BODY>`) {
		t.Fatalf("injected HTML = %q", got)
	}
}

func TestInjectToolbarIntoHTMLBytesAppendsForHTMLWithoutBodyClose(t *testing.T) {
	body := []byte(`<!doctype html><html><head></head>`)

	got := string(injectToolbarIntoHTMLBytes(body, `<script>toolbar()</script>`))

	if !strings.HasSuffix(got, `<script>toolbar()</script>`) {
		t.Fatalf("injected HTML = %q, want toolbar appended", got)
	}
}

func TestInjectToolbarIntoHTMLBytesReturnsOriginalForNonHTML(t *testing.T) {
	body := []byte(`plain text response`)
	got := injectToolbarIntoHTMLBytes(body, `<script>toolbar()</script>`)

	if len(got) == 0 || &got[0] != &body[0] {
		t.Fatalf("inject returned a copied slice for non-HTML body")
	}
}

func TestIsHTMLContentType(t *testing.T) {
	tests := []struct {
		contentType string
		want        bool
	}{
		{contentType: "text/html", want: true},
		{contentType: "Text/HTML; charset=utf-8", want: true},
		{contentType: "application/xhtml+xml", want: false},
		{contentType: "application/json", want: false},
		{contentType: "", want: false},
	}

	for _, tt := range tests {
		if got := isHTMLContentType(tt.contentType); got != tt.want {
			t.Fatalf("isHTMLContentType(%q) = %v, want %v", tt.contentType, got, tt.want)
		}
	}
}

func makeRewriteBenchmarkHTML(repeat int) []byte {
	var b strings.Builder
	b.Grow(repeat * 160)
	b.WriteString(`<!doctype html><html><head><base href="/"></head><body>`)
	for i := 0; i < repeat; i++ {
		b.WriteString(`<a href="/home">home</a><img src="/logo.png"><form action="/save"></form>`)
	}
	b.WriteString(`</body></html>`)
	return []byte(b.String())
}

func rewriteHTMLAbsolutePathsReplaceAllForBenchmark(body []byte, prefix string) []byte {
	replacements := []struct {
		old []byte
		new []byte
	}{
		{[]byte(`href="/`), []byte(`href="` + prefix + `/`)},
		{[]byte(`src="/`), []byte(`src="` + prefix + `/`)},
		{[]byte(`action="/`), []byte(`action="` + prefix + `/`)},
		{[]byte(`<base href="/">`), []byte(`<base href="` + prefix + `/">`)},
	}

	for _, rep := range replacements {
		body = bytes.ReplaceAll(body, rep.old, rep.new)
	}
	return body
}

func injectToolbarIntoHTMLBytesOldForBenchmark(body []byte, toolbarHTML string) []byte {
	if toolbarHTML == "" || len(body) == 0 {
		return body
	}

	toolbar := []byte(toolbarHTML)
	if idx := lastIndexFoldASCII(body, htmlBodyCloseMarker); idx != -1 {
		out := make([]byte, 0, len(body)+len(toolbar))
		out = append(out, body[:idx]...)
		out = append(out, toolbar...)
		out = append(out, body[idx:]...)
		return out
	}

	if containsFoldASCIIForBenchmark(body, htmlStartMarker) ||
		containsFoldASCIIForBenchmark(body, htmlHeadMarker) ||
		containsFoldASCIIForBenchmark(body, htmlBodyStartMarker) ||
		containsFoldASCIIForBenchmark(body, htmlDoctypeMarker) {
		return append(body, toolbar...)
	}

	return body
}

func containsFoldASCIIForBenchmark(s []byte, substr []byte) bool {
	if len(substr) == 0 {
		return true
	}
	if len(substr) > len(s) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if equalFoldASCIIBytes(s[i:i+len(substr)], substr) {
			return true
		}
	}
	return false
}

func BenchmarkRewriteHTMLAbsolutePaths(b *testing.B) {
	body := makeRewriteBenchmarkHTML(256)

	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	for b.Loop() {
		benchmarkBytesSink = rewriteHTMLAbsolutePaths(body, "/app")
	}
}

func BenchmarkRewriteHTMLAbsolutePathsReplaceAll(b *testing.B) {
	body := makeRewriteBenchmarkHTML(256)

	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	for b.Loop() {
		benchmarkBytesSink = rewriteHTMLAbsolutePathsReplaceAllForBenchmark(body, "/app")
	}
}

func BenchmarkInjectToolbarIntoNonHTMLBytes(b *testing.B) {
	body := []byte(strings.Repeat("plain text response\n", 4096))
	toolbar := `<script>toolbar()</script>`

	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	for b.Loop() {
		benchmarkBytesSink = injectToolbarIntoHTMLBytes(body, toolbar)
	}
}

func BenchmarkInjectToolbarIntoNonHTMLBytesOld(b *testing.B) {
	body := []byte(strings.Repeat("plain text response\n", 4096))
	toolbar := `<script>toolbar()</script>`

	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	for b.Loop() {
		benchmarkBytesSink = injectToolbarIntoHTMLBytesOldForBenchmark(body, toolbar)
	}
}

func BenchmarkInjectToolbarIntoHTMLWithoutBodyClose(b *testing.B) {
	body := []byte(`<!doctype html><html><head></head>` + strings.Repeat(`<p>content</p>`, 4096))
	toolbar := `<script>toolbar()</script>`

	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	for b.Loop() {
		benchmarkBytesSink = injectToolbarIntoHTMLBytes(body, toolbar)
	}
}

func BenchmarkInjectToolbarIntoHTMLWithoutBodyCloseOld(b *testing.B) {
	body := []byte(`<!doctype html><html><head></head>` + strings.Repeat(`<p>content</p>`, 4096))
	toolbar := `<script>toolbar()</script>`

	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	for b.Loop() {
		benchmarkBytesSink = injectToolbarIntoHTMLBytesOldForBenchmark(body, toolbar)
	}
}

func BenchmarkIsHTMLContentType(b *testing.B) {
	contentType := "Text/HTML; charset=utf-8"

	b.ReportAllocs()
	for b.Loop() {
		benchmarkBoolSink = isHTMLContentType(contentType)
	}
}

func BenchmarkIsHTMLContentTypeToLower(b *testing.B) {
	contentType := "Text/HTML; charset=utf-8"

	b.ReportAllocs()
	for b.Loop() {
		benchmarkBoolSink = strings.Contains(strings.ToLower(contentType), "text/html")
	}
}

func BenchmarkNormalizeRequestHostNoPort(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		benchmarkHostSink = normalizeRequestHost("app.example.com")
	}
}

func BenchmarkNormalizeRequestHostWithPort(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		benchmarkHostSink = normalizeRequestHost("App.Example.COM:443")
	}
}

func BenchmarkNormalizeRequestHostLowercaseWithPort(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		benchmarkHostSink = normalizeRequestHost("app.example.com:443")
	}
}

func BenchmarkLocalServiceBaseURL(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		benchmarkHostSink = localServiceBaseURL(7999)
	}
}

func BenchmarkLocalServiceBaseURLOld(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		benchmarkHostSink = fmt.Sprintf("http://127.0.0.1:%d", 7999)
	}
}

func BenchmarkLocalServiceURL(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		benchmarkHostSink = localServiceURL(7999, "/api/auth/check")
	}
}

func BenchmarkLocalServiceURLOld(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		benchmarkHostSink = fmt.Sprintf("http://127.0.0.1:%d%s", 7999, ensureLeadingSlash("/api/auth/check"))
	}
}

func BenchmarkLocalServiceTargetURL(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		benchmarkURLSink = localServiceTargetURL(7999)
	}
}

func BenchmarkLocalServiceTargetURLOld(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		targetURL, _ := url.Parse(localServiceBaseURL(7999))
		benchmarkURLSink = targetURL
	}
}

func BenchmarkGatewayThrottleDedupeKey(b *testing.B) {
	blockedUntil := time.Unix(1760000000, 0)
	b.ReportAllocs()
	for b.Loop() {
		benchmarkHostSink = gatewayThrottleDedupeKey("198.51.100.10", blockedUntil)
	}
}

func BenchmarkGatewayThrottleDedupeKeyOld(b *testing.B) {
	blockedUntil := time.Unix(1760000000, 0)
	b.ReportAllocs()
	for b.Loop() {
		benchmarkHostSink = fmt.Sprintf("gateway-throttle:%s:%d", "198.51.100.10", blockedUntil.Unix())
	}
}

func BenchmarkPathRuleRouteRuntimeLookup(b *testing.B) {
	rules := make([]models.Rule, 128)
	for i := range rules {
		rules[i] = models.Rule{
			Path:        fmt.Sprintf("/app-%03d", i),
			Target:      fmt.Sprintf("http://127.0.0.1:%d/base", 9000+i),
			RewriteHTML: true,
		}
	}
	rules = append(rules, models.Rule{
		Path:        "/app",
		Target:      "http://127.0.0.1:9999/base",
		RewriteHTML: true,
	})

	handler := &Handler{Rules: rules}
	handler.publishRequestSnapshotLocked()
	snapshot := handler.snapshotForRequest()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/app/assets/main.js?cache=1", nil)

	b.ReportAllocs()
	for b.Loop() {
		rule, redirect := matchRule(req, snapshot)
		if redirect != "" || rule == nil {
			b.Fatalf("matchRule returned rule=%#v redirect=%q", rule, redirect)
		}
		runtime := reverseProxyTargetRuntimeFor(snapshot, rule.Target)
		if runtime.err != nil || runtime.transportURL == nil || !runtime.supportsHTMLFeatures {
			b.Fatalf("target runtime = %#v, err=%v", runtime, runtime.err)
		}
		benchmarkRuleSink = rule
		benchmarkTargetRuntimeSink = runtime
	}
}

func BenchmarkPathRuleLongestPrefixLookup(b *testing.B) {
	snapshot := pathRuleBenchmarkSnapshot()
	requestPath := "/app/assets/main.js"

	b.ReportAllocs()
	for b.Loop() {
		rule, longest := longestPathRuleMatch(requestPath, snapshot)
		if rule == nil || longest == 0 {
			b.Fatalf("longestPathRuleMatch returned rule=%#v longest=%d", rule, longest)
		}
		benchmarkRuleSink = rule
	}
}

func BenchmarkPathRuleLongestPrefixLookupOld(b *testing.B) {
	snapshot := pathRuleBenchmarkSnapshot()
	rulesByLength := snapshot.rulesByLength
	requestPath := "/app/assets/main.js"

	b.ReportAllocs()
	for b.Loop() {
		rule, longest := longestPathRuleMatchOldForBenchmark(requestPath, rulesByLength)
		if rule == nil || longest == 0 {
			b.Fatalf("old match returned rule=%#v longest=%d", rule, longest)
		}
		benchmarkRuleSink = rule
	}
}

func pathRuleBenchmarkSnapshot() requestSnapshot {
	rules := make([]models.Rule, 128)
	for i := range rules {
		rules[i] = models.Rule{
			Path:   fmt.Sprintf("/app-%03d", i),
			Target: fmt.Sprintf("http://127.0.0.1:%d/base", 9000+i),
		}
	}
	rules = append(rules, models.Rule{
		Path:   "/app",
		Target: "http://127.0.0.1:9999/base",
	})
	handler := &Handler{Rules: rules}
	handler.publishRequestSnapshotLocked()
	return handler.snapshotForRequest()
}

func longestPathRuleMatchOldForBenchmark(requestPath string, rulesByLength []models.Rule) (*models.Rule, int) {
	for i := range rulesByLength {
		rule := &rulesByLength[i]
		if rule.Path != "" && strings.HasPrefix(requestPath, rule.Path) {
			return rule, len(rule.Path)
		}
	}
	return nil, 0
}
