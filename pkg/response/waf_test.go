package response

import (
	"bytes"
	"encoding/json"
	"go-reauth-proxy/pkg/i18n"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

var wafBenchmarkBoolSink bool

func TestWAFBlockedJSONResponse(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.test/search", nil)
	req.Header.Set("Accept", "Application/JSON")
	rec := httptest.NewRecorder()

	WAFBlocked(rec, req, WAFBlockPageOptions{
		Status:  http.StatusForbidden,
		TraceID: "waf_test_trace",
	})

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d", rec.Code)
	}
	if rec.Header().Get("X-Fn-Knock-WAF-Blocked") != "1" {
		t.Fatalf("missing WAF blocked header")
	}
	if rec.Header().Get("X-Fn-Knock-WAF-Trace-ID") != "waf_test_trace" {
		t.Fatalf("missing trace header")
	}
	var body struct {
		Success bool   `json:"success"`
		Code    string `json:"code"`
		Message string `json:"message"`
		TraceID string `json:"trace_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.Success ||
		body.Code != "WAF_BLOCKED" ||
		body.Message != "请求已被 WAF 拦截" ||
		body.TraceID != "waf_test_trace" {
		t.Fatalf("unexpected body: %#v", body)
	}
	if rec.Header().Get("Content-Language") != "zh-CN" {
		t.Fatalf("unexpected content language: %q", rec.Header().Get("Content-Language"))
	}
}

func TestAppendWAFBlockedJSONMatchesEncodingJSON(t *testing.T) {
	tests := []struct {
		name    string
		message string
		traceID string
	}{
		{name: "plain", message: "Request blocked", traceID: "waf_trace"},
		{name: "html escaped", message: "<blocked>&denied", traceID: "waf_<trace>&"},
		{name: "controls", message: "line\nnext\t\u0001", traceID: "trace\rid"},
		{name: "unicode separators", message: "line\u2028para\u2029", traceID: "trace\u2028id"},
		{name: "invalid utf8", message: string([]byte{'b', 'a', 'd', 0xff}), traceID: string([]byte{'i', 'd', 0xff})},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := appendWAFBlockedJSON(nil, tt.message, tt.traceID)
			want := legacyWAFBlockedJSONForBenchmark(tt.message, tt.traceID)
			if !bytes.Equal(got, want) {
				t.Fatalf("JSON mismatch\ngot:  %s\nwant: %s", got, want)
			}
		})
	}
}

func TestWantsJSONPrefersHTML(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.test/search", nil)
	req.Header.Set("Accept", "text/html, application/json")

	if wantsJSON(req) {
		t.Fatal("wantsJSON() = true, want false when text/html is accepted")
	}
}

func BenchmarkWantsJSON(b *testing.B) {
	req := httptest.NewRequest(http.MethodGet, "http://example.test/search", nil)
	req.Header.Set("Accept", "Application/JSON")

	b.ReportAllocs()
	for b.Loop() {
		wafBenchmarkBoolSink = wantsJSON(req)
	}
}

func BenchmarkWantsJSONToLower(b *testing.B) {
	req := httptest.NewRequest(http.MethodGet, "http://example.test/search", nil)
	req.Header.Set("Accept", "Application/JSON")

	b.ReportAllocs()
	for b.Loop() {
		accept := strings.ToLower(req.Header.Get("Accept"))
		wafBenchmarkBoolSink = strings.Contains(accept, "application/json") && !strings.Contains(accept, "text/html")
	}
}

func BenchmarkAppendWAFBlockedJSON(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		responseBenchmarkBytesSink = appendWAFBlockedJSON(nil, "Request blocked by WAF", "waf_test_trace")
	}
}

func BenchmarkAppendWAFBlockedJSONOld(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		responseBenchmarkBytesSink = legacyWAFBlockedJSONForBenchmark("Request blocked by WAF", "waf_test_trace")
	}
}

func legacyWAFBlockedJSONForBenchmark(message string, traceID string) []byte {
	var buf bytes.Buffer
	_ = json.NewEncoder(&buf).Encode(struct {
		Success bool   `json:"success"`
		Code    string `json:"code"`
		Message string `json:"message"`
		TraceID string `json:"trace_id"`
	}{
		Success: false,
		Code:    "WAF_BLOCKED",
		Message: message,
		TraceID: traceID,
	})
	return buf.Bytes()
}

func TestWAFBlockedHTMLResponse(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.test/search", nil)
	req.Header.Set("Accept", "text/html")
	rec := httptest.NewRecorder()

	WAFBlocked(rec, req, WAFBlockPageOptions{
		Status:  http.StatusTeapot,
		TraceID: "waf_html_trace",
	})

	if rec.Code != http.StatusTeapot {
		t.Fatalf("expected status 418, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "请求已拦截") ||
		!strings.Contains(body, "访问被安全策略拒绝。") ||
		!strings.Contains(body, "waf_html_trace") {
		t.Fatalf("expected title and trace in HTML body: %s", body)
	}
	if strings.Contains(body, "/__assets__/") {
		t.Fatalf("WAF block page must not depend on gateway asset requests: %s", body)
	}
	if got := strings.Count(body, "data:image/png;base64,"); got != 2 {
		t.Fatalf("expected embedded page icon and logo, got %d data URLs", got)
	}
}

func TestWAFBlockedHTMLResponseUsesGlobalDefaultLocale(t *testing.T) {
	i18n.SetDefaultLocale(i18n.LocaleEn)
	t.Cleanup(func() {
		i18n.SetDefaultLocale(i18n.DefaultLocale)
	})

	req := httptest.NewRequest(http.MethodGet, "http://example.test/search", nil)
	req.Header.Set("Accept", "text/html")
	req.Header.Set("X-Fn-Knock-Locale", "zh-CN")
	rec := httptest.NewRecorder()

	WAFBlocked(rec, req, WAFBlockPageOptions{
		Status:  http.StatusForbidden,
		TraceID: "waf_en_trace",
	})

	body := rec.Body.String()
	if rec.Header().Get("Content-Language") != "en" {
		t.Fatalf("unexpected content language: %q", rec.Header().Get("Content-Language"))
	}
	if !strings.Contains(body, "Request blocked") ||
		!strings.Contains(body, "Access denied by security policy.") ||
		!strings.Contains(body, "waf_en_trace") {
		t.Fatalf("expected English WAF body: %s", body)
	}
}

func TestEmbeddedFaviconDataURLOnlyAcceptsEmbeddedImages(t *testing.T) {
	if got := embeddedFaviconDataURL("/__assets__/favicon/favicon-32x32.png"); !strings.HasPrefix(string(got), "data:image/png;base64,") {
		t.Fatalf("unexpected embedded favicon data URL: %q", got)
	}
	if got := embeddedFaviconDataURL("/__assets__/favicon/site.webmanifest"); got != "" {
		t.Fatalf("manifest must not be exposed as an image data URL: %q", got)
	}
	if got := embeddedFaviconDataURL("/__assets__/favicon/missing.png"); got != "" {
		t.Fatalf("unknown favicon path must not produce a data URL: %q", got)
	}
}
