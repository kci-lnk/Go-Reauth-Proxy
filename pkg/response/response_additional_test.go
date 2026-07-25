package response

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	proxyerrors "go-reauth-proxy/pkg/errors"
	"go-reauth-proxy/pkg/i18n"
	"go-reauth-proxy/pkg/models"
	"go-reauth-proxy/pkg/version"
)

func TestJSONWithDataEncodesPayload(t *testing.T) {
	rec := httptest.NewRecorder()

	JSON(rec, true, 201, "created", map[string]string{"id": "route-1"})

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body struct {
		Success bool              `json:"success"`
		Code    int               `json:"code"`
		Message string            `json:"message"`
		Data    map[string]string `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !body.Success || body.Code != 201 || body.Message != "created" || body.Data["id"] != "route-1" {
		t.Fatalf("unexpected response body: %#v", body)
	}
}

func TestSuccessWithNilDataWritesSuccessEnvelope(t *testing.T) {
	rec := httptest.NewRecorder()

	Success(rec, nil)

	var body Response
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !body.Success || body.Code != http.StatusOK || body.Message == "" || body.Data != nil {
		t.Fatalf("unexpected response body: %#v", body)
	}
}

func TestErrorWritesApplicationEnvelope(t *testing.T) {
	rec := httptest.NewRecorder()

	Error(rec, proxyerrors.CodeBadRequest, "bad request")

	var body Response
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Success || body.Code != proxyerrors.CodeBadRequest || body.Message != "bad request" || body.Data != nil {
		t.Fatalf("unexpected error envelope: %#v", body)
	}
}

func TestAppendJSONResponseNoDataReusesProvidedBuffer(t *testing.T) {
	buf := make([]byte, 0, 512)
	backing := buf[:cap(buf)]

	got := appendJSONResponseNoData(buf, true, 200, "ok", 42)

	if len(got) == 0 {
		t.Fatal("response is empty")
	}
	if &got[0] != &backing[0] {
		t.Fatal("appendJSONResponseNoData did not reuse provided buffer")
	}
}

func TestAppendJSONResponseNoDataAllocatesForZeroCap(t *testing.T) {
	got := appendJSONResponseNoData(nil, false, 500, "boom", 99)

	if !json.Valid(got) {
		t.Fatalf("response is not valid JSON: %s", got)
	}
}

func TestAppendJSONStringPlainASCII(t *testing.T) {
	got := string(appendJSONString(nil, "plain ascii"))

	if got != `"plain ascii"` {
		t.Fatalf("appendJSONString = %q", got)
	}
}

func TestAppendJSONStringEscapesQuoteAndBackslash(t *testing.T) {
	got := string(appendJSONString(nil, `bad "token" \ path`))

	if got != `"bad \"token\" \\ path"` {
		t.Fatalf("appendJSONString = %q", got)
	}
}

func TestAppendJSONStringEscapesHTMLRunes(t *testing.T) {
	got := string(appendJSONString(nil, "<tag>&"))

	if got != `"\u003ctag\u003e\u0026"` {
		t.Fatalf("appendJSONString = %q", got)
	}
}

func TestAppendJSONStringEscapesControlRunes(t *testing.T) {
	got := string(appendJSONString(nil, "line\n\t\u0001"))

	if got != `"line\n\t\u0001"` {
		t.Fatalf("appendJSONString = %q", got)
	}
}

func TestAppendJSONStringEscapesUnicodeSeparators(t *testing.T) {
	got := string(appendJSONString(nil, "line\u2028para\u2029"))

	if got != `"line\u2028para\u2029"` {
		t.Fatalf("appendJSONString = %q", got)
	}
}

func TestAppendJSONStringReplacesInvalidUTF8(t *testing.T) {
	got := string(appendJSONString(nil, string([]byte{'o', 'k', 0xff})))

	if got != `"ok\ufffd"` {
		t.Fatalf("appendJSONString = %q", got)
	}
}

func TestAppendJSONStringAppendsToExistingBuffer(t *testing.T) {
	got := string(appendJSONString([]byte("prefix:"), "value"))

	if got != `prefix:"value"` {
		t.Fatalf("appendJSONString with prefix = %q", got)
	}
}

func TestBuildPageDataNilRequestHasStableDefaults(t *testing.T) {
	data := buildPageData(nil, nil)

	if data.RequestHost != "" || data.RequestPath != "" {
		t.Fatalf("unexpected request fields: host=%q path=%q", data.RequestHost, data.RequestPath)
	}
	if data.Version != version.Version || data.Labels["logout"] == "" || data.HTMLLang == "" {
		t.Fatalf("missing default page fields: %#v", data)
	}
}

func TestBuildPageDataCapturesHostPathAndQuery(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://app.example.test/private/path?x=1", nil)

	data := buildPageData(req, nil)

	if data.RequestHost != "app.example.test" || data.RequestPath != "/private/path?x=1" {
		t.Fatalf("unexpected request target: host=%q path=%q", data.RequestHost, data.RequestPath)
	}
}

func TestBuildPageDataIncludesToolbarForRules(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://gateway.example.test/app", nil)

	data := buildPageData(req, []models.Rule{{Path: "/app", Target: "http://127.0.0.1:3000"}})

	if !strings.Contains(string(data.ToolbarHTML), "reauth-proxy-toolbar") {
		t.Fatalf("toolbar HTML missing: %s", data.ToolbarHTML)
	}
}

func TestBuildPageDataSuppressesToolbarForFNOS(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://gateway.example.test/app", nil)
	req.Header.Set("User-Agent", "FNOS Browser")

	data := buildPageData(req, []models.Rule{{Path: "/app", Target: "http://127.0.0.1:3000"}})

	if data.ToolbarHTML != "" {
		t.Fatalf("toolbar should be suppressed for FNOS user agent: %s", data.ToolbarHTML)
	}
}

func TestHTMLUsesExplicitHTTPStatusInRange(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://gateway.example.test/teapot", nil)
	rec := httptest.NewRecorder()

	HTML(rec, req, http.StatusTeapot, "short and stout", nil)

	if rec.Code != http.StatusTeapot {
		t.Fatalf("status = %d, want 418", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "short and stout") {
		t.Fatalf("body missing message: %s", rec.Body.String())
	}
}

func TestHTMLMapsProxyAuthFailureToBadGateway(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://gateway.example.test/auth", nil)
	rec := httptest.NewRecorder()

	HTML(rec, req, proxyerrors.CodeProxyAuthFailed, "auth bridge failed", nil)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
}

func TestHTMLMapsProxyTimeoutToGatewayTimeout(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://gateway.example.test/slow", nil)
	rec := httptest.NewRecorder()

	HTML(rec, req, proxyerrors.CodeProxyTimeout, "upstream timeout", nil)

	if rec.Code != http.StatusGatewayTimeout {
		t.Fatalf("status = %d, want 504", rec.Code)
	}
}

func TestHTMLSetsContentLanguageFromRequest(t *testing.T) {
	i18n.SetDefaultLocale(i18n.LocaleEn)
	t.Cleanup(func() {
		i18n.SetDefaultLocale(i18n.DefaultLocale)
	})

	req := httptest.NewRequest(http.MethodGet, "http://gateway.example.test/", nil)
	rec := httptest.NewRecorder()

	HTML(rec, req, proxyerrors.CodeUnauthorized, "login required", nil)

	if rec.Header().Get("Content-Language") != i18n.LocaleEn {
		t.Fatalf("content language = %q", rec.Header().Get("Content-Language"))
	}
}

func TestHTMLHidesSelectLinkByDefault(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://gateway.example.test/app", nil)
	rec := httptest.NewRecorder()

	HTML(rec, req, proxyerrors.CodeProxyTimeout, "upstream timeout", []models.Rule{{Path: "/app"}})

	body := rec.Body.String()
	if strings.Contains(body, "/__select__") {
		t.Fatalf("anonymous error page should not include select link: %s", body)
	}
	if strings.Contains(body, "reauth-proxy-toolbar") {
		t.Fatalf("anonymous error page should not include route toolbar: %s", body)
	}
}

func TestHTMLWithSelectLinkShowsLinkForAuthenticatedRequest(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://gateway.example.test/app", nil)
	rec := httptest.NewRecorder()

	HTMLWithSelectLink(rec, req, proxyerrors.CodeProxyTimeout, "upstream timeout", nil, true)

	if body := rec.Body.String(); !strings.Contains(body, "/__select__") {
		t.Fatalf("authenticated error page should include select link: %s", body)
	}
}

func TestWelcomeDoesNotShowBackLink(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://gateway.example.test/", nil)
	rec := httptest.NewRecorder()

	Welcome(rec, req, []models.Rule{{Path: "/app"}})

	if strings.Contains(rec.Body.String(), "/__select__") {
		t.Fatalf("welcome should not include select link: %s", rec.Body.String())
	}
}

func TestRouteNotFoundShowsBackLinkForAuthenticatedRequest(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://gateway.example.test/missing", nil)
	rec := httptest.NewRecorder()

	RouteNotFound(rec, req, []models.Rule{{Path: "/app"}}, true)

	if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "/__select__") {
		t.Fatalf("unexpected route-not-found page: status=%d body=%s", rec.Code, rec.Body.String())
	}
	if cacheControl := rec.Header().Get("Cache-Control"); !strings.Contains(cacheControl, "no-store") {
		t.Fatalf("Cache-Control = %q, want no-store", cacheControl)
	}
}

func TestRouteNotFoundHidesNavigationForAnonymousRequest(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://gateway.example.test/missing", nil)
	rec := httptest.NewRecorder()

	RouteNotFound(rec, req, []models.Rule{{Path: "/private-app"}}, false)

	body := rec.Body.String()
	if strings.Contains(body, "/__select__") || strings.Contains(body, "/private-app") || strings.Contains(body, "reauth-proxy-toolbar") {
		t.Fatalf("anonymous route-not-found page exposed protected navigation: %s", body)
	}
}

func TestGatewayLabelsContainTraceIDLabel(t *testing.T) {
	labels := gatewayLabels(i18n.LocaleEn)

	if labels["traceId"] == "" || labels["confirm"] == "" || labels["cancel"] == "" {
		t.Fatalf("missing gateway labels: %#v", labels)
	}
}

func TestMapHTTPStatusRejectsTooLowStatus(t *testing.T) {
	if got := mapHTTPStatus(199); got != http.StatusInternalServerError {
		t.Fatalf("mapHTTPStatus(199) = %d", got)
	}
}

func TestMapHTTPStatusRejectsTooHighStatus(t *testing.T) {
	if got := mapHTTPStatus(600); got != http.StatusInternalServerError {
		t.Fatalf("mapHTTPStatus(600) = %d", got)
	}
}

func TestMapHTTPStatusMapsUnauthorized(t *testing.T) {
	if got := mapHTTPStatus(proxyerrors.CodeUnauthorized); got != http.StatusUnauthorized {
		t.Fatalf("mapHTTPStatus(CodeUnauthorized) = %d", got)
	}
}

func TestMapHTTPStatusMapsNotFound(t *testing.T) {
	if got := mapHTTPStatus(proxyerrors.CodeNotFound); got != http.StatusNotFound {
		t.Fatalf("mapHTTPStatus(CodeNotFound) = %d", got)
	}
}

func TestMapHTTPStatusMapsBadRequest(t *testing.T) {
	if got := mapHTTPStatus(proxyerrors.CodeBadRequest); got != http.StatusBadRequest {
		t.Fatalf("mapHTTPStatus(CodeBadRequest) = %d", got)
	}
}

func TestAccessDeniedHTMLSetsNoStoreCache(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://app.example.test/private", nil)
	rec := httptest.NewRecorder()

	AccessDenied(rec, req)

	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("cache control = %q", rec.Header().Get("Cache-Control"))
	}
}

func TestAccessDeniedJSONPrefersHTMLWhenBothAccepted(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://app.example.test/private", nil)
	req.Header.Set("Accept", "text/html, application/json")
	rec := httptest.NewRecorder()

	AccessDenied(rec, req)

	if got := rec.Header().Get("Content-Type"); !strings.Contains(got, "text/html") {
		t.Fatalf("content type = %q, want HTML", got)
	}
}

func TestAppendAccessDeniedJSONEscapesMessage(t *testing.T) {
	got := appendAccessDeniedJSON(nil, `<denied>&"no"`)

	if !json.Valid(got) || strings.Contains(string(got), `<denied>`) {
		t.Fatalf("message was not JSON escaped: %s", got)
	}
}

func TestWAFBlockedDefaultsInvalidStatusToForbidden(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://gateway.example.test/search", nil)
	rec := httptest.NewRecorder()

	WAFBlocked(rec, req, WAFBlockPageOptions{Status: 200, TraceID: "trace"})

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestWAFBlockedAllowsFiveHundredStatus(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://gateway.example.test/search", nil)
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()

	WAFBlocked(rec, req, WAFBlockPageOptions{Status: http.StatusServiceUnavailable, TraceID: "trace"})

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

func TestWAFBlockedHTMLUsesStatusWhenTraceMissing(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://gateway.example.test/search", nil)
	rec := httptest.NewRecorder()

	WAFBlocked(rec, req, WAFBlockPageOptions{Status: http.StatusTooManyRequests})

	if !strings.Contains(rec.Body.String(), "429") {
		t.Fatalf("body should include status fallback trace: %s", rec.Body.String())
	}
}

func TestWantsJSONNilRequestFalse(t *testing.T) {
	if wantsJSON(nil) {
		t.Fatal("wantsJSON(nil) = true")
	}
}

func TestWantsJSONRequiresApplicationJSON(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://gateway.example.test/", nil)
	req.Header.Set("Accept", "application/problem+json")

	if wantsJSON(req) {
		t.Fatal("wantsJSON should only match application/json")
	}
}

func TestServeFaviconUnknownPathReturnsNotFound(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://gateway.example.test/__assets__/favicon/missing.ico", nil)
	rec := httptest.NewRecorder()

	ServeFavicon(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestServeFaviconSetsCacheHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://gateway.example.test/__assets__/favicon/favicon-16x16.png", nil)
	rec := httptest.NewRecorder()

	ServeFavicon(rec, req)

	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "public, max-age=86400" {
		t.Fatalf("unexpected favicon response: status=%d cache=%q", rec.Code, rec.Header().Get("Cache-Control"))
	}
}

func TestNormalizeToolbarHostLowercasesTrimsAndDropsTrailingDot(t *testing.T) {
	got := normalizeToolbarHost("  APP.Example.COM.  ")

	if got != "app.example.com" {
		t.Fatalf("normalizeToolbarHost = %q", got)
	}
}

func TestToolbarHostMatchesNormalizedASCII(t *testing.T) {
	if !toolbarHostMatchesNormalized("APP.Example.COM.", "app.example.com") {
		t.Fatal("expected ASCII host match")
	}
}

func TestToolbarHostMatchesNormalizedNonASCIIFallback(t *testing.T) {
	if !toolbarHostMatchesNormalized("例子.COM", "例子.com") {
		t.Fatal("expected non-ASCII host match through fallback")
	}
}

func TestToolbarHostMatchesNormalizedLengthMismatch(t *testing.T) {
	if toolbarHostMatchesNormalized("app.example.com", "app.example.com.extra") {
		t.Fatal("expected length mismatch not to match")
	}
}

func TestIsToolbarNavigableTargetAcceptsEmptyTarget(t *testing.T) {
	if !isToolbarNavigableTarget("") {
		t.Fatal("empty target should be treated as navigable")
	}
}

func TestIsToolbarNavigableTargetRejectsHostWithWhitespace(t *testing.T) {
	if isToolbarNavigableTarget("https://bad host.example/path") {
		t.Fatal("target with whitespace in host should be rejected")
	}
}

func TestFilterToolbarHostRulesByHostReturnsSameSliceWhenNoExcludedHost(t *testing.T) {
	rules := []models.HostRule{{Host: "app.example.com"}, {Host: "api.example.com"}}

	got := filterToolbarHostRulesByHost(rules, "")

	if len(got) != len(rules) || &got[0] != &rules[0] {
		t.Fatalf("expected original slice, got %#v", got)
	}
}

func TestFilterToolbarHostRulesByHostRemovesMatchingHost(t *testing.T) {
	rules := []models.HostRule{{Host: "app.example.com"}, {Host: "api.example.com"}}

	got := filterToolbarHostRulesByHost(rules, " APP.EXAMPLE.COM. ")

	if len(got) != 1 || got[0].Host != "api.example.com" {
		t.Fatalf("unexpected filtered host rules: %#v", got)
	}
}

func TestToolbarHostMatchesExcludedNormalizedRequiresNonEmptyExclusion(t *testing.T) {
	if toolbarHostMatchesExcludedNormalized("app.example.com", "") {
		t.Fatal("empty excluded host should not match")
	}
}

func TestWriteJSONStringEscapesForToolbarPayload(t *testing.T) {
	var b strings.Builder

	writeJSONString(&b, `bad </script> & "quote"`)

	if strings.Contains(b.String(), "</script>") || !json.Valid([]byte(b.String())) {
		t.Fatalf("toolbar string was not escaped as JSON: %s", b.String())
	}
}
