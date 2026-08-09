package response

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWOLPageIsResponsiveSignedAndNonCacheable(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://gateway.example.com/__wol__", nil)
	req.Header.Set("Accept-Language", "en")
	rec := httptest.NewRecorder()

	WOLPage(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	if cacheControl := rec.Header().Get("Cache-Control"); !strings.Contains(cacheControl, "no-store") {
		t.Fatalf("Cache-Control = %q, want no-store", cacheControl)
	}
	for name, want := range map[string]string{
		"Content-Security-Policy": "frame-ancestors 'none'",
		"X-Frame-Options":         "DENY",
		"X-Content-Type-Options":  "nosniff",
		"Referrer-Policy":         "no-referrer",
	} {
		if got := rec.Header().Get(name); got != want {
			t.Fatalf("%s = %q, want %q", name, got, want)
		}
	}
	body := rec.Body.String()
	for _, fragment := range []string{
		`@media(min-width:680px)`,
		`/__auth__/api/auth/wol/targets`,
		`function apiFetch(url,options)`,
		`var labels={loading:"`,
		`wake:"`,
		`m9 10 3-3 3 3`,
	} {
		if !strings.Contains(body, fragment) {
			t.Fatalf("WOL page omitted %q", fragment)
		}
	}
	for _, forbidden := range []string{
		"runtime-hmac-secret",
		"x-signature",
		"hmacSecret",
		"function hmacSha256",
	} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("WOL page exposed obsolete browser signing material %q", forbidden)
		}
	}
	if strings.Contains(body, `:"\"`) {
		t.Fatalf("WOL page rendered JavaScript labels with visible quote characters: %s", body)
	}
	if strings.Contains(body, `m9 10 2 2 4-4`) {
		t.Fatal("WOL page rendered the obsolete malformed MonitorUp arrow")
	}
	if language := rec.Header().Get("Content-Language"); language == "" {
		t.Fatal("Content-Language must use the resolved locale")
	}
	for _, internalField := range []string{"ipAddress", "observedIp", "lastError"} {
		if strings.Contains(body, internalField) {
			t.Fatalf("WOL page exposed internal field %q", internalField)
		}
	}
}
