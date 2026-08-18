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
		`@media(min-width:1180px)`,
		`grid-template-columns:repeat(auto-fit,minmax(min(100%,280px),1fr))`,
		`.grid[data-count="single"]`,
		`grid.dataset.count=items.length===1?'single':'multiple'`,
		`new Intl.RelativeTimeFormat`,
		`function updateRelativeTimes()`,
		`setInterval(updateRelativeTimes,30000)`,
		`/__auth__/api/auth/wol/targets`,
		`/shutdown`,
		`id="shutdown-modal"`,
		`shutdownDeadline=Date.now()+3000`,
		`Date.now()<shutdownDeadline`,
		`shutdownConfirmCountdown.replace('{seconds}'`,
		`item.shutdownAvailable`,
		`item.status.state==='online'`,
		`function shutdownIcon()`,
		`M12 2v10`,
		`M18.4 6.6a9 9 0 1 1-12.77.04`,
		`grid-template-columns:40px minmax(0,1fr) 40px`,
		`class="heading"`,
		`class="top-balance"`,
		`m15 18-6-6 6-6`,
		`actionButtons.childNodes.length`,
		`env(safe-area-inset-bottom)`,
		`max-height:calc(100dvh - 28px)`,
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
		`class="desc"`,
		`查看设备在线状态，唤醒或关机。`,
		"runtime-hmac-secret",
		"x-signature",
		"hmacSecret",
		"function hmacSha256",
		`['circle','cx','12','cy','12','r','10']`,
		`['rect','width','6','height','6','x','9','y','9','rx','1']`,
		`class="title-icon"`,
		`← {{.Data.Back}}`,
	} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("WOL page contains forbidden fragment %q", forbidden)
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
	for _, internalField := range []string{"ipAddress", "observedIp", "lastError", "username", "hostKeyFingerprint", "credentialConfigured", "privateKey", "password"} {
		if strings.Contains(body, internalField) {
			t.Fatalf("WOL page exposed internal field %q", internalField)
		}
	}
}
