package proxy

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestDockerAdminPanelExternalCookieNameIsStableAndPathScoped(t *testing.T) {
	if got := dockerAdminPanelExternalCookieName("/"); got != dockerAdminPanelSessionCookieName {
		t.Fatalf("root cookie name = %q", got)
	}
	left := dockerAdminPanelExternalCookieName("/docker/")
	right := dockerAdminPanelExternalCookieName("docker")
	if left != right || left == dockerAdminPanelSessionCookieName {
		t.Fatalf("scoped names = %q and %q", left, right)
	}
	if left == dockerAdminPanelExternalCookieName("/other") {
		t.Fatalf("different paths share cookie name %q", left)
	}
}

func TestScopeDockerAdminPanelRequestCookieLeavesUnrelatedRawHeadersUntouched(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://example.test/docker/", nil)
	req.Header = http.Header{
		"cookie": {
			`bad name=x; tokenonly; weird="unterminated; ` + dockerAdminPanelSessionCookieName + `=not-a-real-segment`,
			`ordinary=keep; slash=a\b; quote=a"b`,
		},
	}
	want := req.Header.Clone()

	scopeDockerAdminPanelRequestCookie(req, "/docker")

	if !reflect.DeepEqual(req.Header, want) {
		t.Fatalf("unrelated raw Cookie headers changed: got %#v, want %#v", req.Header, want)
	}
}

func TestScopeDockerAdminPanelRequestCookiePreservesMalformedUnrelatedSegments(t *testing.T) {
	externalName := dockerAdminPanelExternalCookieName("/docker")
	otherName := dockerAdminPanelExternalCookieName("/other")
	req := httptest.NewRequest(http.MethodGet, "https://example.test/docker/", nil)
	req.Header = http.Header{
		"cookie": {
			`bad name=x; tokenonly; ` + externalName + `=docker-session; weird="unterminated`,
			`ordinary=keep; ` + otherName + `=other-session; ` + dockerAdminPanelSessionCookieName + `=legacy-root`,
		},
	}

	scopeDockerAdminPanelRequestCookie(req, "/docker")

	want := []string{
		`bad name=x; tokenonly; weird="unterminated`,
		`ordinary=keep`,
		dockerAdminPanelSessionCookieName + `=docker-session`,
	}
	if got := req.Header.Values("Cookie"); !reflect.DeepEqual(got, want) {
		t.Fatalf("raw Cookie headers = %#v, want %#v", got, want)
	}
}

func TestScopeDockerAdminPanelRequestCookieUsesOnlyCurrentPath(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://example.test/docker/", nil)
	req.AddCookie(&http.Cookie{Name: "ordinary", Value: "keep"})
	req.AddCookie(&http.Cookie{Name: dockerAdminPanelSessionCookieName, Value: "legacy-root"})
	req.AddCookie(&http.Cookie{
		Name:  dockerAdminPanelExternalCookieName("/docker"),
		Value: "docker-session",
	})
	req.AddCookie(&http.Cookie{
		Name:  dockerAdminPanelExternalCookieName("/other"),
		Value: "other-session",
	})

	scopeDockerAdminPanelRequestCookie(req, "/docker")

	if cookie, err := req.Cookie(dockerAdminPanelSessionCookieName); err != nil || cookie.Value != "docker-session" {
		t.Fatalf("canonical upstream cookie = %#v, %v", cookie, err)
	}
	if cookie, err := req.Cookie("ordinary"); err != nil || cookie.Value != "keep" {
		t.Fatalf("ordinary cookie = %#v, %v", cookie, err)
	}
	for _, cookie := range req.Cookies() {
		if strings.Contains(cookie.Name, dockerAdminPanelScopedCookieInfix) {
			t.Fatalf("external cookie leaked upstream: %#v", cookie)
		}
	}
}

func TestScopeDockerAdminPanelRequestCookieDoesNotReuseLegacyRootForPath(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://example.test/docker/", nil)
	req.AddCookie(&http.Cookie{Name: dockerAdminPanelSessionCookieName, Value: "legacy-root"})

	scopeDockerAdminPanelRequestCookie(req, "/docker")

	if _, err := req.Cookie(dockerAdminPanelSessionCookieName); err != http.ErrNoCookie {
		t.Fatalf("legacy root cookie remains available to path upstream: %v", err)
	}
}

func TestScopeDockerAdminPanelResponseCookieRewritesOnlyPanelCookie(t *testing.T) {
	resp := &http.Response{Header: http.Header{}}
	resp.Header.Add("Set-Cookie", "ordinary=keep; Path=/; HttpOnly")
	resp.Header.Add(
		"Set-Cookie",
		dockerAdminPanelSessionCookieName+"=session; Path=/; Max-Age=3600; HttpOnly; Secure; SameSite=Lax",
	)

	scopeDockerAdminPanelResponseCookie(resp, "/docker")

	values := resp.Header.Values("Set-Cookie")
	if len(values) != 2 || values[0] != "ordinary=keep; Path=/; HttpOnly" {
		t.Fatalf("Set-Cookie values = %#v", values)
	}
	panelCookie, err := http.ParseSetCookie(values[1])
	if err != nil {
		t.Fatal(err)
	}
	if panelCookie.Name != dockerAdminPanelExternalCookieName("/docker") || panelCookie.Path != "/docker" {
		t.Fatalf("scoped panel cookie = %#v", panelCookie)
	}
	if !panelCookie.HttpOnly || !panelCookie.Secure || panelCookie.SameSite != http.SameSiteLaxMode || panelCookie.MaxAge != 3600 {
		t.Fatalf("panel cookie attributes changed: %#v", panelCookie)
	}
}

func TestScopeDockerAdminPanelResponseCookieKeepsRootDeploymentCanonical(t *testing.T) {
	resp := &http.Response{Header: http.Header{}}
	resp.Header.Add("Set-Cookie", dockerAdminPanelSessionCookieName+"=session; Path=/; HttpOnly")

	scopeDockerAdminPanelResponseCookie(resp, "/")

	cookie, err := http.ParseSetCookie(resp.Header.Get("Set-Cookie"))
	if err != nil {
		t.Fatal(err)
	}
	if cookie.Name != dockerAdminPanelSessionCookieName || cookie.Path != "/" || !cookie.HttpOnly {
		t.Fatalf("root panel cookie changed unexpectedly: %#v", cookie)
	}
}

func TestScopeDockerAdminPanelResponseCookieScopesLogoutDeletion(t *testing.T) {
	resp := &http.Response{Header: http.Header{}}
	resp.Header.Add(
		"Set-Cookie",
		dockerAdminPanelSessionCookieName+"=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly",
	)

	scopeDockerAdminPanelResponseCookie(resp, "/docker")

	cookie, err := http.ParseSetCookie(resp.Header.Get("Set-Cookie"))
	if err != nil {
		t.Fatal(err)
	}
	if cookie.Name != dockerAdminPanelExternalCookieName("/docker") || cookie.Path != "/docker" {
		t.Fatalf("logout cookie was not scoped: %#v", cookie)
	}
	if cookie.Value != "" || cookie.Expires.IsZero() || !cookie.Expires.Before(time.Now()) || cookie.MaxAge > 0 {
		t.Fatalf("logout cookie no longer expires the session: %#v", cookie)
	}
}
