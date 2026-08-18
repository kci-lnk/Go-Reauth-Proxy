package response

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestServeWebsiteIconUsesRuleDataAndStableCaching(t *testing.T) {
	icon := []byte("mapped-icon")
	iconPath := WebsiteIconPathPrefix + "550e8400-e29b-41d4-a716-446655440000.png"
	req := httptest.NewRequest(http.MethodGet, "http://app.example.com"+iconPath, nil)
	rec := httptest.NewRecorder()
	ServeWebsiteIcon(rec, req, "data:image/png;base64,"+base64.StdEncoding.EncodeToString(icon))

	if rec.Code != http.StatusOK || rec.Body.String() != string(icon) {
		t.Fatalf("unexpected website icon response: status=%d body=%q", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != "image/png" {
		t.Fatalf("content type = %q, want image/png", got)
	}
	if got := rec.Header().Get("ETag"); got == "" {
		t.Fatal("website icon response is missing ETag")
	}

	conditional := httptest.NewRequest(http.MethodGet, "http://app.example.com"+iconPath, nil)
	conditional.Header.Set("If-None-Match", rec.Header().Get("ETag"))
	conditionalRec := httptest.NewRecorder()
	ServeWebsiteIcon(conditionalRec, conditional, "data:image/png;base64,"+base64.StdEncoding.EncodeToString(icon))
	if conditionalRec.Code != http.StatusNotModified {
		t.Fatalf("conditional status = %d, want 304", conditionalRec.Code)
	}
}

func TestServeWebsiteIconFallsBackAndSandboxesSVG(t *testing.T) {
	fallbackReq := httptest.NewRequest(http.MethodGet, "http://app.example.com"+WebsiteIconPathPrefix+"fallback.png", nil)
	fallbackRec := httptest.NewRecorder()
	ServeWebsiteIcon(fallbackRec, fallbackReq, "")
	if fallbackRec.Code != http.StatusOK || fallbackRec.Body.Len() == 0 {
		t.Fatalf("fallback status=%d bytes=%d", fallbackRec.Code, fallbackRec.Body.Len())
	}
	if got := fallbackRec.Header().Get("Content-Type"); got != "image/png" {
		t.Fatalf("fallback content type = %q, want image/png", got)
	}

	svg := []byte(`<svg xmlns="http://www.w3.org/2000/svg"></svg>`)
	svgReq := httptest.NewRequest(http.MethodGet, "http://app.example.com"+WebsiteIconPathPrefix+"icon.svg", nil)
	svgRec := httptest.NewRecorder()
	ServeWebsiteIcon(svgRec, svgReq, "data:image/svg+xml;base64,"+base64.StdEncoding.EncodeToString(svg))
	if got := svgRec.Header().Get("Content-Security-Policy"); !strings.Contains(got, "sandbox") {
		t.Fatalf("SVG response CSP = %q, want sandbox", got)
	}
}

func TestFaviconPathsUseReservedNamespace(t *testing.T) {
	for _, path := range []string{
		"/favicon-16x16.png",
		"/favicon-32x32.png",
		"/apple-touch-icon.png",
		"/android-chrome-192x192.png",
		"/android-chrome-512x512.png",
		"/site.webmanifest",
	} {
		if IsFaviconPath(path) {
			t.Fatalf("IsFaviconPath(%q) = true, want false for root favicon path", path)
		}
	}

	for _, path := range []string{
		"/__assets__/favicon/favicon-16x16.png",
		"/__assets__/favicon/favicon-32x32.png",
		"/__assets__/favicon/apple-touch-icon.png",
		"/__assets__/favicon/android-chrome-192x192.png",
		"/__assets__/favicon/android-chrome-512x512.png",
		"/__assets__/favicon/site.webmanifest",
	} {
		if !IsFaviconPath(path) {
			t.Fatalf("IsFaviconPath(%q) = false, want true for reserved favicon path", path)
		}
	}
}

func TestGatewayPagesUseReservedFaviconLinks(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://gateway.example.com/", nil)
	rec := httptest.NewRecorder()

	Welcome(rec, req, nil)

	body := rec.Body.String()
	for _, want := range []string{
		`href="/__assets__/favicon/apple-touch-icon.png"`,
		`href="/__assets__/favicon/favicon-32x32.png"`,
		`href="/__assets__/favicon/favicon-16x16.png"`,
		`href="/__assets__/favicon/site.webmanifest"`,
		`src="/__assets__/favicon/android-chrome-512x512.png"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("gateway page missing reserved favicon link %q: %s", want, body)
		}
	}

	for _, forbidden := range []string{
		`href="/apple-touch-icon.png"`,
		`href="/favicon-32x32.png"`,
		`href="/favicon-16x16.png"`,
		`href="/site.webmanifest"`,
		`src="/android-chrome-512x512.png"`,
	} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("gateway page still includes root favicon link %q: %s", forbidden, body)
		}
	}
}

func TestFaviconManifestUsesReservedIconSources(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://gateway.example.com/__assets__/favicon/site.webmanifest", nil)
	rec := httptest.NewRecorder()

	ServeFavicon(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	var manifest struct {
		Icons []struct {
			Src string `json:"src"`
		} `json:"icons"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &manifest); err != nil {
		t.Fatalf("decode manifest: %v\n%s", err, rec.Body.String())
	}
	if len(manifest.Icons) == 0 {
		t.Fatal("manifest icons are empty")
	}
	for _, icon := range manifest.Icons {
		if !strings.HasPrefix(icon.Src, "/__assets__/favicon/") {
			t.Fatalf("manifest icon src = %q, want reserved favicon path", icon.Src)
		}
	}
}
