package proxy

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"go-reauth-proxy/pkg/models"
	"go-reauth-proxy/pkg/response"
)

func TestHostRuleServesStableWebsiteIconBeforeAuthentication(t *testing.T) {
	icon := []byte("private-mapped-icon")
	iconPath := "/__assets__/website_icon.550e8400-e29b-41d4-a716-446655440000.png"
	handler := &Handler{
		CrawlerBlocker: models.CrawlerBlockerConfig{Enabled: true},
		HostRules: []models.HostRule{{
			Host:            "private.example.com",
			Target:          "http://127.0.0.1:1",
			UseAuth:         true,
			Favicon:         "data:image/png;base64," + base64.StdEncoding.EncodeToString(icon),
			WebsiteIconPath: iconPath,
			Visibility:      models.HostRuleVisibility{Mode: models.HostVisibilityModeCustom},
		}},
		authCache:      newAuthStateCache(),
		preflightCache: newPreflightStateCache(),
	}
	handler.publishRequestSnapshotLocked()

	req := httptest.NewRequest(http.MethodGet, "http://private.example.com"+iconPath, nil)
	req.Header.Set("User-Agent", "Googlebot/2.1")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK || rec.Body.String() != string(icon) {
		t.Fatalf("stable website icon status=%d body=%q", rec.Code, rec.Body.String())
	}

	guessed := httptest.NewRequest(http.MethodGet, "http://private.example.com/__assets__/website_icon.00000000-0000-4000-8000-000000000000.png", nil)
	guessedRec := httptest.NewRecorder()
	handler.ServeHTTP(guessedRec, guessed)
	if guessedRec.Code != http.StatusNotFound {
		t.Fatalf("guessed website icon status=%d, want 404", guessedRec.Code)
	}
}

func TestHostRuleServesDerivedWebsiteIconPath(t *testing.T) {
	icon := "data:image/png;base64," + base64.StdEncoding.EncodeToString([]byte("derived-private-icon"))
	iconPath := response.EffectiveWebsiteIconPath("", icon)
	handler := &Handler{
		HostRules: []models.HostRule{{
			Host:    "private.example.com",
			Target:  "http://127.0.0.1:1",
			UseAuth: true,
			Favicon: icon,
		}},
		authCache:      newAuthStateCache(),
		preflightCache: newPreflightStateCache(),
	}
	handler.publishRequestSnapshotLocked()

	req := httptest.NewRequest(http.MethodGet, "http://private.example.com"+iconPath, nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK || rec.Body.String() != "derived-private-icon" {
		t.Fatalf("derived website icon status=%d body=%q", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Cache-Control"); got != "public, max-age=31536000, immutable" {
		t.Fatalf("derived website icon Cache-Control = %q", got)
	}
}

func TestHostRuleProxiesRootFaviconPathToUpstream(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/favicon-32x32.png" {
			t.Fatalf("upstream path = %q, want /favicon-32x32.png", r.URL.Path)
		}
		w.Header().Set("Content-Type", "image/png")
		_, _ = io.WriteString(w, "upstream-favicon")
	}))
	defer upstream.Close()

	handler := &Handler{
		HostRules: []models.HostRule{
			{
				Host:   "app.example.com",
				Target: upstream.URL,
			},
		},
		authCache:      newAuthStateCache(),
		preflightCache: newPreflightStateCache(),
	}
	handler.publishRequestSnapshotLocked()

	req := httptest.NewRequest(http.MethodGet, "http://app.example.com/favicon-32x32.png", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	if got := rec.Body.String(); got != "upstream-favicon" {
		t.Fatalf("body = %q, want upstream favicon response", got)
	}
}
