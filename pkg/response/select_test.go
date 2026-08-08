package response

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go-reauth-proxy/pkg/models"
)

func disabledGatewayPortalConfigForSelectTest(t *testing.T) models.GatewayPortalConfig {
	t.Helper()

	var cfg models.GatewayPortalConfig
	if err := json.Unmarshal([]byte(`{"enabled":false}`), &cfg); err != nil {
		t.Fatalf("unmarshal disabled gateway portal config: %v", err)
	}
	return cfg
}

func TestSelectPageRemainsAvailableWhenPortalToolbarDisabled(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://gateway.example.com/__select__", nil)
	rec := httptest.NewRecorder()

	SelectPage(
		rec,
		req,
		nil,
		[]models.HostRule{{Host: "app.example.com", Target: "http://127.0.0.1:3000"}},
		disabledGatewayPortalConfigForSelectTest(t),
	)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "app.example.com") {
		t.Fatalf("select page did not include host rule while portal disabled: %s", body)
	}
	if strings.Contains(body, "reauth-proxy-toolbar") {
		t.Fatalf("select page included toolbar while portal disabled: %s", body)
	}
}

func TestSelectPagePlacesWOLShortcutBeforeLogout(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://gateway.example.com/__select__", nil)
	rec := httptest.NewRecorder()

	SelectPage(rec, req, nil, nil, models.GatewayPortalConfig{ShowWOL: true})

	body := rec.Body.String()
	if !strings.Contains(body, `class="header-actions"`) {
		t.Fatal("select page does not group WOL and logout in the header action area")
	}
	if !strings.Contains(body, `m9 10 3-3 3 3`) || strings.Contains(body, `m9 10 2 2 4-4`) {
		t.Fatal("select page does not render the canonical MonitorUp icon")
	}
	wol := strings.Index(body, `href="/__wol__"`)
	logout := strings.Index(body, `id="logout-modal"`)
	if wol < 0 || logout < 0 || wol > logout {
		t.Fatalf("select page does not place WOL before logout: %s", body)
	}
}

func TestSelectPageFiltersWebSocketHostRules(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://gateway.example.com/__select__", nil)
	rec := httptest.NewRecorder()

	SelectPage(
		rec,
		req,
		nil,
		[]models.HostRule{
			{Host: "app.example.com", Target: "https://127.0.0.1:3000"},
			{Host: "socket.example.com", Target: "wss://127.0.0.1:3001"},
		},
		models.GatewayPortalConfig{},
	)

	body := rec.Body.String()
	if !strings.Contains(body, "app.example.com") {
		t.Fatalf("select page did not include HTTP(S) host rule: %s", body)
	}
	if strings.Contains(body, "socket.example.com") || strings.Contains(body, "wss://127.0.0.1:3001") {
		t.Fatalf("select page included WebSocket host rule: %s", body)
	}
}

func TestSelectPageFiltersWebSocketPathRules(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://gateway.example.com/__select__", nil)
	rec := httptest.NewRecorder()

	SelectPage(
		rec,
		req,
		[]models.Rule{
			{Path: "/app", Target: "http://127.0.0.1:3000"},
			{Path: "/socket", Target: "ws://127.0.0.1:3001"},
		},
		nil,
		models.GatewayPortalConfig{},
	)

	body := rec.Body.String()
	if !strings.Contains(body, "/app") {
		t.Fatalf("select page did not include HTTP(S) path rule: %s", body)
	}
	if strings.Contains(body, "/socket") || strings.Contains(body, "ws://127.0.0.1:3001") {
		t.Fatalf("select page included WebSocket path rule: %s", body)
	}
}

func TestSelectPageRendersConfiguredHostFavicon(t *testing.T) {
	const icon = "data:image/png;base64,AAAA"
	req := httptest.NewRequest(http.MethodGet, "http://gateway.example.com/__select__", nil)
	rec := httptest.NewRecorder()

	SelectPage(
		rec,
		req,
		nil,
		[]models.HostRule{{Host: "app.example.com", Target: "https://127.0.0.1:3000", Favicon: icon}},
		models.GatewayPortalConfig{DisplayStyle: models.GatewayPortalDisplayStyleTitle, ShowAppIcon: true},
	)

	body := rec.Body.String()
	if !strings.Contains(body, `class="route-icon-img" src="`+icon+`"`) {
		t.Fatalf("select page did not render configured host favicon: %s", body)
	}
	if strings.Contains(body, "#ZgotmplZ") {
		t.Fatalf("select page rendered sanitized placeholder instead of favicon: %s", body)
	}
}
