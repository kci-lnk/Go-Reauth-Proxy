package admin

import (
	"bytes"
	"encoding/json"
	"go-reauth-proxy/pkg/config"
	"go-reauth-proxy/pkg/models"
	"go-reauth-proxy/pkg/proxy"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestHostRulesAdminAcceptsNullableFavicon(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.json")
	cfgManager := config.NewManager(configPath)
	initialCfg, err := cfgManager.Load()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	proxyHandler := proxy.NewHandler(7996, 7999, cfgManager, initialCfg, filepath.Join(t.TempDir(), "logs"), nil)
	server := NewServer(proxyHandler, 7996, cfgManager, initialCfg, nil)

	body := []byte(`[
		{"host":"missing.example.com","target":"http://127.0.0.1:8080"},
		{"host":"null.example.com","target":"http://127.0.0.1:8081","favicon":null},
		{"host":"icon.example.com","target":"http://127.0.0.1:8082","favicon":" data:image/png;base64,AAAA "}
	]`)
	req := httptest.NewRequest(http.MethodPost, "/api/host-rules", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	server.handleAddHostRule(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Success bool              `json:"success"`
		Data    []models.HostRule `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.Success || len(resp.Data) != 3 {
		t.Fatalf("response = %#v, want three host rules", resp)
	}
	if resp.Data[0].Favicon != "" {
		t.Fatalf("missing favicon = %q, want empty", resp.Data[0].Favicon)
	}
	if resp.Data[1].Favicon != "" {
		t.Fatalf("null favicon = %q, want empty", resp.Data[1].Favicon)
	}
	if resp.Data[2].Favicon != "data:image/png;base64,AAAA" {
		t.Fatalf("data URL favicon = %q, want trimmed data URL", resp.Data[2].Favicon)
	}
}

func TestHostRulesAdminAcceptsAndNormalizesDefaultHostRule(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.json")
	cfgManager := config.NewManager(configPath)
	initialCfg, err := cfgManager.Load()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	proxyHandler := proxy.NewHandler(7996, 7999, cfgManager, initialCfg, filepath.Join(t.TempDir(), "logs"), nil)
	server := NewServer(proxyHandler, 7996, cfgManager, initialCfg, nil)

	body := []byte(`[
		{"host":"app-a.example.com","target":"http://127.0.0.1:8080","is_default":true},
		{"host":"app-b.example.com","target":"http://127.0.0.1:8081","is_default":true}
	]`)
	req := httptest.NewRequest(http.MethodPost, "/api/host-rules", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	server.handleAddHostRule(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Success bool              `json:"success"`
		Data    []models.HostRule `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.Success || len(resp.Data) != 2 {
		t.Fatalf("response = %#v, want two host rules", resp)
	}
	if !resp.Data[0].IsDefault {
		t.Fatalf("first host rule should remain default: %#v", resp.Data)
	}
	if resp.Data[1].IsDefault {
		t.Fatalf("second host rule should be cleared as default: %#v", resp.Data)
	}
}

func TestHostRulesAdminPreservesDisabledAndAvailability(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.json")
	cfgManager := config.NewManager(configPath)
	initialCfg, err := cfgManager.Load()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	proxyHandler := proxy.NewHandler(7996, 7999, cfgManager, initialCfg, filepath.Join(t.TempDir(), "logs"), nil)
	server := NewServer(proxyHandler, 7996, cfgManager, initialCfg, nil)

	body := []byte(`[
		{
			"host":"app.example.com",
			"target":"http://127.0.0.1:8080",
			"protocol_mode":"http1",
			"disabled":true,
			"availability":{"enabled":true,"start_time":"22:00","end_time":"06:00"}
		}
	]`)
	req := httptest.NewRequest(http.MethodPost, "/api/host-rules", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	server.handleAddHostRule(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Success bool              `json:"success"`
		Data    []models.HostRule `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.Success || len(resp.Data) != 1 {
		t.Fatalf("response = %#v, want one host rule", resp)
	}
	if !resp.Data[0].Disabled {
		t.Fatalf("disabled = false, want true")
	}
	if resp.Data[0].ProtocolMode != models.HostProtocolModeHTTP1 {
		t.Fatalf("protocol_mode = %q, want http1", resp.Data[0].ProtocolMode)
	}
	if resp.Data[0].Availability == nil ||
		!resp.Data[0].Availability.Enabled ||
		resp.Data[0].Availability.StartTime != "22:00" ||
		resp.Data[0].Availability.EndTime != "06:00" {
		t.Fatalf("availability = %#v", resp.Data[0].Availability)
	}
}
