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

func TestCrawlerBlockerAdminHandlersPersistConfig(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.json")
	cfgManager := config.NewManager(configPath)
	initialCfg, err := cfgManager.Load()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	proxyHandler := proxy.NewHandler(7996, 7999, cfgManager, initialCfg, filepath.Join(t.TempDir(), "logs"), nil)
	server := NewServer(proxyHandler, 7996, cfgManager, initialCfg, nil)

	getReq := httptest.NewRequest(http.MethodGet, "/api/config/crawler-blocker", nil)
	getRec := httptest.NewRecorder()
	server.handleGetCrawlerBlockerConfig(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("get status = %d, body = %s", getRec.Code, getRec.Body.String())
	}
	var getResp struct {
		Success bool                        `json:"success"`
		Data    models.CrawlerBlockerConfig `json:"data"`
	}
	if err := json.Unmarshal(getRec.Body.Bytes(), &getResp); err != nil {
		t.Fatalf("decode get response: %v", err)
	}
	if !getResp.Success || getResp.Data.Enabled {
		t.Fatalf("default response = %#v, want disabled", getResp)
	}

	body, _ := json.Marshal(models.CrawlerBlockerConfig{
		Enabled:   true,
		UpdatedAt: "2026-06-28T00:00:00Z",
	})
	setReq := httptest.NewRequest(http.MethodPost, "/api/config/crawler-blocker", bytes.NewReader(body))
	setRec := httptest.NewRecorder()
	server.handleSetCrawlerBlockerConfig(setRec, setReq)
	if setRec.Code != http.StatusOK {
		t.Fatalf("set status = %d, body = %s", setRec.Code, setRec.Body.String())
	}
	var setResp struct {
		Success bool                        `json:"success"`
		Data    models.CrawlerBlockerConfig `json:"data"`
	}
	if err := json.Unmarshal(setRec.Body.Bytes(), &setResp); err != nil {
		t.Fatalf("decode set response: %v", err)
	}
	if !setResp.Success || !setResp.Data.Enabled || setResp.Data.UpdatedAt != "2026-06-28T00:00:00Z" {
		t.Fatalf("set response = %#v, want enabled config", setResp)
	}

	saved, err := cfgManager.Load()
	if err != nil {
		t.Fatalf("reload config: %v", err)
	}
	if !saved.CrawlerBlocker.Enabled || saved.CrawlerBlocker.UpdatedAt != "2026-06-28T00:00:00Z" {
		t.Fatalf("persisted crawler blocker = %#v, want enabled config", saved.CrawlerBlocker)
	}
}
