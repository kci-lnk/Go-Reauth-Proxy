package admin

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"go-reauth-proxy/pkg/config"
	"go-reauth-proxy/pkg/models"
	"go-reauth-proxy/pkg/proxy"
)

func TestAdminHandleAddRuleDefaultsStripAndRewrite(t *testing.T) {
	server := newAdditionalAdminHTTPServer(t)
	rec := httptest.NewRecorder()
	server.handleAddRule(rec, httptest.NewRequest(http.MethodPost, "/api/rules", bytes.NewReader([]byte(`[{"path":"/app","target":"http://127.0.0.1:8080"}]`))))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	rules := server.ProxyHandler.GetRules()
	if len(rules) != 1 || !rules[0].StripPath || !rules[0].RewriteHTML || rules[0].UseAuth {
		t.Fatalf("rules = %#v", rules)
	}
}

func TestAdminHandleAddRuleRejectsInvalidJSON(t *testing.T) {
	server := newAdditionalAdminHTTPServer(t)
	rec := httptest.NewRecorder()
	server.handleAddRule(rec, httptest.NewRequest(http.MethodPost, "/api/rules", bytes.NewReader([]byte(`{`))))
	if rec.Code != http.StatusOK || !bytes.Contains(rec.Body.Bytes(), []byte(`"success":false`)) {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
}

func TestAdminHandleAddRuleRejectsRootPath(t *testing.T) {
	server := newAdditionalAdminHTTPServer(t)
	rec := httptest.NewRecorder()
	server.handleAddRule(rec, httptest.NewRequest(http.MethodPost, "/api/rules", bytes.NewReader([]byte(`[{"path":"/","target":"http://127.0.0.1:8080"}]`))))
	if rec.Code != http.StatusOK || !bytes.Contains(rec.Body.Bytes(), []byte(`"success":false`)) {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
}

func TestAdminHandleGetRulesReturnsConfiguredRules(t *testing.T) {
	server := newAdditionalAdminHTTPServer(t)
	if err := server.ProxyHandler.SetRules([]models.Rule{{Path: "/app", Target: "http://127.0.0.1:8080"}}); err != nil {
		t.Fatalf("SetRules() returned error: %v", err)
	}
	rec := httptest.NewRecorder()
	server.handleGetRules(rec, httptest.NewRequest(http.MethodGet, "/api/rules", nil))
	if rec.Code != http.StatusOK || !bytes.Contains(rec.Body.Bytes(), []byte(`"/app"`)) {
		t.Fatalf("response = %d %s", rec.Code, rec.Body.String())
	}
}

func TestAdminHandleFlushRulesClearsRules(t *testing.T) {
	server := newAdditionalAdminHTTPServer(t)
	if err := server.ProxyHandler.SetRules([]models.Rule{{Path: "/app", Target: "http://127.0.0.1:8080"}}); err != nil {
		t.Fatalf("SetRules() returned error: %v", err)
	}
	rec := httptest.NewRecorder()
	server.handleFlushRules(rec, httptest.NewRequest(http.MethodDelete, "/api/rules", nil))
	if rec.Code != http.StatusOK || len(server.ProxyHandler.GetRules()) != 0 {
		t.Fatalf("flush response = %d %s rules=%#v", rec.Code, rec.Body.String(), server.ProxyHandler.GetRules())
	}
}

func TestAdminHandleSetStreamRulesDefaultsUseAuth(t *testing.T) {
	server := newAdditionalAdminHTTPServer(t)
	rec := httptest.NewRecorder()
	server.handleSetStreamRules(rec, httptest.NewRequest(http.MethodPost, "/api/stream-rules", bytes.NewReader([]byte(`[{"listen_port":3306,"target":"127.0.0.1:3307"}]`))))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	rules := server.ProxyHandler.GetStreamRules()
	if len(rules) != 1 || !rules[0].UseAuth || rules[0].Protocol != models.StreamProtocolTCP {
		t.Fatalf("stream rules = %#v", rules)
	}
}

func TestAdminHandleSetStreamRulesRejectsInvalidJSON(t *testing.T) {
	server := newAdditionalAdminHTTPServer(t)
	rec := httptest.NewRecorder()
	server.handleSetStreamRules(rec, httptest.NewRequest(http.MethodPost, "/api/stream-rules", bytes.NewReader([]byte(`{`))))
	if rec.Code != http.StatusOK || !bytes.Contains(rec.Body.Bytes(), []byte(`"success":false`)) {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
}

func TestAdminHandleSetStreamRulesRejectsInvalidTarget(t *testing.T) {
	server := newAdditionalAdminHTTPServer(t)
	rec := httptest.NewRecorder()
	server.handleSetStreamRules(rec, httptest.NewRequest(http.MethodPost, "/api/stream-rules", bytes.NewReader([]byte(`[{"listen_port":3306,"target":"bad"}]`))))
	if rec.Code != http.StatusOK || !bytes.Contains(rec.Body.Bytes(), []byte(`"success":false`)) {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
}

func TestAdminHandleSetDefaultRouteRequiresValue(t *testing.T) {
	server := newAdditionalAdminHTTPServer(t)
	rec := httptest.NewRecorder()
	server.handleSetDefaultRoute(rec, httptest.NewRequest(http.MethodPost, "/api/default-route", bytes.NewReader([]byte(`{}`))))
	if rec.Code != http.StatusOK || !bytes.Contains(rec.Body.Bytes(), []byte(`"success":false`)) {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
}

func TestAdminHandleSetProxyProtocolForceRequiresValue(t *testing.T) {
	server := newAdditionalAdminHTTPServer(t)
	rec := httptest.NewRecorder()
	server.handleSetProxyProtocolForce(rec, httptest.NewRequest(http.MethodPost, "/api/config/proxy-protocol", bytes.NewReader([]byte(`{}`))))
	if rec.Code != http.StatusOK || !bytes.Contains(rec.Body.Bytes(), []byte(`"success":false`)) {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
}

func TestAdminHandleSetAuthRejectsEdgeConflict(t *testing.T) {
	server := newAdditionalAdminHTTPServer(t)
	rec := httptest.NewRecorder()
	server.handleSetAuth(rec, httptest.NewRequest(http.MethodPost, "/api/auth", bytes.NewReader([]byte(`{"edge_client_ip_enabled":false,"aliyun_esa_enabled":true}`))))
	if rec.Code != http.StatusOK || !bytes.Contains(rec.Body.Bytes(), []byte(`"success":false`)) {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
}

func TestMergeAuthConfigEnablesMasterSwitchForAliyun(t *testing.T) {
	enabled := true
	got, err := mergeAuthConfig(models.AuthConfig{}, authConfigPatch{AliyunESAEnabled: &enabled})
	if err != nil {
		t.Fatalf("mergeAuthConfig() returned error: %v", err)
	}
	if !got.EdgeClientIPEnabled || !got.AliyunESAEnabled {
		t.Fatalf("merged auth config = %#v", got)
	}
}

func TestAdminHandleSetLoggingConfigRejectsNegativeMaxDays(t *testing.T) {
	server := newAdditionalAdminHTTPServer(t)
	rec := httptest.NewRecorder()
	server.handleSetLoggingConfig(rec, httptest.NewRequest(http.MethodPost, "/api/logging", bytes.NewReader([]byte(`{"enabled":true,"max_days":-1}`))))
	if rec.Code != http.StatusOK || !bytes.Contains(rec.Body.Bytes(), []byte(`"success":false`)) {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
}

func TestAdminHandleDrainWAFEventsAcceptsEmptyBody(t *testing.T) {
	server := newAdditionalAdminHTTPServer(t)
	rec := httptest.NewRecorder()
	server.handleDrainWAFEvents(rec, httptest.NewRequest(http.MethodPost, "/api/waf/events/drain", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
}

func TestAdminHandleGetLoggingEntriesRejectsInvalidPage(t *testing.T) {
	server := newAdditionalAdminHTTPServer(t)
	rec := httptest.NewRecorder()
	server.handleGetLoggingEntries(rec, httptest.NewRequest(http.MethodGet, "/api/logs/entries?page=0", nil))
	if rec.Code != http.StatusOK || !bytes.Contains(rec.Body.Bytes(), []byte(`"success":false`)) {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
}

func TestAdminHandleGetLoggingEntriesFallsBackForUnknownPagination(t *testing.T) {
	server := newAdditionalAdminHTTPServer(t)
	rec := httptest.NewRecorder()
	server.handleGetLoggingEntries(rec, httptest.NewRequest(http.MethodGet, "/api/logs/entries?pagination=offset", nil))
	if rec.Code != http.StatusOK || !bytes.Contains(rec.Body.Bytes(), []byte(`"pagination":"page"`)) {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
}

func TestAdminHandleSetSSLRejectsMixedLegacyAndDeploymentModes(t *testing.T) {
	server := newAdditionalAdminHTTPServer(t)
	rec := httptest.NewRecorder()
	server.handleSetSSL(rec, httptest.NewRequest(http.MethodPost, "/api/ssl", bytes.NewReader([]byte(`{"cert":"cert","key":"key","deployment_mode":"single_active"}`))))
	if rec.Code != http.StatusOK || !bytes.Contains(rec.Body.Bytes(), []byte(`"success":false`)) {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
}

func TestAdminHandleClearSSLSucceedsWhenEmpty(t *testing.T) {
	server := newAdditionalAdminHTTPServer(t)
	rec := httptest.NewRecorder()
	server.handleClearSSL(rec, httptest.NewRequest(http.MethodDelete, "/api/ssl", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
}

func TestAdminHandleSetGatewayVisibilityRejectsInvalidCIDR(t *testing.T) {
	server := newAdditionalAdminHTTPServer(t)
	rec := httptest.NewRecorder()
	server.handleSetGatewayVisibility(rec, httptest.NewRequest(http.MethodPost, "/api/config/visibility", bytes.NewReader([]byte(`{"enabled":true,"cidrs":["bad"]}`))))
	if rec.Code != http.StatusOK || !bytes.Contains(rec.Body.Bytes(), []byte(`"success":false`)) {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
}

func TestAdminHandleSetReverseProxyThrottleStoresConfig(t *testing.T) {
	server := newAdditionalAdminHTTPServer(t)
	rec := httptest.NewRecorder()
	server.handleSetReverseProxyThrottle(rec, httptest.NewRequest(http.MethodPost, "/api/config/throttle", bytes.NewReader([]byte(`{"enabled":true,"requests_per_second":3,"burst":4,"block_seconds":5}`))))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if server.ProxyHandler.GetReverseProxyThrottle().RequestsPerSecond != 3 {
		t.Fatalf("throttle = %#v", server.ProxyHandler.GetReverseProxyThrottle())
	}
}

func TestAdminHandleGetInfoReturnsVersionEnvelope(t *testing.T) {
	server := newAdditionalAdminHTTPServer(t)
	rec := httptest.NewRecorder()
	server.handleInfo(rec, httptest.NewRequest(http.MethodGet, "/api/info", nil))
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if rec.Code != http.StatusOK || body["success"] != true {
		t.Fatalf("response = %d %s", rec.Code, rec.Body.String())
	}
}

func newAdditionalAdminHTTPServer(t *testing.T) *Server {
	t.Helper()
	cfgManager := config.NewManager(filepath.Join(t.TempDir(), "config.json"))
	initialCfg, err := cfgManager.Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	handler := proxy.NewHandler(7996, 7999, cfgManager, initialCfg, filepath.Join(t.TempDir(), "logs"), nil)
	return NewServer(handler, 7996, cfgManager, initialCfg, nil)
}
