package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go-reauth-proxy/pkg/gatewaylog"
	"go-reauth-proxy/pkg/i18n"
	"go-reauth-proxy/pkg/models"
)

func TestManagerRuntimeDirEmptyPathReturnsDot(t *testing.T) {
	if got := NewManager("").RuntimeDir(); got != "." {
		t.Fatalf("RuntimeDir() = %q, want .", got)
	}
}

func TestManagerRuntimeDirUsesConfigDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "config.json")
	if got, want := NewManager(path).RuntimeDir(), filepath.Dir(path); got != want {
		t.Fatalf("RuntimeDir() = %q, want %q", got, want)
	}
}

func TestManagerLoadCreatesDefaultConfigFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	cfg, err := NewManager(path).Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if len(cfg.Rules) != 0 || len(cfg.HostRules) != 0 || len(cfg.StreamRules) != 0 {
		t.Fatalf("default rule slices = %#v %#v %#v, want empty", cfg.Rules, cfg.HostRules, cfg.StreamRules)
	}
	if cfg.DefaultRoute != "/__select__" || cfg.AdminPort != 7996 || cfg.AuthConfig.AuthPort != 7997 {
		t.Fatalf("unexpected defaults: %#v", cfg)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("default config was not written: %v", err)
	}
}

func TestManagerLoadRejectsInvalidJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"rules": [`), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if _, err := NewManager(path).Load(); err == nil {
		t.Fatal("Load() returned nil error for invalid JSON")
	}
}

func TestManagerLoadAppliesMissingAuthCacheDefaults(t *testing.T) {
	cfg := loadConfigFromJSON(t, `{"auth_config":{"auth_port":7997}}`)
	if cfg.AuthConfig.AuthCacheTTL != defaultAuthCacheTTLSeconds {
		t.Fatalf("AuthCacheTTL = %d, want default", cfg.AuthConfig.AuthCacheTTL)
	}
	if cfg.AuthConfig.AuthCacheFailTTL != defaultAuthCacheUnauthorizedTTLSeconds {
		t.Fatalf("AuthCacheFailTTL = %d, want default", cfg.AuthConfig.AuthCacheFailTTL)
	}
}

func TestManagerLoadPreservesExplicitZeroAuthCacheTTL(t *testing.T) {
	cfg := loadConfigFromJSON(t, `{"auth_config":{"auth_cache_ttl_seconds":0,"auth_cache_unauthorized_ttl_seconds":0}}`)
	if cfg.AuthConfig.AuthCacheTTL != 0 || cfg.AuthConfig.AuthCacheFailTTL != 0 {
		t.Fatalf("explicit zero auth cache TTLs changed: %#v", cfg.AuthConfig)
	}
}

func TestManagerLoadMigratesLegacyEdgeVendorToMasterSwitch(t *testing.T) {
	cfg := loadConfigFromJSON(t, `{"auth_config":{"aliyun_esa_enabled":true}}`)
	if !cfg.AuthConfig.EdgeClientIPEnabled || !cfg.AuthConfig.AliyunESAEnabled {
		t.Fatalf("legacy edge vendor was not migrated: %#v", cfg.AuthConfig)
	}
}

func TestManagerLoadKeepsTencentEdgeOneMutuallyExclusive(t *testing.T) {
	cfg := loadConfigFromJSON(t, `{"auth_config":{"edge_client_ip_enabled":true,"aliyun_esa_enabled":true,"tencent_edgeone_enabled":true}}`)
	if cfg.AuthConfig.AliyunESAEnabled || !cfg.AuthConfig.TencentEdgeOneEnabled {
		t.Fatalf("vendor selection = %#v, want Tencent only", cfg.AuthConfig)
	}
}

func TestManagerLoadAppliesMissingReverseProxyThrottleDefaults(t *testing.T) {
	cfg := loadConfigFromJSON(t, `{}`)
	if !cfg.ReverseProxyThrottle.Enabled ||
		cfg.ReverseProxyThrottle.RequestsPerSecond != defaultReverseProxyThrottleRPS ||
		cfg.ReverseProxyThrottle.Burst != defaultReverseProxyThrottleBurst ||
		cfg.ReverseProxyThrottle.BlockSeconds != defaultReverseProxyThrottleBlockSecs {
		t.Fatalf("reverse proxy throttle defaults = %#v", cfg.ReverseProxyThrottle)
	}
}

func TestManagerLoadPreservesExplicitDisabledReverseProxyThrottle(t *testing.T) {
	cfg := loadConfigFromJSON(t, `{"reverse_proxy_throttle":{"enabled":false}}`)
	if cfg.ReverseProxyThrottle.Enabled {
		t.Fatalf("disabled throttle became enabled: %#v", cfg.ReverseProxyThrottle)
	}
	if cfg.ReverseProxyThrottle.RequestsPerSecond != 0 || cfg.ReverseProxyThrottle.Burst != 0 || cfg.ReverseProxyThrottle.BlockSeconds != 0 {
		t.Fatalf("disabled throttle was unexpectedly defaulted: %#v", cfg.ReverseProxyThrottle)
	}
}

func TestManagerSaveNormalizesNilSlices(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	manager := NewManager(path)
	if err := manager.Save(&AppConfig{}); err != nil {
		t.Fatalf("Save() returned error: %v", err)
	}
	cfg, err := manager.Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if cfg.Rules == nil || cfg.HostRules == nil || cfg.StreamRules == nil || cfg.GeneralBlacklist.Items == nil {
		t.Fatalf("nil slices remained after Save/Load: %#v", cfg)
	}
}

func TestManagerUpdatePersistsMutation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	manager := NewManager(path)
	if err := manager.Update(func(cfg *AppConfig) error {
		cfg.DefaultRoute = "/app"
		cfg.Rules = []models.Rule{{Path: "/app", Target: "http://127.0.0.1:8080"}}
		return nil
	}); err != nil {
		t.Fatalf("Update() returned error: %v", err)
	}
	cfg, err := manager.Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if cfg.DefaultRoute != "/app" || len(cfg.Rules) != 1 {
		t.Fatalf("persisted config = %#v, want updated route", cfg)
	}
}

func TestManagerUpdateCallbackErrorDoesNotPersist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	manager := NewManager(path)
	if _, err := manager.Load(); err != nil {
		t.Fatalf("initial Load() returned error: %v", err)
	}
	err := manager.Update(func(cfg *AppConfig) error {
		cfg.DefaultRoute = "/bad"
		return os.ErrPermission
	})
	if err == nil {
		t.Fatal("Update() returned nil error")
	}
	cfg, err := manager.Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if cfg.DefaultRoute == "/bad" {
		t.Fatalf("failed update was persisted: %#v", cfg)
	}
}

func TestManagerLoadTrimsPublicAuthBaseURL(t *testing.T) {
	cfg := loadConfigFromJSON(t, `{"auth_config":{"public_auth_base_url":"https://auth.example.test///"}}`)
	if cfg.AuthConfig.PublicAuthBaseURL != "https://auth.example.test" {
		t.Fatalf("PublicAuthBaseURL = %q", cfg.AuthConfig.PublicAuthBaseURL)
	}
}

func TestManagerLoadTrimsAuthHost(t *testing.T) {
	cfg := loadConfigFromJSON(t, `{"auth_config":{"auth_host":" auth.example.test "}}`)
	if cfg.AuthConfig.AuthHost != "auth.example.test" {
		t.Fatalf("AuthHost = %q", cfg.AuthConfig.AuthHost)
	}
}

func TestManagerLoadClampsNegativePublicPorts(t *testing.T) {
	cfg := loadConfigFromJSON(t, `{"auth_config":{"public_http_port":-80,"public_https_port":-443}}`)
	if cfg.AuthConfig.PublicHTTPPort != 0 || cfg.AuthConfig.PublicHTTPSPort != 0 {
		t.Fatalf("negative public ports were not clamped: %#v", cfg.AuthConfig)
	}
}

func TestManagerLoadMigratesLegacySSLPair(t *testing.T) {
	cfg := loadConfigFromJSON(t, `{"ssl_cert":" cert ","ssl_key":" key "}`)
	if len(cfg.SSL.Certificates) != 1 {
		t.Fatalf("SSL certificates = %#v, want one legacy certificate", cfg.SSL.Certificates)
	}
	cert := cfg.SSL.Certificates[0]
	if cert.ID != "legacy-default" || cert.Cert != "cert" || cert.Key != "key" || !cert.IsDefault {
		t.Fatalf("legacy SSL certificate = %#v", cert)
	}
}

func TestManagerLoadNormalizesInvalidSSLDeploymentMode(t *testing.T) {
	cfg := loadConfigFromJSON(t, `{"ssl":{"deployment_mode":"unknown","certificates":[]}}`)
	if cfg.SSL.DeploymentMode != models.SSLDeploymentModeSingleActive {
		t.Fatalf("SSL deployment mode = %q", cfg.SSL.DeploymentMode)
	}
}

func TestManagerSaveCreatesNestedDirectories(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a", "b", "config.json")
	if err := NewManager(path).Save(defaultConfig()); err != nil {
		t.Fatalf("Save() returned error: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("saved file missing: %v", err)
	}
}

func TestManagerLoadAppliesLoggingMaxDaysDefault(t *testing.T) {
	cfg := loadConfigFromJSON(t, `{"logging":{"enabled":true,"max_days":0}}`)
	if cfg.Logging.MaxDays != gatewaylog.DefaultMaxDays {
		t.Fatalf("Logging.MaxDays = %d, want %d", cfg.Logging.MaxDays, gatewaylog.DefaultMaxDays)
	}
}

func TestManagerLoadNormalizesLocale(t *testing.T) {
	cfg := loadConfigFromJSON(t, `{"locale":{"default_locale":"zh"}}`)
	if cfg.Locale.DefaultLocale != i18n.DefaultLocale {
		t.Fatalf("Locale.DefaultLocale = %q, want %q", cfg.Locale.DefaultLocale, i18n.DefaultLocale)
	}
}

func TestManagerLoadRewritesMigratedConfigToDisk(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"auth_config":{"auth_port":7997}}`), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if _, err := NewManager(path).Load(); err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if !strings.Contains(string(data), "auth_cache_ttl_seconds") {
		t.Fatalf("migrated config was not written to disk: %s", string(data))
	}
}

func loadConfigFromJSON(t *testing.T, raw string) *AppConfig {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if !json.Valid([]byte(raw)) {
		t.Fatalf("test JSON is invalid: %s", raw)
	}
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := NewManager(path).Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	return cfg
}
