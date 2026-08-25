package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
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
	if cfg.GatewayListener.Scope != models.GatewayListenerScopeAll {
		t.Fatalf("default listener scope = %q, want %q", cfg.GatewayListener.Scope, models.GatewayListenerScopeAll)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("default config was not written: %v", err)
	}
}

func TestManagerLoadNormalizesGatewayListenerScope(t *testing.T) {
	cfg := loadConfigFromJSON(t, `{"gateway_listener":{"scope":" LOOPBACK "}}`)
	if cfg.GatewayListener.Scope != models.GatewayListenerScopeLoopback {
		t.Fatalf("normalized listener scope = %q", cfg.GatewayListener.Scope)
	}
	cfg = loadConfigFromJSON(t, `{"gateway_listener":{"scope":"public"}}`)
	if cfg.GatewayListener.Scope != defaultGatewayListenerScope() {
		t.Fatalf("invalid listener scope = %q, want platform default", cfg.GatewayListener.Scope)
	}
}

func TestManagerLoadRestoresAndValidatesStreamAvailability(t *testing.T) {
	cfg := loadConfigFromJSON(t, `{"stream_availability":{"enabled":true,"start_time":" 22:00 ","end_time":"06:00"}}`)
	if cfg.StreamAvailability == nil || cfg.StreamAvailability.StartTime != "22:00" || cfg.StreamAvailability.EndTime != "06:00" {
		t.Fatalf("stream availability = %#v", cfg.StreamAvailability)
	}

	cfg = loadConfigFromJSON(t, `{"stream_availability":{"enabled":true,"start_time":"09:00","end_time":"09:00"}}`)
	if cfg.StreamAvailability != nil {
		t.Fatalf("invalid stream availability was retained: %#v", cfg.StreamAvailability)
	}
}

func TestApplyDefaultsMarksNormalizedStreamAvailabilityAsChanged(t *testing.T) {
	cfg := defaultConfig()
	cfg.StreamAvailability = &models.StreamAvailability{
		Enabled: true, StartTime: " 22:00 ", EndTime: "06:00",
	}
	if !applyDefaults(cfg) {
		t.Fatal("applyDefaults did not report the normalized availability")
	}
	if cfg.StreamAvailability == nil || cfg.StreamAvailability.StartTime != "22:00" {
		t.Fatalf("stream availability = %#v", cfg.StreamAvailability)
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

func TestReadFileLimitedRejectsOversizedConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte("123456789"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if _, err := readFileLimited(path, 8); !errors.Is(err, errConfigFileTooLarge) {
		t.Fatalf("readFileLimited() error = %v, want %v", err, errConfigFileTooLarge)
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

func TestManagerLoadNormalizesGatewayUnmatchedRouteBehavior(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want string
	}{
		{name: "missing", raw: `{}`, want: models.GatewayUnmatchedRouteBehaviorErrorPage},
		{name: "invalid", raw: `{"unmatched_route":{"behavior":"drop"}}`, want: models.GatewayUnmatchedRouteBehaviorErrorPage},
		{name: "reset", raw: `{"unmatched_route":{"behavior":"reset_connection"}}`, want: models.GatewayUnmatchedRouteBehaviorResetConnection},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := loadConfigFromJSON(t, tc.raw)
			if got := cfg.UnmatchedRoute.Behavior; got != tc.want {
				t.Fatalf("behavior = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestManagerLoadNormalizesGatewayUpstreamErrorDetail(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want string
	}{
		{name: "missing", raw: `{}`, want: models.GatewayUpstreamErrorDetailLess},
		{name: "invalid", raw: `{"unmatched_route":{"upstream_error_detail":"debug"}}`, want: models.GatewayUpstreamErrorDetailLess},
		{name: "more", raw: `{"unmatched_route":{"upstream_error_detail":"more"}}`, want: models.GatewayUpstreamErrorDetailMore},
		{name: "reset", raw: `{"unmatched_route":{"upstream_error_detail":"reset_connection"}}`, want: models.GatewayUpstreamErrorDetailResetConnection},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := loadConfigFromJSON(t, tc.raw)
			if got := cfg.UnmatchedRoute.UpstreamErrorDetail; got != tc.want {
				t.Fatalf("upstream error detail = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestManagerPersistsGatewayUnmatchedRouteBehavior(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	manager := NewManager(path)
	cfg, err := manager.Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	cfg.UnmatchedRoute.Behavior = models.GatewayUnmatchedRouteBehaviorResetConnection
	cfg.UnmatchedRoute.UpstreamErrorDetail = models.GatewayUpstreamErrorDetailResetConnection
	if err := manager.Save(cfg); err != nil {
		t.Fatalf("Save() returned error: %v", err)
	}
	reloaded, err := manager.Load()
	if err != nil {
		t.Fatalf("reload returned error: %v", err)
	}
	if got := reloaded.UnmatchedRoute.Behavior; got != models.GatewayUnmatchedRouteBehaviorResetConnection {
		t.Fatalf("reloaded behavior = %q, want reset_connection", got)
	}
	if got := reloaded.UnmatchedRoute.UpstreamErrorDetail; got != models.GatewayUpstreamErrorDetailResetConnection {
		t.Fatalf("reloaded upstream error detail = %q, want reset_connection", got)
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

func TestManagerLoadNormalizesHostProtocolModes(t *testing.T) {
	cfg := loadConfigFromJSON(t, `{
		"host_rules": [
			{"host":"missing.example.test","target":"http://127.0.0.1:8080"},
			{"host":"h1.example.test","target":"http://127.0.0.1:8081","protocol_mode":" HTTP1 "},
			{"host":"invalid.example.test","target":"http://127.0.0.1:8082","protocol_mode":"quic"}
		]
	}`)
	if got := cfg.HostRules[0].ProtocolMode; got != models.HostProtocolModeAuto {
		t.Fatalf("missing protocol mode = %q, want auto", got)
	}
	if got := cfg.HostRules[1].ProtocolMode; got != models.HostProtocolModeHTTP1 {
		t.Fatalf("HTTP1 protocol mode = %q, want http1", got)
	}
	if got := cfg.HostRules[2].ProtocolMode; got != models.HostProtocolModeAuto {
		t.Fatalf("invalid protocol mode = %q, want auto", got)
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

func TestManagerSaveAtomicallyReplacesAndPreservesExistingMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not expose Unix permission bits")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{"default_route":"/old"}`), 0o600); err != nil {
		t.Fatalf("write old config: %v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("chmod old config: %v", err)
	}

	cfg := defaultConfig()
	cfg.DefaultRoute = "/new"
	if err := NewManager(path).Save(cfg); err != nil {
		t.Fatalf("Save() returned error: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read saved config: %v", err)
	}
	if !json.Valid(data) || !strings.Contains(string(data), `"default_route": "/new"`) {
		t.Fatalf("saved config is not the complete replacement: %s", data)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat saved config: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("saved config mode = %o, want preserved 600", got)
	}
	assertNoAtomicConfigTemps(t, dir, path)
}

func TestManagerSaveCreatesAndHardensPrivateConfigPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not expose Unix permission bits")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	manager := NewManager(path)
	if err := manager.Save(defaultConfig()); err != nil {
		t.Fatalf("create config: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat created config: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("created config mode = %o, want 600", got)
	}

	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("make config permissive: %v", err)
	}
	if _, err := manager.Load(); err != nil {
		t.Fatalf("load permissive config: %v", err)
	}
	info, err = os.Stat(path)
	if err != nil {
		t.Fatalf("stat hardened config: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("hardened config mode = %o, want 600", got)
	}
}

func TestWriteFileAtomicallyRenameFailurePreservesExistingFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not expose Unix permission bits")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	oldData := []byte(`{"default_route":"/old"}`)
	newData := []byte(`{"default_route":"/new"}`)
	if err := os.WriteFile(path, oldData, 0o600); err != nil {
		t.Fatalf("write old config: %v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("chmod old config: %v", err)
	}

	wantErr := errors.New("forced rename failure")
	renameCalled := false
	err := writeFileAtomicallyWithRename(path, newData, 0o644, func(oldPath string, newPath string) error {
		renameCalled = true
		if newPath != path || filepath.Dir(oldPath) != dir {
			t.Fatalf("rename paths = %q -> %q, want same-directory temp -> %q", oldPath, newPath, path)
		}
		got, readErr := os.ReadFile(oldPath)
		if readErr != nil {
			t.Fatalf("read completed temp file: %v", readErr)
		}
		if string(got) != string(newData) {
			t.Fatalf("temp data = %q, want %q", got, newData)
		}
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("writeFileAtomicallyWithRename() error = %v, want %v", err, wantErr)
	}
	if !renameCalled {
		t.Fatal("atomic rename was not attempted")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read old config after failure: %v", err)
	}
	if string(got) != string(oldData) {
		t.Fatalf("old config changed after failed rename: got %q want %q", got, oldData)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat old config after failure: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("old config mode = %o after failure, want 600", got)
	}
	assertNoAtomicConfigTemps(t, dir, path)
}

func assertNoAtomicConfigTemps(t *testing.T, dir string, path string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, "."+filepath.Base(path)+".tmp-*"))
	if err != nil {
		t.Fatalf("glob atomic config temps: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("atomic config temp files were not cleaned up: %#v", matches)
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

func TestManagerUpdateSkipsIdenticalDurableRewrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	manager := NewManager(path)
	if err := manager.Save(DefaultConfig()); err != nil {
		t.Fatalf("Save() returned error: %v", err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat config before no-op update: %v", err)
	}

	if err := manager.Update(func(*AppConfig) error { return nil }); err != nil {
		t.Fatalf("Update() returned error: %v", err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat config after no-op update: %v", err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("no-op update atomically replaced an identical config file")
	}
}

func TestManagerRepeatedLoadSkipsIdenticalMigrationRewrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	manager := NewManager(path)
	if err := manager.Save(DefaultConfig()); err != nil {
		t.Fatalf("Save() returned error: %v", err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat config before repeated load: %v", err)
	}

	if _, err := manager.Load(); err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat config after repeated load: %v", err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("repeated load replaced an already-normalized config file")
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

func TestManagerLoadPersistsNormalizedHostProtocolMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	raw := `{"host_rules":[{"host":"video.example.test","target":"http://127.0.0.1:8080","protocol_mode":"invalid"}]}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := NewManager(path).Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if got := cfg.HostRules[0].ProtocolMode; got != models.HostProtocolModeAuto {
		t.Fatalf("normalized protocol mode = %q, want auto", got)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if !strings.Contains(string(data), `"protocol_mode": "auto"`) {
		t.Fatalf("normalized protocol mode was not persisted: %s", data)
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
