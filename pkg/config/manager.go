package config

import (
	"encoding/json"
	"go-reauth-proxy/pkg/gatewaylog"
	"go-reauth-proxy/pkg/i18n"
	"go-reauth-proxy/pkg/logger"
	"go-reauth-proxy/pkg/models"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const (
	defaultAuthCacheTTLSeconds             = 1
	defaultAuthCacheUnauthorizedTTLSeconds = 1
	defaultReverseProxyThrottleRPS         = 100
	defaultReverseProxyThrottleBurst       = 200
	defaultReverseProxyThrottleBlockSecs   = 30
)

type AppConfig struct {
	Rules                []models.Rule                     `json:"rules"`
	HostRules            []models.HostRule                 `json:"host_rules,omitempty"`
	StreamRules          []models.StreamRule               `json:"stream_rules,omitempty"`
	DefaultRoute         string                            `json:"default_route"`
	AuthConfig           models.AuthConfig                 `json:"auth_config"`
	AdminPort            int                               `json:"admin_port,omitempty"`
	ProxyProtocolForce   bool                              `json:"proxy_protocol_force,omitempty"`
	GatewayListener      models.GatewayListenerConfig      `json:"gateway_listener,omitempty"`
	ReverseProxyThrottle models.ReverseProxyThrottleConfig `json:"reverse_proxy_throttle,omitempty"`
	Visibility           models.GatewayVisibilityConfig    `json:"visibility,omitempty"`
	ForwardedHeaders     models.ForwardedHeadersConfig     `json:"forwarded_headers,omitempty"`
	PreserveHost         models.PreserveHostConfig         `json:"preserve_host,omitempty"`
	CrawlerBlocker       models.CrawlerBlockerConfig       `json:"crawler_blocker,omitempty"`
	Portal               models.GatewayPortalConfig        `json:"portal,omitempty"`
	FnosPortIconHijack   models.FnosPortIconHijackConfig   `json:"fnos_port_icon_hijack,omitempty"`
	IptablesChainName    string                            `json:"iptables_chain_name,omitempty"`
	Logging              models.LoggingConfig              `json:"logging,omitempty"`
	GeneralBlacklist     models.GeneralBlacklistConfig     `json:"general_blacklist,omitempty"`
	WAF                  models.WAFConfig                  `json:"waf,omitempty"`
	Locale               models.LocaleConfig               `json:"locale,omitempty"`
	SSL                  models.SSLConfig                  `json:"ssl,omitempty"`
	SSLCert              string                            `json:"ssl_cert,omitempty"`
	SSLKey               string                            `json:"ssl_key,omitempty"`
}

type Manager struct {
	filePath string
	mu       sync.RWMutex
}

func NewManager(filePath string) *Manager {
	return &Manager{
		filePath: filePath,
	}
}

func (m *Manager) RuntimeDir() string {
	if m == nil || strings.TrimSpace(m.filePath) == "" {
		return "."
	}
	return filepath.Dir(m.filePath)
}

func defaultConfig() *AppConfig {
	return &AppConfig{
		Rules:        []models.Rule{},
		HostRules:    []models.HostRule{},
		StreamRules:  []models.StreamRule{},
		DefaultRoute: "/__select__",
		AuthConfig: models.AuthConfig{
			AuthPort:              7997,
			AuthURL:               "/api/auth/verify",
			LoginURL:              "/login",
			LogoutURL:             "/api/auth/logout",
			PreflightURL:          "/api/auth/preflight",
			AuthCacheTTL:          defaultAuthCacheTTLSeconds,
			AuthCacheFailTTL:      defaultAuthCacheUnauthorizedTTLSeconds,
			EdgeClientIPEnabled:   false,
			AliyunESAEnabled:      false,
			TencentEdgeOneEnabled: false,
			PublicAuthBaseURL:     "",
			PublicHTTPPort:        0,
			PublicHTTPSPort:       0,
			AuthHost:              "",
		},
		AdminPort:          7996,
		ProxyProtocolForce: false,
		GatewayListener: models.GatewayListenerConfig{
			Scope: defaultGatewayListenerScope(),
		},
		ReverseProxyThrottle: models.ReverseProxyThrottleConfig{
			Enabled:           true,
			RequestsPerSecond: defaultReverseProxyThrottleRPS,
			Burst:             defaultReverseProxyThrottleBurst,
			BlockSeconds:      defaultReverseProxyThrottleBlockSecs,
		},
		Visibility: models.GatewayVisibilityConfig{
			Enabled:   false,
			CIDRs:     []string{},
			UpdatedAt: "",
		},
		ForwardedHeaders: models.ForwardedHeadersConfig{
			Enabled:     false,
			OmitTargets: []string{},
			UpdatedAt:   "",
		},
		PreserveHost: models.PreserveHostConfig{
			Enabled:     true,
			OmitTargets: []string{},
			UpdatedAt:   "",
		},
		CrawlerBlocker: models.CrawlerBlockerConfig{
			Enabled:   false,
			UpdatedAt: "",
		},
		Portal: models.GatewayPortalConfig{
			Enabled:      true,
			DisplayStyle: models.GatewayPortalDisplayStyleDomain,
			ShowAppIcon:  false,
			IconDragMode: models.GatewayPortalIconDragModeCorners,
		},
		FnosPortIconHijack: models.FnosPortIconHijackConfig{
			Enabled:   false,
			UpdatedAt: "",
		},
		Logging: models.LoggingConfig{
			Enabled: false,
			MaxDays: gatewaylog.DefaultMaxDays,
		},
		GeneralBlacklist: models.GeneralBlacklistConfig{
			Items: []models.GeneralBlacklistRecord{},
		},
		SSL: models.SSLConfig{
			DeploymentMode: models.SSLDeploymentModeSingleActive,
			Certificates:   []models.SSLDeployedCertificate{},
		},
		Locale: models.LocaleConfig{
			DefaultLocale: i18n.DefaultLocale,
		},
	}
}

// DefaultConfig returns a fresh gateway configuration with no user-managed
// data. Callers may safely modify the returned value.
func DefaultConfig() *AppConfig {
	return defaultConfig()
}

func applyDefaults(cfg *AppConfig) bool {
	changed := false

	if cfg.Rules == nil {
		cfg.Rules = []models.Rule{}
		changed = true
	}
	if cfg.HostRules == nil {
		cfg.HostRules = []models.HostRule{}
		changed = true
	}
	for i := range cfg.HostRules {
		normalized := models.NormalizeHostProtocolMode(cfg.HostRules[i].ProtocolMode)
		if cfg.HostRules[i].ProtocolMode != normalized {
			cfg.HostRules[i].ProtocolMode = normalized
			changed = true
		}
	}
	if cfg.StreamRules == nil {
		cfg.StreamRules = []models.StreamRule{}
		changed = true
	}
	if cfg.SSL.Certificates == nil {
		cfg.SSL.Certificates = []models.SSLDeployedCertificate{}
		changed = true
	}
	if cfg.SSL.DeploymentMode != models.SSLDeploymentModeMultiSNI {
		if cfg.SSL.DeploymentMode != models.SSLDeploymentModeSingleActive {
			changed = true
		}
		cfg.SSL.DeploymentMode = models.SSLDeploymentModeSingleActive
	}
	if len(cfg.SSL.Certificates) == 0 {
		legacyCert := strings.TrimSpace(cfg.SSLCert)
		legacyKey := strings.TrimSpace(cfg.SSLKey)
		if legacyCert != "" && legacyKey != "" {
			cfg.SSL = models.SSLConfig{
				DeploymentMode: models.SSLDeploymentModeSingleActive,
				Certificates: []models.SSLDeployedCertificate{
					{
						ID:        "legacy-default",
						Label:     "Legacy SSL",
						Cert:      legacyCert,
						Key:       legacyKey,
						IsDefault: true,
					},
				},
			}
			changed = true
		}
	}

	if cfg.DefaultRoute == "" {
		cfg.DefaultRoute = "/__select__"
		changed = true
	}
	if cfg.AuthConfig.AuthPort <= 0 {
		cfg.AuthConfig.AuthPort = 7997
		changed = true
	}
	if cfg.AuthConfig.AuthURL == "" {
		cfg.AuthConfig.AuthURL = "/api/auth/verify"
		changed = true
	}
	if cfg.AuthConfig.LoginURL == "" {
		cfg.AuthConfig.LoginURL = "/login"
		changed = true
	}
	if cfg.AuthConfig.LogoutURL == "" {
		cfg.AuthConfig.LogoutURL = "/api/auth/logout"
		changed = true
	}
	if cfg.AuthConfig.PreflightURL == "" {
		cfg.AuthConfig.PreflightURL = "/api/auth/preflight"
		changed = true
	}
	if cfg.AuthConfig.AuthCacheTTL < 0 {
		cfg.AuthConfig.AuthCacheTTL = 0
		changed = true
	}
	if cfg.AuthConfig.AuthCacheFailTTL < 0 {
		cfg.AuthConfig.AuthCacheFailTTL = 0
		changed = true
	}
	if cfg.AuthConfig.PublicAuthBaseURL != strings.TrimSpace(strings.TrimRight(cfg.AuthConfig.PublicAuthBaseURL, "/")) {
		cfg.AuthConfig.PublicAuthBaseURL = strings.TrimSpace(strings.TrimRight(cfg.AuthConfig.PublicAuthBaseURL, "/"))
		changed = true
	}
	if cfg.AuthConfig.PublicHTTPPort < 0 {
		cfg.AuthConfig.PublicHTTPPort = 0
		changed = true
	}
	if cfg.AuthConfig.PublicHTTPSPort < 0 {
		cfg.AuthConfig.PublicHTTPSPort = 0
		changed = true
	}
	if cfg.AuthConfig.AuthHost != strings.TrimSpace(cfg.AuthConfig.AuthHost) {
		cfg.AuthConfig.AuthHost = strings.TrimSpace(cfg.AuthConfig.AuthHost)
		changed = true
	}
	if cfg.AuthConfig.NormalizeEdgeClientIPSelection() {
		changed = true
	}
	normalizedPortal := models.NormalizeGatewayPortalConfig(cfg.Portal)
	if cfg.Portal != normalizedPortal {
		cfg.Portal = normalizedPortal
		changed = true
	}
	normalizedLocale := i18n.NormalizeConfig(i18n.LocaleConfig{DefaultLocale: cfg.Locale.DefaultLocale})
	if cfg.Locale.DefaultLocale != normalizedLocale.DefaultLocale {
		cfg.Locale.DefaultLocale = normalizedLocale.DefaultLocale
		changed = true
	}
	i18n.SetDefaultLocale(cfg.Locale.DefaultLocale)

	if cfg.AdminPort <= 0 {
		cfg.AdminPort = 7996
		changed = true
	}
	listenerScope := models.NormalizeGatewayListenerScope(cfg.GatewayListener.Scope)
	if listenerScope == "" {
		listenerScope = defaultGatewayListenerScope()
	}
	if cfg.GatewayListener.Scope != listenerScope {
		cfg.GatewayListener.Scope = listenerScope
		changed = true
	}
	if cfg.ReverseProxyThrottle.Enabled {
		if cfg.ReverseProxyThrottle.RequestsPerSecond <= 0 {
			cfg.ReverseProxyThrottle.RequestsPerSecond = defaultReverseProxyThrottleRPS
			changed = true
		}
		if cfg.ReverseProxyThrottle.Burst <= 0 {
			cfg.ReverseProxyThrottle.Burst = defaultReverseProxyThrottleBurst
			changed = true
		}
		if cfg.ReverseProxyThrottle.BlockSeconds <= 0 {
			cfg.ReverseProxyThrottle.BlockSeconds = defaultReverseProxyThrottleBlockSecs
			changed = true
		}
	}
	if cfg.Visibility.CIDRs == nil {
		cfg.Visibility.CIDRs = []string{}
		changed = true
	}
	if cfg.Visibility.UpdatedAt == "" {
		cfg.Visibility.UpdatedAt = ""
	}
	if cfg.ForwardedHeaders.OmitTargets == nil {
		cfg.ForwardedHeaders.OmitTargets = []string{}
		changed = true
	}
	if cfg.ForwardedHeaders.UpdatedAt == "" {
		cfg.ForwardedHeaders.UpdatedAt = ""
	}
	if cfg.PreserveHost.OmitTargets == nil {
		cfg.PreserveHost.OmitTargets = []string{}
		changed = true
	}
	if cfg.PreserveHost.UpdatedAt == "" {
		cfg.PreserveHost.UpdatedAt = ""
	}
	if cfg.CrawlerBlocker.UpdatedAt == "" {
		cfg.CrawlerBlocker.UpdatedAt = ""
	}
	if cfg.Logging.MaxDays <= 0 {
		cfg.Logging.MaxDays = gatewaylog.DefaultMaxDays
		changed = true
	}
	if cfg.GeneralBlacklist.Items == nil {
		cfg.GeneralBlacklist.Items = []models.GeneralBlacklistRecord{}
		changed = true
	}
	if cfg.WAF.DisabledHosts == nil {
		cfg.WAF.DisabledHosts = []string{}
		changed = true
	}
	if cfg.WAF.DisabledPathPrefixes == nil {
		cfg.WAF.DisabledPathPrefixes = []string{}
		changed = true
	}

	return changed
}

func detectAuthConfigFieldPresence(data []byte) (hasAuthCacheTTL bool, hasAuthCacheFailTTL bool, hasEdgeClientIPEnabled bool) {
	var raw struct {
		AuthConfig map[string]json.RawMessage `json:"auth_config"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return false, false, false
	}
	if raw.AuthConfig == nil {
		return false, false, false
	}

	_, hasAuthCacheTTL = raw.AuthConfig["auth_cache_ttl_seconds"]
	_, hasAuthCacheFailTTL = raw.AuthConfig["auth_cache_unauthorized_ttl_seconds"]
	_, hasEdgeClientIPEnabled = raw.AuthConfig["edge_client_ip_enabled"]
	return hasAuthCacheTTL, hasAuthCacheFailTTL, hasEdgeClientIPEnabled
}

func detectReverseProxyThrottleFieldPresence(data []byte) bool {
	var raw struct {
		ReverseProxyThrottle json.RawMessage `json:"reverse_proxy_throttle"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return false
	}
	return len(raw.ReverseProxyThrottle) > 0
}

func applyMissingAuthCacheDefaults(cfg *AppConfig, hasAuthCacheTTL bool, hasAuthCacheFailTTL bool) bool {
	changed := false

	if !hasAuthCacheTTL && cfg.AuthConfig.AuthCacheTTL == 0 {
		cfg.AuthConfig.AuthCacheTTL = defaultAuthCacheTTLSeconds
		changed = true
	}
	if !hasAuthCacheFailTTL && cfg.AuthConfig.AuthCacheFailTTL == 0 {
		cfg.AuthConfig.AuthCacheFailTTL = defaultAuthCacheUnauthorizedTTLSeconds
		changed = true
	}

	return changed
}

func applyMissingReverseProxyThrottleDefaults(cfg *AppConfig, hasReverseProxyThrottle bool) bool {
	if hasReverseProxyThrottle {
		return false
	}

	cfg.ReverseProxyThrottle = models.ReverseProxyThrottleConfig{
		Enabled:           true,
		RequestsPerSecond: defaultReverseProxyThrottleRPS,
		Burst:             defaultReverseProxyThrottleBurst,
		BlockSeconds:      defaultReverseProxyThrottleBlockSecs,
	}
	return true
}

func (m *Manager) loadUnlocked() (*AppConfig, bool, bool, error) {
	data, err := os.ReadFile(m.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return defaultConfig(), false, true, nil
		}
		return nil, false, false, err
	}

	var cfg AppConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, true, false, err
	}
	hasAuthCacheTTL, hasAuthCacheFailTTL, hasEdgeClientIPEnabled := detectAuthConfigFieldPresence(data)
	migrated := false
	if !hasEdgeClientIPEnabled && (cfg.AuthConfig.AliyunESAEnabled || cfg.AuthConfig.TencentEdgeOneEnabled) {
		cfg.AuthConfig.EdgeClientIPEnabled = true
		migrated = true
	}
	if applyDefaults(&cfg) {
		migrated = true
	}
	hasReverseProxyThrottle := detectReverseProxyThrottleFieldPresence(data)
	if applyMissingAuthCacheDefaults(&cfg, hasAuthCacheTTL, hasAuthCacheFailTTL) {
		migrated = true
	}
	if applyMissingReverseProxyThrottleDefaults(&cfg, hasReverseProxyThrottle) {
		migrated = true
	}
	return &cfg, true, migrated, nil
}

func (m *Manager) saveUnlocked(cfg *AppConfig) error {
	dir := filepath.Dir(m.filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	return writeFileAtomically(m.filePath, data, 0644)
}

type atomicRenameFunc func(oldPath string, newPath string) error

func writeFileAtomically(path string, data []byte, perm os.FileMode) error {
	return writeFileAtomicallyWithRename(path, data, perm, platformAtomicRename)
}

func writeFileAtomicallyWithRename(path string, data []byte, perm os.FileMode, rename atomicRenameFunc) error {
	dir := filepath.Dir(path)
	targetPerm := perm
	if info, err := os.Stat(path); err == nil {
		// os.WriteFile preserves the mode of an existing file. Preserve that
		// behavior when replacing the inode so a manually-hardened config does
		// not become more permissive after the next save.
		targetPerm = info.Mode().Perm()
	} else if !os.IsNotExist(err) {
		return err
	}

	temp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	removeTemp := true
	defer func() {
		_ = temp.Close()
		if removeTemp {
			_ = os.Remove(tempPath)
		}
	}()

	if err := temp.Chmod(targetPerm); err != nil {
		return err
	}
	if n, err := temp.Write(data); err != nil {
		return err
	} else if n != len(data) {
		return io.ErrShortWrite
	}
	if err := temp.Sync(); err != nil {
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := rename(tempPath, path); err != nil {
		return err
	}
	removeTemp = false

	// Persist the directory entry update as well as the file contents. Without
	// this sync, a successful Rename can still disappear after a power loss.
	return syncParentDirectory(dir)
}

func (m *Manager) Load() (*AppConfig, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	cfg, existed, migrated, err := m.loadUnlocked()
	if err != nil {
		if event := logger.DebugEvent("config", "load_failed"); event != nil {
			event.Str("path", logger.SanitizeLogString(m.filePath)).
				Str("error", logger.SanitizeLogString(err.Error())).
				Send()
		}
		return nil, err
	}
	if !existed || migrated {
		if err := m.saveUnlocked(cfg); err != nil {
			if event := logger.DebugEvent("config", "save_failed"); event != nil {
				event.Str("path", logger.SanitizeLogString(m.filePath)).
					Bool("created_default", !existed).
					Bool("migrated", migrated).
					Str("error", logger.SanitizeLogString(err.Error())).
					Send()
			}
			return nil, err
		}
	}
	if event := logger.DebugEvent("config", "load_end"); event != nil {
		event.Str("path", logger.SanitizeLogString(m.filePath)).
			Bool("existed", existed).
			Bool("created_default", !existed).
			Bool("migrated", migrated).
			Int("path_rule_count", len(cfg.Rules)).
			Int("host_rule_count", len(cfg.HostRules)).
			Int("stream_rule_count", len(cfg.StreamRules)).
			Bool("gateway_logging_enabled", cfg.Logging.Enabled).
			Bool("waf_enabled", cfg.WAF.Enabled).
			Send()
	}
	return cfg, nil
}

func (m *Manager) Save(config *AppConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	applyDefaults(config)
	err := m.saveUnlocked(config)
	if event := logger.DebugEvent("config", "save"); event != nil {
		event.Str("path", logger.SanitizeLogString(m.filePath)).
			Bool("ok", err == nil).
			Str("error", func() string {
				if err == nil {
					return ""
				}
				return logger.SanitizeLogString(err.Error())
			}()).
			Send()
	}
	return err
}

func (m *Manager) Update(updateFn func(*AppConfig) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	cfg, _, _, err := m.loadUnlocked()
	if err != nil {
		if event := logger.DebugEvent("config", "update_load_failed"); event != nil {
			event.Str("path", logger.SanitizeLogString(m.filePath)).
				Str("error", logger.SanitizeLogString(err.Error())).
				Send()
		}
		return err
	}

	if err := updateFn(cfg); err != nil {
		if event := logger.DebugEvent("config", "update_callback_failed"); event != nil {
			event.Str("path", logger.SanitizeLogString(m.filePath)).
				Str("error", logger.SanitizeLogString(err.Error())).
				Send()
		}
		return err
	}

	applyDefaults(cfg)
	err = m.saveUnlocked(cfg)
	if event := logger.DebugEvent("config", "update_saved"); event != nil {
		event.Str("path", logger.SanitizeLogString(m.filePath)).
			Bool("ok", err == nil).
			Int("path_rule_count", len(cfg.Rules)).
			Int("host_rule_count", len(cfg.HostRules)).
			Int("stream_rule_count", len(cfg.StreamRules)).
			Bool("gateway_logging_enabled", cfg.Logging.Enabled).
			Bool("waf_enabled", cfg.WAF.Enabled).
			Str("error", func() string {
				if err == nil {
					return ""
				}
				return logger.SanitizeLogString(err.Error())
			}()).
			Send()
	}
	return err
}
