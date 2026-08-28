package config

import (
	"bytes"
	"encoding/json"
	"errors"
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
	defaultAuthCacheTTLSeconds                   = 1
	defaultAuthCacheUnauthorizedTTLSeconds       = 1
	maxConfigFileBytes                     int64 = 128 << 20
)

var errConfigFileTooLarge = errors.New("gateway config file is too large")

type AppConfig struct {
	Rules                []models.Rule                      `json:"rules"`
	HostRules            []models.HostRule                  `json:"host_rules,omitempty"`
	VisibilityPolicies   map[string]models.CompiledIPSet    `json:"visibility_policies,omitempty"`
	StreamRules          []models.StreamRule                `json:"stream_rules,omitempty"`
	StreamAccessPolicies map[string]models.CompiledIPSet    `json:"stream_access_policies,omitempty"`
	StreamAvailability   *models.StreamAvailability         `json:"stream_availability,omitempty"`
	DefaultRoute         string                             `json:"default_route"`
	AuthConfig           models.AuthConfig                  `json:"auth_config"`
	AdminPort            int                                `json:"admin_port,omitempty"`
	ProxyProtocolForce   bool                               `json:"proxy_protocol_force,omitempty"`
	ProxyProtocol        models.GatewayProxyProtocolConfig  `json:"proxy_protocol,omitempty"`
	GatewayListener      models.GatewayListenerConfig       `json:"gateway_listener,omitempty"`
	ReverseProxyThrottle models.ReverseProxyThrottleConfig  `json:"reverse_proxy_throttle,omitempty"`
	Visibility           models.GatewayVisibilityConfig     `json:"visibility,omitempty"`
	ForwardedHeaders     models.ForwardedHeadersConfig      `json:"forwarded_headers,omitempty"`
	PreserveHost         models.PreserveHostConfig          `json:"preserve_host,omitempty"`
	CrawlerBlocker       models.CrawlerBlockerConfig        `json:"crawler_blocker,omitempty"`
	Portal               models.GatewayPortalConfig         `json:"portal,omitempty"`
	UnmatchedRoute       models.GatewayUnmatchedRouteConfig `json:"unmatched_route,omitempty"`
	FnosPortIconHijack   models.FnosPortIconHijackConfig    `json:"fnos_port_icon_hijack,omitempty"`
	IptablesChainName    string                             `json:"iptables_chain_name,omitempty"`
	Logging              models.LoggingConfig               `json:"logging,omitempty"`
	GeneralBlacklist     models.GeneralBlacklistConfig      `json:"general_blacklist,omitempty"`
	WAF                  models.WAFConfig                   `json:"waf,omitempty"`
	Locale               models.LocaleConfig                `json:"locale,omitempty"`
	SSL                  models.SSLConfig                   `json:"ssl,omitempty"`
	SSLCert              string                             `json:"ssl_cert,omitempty"`
	SSLKey               string                             `json:"ssl_key,omitempty"`
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
		Rules:                []models.Rule{},
		HostRules:            []models.HostRule{},
		VisibilityPolicies:   map[string]models.CompiledIPSet{},
		StreamRules:          []models.StreamRule{},
		StreamAccessPolicies: map[string]models.CompiledIPSet{},
		DefaultRoute:         "/__select__",
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
		ProxyProtocol: models.GatewayProxyProtocolConfig{
			Enabled:        false,
			TrustedSources: []string{},
		},
		GatewayListener: models.GatewayListenerConfig{
			Scope: defaultGatewayListenerScope(),
		},
		ReverseProxyThrottle: models.DefaultReverseProxyThrottleConfig(),
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
			Version:      models.GatewayPortalVersionV1,
		},
		UnmatchedRoute: models.GatewayUnmatchedRouteConfig{
			Behavior:            models.GatewayUnmatchedRouteBehaviorErrorPage,
			UpstreamErrorDetail: models.GatewayUpstreamErrorDetailLess,
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
		WAF: models.WAFConfig{
			BlockBehavior:        models.WAFBlockBehaviorErrorPage,
			DisabledHosts:        []string{},
			DisabledPathPrefixes: []string{},
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
	if cfg.StreamAccessPolicies == nil {
		cfg.StreamAccessPolicies = map[string]models.CompiledIPSet{}
		changed = true
	}
	previousStreamAvailability := cfg.StreamAvailability
	streamAvailability, err := models.NormalizeDailyAvailability(previousStreamAvailability)
	if err != nil {
		streamAvailability = nil
	}
	if !dailyAvailabilityEqual(previousStreamAvailability, streamAvailability) {
		changed = true
	}
	cfg.StreamAvailability = streamAvailability
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
	normalizedUnmatchedRoute := models.NormalizeGatewayUnmatchedRouteConfig(cfg.UnmatchedRoute)
	if cfg.UnmatchedRoute != normalizedUnmatchedRoute {
		cfg.UnmatchedRoute = normalizedUnmatchedRoute
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
	if cfg.ProxyProtocol.TrustedSources == nil {
		cfg.ProxyProtocol.TrustedSources = []string{}
		changed = true
	}
	if cfg.ReverseProxyThrottle.Enabled {
		if cfg.ReverseProxyThrottle.RequestsPerSecond <= 0 {
			cfg.ReverseProxyThrottle.RequestsPerSecond =
				models.DefaultReverseProxyThrottleRequestsPerSecond
			changed = true
		}
		if cfg.ReverseProxyThrottle.Burst <= 0 {
			cfg.ReverseProxyThrottle.Burst = models.DefaultReverseProxyThrottleBurst
			changed = true
		}
		if cfg.ReverseProxyThrottle.BlockSeconds <= 0 {
			cfg.ReverseProxyThrottle.BlockSeconds =
				models.DefaultReverseProxyThrottleBlockSeconds
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
	if cfg.WAF.BlockBehavior != models.WAFBlockBehaviorErrorPage &&
		cfg.WAF.BlockBehavior != models.WAFBlockBehaviorResetConnection {
		cfg.WAF.BlockBehavior = models.WAFBlockBehaviorErrorPage
		changed = true
	}

	return changed
}

func dailyAvailabilityEqual(left, right *models.DailyAvailability) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Enabled == right.Enabled &&
		left.StartTime == right.StartTime &&
		left.EndTime == right.EndTime
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

	cfg.ReverseProxyThrottle = models.DefaultReverseProxyThrottleConfig()
	return true
}

func (m *Manager) loadUnlocked() (*AppConfig, bool, bool, error) {
	data, err := readFileLimited(m.filePath, maxConfigFileBytes)
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
	if int64(len(data)) > maxConfigFileBytes {
		return errConfigFileTooLarge
	}
	// Startup replays the durable gateway configuration to rebuild runtime
	// state. Replacing an identical file still forces a file fsync, rename, and
	// parent-directory fsync; on a DSM volume waking from hibernation that can
	// take longer than the RPC deadline and cause retries to pile up. Preserve
	// the existing inode when the exact durable representation is unchanged.
	if info, statErr := os.Lstat(m.filePath); statErr == nil && info.Mode().IsRegular() {
		if current, readErr := readFileLimited(m.filePath, maxConfigFileBytes); readErr == nil && bytes.Equal(current, data) {
			return hardenConfigPermissions(m.filePath)
		}
	}

	return writeFileAtomically(m.filePath, data, 0600)
}

func readFileLimited(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() > limit {
		return nil, errConfigFileTooLarge
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errConfigFileTooLarge
	}
	return data, nil
}

type atomicRenameFunc func(oldPath string, newPath string) error

func writeFileAtomically(path string, data []byte, perm os.FileMode) error {
	return writeFileAtomicallyWithRename(path, data, perm, platformAtomicRename)
}

func writeFileAtomicallyWithRename(path string, data []byte, perm os.FileMode, rename atomicRenameFunc) error {
	dir := filepath.Dir(path)
	targetPerm := perm
	if info, err := os.Stat(path); err == nil {
		// Preserve permissions that are already stricter, but never carry
		// group/world access onto a replacement containing gateway secrets.
		targetPerm = info.Mode().Perm() & perm
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
	if err := hardenConfigPermissions(m.filePath); err != nil {
		if event := logger.DebugEvent("config", "permissions_failed"); event != nil {
			event.Str("path", logger.SanitizeLogString(m.filePath)).
				Str("error", logger.SanitizeLogString(err.Error())).
				Send()
		}
		return nil, err
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

func hardenConfigPermissions(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	current := info.Mode().Perm()
	hardened := current & 0600
	if current == hardened {
		return nil
	}
	return os.Chmod(path, hardened)
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

	cfg, existed, _, err := m.loadUnlocked()
	if err != nil {
		if event := logger.DebugEvent("config", "update_load_failed"); event != nil {
			event.Str("path", logger.SanitizeLogString(m.filePath)).
				Str("error", logger.SanitizeLogString(err.Error())).
				Send()
		}
		return err
	}
	before, err := json.Marshal(cfg)
	if err != nil {
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
	after, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	if existed && bytes.Equal(before, after) {
		// Update callbacks now patch only their owned setting. If that setting is
		// already current, do not let unrelated legacy/default normalization turn
		// a cold-start replay into a physical config rewrite.
		if info, statErr := os.Lstat(m.filePath); statErr == nil && info.Mode().IsRegular() {
			return hardenConfigPermissions(m.filePath)
		}
	}
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
