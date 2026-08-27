package models

import (
	"encoding/json"
	"strings"
)

const (
	HostProtocolModeAuto  = "auto"
	HostProtocolModeHTTP1 = "http1"
	HostProtocolModeHTTP2 = "http2"
)

const (
	HostTargetPathModeEntry  = "entry"
	HostTargetPathModePrefix = "prefix"
)

const (
	HostVisibilityModeInherit  = "inherit"
	HostVisibilityModeCustom   = "custom"
	HostVisibilityModeDisabled = "disabled"
)

func NormalizeHostVisibilityMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case HostVisibilityModeCustom:
		return HostVisibilityModeCustom
	case HostVisibilityModeDisabled:
		return HostVisibilityModeDisabled
	default:
		return HostVisibilityModeInherit
	}
}

const (
	GatewayListenerScopeLoopback = "loopback"
	GatewayListenerScopeAll      = "all"
)

type GatewayListenerConfig struct {
	Scope string `json:"scope"`
}

type GatewayProxyProtocolConfig struct {
	Enabled        bool     `json:"enabled"`
	TrustedSources []string `json:"trusted_sources"`
}

// NormalizeGatewayListenerScope validates and canonicalizes the externally
// visible listener policy. An empty result means the value is unsupported.
func NormalizeGatewayListenerScope(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case GatewayListenerScopeLoopback:
		return GatewayListenerScopeLoopback
	case GatewayListenerScopeAll:
		return GatewayListenerScopeAll
	default:
		return ""
	}
}

// NormalizeHostProtocolMode keeps host protocol configuration forward-compatible.
// Missing and unknown values preserve the historical behavior: prefer HTTP/2 and
// allow HTTP/1.1 fallback.
func NormalizeHostProtocolMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case HostProtocolModeHTTP1:
		return HostProtocolModeHTTP1
	case HostProtocolModeHTTP2:
		return HostProtocolModeHTTP2
	default:
		return HostProtocolModeAuto
	}
}

// NormalizeHostTargetPathMode preserves the historical Host target behavior
// for missing and unknown values. Prefix mode must always be selected
// explicitly because it changes every non-root upstream request path.
func NormalizeHostTargetPathMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case HostTargetPathModePrefix:
		return HostTargetPathModePrefix
	default:
		return HostTargetPathModeEntry
	}
}

type Rule struct {
	Path        string `json:"path" example:"/api"`                  // Path prefix to match (e.g., "/api")
	Target      string `json:"target" example:"ws://localhost:8080"` // Target URL (e.g., "http://localhost:7996" or "ws://localhost:7996")
	UseAuth     bool   `json:"use_auth" example:"false"`             // If true, invokes global authentication check before proxying.
	StripPath   bool   `json:"strip_path" example:"true"`            // If true, strips the Path prefix from the request before forwarding.
	RewriteHTML bool   `json:"rewrite_html" example:"true"`          // If true, rewrites absolute paths in HTML response to include Path prefix.
	UseRootMode bool   `json:"use_root_mode" example:"false"`        // If true, sets cookie and redirects matched path to /.
}

type HostRule struct {
	Host             string                `json:"host" example:"redis.example.com"`
	Target           string                `json:"target" example:"http://127.0.0.1:5173"`
	TargetPathMode   string                `json:"target_path_mode" example:"entry"` // entry uses the target path only for public /; prefix mounts every request below it.
	ProtocolMode     string                `json:"protocol_mode,omitempty" example:"auto"`
	GroupID          string                `json:"group_id,omitempty"`
	GroupName        string                `json:"group_name,omitempty"`
	GroupMetadataSet bool                  `json:"-"`
	UseAuth          bool                  `json:"use_auth" example:"true"`
	AccessMode       string                `json:"access_mode,omitempty" example:"login_first"`
	SuppressToolbar  bool                  `json:"suppress_toolbar,omitempty" example:"false"`
	PreserveHost     bool                  `json:"preserve_host,omitempty" example:"true"`
	IsDefault        bool                  `json:"is_default,omitempty" example:"false"`
	Disabled         bool                  `json:"disabled,omitempty" example:"false"`
	Availability     *HostRuleAvailability `json:"availability,omitempty"`
	Visibility       HostRuleVisibility    `json:"visibility,omitempty"`
	AdvancedAuth     AdvancedAuthConfig    `json:"advanced_auth,omitempty"`
	AdvancedAuthSet  bool                  `json:"-"`
	Title            string                `json:"title,omitempty" example:"Redis"`
	Favicon          string                `json:"favicon,omitempty" example:"data:image/png;base64,..."`
	WebsiteIconPath  string                `json:"website_icon_path,omitempty" example:"/__assets__/website_icon.550e8400-e29b-41d4-a716-446655440000.png"`
	BasicAuth        BasicAuthConfig       `json:"basic_auth,omitempty"`
	Locations        []HostLocation        `json:"locations,omitempty"`
}

type AdvancedAuthConfig struct {
	Enabled            bool                `json:"enabled,omitempty"`
	IdleTTLSeconds     int64               `json:"idle_ttl_seconds,omitempty"`
	MaxLifetimeSeconds int64               `json:"max_lifetime_seconds,omitempty"`
	PolicyVersion      string              `json:"policy_version,omitempty"`
	Groups             []AdvancedAuthGroup `json:"groups,omitempty"`
}

type AdvancedAuthGroup struct {
	ID         string                  `json:"id"`
	Conditions []AdvancedAuthCondition `json:"conditions"`
}

type AdvancedAuthCondition struct {
	ID       string   `json:"id"`
	Target   string   `json:"target"`
	Operator string   `json:"operator"`
	Name     string   `json:"name,omitempty"`
	Values   []string `json:"values,omitempty"`
	CIDRs    []string `json:"cidrs,omitempty"` // Deprecated compatibility input.
	PolicyID string   `json:"policy_id,omitempty"`
}

type HostRuleVisibility struct {
	Mode     string   `json:"mode,omitempty"`
	CIDRs    []string `json:"cidrs,omitempty"` // Deprecated compatibility input.
	PolicyID string   `json:"policy_id,omitempty"`
}

type DailyAvailability struct {
	Enabled   bool   `json:"enabled" example:"true"`
	StartTime string `json:"start_time" example:"09:00"`
	EndTime   string `json:"end_time" example:"18:00"`
}

type HostRuleAvailability = DailyAvailability
type StreamAvailability = DailyAvailability

const (
	HostLocationMatchExact  = "exact"
	HostLocationMatchPrefix = "prefix"

	HostLocationActionProxy    = "proxy"
	HostLocationActionResponse = "response"
)

type HostLocation struct {
	Path        string               `json:"path" example:"/api"`
	Match       string               `json:"match,omitempty" example:"prefix"`
	Action      string               `json:"action,omitempty" example:"proxy"`
	Target      string               `json:"target,omitempty" example:"wss://127.0.0.1:8080"`
	StripPath   bool                 `json:"strip_path" example:"true"`
	RewriteHTML bool                 `json:"rewrite_html" example:"true"`
	Response    HostLocationResponse `json:"response,omitempty"`
}

type HostLocationResponse struct {
	Status      int               `json:"status,omitempty" example:"200"`
	ContentType string            `json:"content_type,omitempty" example:"text/plain; charset=utf-8"`
	Headers     map[string]string `json:"headers,omitempty"`
	Body        string            `json:"body,omitempty" example:"ok"`
}

type BasicAuthConfig struct {
	Enabled  bool   `json:"enabled" example:"true"`
	Username string `json:"username" example:"admin"`
	Password string `json:"password" example:"password"`
}

const (
	StreamProtocolTCP      = "tcp"
	StreamProtocolUDP      = "udp"
	StreamValidationOff    = "off"
	StreamValidationStrict = "strict"
)

type StreamRule struct {
	Protocol       string               `json:"protocol" example:"tcp"`
	ListenPort     int                  `json:"listen_port" example:"3306"`
	Target         string               `json:"target" example:"127.0.0.1:3306"`
	UseAuth        bool                 `json:"use_auth" example:"true"`
	Disabled       bool                 `json:"disabled,omitempty"`
	ValidationMode string               `json:"validation_mode,omitempty"`
	ServiceProfile StreamServiceProfile `json:"service_profile,omitempty"`
	BypassPolicy   StreamBypassPolicy   `json:"bypass_policy,omitempty"`
	ProbeStatus    string               `json:"probe_status,omitempty"`
}

type StreamServiceProfile struct {
	ServiceID         string            `json:"service_id,omitempty"`
	ServiceFamily     string            `json:"service_family,omitempty"`
	DeviceRole        string            `json:"device_role,omitempty"`
	ServiceConfidence string            `json:"service_confidence,omitempty"`
	RoleConfidence    string            `json:"role_confidence,omitempty"`
	Source            string            `json:"source,omitempty"`
	ObservedAt        string            `json:"observed_at,omitempty"`
	ClassifierVersion string            `json:"classifier_version,omitempty"`
	TargetFingerprint string            `json:"target_fingerprint,omitempty"`
	EvidenceCodes     []string          `json:"evidence_codes,omitempty"`
	StrictCapable     bool              `json:"strict_capable,omitempty"`
	Metadata          map[string]string `json:"metadata,omitempty"`
}

type StreamBypassCondition struct {
	ID       string   `json:"id"`
	Target   string   `json:"target"`
	Operator string   `json:"operator"`
	CIDRs    []string `json:"cidrs,omitempty"` // Deprecated compatibility input.
	PolicyID string   `json:"policy_id,omitempty"`
}

type StreamBypassGroup struct {
	ID         string                  `json:"id"`
	Conditions []StreamBypassCondition `json:"conditions"`
}

type StreamBypassPolicy struct {
	Enabled            bool                `json:"enabled,omitempty"`
	PolicyVersion      string              `json:"policy_version,omitempty"`
	Groups             []StreamBypassGroup `json:"groups,omitempty"`
	BroadRuleConfirmed bool                `json:"broad_rule_confirmed,omitempty"`
}

type StreamServiceDescriptor struct {
	ServiceID            string   `json:"service_id"`
	DisplayName          string   `json:"display_name"`
	ServiceFamily        string   `json:"service_family"`
	Transports           []string `json:"transports"`
	ActiveProbeSupported bool     `json:"active_probe_supported"`
	StrictCapable        bool     `json:"strict_capable"`
}

type StreamProbeResult struct {
	Status  string               `json:"status"`
	Profile StreamServiceProfile `json:"profile,omitempty"`
	Message string               `json:"message,omitempty"`
}

type AuthConfig struct {
	AuthPort              int    `json:"auth_port" example:"3000"`                                  // Local Auth Service Port
	AuthURL               string `json:"auth_url" example:"/api/auth/verify"`                       // Relative Verify URL (default /api/auth/verify)
	LoginURL              string `json:"login_url" example:"/login"`                                // Relative Login URL (default /login)
	LogoutURL             string `json:"logout_url" example:"/api/auth/logout"`                     // Relative Logout URL (default /api/auth/logout)
	PreflightURL          string `json:"preflight_url" example:"/api/auth/preflight"`               // Relative Preflight URL (default /api/auth/preflight)
	AuthCacheTTL          int    `json:"auth_cache_ttl_seconds,omitempty" example:"1"`              // Successful auth-result cache TTL in seconds. 0 disables the cache.
	AuthCacheFailTTL      int    `json:"auth_cache_unauthorized_ttl_seconds,omitempty" example:"1"` // Unauthorized auth-result cache TTL in seconds. 0 disables the cache.
	EdgeClientIPEnabled   bool   `json:"edge_client_ip_enabled,omitempty" example:"false"`          // Master switch for edge vendor client IP/header handling.
	AliyunESAEnabled      bool   `json:"aliyun_esa_enabled,omitempty" example:"false"`              // Enables Alibaba Cloud ESA client IP/header handling.
	TencentEdgeOneEnabled bool   `json:"tencent_edgeone_enabled,omitempty" example:"false"`         // Enables Tencent EdgeOne client IP/header handling.
	PublicAuthBaseURL     string `json:"public_auth_base_url,omitempty" example:"https://auth.example.com"`
	PublicHTTPPort        int    `json:"public_http_port,omitempty" example:"80"`
	PublicHTTPSPort       int    `json:"public_https_port,omitempty" example:"443"`
	AuthHost              string `json:"auth_host,omitempty" example:"auth.example.com"`
	TrustForwardedProto   bool   `json:"trust_forwarded_proto,omitempty" example:"false"`
}

func (c *AuthConfig) NormalizeEdgeClientIPSelection() bool {
	if c == nil {
		return false
	}

	changed := false
	if !c.EdgeClientIPEnabled {
		if c.AliyunESAEnabled {
			c.AliyunESAEnabled = false
			changed = true
		}
		if c.TencentEdgeOneEnabled {
			c.TencentEdgeOneEnabled = false
			changed = true
		}
		return changed
	}

	// Keep vendor selection mutually exclusive. When both are set, Tencent wins.
	if c.TencentEdgeOneEnabled && c.AliyunESAEnabled {
		c.AliyunESAEnabled = false
		changed = true
	}

	return changed
}

func (c AuthConfig) EdgeClientIPActive() bool {
	return c.EdgeClientIPEnabled && (c.AliyunESAEnabled || c.TencentEdgeOneEnabled)
}

func (c AuthConfig) AliyunESAActive() bool {
	return c.EdgeClientIPEnabled && c.AliyunESAEnabled && !c.TencentEdgeOneEnabled
}

func (c AuthConfig) TencentEdgeOneActive() bool {
	return c.EdgeClientIPEnabled && c.TencentEdgeOneEnabled
}

type LoggingConfig struct {
	Enabled         bool `json:"enabled"`
	RecordLocalhost bool `json:"record_localhost"`
	MaxDays         int  `json:"max_days,omitempty"`
}

const (
	GeneralBlacklistSourceManual     = "manual"
	GeneralBlacklistSourceRequestLog = "request_log"
	GeneralBlacklistSourceActiveIP   = "active_ip"
	GeneralBlacklistSourceWAFLog     = "waf_log"
)

type GeneralBlacklistRecord struct {
	IP        string `json:"ip"`
	Source    string `json:"source,omitempty"`
	Comment   string `json:"comment,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

type GeneralBlacklistConfig struct {
	Items []GeneralBlacklistRecord `json:"items,omitempty"`
}

type GeneralBlacklistList struct {
	Total int                      `json:"total"`
	Items []GeneralBlacklistRecord `json:"items"`
}

type GeneralBlacklistMutationResult struct {
	Added   int                      `json:"added"`
	Updated int                      `json:"updated"`
	Removed int                      `json:"removed"`
	Total   int                      `json:"total"`
	Items   []GeneralBlacklistRecord `json:"items"`
}

type GeneralBlacklistStatus struct {
	Records map[string]GeneralBlacklistRecord `json:"records"`
}

type WAFConfig struct {
	Enabled                       bool     `json:"enabled,omitempty"`
	Mode                          string   `json:"mode,omitempty"`
	RulesDir                      string   `json:"rules_dir,omitempty"`
	ActiveBundleID                string   `json:"active_bundle_id,omitempty"`
	ParanoiaLevel                 int      `json:"paranoia_level,omitempty"`
	ExecutingParanoiaLevel        int      `json:"executing_paranoia_level,omitempty"`
	InboundAnomalyThreshold       int      `json:"inbound_anomaly_threshold,omitempty"`
	OutboundAnomalyThreshold      int      `json:"outbound_anomaly_threshold,omitempty"`
	RequestBodyAccess             bool     `json:"request_body_access,omitempty"`
	RequestBodyLimitBytes         int      `json:"request_body_limit_bytes,omitempty"`
	RequestBodyInMemoryLimitBytes int      `json:"request_body_in_memory_limit_bytes,omitempty"`
	ResponseBodyAccess            bool     `json:"response_body_access,omitempty"`
	DisabledHosts                 []string `json:"disabled_hosts,omitempty"`
	DisabledPathPrefixes          []string `json:"disabled_path_prefixes,omitempty"`
	UpdatedAt                     string   `json:"updated_at,omitempty"`
	PrivateIPExemptEnabled        bool     `json:"private_ip_exempt_enabled,omitempty"`
}

type ReverseProxyThrottleConfig struct {
	Enabled           bool `json:"enabled,omitempty"`
	RequestsPerSecond int  `json:"requests_per_second,omitempty" example:"500"`
	Burst             int  `json:"burst,omitempty" example:"1000"`
	BlockSeconds      int  `json:"block_seconds,omitempty" example:"30"`
}

const (
	DefaultReverseProxyThrottleRequestsPerSecond = 500
	DefaultReverseProxyThrottleBurst             = 1000
	DefaultReverseProxyThrottleBlockSeconds      = 30
)

func DefaultReverseProxyThrottleConfig() ReverseProxyThrottleConfig {
	return ReverseProxyThrottleConfig{
		Enabled:           true,
		RequestsPerSecond: DefaultReverseProxyThrottleRequestsPerSecond,
		Burst:             DefaultReverseProxyThrottleBurst,
		BlockSeconds:      DefaultReverseProxyThrottleBlockSeconds,
	}
}

type GatewayVisibilityConfig struct {
	Enabled   bool           `json:"enabled,omitempty"`
	CIDRs     []string       `json:"cidrs,omitempty"` // Deprecated compatibility input.
	UpdatedAt string         `json:"updated_at,omitempty"`
	PolicyID  string         `json:"policy_id,omitempty"`
	Policy    *CompiledIPSet `json:"-"`
}

type CompiledIPSet struct {
	ID            string         `json:"id,omitempty"`
	FormatVersion uint32         `json:"format_version"`
	IPv4Ranges    Base64URLBytes `json:"ipv4_ranges"`
	IPv6Ranges    Base64URLBytes `json:"ipv6_ranges"`
}

type ForwardedHeadersConfig struct {
	Enabled     bool     `json:"enabled,omitempty"`
	OmitTargets []string `json:"omit_targets,omitempty"`
	UpdatedAt   string   `json:"updated_at,omitempty"`
}

type PreserveHostConfig struct {
	Enabled     bool     `json:"enabled,omitempty"`
	OmitTargets []string `json:"omit_targets,omitempty"`
	UpdatedAt   string   `json:"updated_at,omitempty"`
}

type CrawlerBlockerConfig struct {
	Enabled   bool   `json:"enabled,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

const (
	GatewayPortalDisplayStyleDomain = "domain"
	GatewayPortalDisplayStyleTitle  = "title"

	GatewayPortalIconDragModeCorners = "corners"
	GatewayPortalIconDragModeFree    = "free"

	GatewayPortalVersionV1 = "v1"
	GatewayPortalVersionV2 = "v2"
)

type GatewayPortalConfig struct {
	Enabled      bool   `json:"enabled" example:"true"`
	DisplayStyle string `json:"display_style,omitempty" example:"domain"`
	ShowAppIcon  bool   `json:"show_app_icon,omitempty" example:"false"`
	ShowWOL      bool   `json:"show_wol,omitempty" example:"false"`
	IconDragMode string `json:"icon_drag_mode,omitempty" example:"corners"`
	Version      string `json:"version,omitempty" example:"v1"`
	enabledSet   bool
}

// NewGatewayPortalConfig builds a portal config whose enabled value was
// explicitly supplied by a caller rather than inferred from a legacy payload.
func NewGatewayPortalConfig(enabled bool, displayStyle string, showAppIcon bool, iconDragMode string, version string, showWOL bool) GatewayPortalConfig {
	return GatewayPortalConfig{
		Enabled:      enabled,
		DisplayStyle: displayStyle,
		ShowAppIcon:  showAppIcon,
		ShowWOL:      showWOL,
		IconDragMode: iconDragMode,
		Version:      version,
		enabledSet:   true,
	}
}

func (cfg *GatewayPortalConfig) UnmarshalJSON(data []byte) error {
	var raw struct {
		Enabled      *bool  `json:"enabled"`
		DisplayStyle string `json:"display_style"`
		ShowAppIcon  bool   `json:"show_app_icon"`
		ShowWOL      bool   `json:"show_wol"`
		IconDragMode string `json:"icon_drag_mode"`
		Version      string `json:"version"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	cfg.Enabled = true
	cfg.enabledSet = false
	if raw.Enabled != nil {
		cfg.Enabled = *raw.Enabled
		cfg.enabledSet = true
	}
	cfg.DisplayStyle = raw.DisplayStyle
	cfg.ShowAppIcon = raw.ShowAppIcon
	cfg.ShowWOL = raw.ShowWOL
	cfg.IconDragMode = raw.IconDragMode
	cfg.Version = raw.Version
	return nil
}

func NormalizeGatewayPortalConfig(cfg GatewayPortalConfig) GatewayPortalConfig {
	enabled := cfg.Enabled
	if !cfg.enabledSet && !cfg.Enabled {
		enabled = true
	}

	normalized := GatewayPortalConfig{
		Enabled:     enabled,
		ShowAppIcon: cfg.ShowAppIcon,
		ShowWOL:     cfg.ShowWOL,
		IconDragMode: func() string {
			if cfg.IconDragMode == GatewayPortalIconDragModeFree {
				return GatewayPortalIconDragModeFree
			}
			return GatewayPortalIconDragModeCorners
		}(),
		Version: func() string {
			if cfg.Version == GatewayPortalVersionV2 {
				return GatewayPortalVersionV2
			}
			return GatewayPortalVersionV1
		}(),
		enabledSet: true,
	}
	if cfg.DisplayStyle == GatewayPortalDisplayStyleTitle {
		normalized.DisplayStyle = GatewayPortalDisplayStyleTitle
	} else {
		normalized.DisplayStyle = GatewayPortalDisplayStyleDomain
	}
	return normalized
}

const (
	GatewayUnmatchedRouteBehaviorErrorPage       = "error_page"
	GatewayUnmatchedRouteBehaviorResetConnection = "reset_connection"
	GatewayUpstreamErrorDetailLess               = "less"
	GatewayUpstreamErrorDetailMore               = "more"
	GatewayUpstreamErrorDetailResetConnection    = "reset_connection"
)

type GatewayUnmatchedRouteConfig struct {
	Behavior            string `json:"behavior,omitempty" example:"error_page"`
	UpstreamErrorDetail string `json:"upstream_error_detail,omitempty" example:"less"`
}

func NormalizeGatewayUnmatchedRouteConfig(cfg GatewayUnmatchedRouteConfig) GatewayUnmatchedRouteConfig {
	behavior := GatewayUnmatchedRouteBehaviorErrorPage
	if cfg.Behavior == GatewayUnmatchedRouteBehaviorResetConnection {
		behavior = GatewayUnmatchedRouteBehaviorResetConnection
	}
	upstreamErrorDetail := GatewayUpstreamErrorDetailLess
	switch cfg.UpstreamErrorDetail {
	case GatewayUpstreamErrorDetailMore:
		upstreamErrorDetail = GatewayUpstreamErrorDetailMore
	case GatewayUpstreamErrorDetailResetConnection:
		upstreamErrorDetail = GatewayUpstreamErrorDetailResetConnection
	}
	return GatewayUnmatchedRouteConfig{
		Behavior:            behavior,
		UpstreamErrorDetail: upstreamErrorDetail,
	}
}

type FnosPortIconHijackConfig struct {
	Enabled   bool   `json:"enabled,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

type ReverseProxyThrottleExemptIPsRuntime struct {
	Enabled   bool           `json:"enabled,omitempty"`
	IPs       []string       `json:"ips,omitempty"`
	CIDRs     []string       `json:"cidrs,omitempty"` // Deprecated compatibility input.
	UpdatedAt string         `json:"updated_at,omitempty"`
	PolicyID  string         `json:"policy_id,omitempty"`
	Policy    *CompiledIPSet `json:"-"`
}

type GatewayTrustedClientIPsRuntime struct {
	IPs       []string       `json:"ips,omitempty"`
	CIDRs     []string       `json:"cidrs,omitempty"` // Deprecated compatibility input.
	UpdatedAt string         `json:"updated_at,omitempty"`
	PolicyID  string         `json:"policy_id,omitempty"`
	Policy    *CompiledIPSet `json:"-"`
}

type LocaleConfig struct {
	DefaultLocale string `json:"default_locale,omitempty" example:"zh-CN"`
}

type CommonLocationExemptionsRuntime struct {
	Enabled    bool           `json:"enabled,omitempty"`
	WAFEnabled bool           `json:"waf_enabled,omitempty"`
	CIDRs      []string       `json:"cidrs,omitempty"` // Deprecated compatibility input.
	UpdatedAt  string         `json:"updated_at,omitempty"`
	PolicyID   string         `json:"policy_id,omitempty"`
	Policy     *CompiledIPSet `json:"-"`
}

type PortConfig struct {
	Port  int    `json:"port"`
	Rules []Rule `json:"rules"`
}

type SSLDeploymentMode string

const (
	SSLDeploymentModeSingleActive SSLDeploymentMode = "single_active"
	SSLDeploymentModeMultiSNI     SSLDeploymentMode = "multi_sni"
)

type SSLDeployedCertificate struct {
	ID        string `json:"id,omitempty"`
	Label     string `json:"label,omitempty"`
	Cert      string `json:"cert" example:"-----BEGIN CERTIFICATE-----\n..."`
	Key       string `json:"key" example:"-----BEGIN RSA PRIVATE KEY-----\n..."`
	IsDefault bool   `json:"is_default,omitempty"`
}

type SSLDeployedCertificateInfo struct {
	ID        string   `json:"id,omitempty"`
	Label     string   `json:"label,omitempty"`
	Domains   []string `json:"domains,omitempty"`
	IsDefault bool     `json:"is_default,omitempty"`
}

type SSLLANDeployment struct {
	Enabled   bool     `json:"enabled,omitempty"`
	Addresses []string `json:"addresses,omitempty"`
}

type SSLLANDeploymentInfo struct {
	Enabled   bool     `json:"enabled"`
	Addresses []string `json:"addresses,omitempty"`
}

type SSLConfig struct {
	DeploymentMode SSLDeploymentMode        `json:"deployment_mode,omitempty" example:"single_active"`
	Certificates   []SSLDeployedCertificate `json:"certificates,omitempty"`
	LANDeployment  SSLLANDeployment         `json:"lan_deployment,omitempty"`
}

type SSLInfo struct {
	Enabled        bool                         `json:"enabled"`
	DeploymentMode SSLDeploymentMode            `json:"deployment_mode,omitempty"`
	Certificates   []SSLDeployedCertificateInfo `json:"certificates,omitempty"`
	LANDeployment  SSLLANDeploymentInfo         `json:"lan_deployment"`
}

type SSLRequest struct {
	Cert string `json:"cert" example:"-----BEGIN CERTIFICATE-----\n..."`
	Key  string `json:"key" example:"-----BEGIN RSA PRIVATE KEY-----\n..."`
}

type SSLDeploymentRequest struct {
	DeploymentMode SSLDeploymentMode        `json:"deployment_mode,omitempty" example:"single_active"`
	Certificates   []SSLDeployedCertificate `json:"certificates,omitempty"`
	Cert           string                   `json:"cert,omitempty" example:"-----BEGIN CERTIFICATE-----\n..."`
	Key            string                   `json:"key,omitempty" example:"-----BEGIN RSA PRIVATE KEY-----\n..."`
}
