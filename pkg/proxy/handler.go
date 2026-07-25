package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"go-reauth-proxy/pkg/config"
	"go-reauth-proxy/pkg/diagnostics"
	"go-reauth-proxy/pkg/errors"
	"go-reauth-proxy/pkg/events"
	"go-reauth-proxy/pkg/gatewaylog"
	"go-reauth-proxy/pkg/grpc/pb"
	"go-reauth-proxy/pkg/logger"

	"go-reauth-proxy/pkg/models"
	"go-reauth-proxy/pkg/response"
	"go-reauth-proxy/pkg/rpcbridge"
	proxywaf "go-reauth-proxy/pkg/waf"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/soheilhy/cmux"
	"golang.org/x/net/http/httpguts"

	"github.com/rs/zerolog"
)

const (
	proxyCopyBufferSize      = 256 * 1024
	trafficCounterFlushBytes = 1024 * 1024
)

type proxyBufferPool struct {
	pool sync.Pool
}

func newProxyBufferPool(size int) *proxyBufferPool {
	if size <= 0 {
		size = proxyCopyBufferSize
	}
	return &proxyBufferPool{
		pool: sync.Pool{
			New: func() any {
				buf := make([]byte, size)
				return &buf
			},
		},
	}
}

func (p *proxyBufferPool) Get() []byte {
	if p == nil {
		return make([]byte, proxyCopyBufferSize)
	}
	bufp, ok := p.pool.Get().(*[]byte)
	if !ok || bufp == nil || len(*bufp) == 0 {
		return make([]byte, proxyCopyBufferSize)
	}
	return *bufp
}

func (p *proxyBufferPool) Put(buf []byte) {
	if p == nil || cap(buf) == 0 {
		return
	}
	if cap(buf) > proxyCopyBufferSize*4 {
		return
	}
	buf = buf[:cap(buf)]
	p.pool.Put(&buf)
}

var sharedProxyBufferPool = newProxyBufferPool(proxyCopyBufferSize)

type Handler struct {
	mu                      sync.RWMutex
	listenerChangeMu        sync.Mutex
	Rules                   []models.Rule
	HostRules               []models.HostRule
	StreamRules             []models.StreamRule
	DefaultRoute            string
	AuthConfig              models.AuthConfig
	LoggingConfig           models.LoggingConfig
	AdminPort               int
	ProxyPort               int
	ProxyProtocolForce      bool
	GatewayListener         models.GatewayListenerConfig
	ReverseProxyThrottle    models.ReverseProxyThrottleConfig
	GatewayVisibility       models.GatewayVisibilityConfig
	ForwardedHeaders        models.ForwardedHeadersConfig
	PreserveHost            models.PreserveHostConfig
	CrawlerBlocker          models.CrawlerBlockerConfig
	GatewayPortal           models.GatewayPortalConfig
	GatewayUnmatchedRoute   models.GatewayUnmatchedRouteConfig
	FnosPortIconHijack      models.FnosPortIconHijackConfig
	GeneralBlacklist        models.GeneralBlacklistConfig
	WAFConfig               models.WAFConfig
	sslBundle               atomic.Value
	sslOnChange             atomic.Value
	protocolModeOnChange    atomic.Value
	proxyProtocolOnChange   atomic.Value
	gatewayListenerOnChange atomic.Value
	requestState            atomic.Value

	configManager     *config.Manager
	sslConfig         models.SSLConfig
	gatewayLogManager *gatewaylog.Manager

	trafficTotalIn  atomic.Uint64
	trafficTotalOut atomic.Uint64
	trafficError5xx atomic.Uint64
	trafficByHost   sync.Map

	fnAppMockService           *fnAppMockService
	loggedInActive             sync.Map
	authBridge                 authBridgeClient
	proxyTransport             *http.Transport
	preflightSkipUntilUnixNano atomic.Int64
	authCache                  authStateCache
	preflightCache             preflightStateCache
	loggedInActiveCount        atomic.Int64
	loggedInActiveCleanupNano  atomic.Int64
	reverseProxyThrottle       *reverseProxyThrottle
	reverseProxyThrottleExempt *reverseProxyThrottleExemptIPsRuntime
	commonLocationExemptions   *commonLocationExemptionsRuntime
	gatewayVisibility          *gatewayVisibility
	generalBlacklist           *generalBlacklistRuntime
	forwardedHeaders           *forwardedHeadersConfig
	preserveHost               *preserveHostConfig
	wafRuntime                 *proxywaf.Runtime
	systemEventClient          *events.Client
	throttleEventQueue         chan gatewayThrottleBlockedEvent
}

func (h *Handler) SetAuthBridgeManager(manager *rpcbridge.AuthBridgeManager) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.authBridge = manager
}

func (h *Handler) Close() {
	if h == nil || h.gatewayLogManager == nil {
		return
	}
	h.gatewayLogManager.Close()
}

func (h *Handler) authBridgeManager() authBridgeClient {
	h.mu.RLock()
	bridge := h.authBridge
	h.mu.RUnlock()
	return bridge
}

func (h *Handler) VerifyStreamAuth(ctx context.Context, rule models.StreamRule, clientIP string) (*pb.VerifyStreamAuthResponse, error) {
	bridge := h.authBridgeManager()
	if bridge == nil {
		return nil, rpcbridge.ErrAuthBridgeUnavailable
	}
	return bridge.VerifyStreamAuth(ctx, &pb.VerifyStreamAuthRequest{
		ClientIp:   clientIP,
		Protocol:   rule.Protocol,
		ListenPort: int32(rule.ListenPort),
		Target:     rule.Target,
	})
}

type requestSnapshot struct {
	rules              []models.Rule
	rulesByLength      []models.Rule
	rulesByPath        map[string]*models.Rule
	hostRules          []models.HostRule
	hostRulesByHost    map[string]*models.HostRule
	hostVisibility     map[string][]netip.Prefix
	advancedAuth       map[string]*compiledAdvancedAuthPolicy
	defaultHostRule    *models.HostRule
	targets            map[string]reverseProxyTargetRuntime
	toolbarRules       []models.Rule
	toolbarHostRules   []models.HostRule
	defaultRoute       string
	defaultRule        *models.Rule
	authConfig         models.AuthConfig
	gatewayPortal      models.GatewayPortalConfig
	unmatchedRoute     models.GatewayUnmatchedRouteConfig
	proxyProtocolForce bool
}

type reverseProxyTargetRuntime struct {
	targetURL            *url.URL
	transportURL         *url.URL
	supportsHTMLFeatures bool
	err                  error
}

type preflightDecision struct {
	deny               bool
	redirectLocation   string
	accessDeniedReason string
	credentialIdentity authCredentialIdentity
}

type authCredentialIdentity struct {
	credentialID     string
	credentialName   string
	credentialMethod string
	linkedTOTPID     string
	linkedTOTPName   string
}

func (identity authCredentialIdentity) hasCredential() bool {
	return strings.TrimSpace(identity.credentialID) != "" ||
		strings.TrimSpace(identity.linkedTOTPID) != ""
}

type authCheckResult struct {
	allowed         bool
	authenticated   bool
	suppressToolbar bool
	decision        string
	// statusCode/retryAfter carry an authentication-service rate limit through
	// the bridge without treating it as a normal scope denial (which would be
	// rendered as 403 or redirected to login).
	statusCode            int
	retryAfter            string
	subdomainAccessCustom bool
	allowedSubdomainHosts map[string]struct{}
	credentialIdentity    authCredentialIdentity
	authRuleGroupID       string
	authGrantState        string
	cacheMaxAgeSeconds    int32
}

type authBridgeClient interface {
	SupportsCapability(string) bool
	AuthorizeHTTP(context.Context, *pb.AuthorizeHttpRequest) (*pb.AuthorizeHttpResponse, error)
	VerifyAuth(context.Context, *pb.VerifyAuthRequest) (*pb.VerifyAuthResponse, error)
	PreflightAuth(context.Context, *pb.PreflightAuthRequest) (*pb.PreflightAuthResponse, error)
	VerifyStreamAuth(context.Context, *pb.VerifyStreamAuthRequest) (*pb.VerifyStreamAuthResponse, error)
}

func debugProxyEvent(eventName string, requestID string) *zerolog.Event {
	event := logger.DebugEvent("proxy", eventName)
	if event == nil {
		return nil
	}
	if requestID != "" {
		event.Str("request_id", requestID)
	}
	return event
}

func debugRuleSummaries(rules []models.Rule) []map[string]any {
	out := make([]map[string]any, 0, len(rules))
	for _, rule := range rules {
		out = append(out, map[string]any{
			"path":          logger.SanitizeLogString(rule.Path),
			"target":        logger.SanitizeURL(rule.Target),
			"use_auth":      rule.UseAuth,
			"strip_path":    rule.StripPath,
			"rewrite_html":  rule.RewriteHTML,
			"use_root_mode": rule.UseRootMode,
		})
	}
	return out
}

func debugHostRuleSummaries(rules []models.HostRule) []map[string]any {
	out := make([]map[string]any, 0, len(rules))
	for _, rule := range rules {
		out = append(out, map[string]any{
			"host":               logger.SanitizeLogString(rule.Host),
			"target":             logger.SanitizeURL(rule.Target),
			"protocol_mode":      models.NormalizeHostProtocolMode(rule.ProtocolMode),
			"use_auth":           rule.UseAuth,
			"access_mode":        logger.SanitizeLogString(rule.AccessMode),
			"suppress_toolbar":   rule.SuppressToolbar,
			"preserve_host":      rule.PreserveHost,
			"is_default":         rule.IsDefault,
			"favicon_present":    strings.TrimSpace(rule.Favicon) != "",
			"basic_auth_enabled": rule.BasicAuth.Enabled,
			"location_count":     len(rule.Locations),
		})
	}
	return out
}

func debugStreamRuleSummaries(rules []models.StreamRule) []map[string]any {
	out := make([]map[string]any, 0, len(rules))
	for _, rule := range rules {
		out = append(out, map[string]any{
			"protocol":    logger.SanitizeLogString(rule.Protocol),
			"listen_port": logger.SanitizePort(rule.ListenPort),
			"target":      logger.SanitizeLogString(rule.Target),
			"use_auth":    rule.UseAuth,
		})
	}
	return out
}

func debugAuthConfigSummary(cfg models.AuthConfig) map[string]any {
	return map[string]any{
		"auth_port":                logger.SanitizePort(cfg.AuthPort),
		"auth_url":                 logger.SanitizeLogString(cfg.AuthURL),
		"login_url":                logger.SanitizeLogString(cfg.LoginURL),
		"logout_url":               logger.SanitizeLogString(cfg.LogoutURL),
		"preflight_url":            logger.SanitizeLogString(cfg.PreflightURL),
		"auth_cache_ttl_seconds":   cfg.AuthCacheTTL,
		"auth_cache_fail_ttl_secs": cfg.AuthCacheFailTTL,
		"edge_client_ip_enabled":   cfg.EdgeClientIPEnabled,
		"aliyun_esa_enabled":       cfg.AliyunESAEnabled,
		"tencent_edgeone_enabled":  cfg.TencentEdgeOneEnabled,
		"public_auth_base_url":     logger.SanitizeURL(cfg.PublicAuthBaseURL),
		"public_http_port":         logger.SanitizePort(cfg.PublicHTTPPort),
		"public_https_port":        logger.SanitizePort(cfg.PublicHTTPSPort),
		"auth_host":                logger.SanitizeLogString(cfg.AuthHost),
		"trust_forwarded_proto":    cfg.TrustForwardedProto,
	}
}

func (h *Handler) snapshotForRequest() requestSnapshot {
	if h == nil {
		return requestSnapshot{}
	}
	if value := h.requestState.Load(); value != nil {
		if snapshot, ok := value.(*requestSnapshot); ok && snapshot != nil {
			return *snapshot
		}
	}

	h.mu.RLock()
	s := h.buildRequestSnapshotLocked()
	h.mu.RUnlock()
	return *s
}

func (h *Handler) buildRequestSnapshotLocked() *requestSnapshot {
	rules := append([]models.Rule(nil), h.Rules...)
	rulesByLength := append([]models.Rule(nil), rules...)
	sort.SliceStable(rulesByLength, func(i, j int) bool {
		return len(rulesByLength[i].Path) > len(rulesByLength[j].Path)
	})
	rulesByPath := make(map[string]*models.Rule, len(rules))
	for i := range rules {
		rule := &rules[i]
		if rule.Path == "" {
			continue
		}
		if _, exists := rulesByPath[rule.Path]; exists {
			continue
		}
		rulesByPath[rule.Path] = rule
	}

	hostRules := copyHostRules(h.HostRules)
	hostRulesByHost := make(map[string]*models.HostRule, len(hostRules))
	hostVisibility := make(map[string][]netip.Prefix, len(hostRules))
	advancedAuth := make(map[string]*compiledAdvancedAuthPolicy, len(hostRules))
	var defaultHostRule *models.HostRule
	for i := range hostRules {
		rule := &hostRules[i]
		host := normalizeRequestHost(rule.Host)
		if host == "" {
			continue
		}
		if rule.IsDefault && defaultHostRule == nil {
			defaultHostRule = rule
		}
		if _, exists := hostRulesByHost[host]; exists {
			continue
		}
		hostRulesByHost[host] = rule
		if rule.Visibility.Mode == models.HostVisibilityModeCustom {
			hostVisibility[host] = visibilityPrefixes(rule.Visibility.CIDRs)
		}
		if policy, err := compileAdvancedAuthPolicy(rule.AdvancedAuth); err == nil && policy != nil {
			advancedAuth[host] = policy
		}
	}
	var defaultRule *models.Rule
	if h.DefaultRoute != "" && h.DefaultRoute != "/__select__" {
		if rule, ok := rulesByPath[h.DefaultRoute]; ok {
			defaultRule = rule
		}
	}
	targets := buildReverseProxyTargetRuntimeMap(rules, hostRules)
	toolbarRules, toolbarHostRules := buildToolbarRouteSnapshot(rules, hostRules, targets)

	return &requestSnapshot{
		rules:              rules,
		rulesByLength:      rulesByLength,
		rulesByPath:        rulesByPath,
		hostRules:          hostRules,
		hostRulesByHost:    hostRulesByHost,
		hostVisibility:     hostVisibility,
		advancedAuth:       advancedAuth,
		defaultHostRule:    defaultHostRule,
		targets:            targets,
		toolbarRules:       toolbarRules,
		toolbarHostRules:   toolbarHostRules,
		defaultRoute:       h.DefaultRoute,
		defaultRule:        defaultRule,
		authConfig:         h.AuthConfig,
		gatewayPortal:      models.NormalizeGatewayPortalConfig(h.GatewayPortal),
		unmatchedRoute:     models.NormalizeGatewayUnmatchedRouteConfig(h.GatewayUnmatchedRoute),
		proxyProtocolForce: h.ProxyProtocolForce,
	}
}

func (h *Handler) publishRequestSnapshotLocked() {
	h.requestState.Store(h.buildRequestSnapshotLocked())
}

func resolveClientIP(r *http.Request, authConfig models.AuthConfig, proxyProtocolForce bool) string {
	if authConfig.TencentEdgeOneActive() {
		if ip := normalizeIPAddress(r.Header.Get("EO-Connecting-IP")); ip != "" {
			return ip
		}
		if ip := firstForwardedClientIP(r.Header.Get("X-Forwarded-For")); ip != "" {
			return ip
		}
	}

	if authConfig.AliyunESAActive() {
		if ip := normalizeIPAddress(r.Header.Get("Ali-Real-Client-IP")); ip != "" {
			return ip
		}
		if ip := firstForwardedClientIP(r.Header.Get("X-Forwarded-For")); ip != "" {
			return ip
		}
	}

	if proxyProtocolForce {
		if !authConfig.EdgeClientIPActive() {
			if ip := firstForwardedClientIP(r.Header.Get("X-Forwarded-For")); ip != "" {
				return ip
			}
		}
		if ip := normalizeIPAddress(r.Header.Get("X-Real-IP")); ip != "" {
			return ip
		}
	}
	return normalizeClientIP(r.RemoteAddr)
}

func copyHostLocations(locations []models.HostLocation) []models.HostLocation {
	if locations == nil {
		return nil
	}
	copied := make([]models.HostLocation, len(locations))
	for i, location := range locations {
		copied[i] = location
		copied[i].Response.Headers = copyStringMap(location.Response.Headers)
	}
	return copied
}

func copyHostRules(rules []models.HostRule) []models.HostRule {
	if rules == nil {
		return nil
	}
	copied := make([]models.HostRule, len(rules))
	for i, rule := range rules {
		copied[i] = rule
		copied[i].Availability = copyHostRuleAvailability(rule.Availability)
		copied[i].Visibility.CIDRs = append([]string(nil), rule.Visibility.CIDRs...)
		copied[i].AdvancedAuth.Groups = make([]models.AdvancedAuthGroup, len(rule.AdvancedAuth.Groups))
		for groupIndex, group := range rule.AdvancedAuth.Groups {
			copied[i].AdvancedAuth.Groups[groupIndex] = group
			copied[i].AdvancedAuth.Groups[groupIndex].Conditions = make([]models.AdvancedAuthCondition, len(group.Conditions))
			for conditionIndex, condition := range group.Conditions {
				copiedCondition := condition
				copiedCondition.Values = append([]string(nil), condition.Values...)
				copiedCondition.CIDRs = append([]string(nil), condition.CIDRs...)
				copied[i].AdvancedAuth.Groups[groupIndex].Conditions[conditionIndex] = copiedCondition
			}
		}
		copied[i].Locations = copyHostLocations(rule.Locations)
	}
	return copied
}

func copyHostRuleAvailability(value *models.HostRuleAvailability) *models.HostRuleAvailability {
	if value == nil {
		return nil
	}
	copied := *value
	return &copied
}

func keepFirstDefaultHostRule(rules []models.HostRule) {
	hasDefault := false
	for i := range rules {
		if !rules[i].IsDefault {
			continue
		}
		if !hasDefault {
			hasDefault = true
			continue
		}
		rules[i].IsDefault = false
	}
}

func changedHostProtocolModes(before, after []models.HostRule) []string {
	modeMap := func(rules []models.HostRule) map[string]string {
		modes := make(map[string]string)
		seen := make(map[string]struct{})
		for _, rule := range rules {
			host := normalizeRequestHost(rule.Host)
			mode := models.NormalizeHostProtocolMode(rule.ProtocolMode)
			if host == "" {
				continue
			}
			if _, exists := seen[host]; exists {
				continue
			}
			seen[host] = struct{}{}
			if mode == models.HostProtocolModeAuto {
				continue
			}
			modes[host] = mode
		}
		return modes
	}

	beforeModes := modeMap(before)
	afterModes := modeMap(after)
	changed := make([]string, 0)
	for host, beforeMode := range beforeModes {
		if afterModes[host] != beforeMode {
			changed = append(changed, host)
		}
	}
	for host, afterMode := range afterModes {
		if _, alreadyChecked := beforeModes[host]; alreadyChecked {
			continue
		}
		if beforeModes[host] != afterMode {
			changed = append(changed, host)
		}
	}
	sort.Strings(changed)
	return changed
}

func copyStringMap(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	copied := make(map[string]string, len(values))
	for key, value := range values {
		copied[key] = value
	}
	return copied
}

func copyStreamRule(rule models.StreamRule) *models.StreamRule {
	r := rule
	return &r
}

func normalizeRequestHost(host string) string {
	value := strings.TrimSpace(host)
	if value == "" {
		return ""
	}

	if strings.HasPrefix(value, "[") {
		if idx := strings.LastIndex(value, "]"); idx != -1 {
			return lowerASCIIString(value[:idx+1])
		}
	}

	if idx := strings.LastIndexByte(value, ':'); idx != -1 && strings.IndexByte(value[:idx], ':') == -1 {
		return lowerASCIIString(strings.TrimSpace(value[:idx]))
	}

	return lowerASCIIString(value)
}

func newInternalTransport() *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConns = 2048
	transport.MaxIdleConnsPerHost = 2048
	transport.IdleConnTimeout = 90 * time.Second
	transport.ForceAttemptHTTP2 = true
	return transport
}

func newProxyTransport() *http.Transport {
	transport := newInternalTransport()
	transport.DialContext = (&net.Dialer{
		Timeout:   6 * time.Second,
		KeepAlive: 30 * time.Second,
	}).DialContext
	// Hardcode skipping upstream TLS verification for reverse-proxy targets.
	transport.TLSClientConfig = &tls.Config{
		InsecureSkipVerify: true,
		ClientSessionCache: tls.NewLRUClientSessionCache(256),
	}
	transport.TLSHandshakeTimeout = 10 * time.Second
	// Let long-running admin/API requests such as local service discovery
	// decide their own deadline instead of failing at the gateway layer.
	transport.ResponseHeaderTimeout = 0
	return transport
}

func ensureLeadingSlash(p string) string {
	if p == "" {
		return "/"
	}
	if strings.HasPrefix(p, "/") {
		return p
	}
	return "/" + p
}

func firstForwardedValue(v string) string {
	if v == "" {
		return ""
	}
	first, _, _ := strings.Cut(v, ",")
	return strings.TrimSpace(first)
}

func requestScheme(r *http.Request) string {
	return publicRequestScheme(r)
}

const localServiceURLPrefix = "http://127.0.0.1:"
const localServiceHostPrefix = "127.0.0.1:"

const (
	internalPreflightHeader           = "X-Reauth-Internal-Preflight"
	reauthAccessDeniedHeader          = "X-Reauth-Access-Denied"
	reauthScopeDeniedReason           = "scope"
	reauthSubdomainAccessHeader       = "X-Reauth-Subdomain-Access"
	reauthAllowedSubdomainHostsHeader = "X-Reauth-Allowed-Subdomain-Hosts"
	reauthCredentialIDHeader          = "X-Reauth-Credential-Id"
	reauthCredentialNameHeader        = "X-Reauth-Credential-Name"
	reauthCredentialMethodHeader      = "X-Reauth-Credential-Method"
	reauthLinkedTOTPIDHeader          = "X-Reauth-Linked-Totp-Id"
	reauthLinkedTOTPNameHeader        = "X-Reauth-Linked-Totp-Name"
	reauthSubdomainAccessCustom       = "custom"
	reauthCredentialHeaderB64Prefix   = "b64:"
	maxReauthCredentialHeaderRunes    = 256
	preflightTimeout                  = 1200 * time.Millisecond
	preflightFailureCooldown          = 3 * time.Second
)

func normalizeReauthAccessDeniedReason(value string) string {
	if strings.EqualFold(strings.TrimSpace(value), reauthScopeDeniedReason) {
		return reauthScopeDeniedReason
	}
	return ""
}

func parseAllowedSubdomainHosts(headers http.Header) (bool, map[string]struct{}) {
	if !strings.EqualFold(strings.TrimSpace(headers.Get(reauthSubdomainAccessHeader)), reauthSubdomainAccessCustom) {
		return false, nil
	}
	allowed := make(map[string]struct{})
	for _, rawValue := range headers.Values(reauthAllowedSubdomainHostsHeader) {
		for _, rawHost := range strings.Split(rawValue, ",") {
			host := normalizeRequestHost(rawHost)
			if host == "" {
				continue
			}
			allowed[host] = struct{}{}
		}
	}
	return true, allowed
}

func reauthHeaderValue(headers http.Header, name string) string {
	return truncateRunes(decodeReauthHeaderValue(strings.TrimSpace(headers.Get(name))), maxReauthCredentialHeaderRunes)
}

func decodeReauthHeaderValue(value string) string {
	encoded, ok := strings.CutPrefix(value, reauthCredentialHeaderB64Prefix)
	if !ok {
		return value
	}
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		decoded, err = base64.URLEncoding.DecodeString(encoded)
	}
	if err != nil {
		return ""
	}
	return string(decoded)
}

func truncateRunes(value string, maxRunes int) string {
	if maxRunes <= 0 {
		return ""
	}
	count := 0
	for index := range value {
		if count == maxRunes {
			return value[:index]
		}
		count++
	}
	return value
}

func parseAuthCredentialIdentity(headers http.Header) authCredentialIdentity {
	return authCredentialIdentity{
		credentialID:     reauthHeaderValue(headers, reauthCredentialIDHeader),
		credentialName:   reauthHeaderValue(headers, reauthCredentialNameHeader),
		credentialMethod: reauthHeaderValue(headers, reauthCredentialMethodHeader),
		linkedTOTPID:     reauthHeaderValue(headers, reauthLinkedTOTPIDHeader),
		linkedTOTPName:   reauthHeaderValue(headers, reauthLinkedTOTPNameHeader),
	}
}

func applyAuthCredentialIdentityToLogEntry(entry *gatewaylog.Entry, identity authCredentialIdentity) {
	entry.AuthCredentialID = identity.credentialID
	entry.AuthCredentialName = identity.credentialName
	entry.AuthCredentialMethod = identity.credentialMethod
	entry.AuthLinkedTOTPID = identity.linkedTOTPID
	entry.AuthLinkedTOTPName = identity.linkedTOTPName
}

func applyAuthResultToLogEntry(entry *gatewaylog.Entry, result authCheckResult) {
	entry.LoggedIn = result.authenticated
	entry.AuthDecision = result.decision
	entry.AuthRuleGroupID = result.authRuleGroupID
	entry.AuthGrantState = result.authGrantState
	applyAuthCredentialIdentityToLogEntry(entry, result.credentialIdentity)
}

func localServiceBaseURL(port int) string {
	var stack [len(localServiceURLPrefix) + 20]byte
	buf := stack[:0]
	buf = append(buf, localServiceURLPrefix...)
	buf = strconv.AppendInt(buf, int64(port), 10)
	return string(buf)
}

func localServiceHostPort(port int) string {
	var stack [len(localServiceHostPrefix) + 20]byte
	buf := stack[:0]
	buf = append(buf, localServiceHostPrefix...)
	buf = strconv.AppendInt(buf, int64(port), 10)
	return string(buf)
}

func localServiceTargetURL(port int) *url.URL {
	return &url.URL{
		Scheme: "http",
		Host:   localServiceHostPort(port),
	}
}

func localServiceURL(port int, urlPath string) string {
	urlPath = ensureLeadingSlash(urlPath)
	var stack [len(localServiceURLPrefix) + 20 + 128]byte
	buf := stack[:0]
	buf = append(buf, localServiceURLPrefix...)
	buf = strconv.AppendInt(buf, int64(port), 10)
	buf = append(buf, urlPath...)
	return string(buf)
}

func copyUserAgentHeader(dst, src *http.Request) {
	if ua := src.Header.Get("User-Agent"); ua != "" {
		dst.Header.Set("User-Agent", ua)
		return
	}

	// Prevent Go's default client UA from leaking into upstream requests
	// when the original client did not send one.
	dst.Header.Set("User-Agent", "")
}

type requestAuthContext struct {
	context    *pb.AuthContext
	headers    http.Header
	legacyOnce sync.Once
}

func newRequestAuthContext(r *http.Request, clientIP string, accessMode string) *requestAuthContext {
	if r == nil {
		return &requestAuthContext{context: &pb.AuthContext{ClientIp: clientIP, AccessMode: accessMode}}
	}
	scheme := requestScheme(r)
	effectiveHost := requestHostForRouting(r)
	if effectiveHost == "" {
		effectiveHost = r.Host
	}
	context := &pb.AuthContext{
		ClientIp:              clientIP,
		ForwardedFor:          clientIP,
		ForwardedHost:         effectiveHost,
		ForwardedProto:        scheme,
		ForwardedPath:         r.URL.RequestURI(),
		Host:                  effectiveHost,
		Scheme:                scheme,
		Path:                  r.URL.Path,
		RawQuery:              r.URL.RawQuery,
		RequestUri:            r.URL.RequestURI(),
		Cookie:                r.Header.Get("Cookie"),
		Authorization:         r.Header.Get("Authorization"),
		UserAgent:             r.Header.Get("User-Agent"),
		AccessMode:            accessMode,
		AccessToken:           r.Header.Get("AccessToken"),
		AccessTokenHyphenated: r.Header.Get("Access-Token"),
	}
	if advancedAuthIsUpgradeRequest(r) {
		// Combined authorization normally omits the legacy header map. Preserve
		// only the Upgrade signal so Rust can authorize a matching handshake as
		// a one-request grant without creating a cookie that a 101 response may
		// never persist.
		context.ExtraHeaders = []*pb.Header{{
			Name:   "Upgrade",
			Values: append([]string(nil), r.Header.Values("Upgrade")...),
		}}
	}
	return &requestAuthContext{
		context: context,
		headers: r.Header,
	}
}

func (c *requestAuthContext) proto(includeLegacyHeaders bool) *pb.AuthContext {
	if c == nil {
		return &pb.AuthContext{}
	}
	if includeLegacyHeaders {
		c.legacyOnce.Do(func() {
			c.context.ExtraHeaders = headersToProto(c.headers)
		})
	}
	return c.context
}

func headersToProto(headers http.Header) []*pb.Header {
	if len(headers) == 0 {
		return nil
	}
	out := make([]*pb.Header, 0, len(headers))
	for name, values := range headers {
		copied := append([]string(nil), values...)
		out = append(out, &pb.Header{Name: name, Values: copied})
	}
	return out
}

func protoHeadersToHTTP(headers []*pb.Header) http.Header {
	out := make(http.Header, len(headers))
	for _, header := range headers {
		name := strings.TrimSpace(header.GetName())
		if name == "" {
			continue
		}
		for _, value := range header.GetValues() {
			out.Add(name, value)
		}
	}
	return out
}

func applyNoStoreCacheHeaders(headers http.Header) {
	if headers == nil {
		return
	}

	headers.Set("Cache-Control", "private, no-store, no-cache, max-age=0, must-revalidate")
	headers.Set("Pragma", "no-cache")
	headers.Set("Expires", "0")
	headers.Set("CDN-Cache-Control", "private, no-store")
	headers.Set("Surrogate-Control", "no-store")
}

func shouldDisableAuthResponseCaching(requestPath string) bool {
	cleanPath := path.Clean(ensureLeadingSlash(strings.TrimSpace(requestPath)))
	for _, mountPrefix := range []string{"/auth", "/__auth__"} {
		switch {
		case cleanPath == mountPrefix:
			cleanPath = "/"
		case strings.HasPrefix(cleanPath, mountPrefix+"/"):
			cleanPath = strings.TrimPrefix(cleanPath, mountPrefix)
		}
	}
	if cleanPath == "/api/auth" || strings.HasPrefix(cleanPath, "/api/auth/") {
		return true
	}

	// Authentication view documents contain runtime authentication state and
	// bootstrap data. Keep fingerprinted static assets cacheable, but never let
	// a browser, CDN, or reverse proxy reuse an auth page across sessions.
	switch cleanPath {
	case "/", "/index.html", "/login", "/logout", "/callback", "/oidc/bind":
		return true
	default:
		return false
	}
}

func applyInternalAuthProxyHeaders(req *http.Request, source *http.Request, targetURL *url.URL, clientIP string, authConfig models.AuthConfig) {
	if req == nil {
		return
	}

	if targetURL != nil {
		req.Host = targetURL.Host
		req.URL.Path = targetURL.Path
	}

	req.Header.Set("X-Real-IP", clientIP)
	req.Header.Set("X-Forwarded-For", clientIP)
	if source != nil {
		req.Header.Set("X-Forwarded-Host", source.Host)
		req.Header.Set("X-Forwarded-Proto", requestScheme(source))
	}
	switch {
	case authConfig.TencentEdgeOneActive() && clientIP != "":
		req.Header.Set("EO-Connecting-IP", clientIP)
		req.Header.Del("Ali-Real-Client-IP")
	case authConfig.AliyunESAActive() && clientIP != "":
		req.Header.Set("Ali-Real-Client-IP", clientIP)
		req.Header.Del("EO-Connecting-IP")
	default:
		req.Header.Del("Ali-Real-Client-IP")
		req.Header.Del("EO-Connecting-IP")
	}

	// Strip internal routing hints and any client-supplied real-IP header.
	req.Header.Del("X-Forwarded-Path")
	req.Header.Del("X-Match")
	copyUserAgentHeader(req, source)
}

func applyForwardedHeaderPolicy(out *http.Request, in *http.Request, clientIP string, omitForwardedHeaders bool) {
	if out == nil {
		return
	}

	out.Header.Set("X-Real-IP", clientIP)
	if omitForwardedHeaders {
		out.Header.Del("X-Forwarded-For")
		out.Header.Del("X-Forwarded-Host")
		out.Header.Del("X-Forwarded-Proto")
		return
	}

	if in == nil {
		return
	}

	out.Header.Set("X-Forwarded-For", clientIP)
	out.Header.Set("X-Forwarded-Host", in.Host)
	out.Header.Set("X-Forwarded-Proto", requestScheme(in))
}

func applyPreserveHostPolicy(out *http.Request, in *http.Request, targetURL *url.URL, preserveHost bool) {
	if out == nil {
		return
	}

	if preserveHost && in != nil {
		out.Host = in.Host
		return
	}

	if targetURL != nil {
		out.Host = targetURL.Host
	}
}

func (h *Handler) shouldOmitForwardedHeaders(target *url.URL) bool {
	if h == nil || h.forwardedHeaders == nil {
		return false
	}
	return h.forwardedHeaders.shouldOmit(target)
}

func (h *Handler) shouldOmitPreserveHost(target *url.URL) bool {
	if h == nil || h.preserveHost == nil {
		return false
	}
	return h.preserveHost.shouldOmit(target)
}

func (h *Handler) runPreflight(r *http.Request, authConfig models.AuthConfig, clientIP string, isMatch bool, accessMode string, requestID string, requestAuth *requestAuthContext) preflightDecision {
	if r.Header.Get(internalPreflightHeader) == "1" {
		if event := debugProxyEvent("preflight_skipped_internal", requestID); event != nil {
			event.Send()
		}
		return preflightDecision{}
	}

	if strings.TrimSpace(authConfig.AuthURL) == "" {
		if event := debugProxyEvent("preflight_skipped_no_auth_url", requestID); event != nil {
			event.Send()
		}
		return preflightDecision{}
	}
	now := time.Now()
	lookup, canLookup := buildPreflightCacheLookup(r, clientIP, accessMode, isMatch)
	ttl := preflightCacheTTL(authConfig)

	if canLookup && ttl > 0 {
		if entry, ok := h.preflightCacheGet(lookup.cacheKey, now); ok {
			if shouldBypassFNAppNegativePreflightCache(r, entry.decision) {
				h.preflightCache.mu.Lock()
				h.preflightCache.deleteEntryLocked(lookup.cacheKey)
				h.preflightCache.mu.Unlock()
				if event := debugProxyEvent("preflight_cache_bypassed", requestID); event != nil {
					event.Str("reason", "fn_app_negative").Send()
				}
			} else {
				if event := debugProxyEvent("preflight_cache_hit", requestID); event != nil {
					event.Bool("deny", entry.decision.deny).
						Str("redirect_location", logger.SanitizeURL(entry.decision.redirectLocation)).
						Send()
				}
				return entry.decision
			}
		}
	}
	if skipUntil := h.preflightSkipUntilUnixNano.Load(); skipUntil > now.UnixNano() {
		if event := debugProxyEvent("preflight_skipped_cooldown", requestID); event != nil {
			event.Time("skip_until", time.Unix(0, skipUntil)).Send()
		}
		return preflightDecision{}
	}

	if canLookup && ttl > 0 {
		sharedRequest := r.WithContext(context.WithoutCancel(r.Context()))
		resultCh := h.preflightCache.group.DoChan(lookup.cacheKey, func() (any, error) {
			if entry, ok := h.preflightCacheGet(lookup.cacheKey, time.Now()); ok {
				if shouldBypassFNAppNegativePreflightCache(r, entry.decision) {
					h.preflightCache.mu.Lock()
					h.preflightCache.deleteEntryLocked(lookup.cacheKey)
					h.preflightCache.mu.Unlock()
					if event := debugProxyEvent("preflight_cache_bypassed", requestID); event != nil {
						event.Str("reason", "fn_app_negative_singleflight").Send()
					}
				} else {
					if event := debugProxyEvent("preflight_cache_hit", requestID); event != nil {
						event.Bool("deny", entry.decision.deny).
							Str("redirect_location", logger.SanitizeURL(entry.decision.redirectLocation)).
							Send()
					}
					return preflightCacheExecution{entry: &entry}, nil
				}
			}

			decision, cacheScope, err := h.performPreflight(sharedRequest, authConfig, clientIP, isMatch, accessMode, requestID, requestAuth)
			if err != nil {
				cooldownUntil := time.Now().Add(preflightFailureCooldown).UnixNano()
				h.preflightSkipUntilUnixNano.Store(cooldownUntil)
				if event := debugProxyEvent("preflight_request_failed", requestID); event != nil {
					event.Str("error", logger.SanitizeLogString(err.Error())).
						Time("cooldown_until", time.Unix(0, cooldownUntil)).
						Send()
				}
				log.Printf("Preflight request failed, skipping checks for %s: %v", preflightFailureCooldown, err)
				return preflightCacheExecution{}, nil
			}
			h.preflightSkipUntilUnixNano.Store(0)

			entry := preflightCacheEntry{
				decision:    decision,
				expiresAt:   time.Now().Add(ttl),
				identityKey: lookup.identityKey,
			}
			if cacheScope == pb.AuthCacheScope_AUTH_CACHE_SCOPE_EXACT_REQUEST && !shouldBypassFNAppNegativePreflightCache(r, decision) {
				h.preflightCacheStore(lookup.cacheKey, entry, time.Now())
				return preflightCacheExecution{entry: &entry}, nil
			}
			return preflightCacheExecution{decision: decision}, nil
		})
		var execution preflightCacheExecution
		select {
		case result := <-resultCh:
			execution, _ = result.Val.(preflightCacheExecution)
		case <-r.Context().Done():
			return preflightDecision{}
		}
		if execution.entry != nil {
			return execution.entry.decision
		}
		return execution.decision
	}

	decision, _, err := h.performPreflight(r, authConfig, clientIP, isMatch, accessMode, requestID, requestAuth)
	if err != nil {
		cooldownUntil := time.Now().Add(preflightFailureCooldown).UnixNano()
		h.preflightSkipUntilUnixNano.Store(cooldownUntil)
		if event := debugProxyEvent("preflight_request_failed", requestID); event != nil {
			event.Str("error", logger.SanitizeLogString(err.Error())).
				Time("cooldown_until", time.Unix(0, cooldownUntil)).
				Send()
		}
		log.Printf("Preflight request failed, skipping checks for %s: %v", preflightFailureCooldown, err)
		return preflightDecision{}
	}
	h.preflightSkipUntilUnixNano.Store(0)
	return decision
}

func (h *Handler) performPreflight(r *http.Request, authConfig models.AuthConfig, clientIP string, isMatch bool, accessMode string, requestID string, requestAuth *requestAuthContext) (preflightDecision, pb.AuthCacheScope, error) {
	start := time.Now()
	if event := debugProxyEvent("preflight_request_start", requestID); event != nil {
		event.Str("transport", "auth_bridge").
			Str("client_ip", logger.SanitizeLogString(clientIP)).
			Bool("matched", isMatch).
			Str("access_mode", logger.SanitizeLogString(accessMode)).
			Interface("forwarded_headers", logger.SanitizeHeader(http.Header{
				"X-Forwarded-Path":  []string{r.URL.RequestURI()},
				"X-Forwarded-Host":  []string{r.Host},
				"X-Forwarded-Proto": []string{requestScheme(r)},
				"X-Match":           []string{strconv.FormatBool(isMatch)},
			})).
			Send()
	}

	bridge := h.authBridgeManager()
	if bridge == nil {
		return preflightDecision{}, pb.AuthCacheScope_AUTH_CACHE_SCOPE_NONE, rpcbridge.ErrAuthBridgeUnavailable
	}
	ctx, cancel := context.WithTimeout(r.Context(), preflightTimeout)
	defer cancel()
	var resp *pb.PreflightAuthResponse
	var err error
	cacheScope := pb.AuthCacheScope_AUTH_CACHE_SCOPE_EXACT_REQUEST
	supportsCombined := bridge.SupportsCapability(rpcbridge.CapabilityAuthorizeHTTPV1)
	if supportsCombined {
		var combined *pb.AuthorizeHttpResponse
		combined, err = bridge.AuthorizeHTTP(ctx, &pb.AuthorizeHttpRequest{
			Context:            requestAuth.proto(false),
			Matched:            isMatch,
			Mode:               pb.HttpAuthMode_HTTP_AUTH_MODE_PREFLIGHT_ONLY,
			SubdomainRuleMatch: advancedAuthRuleMatchProto(r),
		})
		if err == nil {
			resp = combined.GetPreflight()
			cacheScope = combined.GetPreflightCacheScope()
			if resp == nil {
				err = fmt.Errorf("auth bridge returned no preflight response")
			}
		}
	}
	if !supportsCombined || err == rpcbridge.ErrAuthBridgeCapabilityUnsupported {
		resp, err = bridge.PreflightAuth(ctx, &pb.PreflightAuthRequest{
			Context: requestAuth.proto(true),
			Matched: isMatch,
		})
	}
	if err != nil {
		return preflightDecision{}, pb.AuthCacheScope_AUTH_CACHE_SCOPE_NONE, err
	}
	return h.preflightDecisionFromResponse(resp, requestID, start), cacheScope, nil
}

func (h *Handler) preflightDecisionFromResponse(resp *pb.PreflightAuthResponse, requestID string, start time.Time) preflightDecision {
	responseHeaders := protoHeadersToHTTP(resp.GetResponseHeaders())

	decision := preflightDecision{
		deny:               resp.GetDeny() || strings.EqualFold(responseHeaders.Get("X-Option"), "deny"),
		credentialIdentity: parseAuthCredentialIdentity(responseHeaders),
	}
	decision.accessDeniedReason = normalizeReauthAccessDeniedReason(resp.GetAccessDeniedReason())
	if decision.accessDeniedReason == "" {
		decision.accessDeniedReason = normalizeReauthAccessDeniedReason(responseHeaders.Get(reauthAccessDeniedHeader))
	}
	if location := strings.TrimSpace(resp.GetRedirectLocation()); location == "" {
		location = strings.TrimSpace(responseHeaders.Get("X-Reauth-Redirect-Location"))
		if strings.HasPrefix(location, "/") || strings.HasPrefix(location, "http://") || strings.HasPrefix(location, "https://") {
			decision.redirectLocation = location
		}
	} else {
		if strings.HasPrefix(location, "/") || strings.HasPrefix(location, "http://") || strings.HasPrefix(location, "https://") {
			decision.redirectLocation = location
		}
	}
	if event := debugProxyEvent("preflight_request_end", requestID); event != nil {
		event.Int("status", http.StatusNoContent).
			Bool("deny", decision.deny).
			Str("access_denied_reason", logger.SanitizeLogString(decision.accessDeniedReason)).
			Str("redirect_location", logger.SanitizeURL(decision.redirectLocation)).
			Int64("duration_ms", time.Since(start).Milliseconds()).
			Interface("response_headers", logger.SanitizeHeader(responseHeaders)).
			Send()
	}
	return decision
}

func shouldRunPreflightForRoute(isSelectRoute bool, isAuthRoute bool, matchedHostRule *models.HostRule, matchedRule *models.Rule) bool {
	// The reserved internal auth namespace is the ingress to the authentication
	// service itself. Applying a consumer-route preflight here recursively asks
	// the auth service to authenticate its own login/logout/callback endpoints,
	// which can make recovery unreachable or create a redirect loop. Reverse
	// proxy throttling, WAF checks, and the auth service's own endpoint checks
	// still run before/after this decision.
	if isAuthRoute {
		return false
	}
	if isSelectRoute {
		return true
	}
	if matchedHostRule != nil {
		return matchedHostRule.UseAuth
	}
	if matchedRule != nil {
		return matchedRule.UseAuth
	}
	return true
}

func isHTTP1OnlyHostOverHTTP2(r *http.Request, rule *models.HostRule) bool {
	return r != nil && r.TLS != nil && r.ProtoMajor == 2 && rule != nil &&
		models.NormalizeHostProtocolMode(rule.ProtocolMode) == models.HostProtocolModeHTTP1
}

func isHTTP2OnlyHostOverHTTP1(r *http.Request, rule *models.HostRule) bool {
	return r != nil && r.TLS != nil && r.ProtoMajor == 1 && rule != nil &&
		models.NormalizeHostProtocolMode(rule.ProtocolMode) == models.HostProtocolModeHTTP2
}

func serveProtocolMisdirectedRequest(w http.ResponseWriter, r *http.Request, closeConnection bool) {
	// RFC 9113 requires a client receiving 421 to retry on a different
	// connection. This lets an authority escape either a coalesced HTTP/2
	// connection or a keep-alive HTTP/1.x connection negotiated before a hot
	// protocol-mode update.
	w.Header().Set("Cache-Control", "no-store")
	if closeConnection {
		// Connection is legal on HTTP/1.x only. Mark both sides so net/http closes
		// the stale TLS connection after writing the response.
		w.Header().Set("Connection", "close")
		if r != nil {
			r.Close = true
		}
	}
	http.Error(w, http.StatusText(http.StatusMisdirectedRequest), http.StatusMisdirectedRequest)
}

func (h *Handler) abortConnection(w http.ResponseWriter) {
	rc := http.NewResponseController(w)
	conn, _, err := rc.Hijack()
	if err == nil && conn != nil {
		if tcpConn := unwrapTCPConn(conn); tcpConn != nil {
			_ = tcpConn.SetLinger(0)
			_ = tcpConn.Close()
			return
		}
		_ = conn.Close()
		return
	}
	panic(http.ErrAbortHandler)
}

type netConnUnwrapper interface {
	NetConn() net.Conn
}

type rawConnUnwrapper interface {
	Raw() net.Conn
}

func unwrapTCPConn(conn net.Conn) *net.TCPConn {
	// Production HTTP/1 connections can be wrapped by TLS, cmux and the
	// PROXY-protocol listener. Bound the walk so a faulty wrapper cannot loop.
	for range 8 {
		if conn == nil {
			return nil
		}
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			return tcpConn
		}

		var next net.Conn
		switch wrapped := conn.(type) {
		case netConnUnwrapper:
			next = wrapped.NetConn()
		case *cmux.MuxConn:
			next = wrapped.Conn
		case rawConnUnwrapper:
			next = wrapped.Raw()
		default:
			return nil
		}
		if next == nil || next == conn {
			return nil
		}
		conn = next
	}
	return nil
}

func NewHandler(adminPort int, proxyPort int, cfgManager *config.Manager, initialCfg *config.AppConfig, logsDir string, systemEventClient *events.Client) *Handler {
	logger.SetDebugAdminPortForRedaction(adminPort)
	logConfig := gatewaylog.NormalizeConfig(initialCfg.Logging)
	normalizedForwardedHeaders, _ := normalizeForwardedHeadersConfig(initialCfg.ForwardedHeaders)
	normalizedPreserveHost, _ := normalizePreserveHostConfig(initialCfg.PreserveHost)
	if strings.TrimSpace(logsDir) == "" {
		logsDir = gatewaylog.DefaultLogsDir(".")
	}
	runtimeDir := "."
	if cfgManager != nil {
		runtimeDir = cfgManager.RuntimeDir()
	}
	wafRuntime := proxywaf.NewRuntime(initialCfg.WAF, runtimeDir)
	wafConfig := wafRuntime.Config()
	initialHostRules := copyHostRules(initialCfg.HostRules)
	for i := range initialHostRules {
		initialHostRules[i].ProtocolMode = models.NormalizeHostProtocolMode(initialHostRules[i].ProtocolMode)
	}

	h := &Handler{
		Rules:                 initialCfg.Rules,
		HostRules:             initialHostRules,
		StreamRules:           initialCfg.StreamRules,
		DefaultRoute:          initialCfg.DefaultRoute,
		AuthConfig:            initialCfg.AuthConfig,
		LoggingConfig:         logConfig,
		AdminPort:             adminPort,
		ProxyPort:             proxyPort,
		ProxyProtocolForce:    initialCfg.ProxyProtocolForce,
		GatewayListener:       initialCfg.GatewayListener,
		ReverseProxyThrottle:  normalizeReverseProxyThrottleConfig(initialCfg.ReverseProxyThrottle),
		GatewayVisibility:     initialCfg.Visibility,
		ForwardedHeaders:      normalizedForwardedHeaders,
		PreserveHost:          normalizedPreserveHost,
		CrawlerBlocker:        normalizeCrawlerBlockerConfig(initialCfg.CrawlerBlocker),
		GatewayPortal:         models.NormalizeGatewayPortalConfig(initialCfg.Portal),
		GatewayUnmatchedRoute: models.NormalizeGatewayUnmatchedRouteConfig(initialCfg.UnmatchedRoute),
		FnosPortIconHijack:    initialCfg.FnosPortIconHijack,
		GeneralBlacklist:      models.GeneralBlacklistConfig{Items: []models.GeneralBlacklistRecord{}},
		WAFConfig:             wafConfig,
		configManager:         cfgManager,
		sslConfig:             copySSLConfig(initialCfg.SSL),
		gatewayLogManager:     gatewaylog.NewManager(logsDir, logConfig),
		fnAppMockService:      newFNAppMockServiceFromEnv(),
		proxyTransport:        newProxyTransport(),
		authCache:             newAuthStateCache(),
		preflightCache:        newPreflightStateCache(),
		generalBlacklist:      newGeneralBlacklistRuntime(initialCfg.GeneralBlacklist),
		forwardedHeaders:      newForwardedHeadersConfig(normalizedForwardedHeaders),
		preserveHost:          newPreserveHostConfig(normalizedPreserveHost),
		wafRuntime:            wafRuntime,
		systemEventClient:     systemEventClient,
	}
	h.GeneralBlacklist = h.generalBlacklist.getConfig()
	if models.NormalizeGatewayListenerScope(h.GatewayListener.Scope) == "" {
		h.GatewayListener.Scope = models.GatewayListenerScopeAll
	}
	if event := debugProxyEvent("handler_initialized", ""); event != nil {
		event.Interface("proxy_port", logger.SanitizePort(proxyPort)).
			Int("path_rule_count", len(h.Rules)).
			Int("host_rule_count", len(h.HostRules)).
			Int("stream_rule_count", len(h.StreamRules)).
			Bool("proxy_protocol_force", h.ProxyProtocolForce).
			Bool("gateway_logging_enabled", h.LoggingConfig.Enabled).
			Bool("crawler_blocker_enabled", h.CrawlerBlocker.Enabled).
			Bool("waf_enabled", h.WAFConfig.Enabled).
			Str("gateway_logs_dir", logger.SanitizeLogString(logsDir)).
			Send()
	}
	h.reverseProxyThrottle = newReverseProxyThrottle(h.ReverseProxyThrottle)
	h.reverseProxyThrottleExempt = newReverseProxyThrottleExemptIPsRuntime(
		models.ReverseProxyThrottleExemptIPsRuntime{
			Enabled:   false,
			IPs:       []string{},
			CIDRs:     []string{},
			UpdatedAt: "",
		},
	)
	h.commonLocationExemptions = newCommonLocationExemptionsRuntime(
		models.CommonLocationExemptionsRuntime{
			Enabled:    false,
			WAFEnabled: false,
			CIDRs:      []string{},
			UpdatedAt:  "",
		},
	)
	visibility, err := newGatewayVisibility(initialCfg.Visibility)
	if err != nil {
		log.Printf("Failed to normalize initial gateway visibility: %v", err)
		visibility, _ = newGatewayVisibility(models.GatewayVisibilityConfig{
			Enabled:   false,
			CIDRs:     []string{},
			UpdatedAt: "",
		})
	}
	h.gatewayVisibility = visibility

	var emptyHook func()
	var emptyProtocolModeHook func([]string)
	h.sslOnChange.Store(emptyHook)
	h.protocolModeOnChange.Store(emptyProtocolModeHook)
	h.proxyProtocolOnChange.Store(emptyHook)
	h.publishRequestSnapshotLocked()

	if len(h.sslConfig.Certificates) == 0 && initialCfg.SSLCert != "" && initialCfg.SSLKey != "" {
		h.sslConfig = buildLegacySSLConfig(initialCfg.SSLCert, initialCfg.SSLKey)
	}
	normalizedSSL, err := normalizeSSLConfig(h.sslConfig)
	if err != nil {
		log.Printf("Failed to normalize initial SSL deployment: %v", err)
		normalizedSSL = models.SSLConfig{
			DeploymentMode: models.SSLDeploymentModeSingleActive,
			Certificates:   []models.SSLDeployedCertificate{},
		}
	}
	h.sslConfig = normalizedSSL
	bundle, err := newSSLRuntimeBundle(h.sslConfig)
	if err != nil {
		log.Printf("Failed to load initial SSL deployment: %v", err)
		bundle = newEmptySSLRuntimeBundle(h.sslConfig.DeploymentMode)
	}
	h.sslBundle.Store(bundle)
	if proxywaf.IsActive(wafConfig) {
		if _, err := wafRuntime.Reload(wafConfig, "", ""); err != nil {
			log.Printf("Failed to load initial WAF rules: %v", err)
		}
	}
	h.startGatewayThrottleEventWorker()
	return h
}

func (h *Handler) SetSSLChangeHook(hook func()) {
	h.sslOnChange.Store(hook)
}

func (h *Handler) getSSLChangeHook() func() {
	val := h.sslOnChange.Load()
	if val == nil {
		return nil
	}
	hook, _ := val.(func())
	return hook
}

// SetHostProtocolModeChangeHook installs the listener-maintenance callback used
// after a hot host-rule update. New TLS handshakes see the atomic rule snapshot;
// the callback lets the server retire idle connections negotiated under the old
// ALPN policy.
func (h *Handler) SetHostProtocolModeChangeHook(hook func([]string)) {
	h.protocolModeOnChange.Store(hook)
}

func (h *Handler) getHostProtocolModeChangeHook() func([]string) {
	val := h.protocolModeOnChange.Load()
	if val == nil {
		return nil
	}
	hook, _ := val.(func([]string))
	return hook
}

func (h *Handler) SetProxyProtocolForceChangeHook(hook func()) {
	h.proxyProtocolOnChange.Store(hook)
}

func (h *Handler) getProxyProtocolForceChangeHook() func() {
	val := h.proxyProtocolOnChange.Load()
	if val == nil {
		return nil
	}
	hook, _ := val.(func())
	return hook
}

// SetGatewayListenerConfigChangeHook installs the runtime transition used when
// the gateway listener scope changes. The hook runs before the new scope is
// persisted so callers never receive a successful configuration update for a
// listener that failed to come up.
func (h *Handler) SetGatewayListenerConfigChangeHook(hook func(models.GatewayListenerConfig) error) {
	h.gatewayListenerOnChange.Store(hook)
}

func (h *Handler) getGatewayListenerConfigChangeHook() func(models.GatewayListenerConfig) error {
	val := h.gatewayListenerOnChange.Load()
	if val == nil {
		return nil
	}
	hook, _ := val.(func(models.GatewayListenerConfig) error)
	return hook
}

func (h *Handler) saveConfigLocked() error {
	if h.configManager == nil {
		return nil
	}

	rulesCopy := make([]models.Rule, len(h.Rules))
	copy(rulesCopy, h.Rules)
	hostRulesCopy := copyHostRules(h.HostRules)
	streamRulesCopy := make([]models.StreamRule, len(h.StreamRules))
	copy(streamRulesCopy, h.StreamRules)

	if err := h.configManager.Update(func(conf *config.AppConfig) error {
		conf.Rules = rulesCopy
		conf.HostRules = hostRulesCopy
		conf.StreamRules = streamRulesCopy
		conf.DefaultRoute = h.DefaultRoute
		conf.AuthConfig = h.AuthConfig
		conf.Logging = h.LoggingConfig
		conf.ProxyProtocolForce = h.ProxyProtocolForce
		conf.GatewayListener = h.GatewayListener
		conf.ReverseProxyThrottle = h.ReverseProxyThrottle
		conf.Visibility = h.GatewayVisibility
		conf.ForwardedHeaders = h.ForwardedHeaders
		conf.PreserveHost = h.PreserveHost
		conf.CrawlerBlocker = h.CrawlerBlocker
		conf.Portal = h.GatewayPortal
		conf.UnmatchedRoute = h.GatewayUnmatchedRoute
		conf.FnosPortIconHijack = h.FnosPortIconHijack
		conf.GeneralBlacklist = h.GeneralBlacklist
		conf.WAF = h.WAFConfig
		conf.SSL = copySSLConfig(h.sslConfig)
		conf.SSLCert, conf.SSLKey = legacySSLPEMFromConfig(h.sslConfig)
		return nil
	}); err != nil {
		if event := debugProxyEvent("config_save_failed", ""); event != nil {
			event.Str("error", logger.SanitizeLogString(err.Error())).Send()
		}
		log.Printf("Failed to save config: %v", err)
		return err
	}
	if event := debugProxyEvent("config_saved", ""); event != nil {
		event.Int("path_rule_count", len(rulesCopy)).
			Int("host_rule_count", len(hostRulesCopy)).
			Int("stream_rule_count", len(streamRulesCopy)).
			Bool("gateway_logging_enabled", h.LoggingConfig.Enabled).
			Bool("waf_enabled", h.WAFConfig.Enabled).
			Send()
	}
	return nil
}

// ResetAllData replaces every user-managed gateway setting with a fresh
// configuration and clears volatile caches and counters. Runtime wiring such
// as the active control port and installed WAF directory is supplied by the
// caller in resetConfig and is therefore preserved.
func (h *Handler) ResetAllData(resetConfig *config.AppConfig) error {
	if h == nil {
		return fmt.Errorf("proxy handler is not initialized")
	}
	if resetConfig == nil {
		return fmt.Errorf("reset config is required")
	}

	loggingConfig := gatewaylog.NormalizeConfig(resetConfig.Logging)
	forwardedHeaders, _ := normalizeForwardedHeadersConfig(resetConfig.ForwardedHeaders)
	preserveHost, _ := normalizePreserveHostConfig(resetConfig.PreserveHost)
	visibility, err := newGatewayVisibility(resetConfig.Visibility)
	if err != nil {
		return fmt.Errorf("normalize reset gateway visibility: %w", err)
	}
	sslConfig, err := normalizeSSLConfig(resetConfig.SSL)
	if err != nil {
		return fmt.Errorf("normalize reset SSL config: %w", err)
	}
	sslBundle, err := newSSLRuntimeBundle(sslConfig)
	if err != nil {
		return fmt.Errorf("build reset SSL runtime: %w", err)
	}

	previousWAF := h.GetWAFConfig()
	wafConfig := resetConfig.WAF
	if h.wafRuntime != nil {
		wafConfig, err = h.wafRuntime.SetConfig(wafConfig)
		if err != nil {
			return fmt.Errorf("reset WAF runtime: %w", err)
		}
	}

	resetConfig.Rules = []models.Rule{}
	resetConfig.HostRules = []models.HostRule{}
	resetConfig.StreamRules = []models.StreamRule{}
	resetConfig.Logging = loggingConfig
	resetConfig.ForwardedHeaders = forwardedHeaders
	resetConfig.PreserveHost = preserveHost
	resetConfig.Visibility = visibility.getConfig()
	resetConfig.GeneralBlacklist = models.GeneralBlacklistConfig{Items: []models.GeneralBlacklistRecord{}}
	resetConfig.WAF = wafConfig
	resetConfig.SSL = copySSLConfig(sslConfig)
	resetConfig.SSLCert = ""
	resetConfig.SSLKey = ""
	if h.configManager != nil {
		if err := h.configManager.Save(resetConfig); err != nil {
			if h.wafRuntime != nil {
				_, _ = h.wafRuntime.SetConfig(previousWAF)
			}
			return fmt.Errorf("persist reset gateway config: %w", err)
		}
	}

	reverseProxyThrottle := newReverseProxyThrottle(resetConfig.ReverseProxyThrottle)
	generalBlacklist := newGeneralBlacklistRuntime(resetConfig.GeneralBlacklist)
	reverseProxyThrottleExempt := newReverseProxyThrottleExemptIPsRuntime(
		models.ReverseProxyThrottleExemptIPsRuntime{},
	)
	commonLocationExemptions := newCommonLocationExemptionsRuntime(
		models.CommonLocationExemptionsRuntime{},
	)

	h.mu.Lock()
	h.Rules = []models.Rule{}
	h.HostRules = []models.HostRule{}
	h.StreamRules = []models.StreamRule{}
	h.DefaultRoute = resetConfig.DefaultRoute
	h.AuthConfig = resetConfig.AuthConfig
	h.LoggingConfig = loggingConfig
	h.ProxyProtocolForce = resetConfig.ProxyProtocolForce
	h.GatewayListener = resetConfig.GatewayListener
	h.ReverseProxyThrottle = resetConfig.ReverseProxyThrottle
	h.GatewayVisibility = resetConfig.Visibility
	h.ForwardedHeaders = forwardedHeaders
	h.PreserveHost = preserveHost
	h.CrawlerBlocker = resetConfig.CrawlerBlocker
	h.GatewayPortal = models.NormalizeGatewayPortalConfig(resetConfig.Portal)
	h.GatewayUnmatchedRoute = models.NormalizeGatewayUnmatchedRouteConfig(resetConfig.UnmatchedRoute)
	h.FnosPortIconHijack = resetConfig.FnosPortIconHijack
	h.GeneralBlacklist = generalBlacklist.getConfig()
	h.WAFConfig = wafConfig
	h.sslConfig = copySSLConfig(sslConfig)
	h.sslBundle.Store(sslBundle)
	h.reverseProxyThrottle = reverseProxyThrottle
	h.reverseProxyThrottleExempt = reverseProxyThrottleExempt
	h.commonLocationExemptions = commonLocationExemptions
	h.gatewayVisibility = visibility
	h.generalBlacklist = generalBlacklist
	h.forwardedHeaders = newForwardedHeadersConfig(forwardedHeaders)
	h.preserveHost = newPreserveHostConfig(preserveHost)
	h.publishRequestSnapshotLocked()
	h.mu.Unlock()

	if h.gatewayLogManager != nil {
		h.gatewayLogManager.UpdateConfig(loggingConfig)
	}
	h.clearAuthCache()
	h.loggedInActive.Range(func(key, _ any) bool {
		h.loggedInActive.Delete(key)
		return true
	})
	h.loggedInActiveCount.Store(0)
	h.trafficTotalIn.Store(0)
	h.trafficTotalOut.Store(0)
	h.trafficError5xx.Store(0)
	h.trafficByHost.Range(func(key, _ any) bool {
		h.trafficByHost.Delete(key)
		return true
	})
	if hook := h.getSSLChangeHook(); hook != nil {
		hook()
	}

	if event := debugProxyEvent("all_data_reset", ""); event != nil {
		event.Send()
	}
	return nil
}

// persistGatewayListenerConfigLocked updates only the listener setting. A
// listener-scope transition is coordinated with a live rebind, so persisting a
// broad Handler snapshot here could accidentally commit unrelated state while
// the runtime transition is in flight.
func (h *Handler) persistGatewayListenerConfigLocked(listener models.GatewayListenerConfig) error {
	if h.configManager == nil {
		return nil
	}
	return h.configManager.Update(func(conf *config.AppConfig) error {
		conf.GatewayListener = listener
		return nil
	})
}

// persistHostRulesLocked saves only a candidate host-rule set while the caller
// holds h.mu. Keeping this update narrowly scoped avoids persisting unrelated
// runtime fields whose own save may previously have failed. Callers publish the
// candidate to requestState only after this returns nil.
func (h *Handler) persistHostRulesLocked(hostRules []models.HostRule) error {
	if h.configManager == nil {
		return nil
	}
	hostRulesCopy := copyHostRules(hostRules)
	if err := h.configManager.Update(func(conf *config.AppConfig) error {
		conf.HostRules = hostRulesCopy
		return nil
	}); err != nil {
		if event := debugProxyEvent("host_rules_save_failed", ""); event != nil {
			event.Str("error", logger.SanitizeLogString(err.Error())).Send()
		}
		log.Printf("Failed to save host rules: %v", err)
		return err
	}
	if event := debugProxyEvent("host_rules_saved", ""); event != nil {
		event.Int("host_rule_count", len(hostRulesCopy)).Send()
	}
	return nil
}

func (h *Handler) GetProxyProtocolForce() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.ProxyProtocolForce
}

func (h *Handler) SetProxyProtocolForce(force bool) error {
	h.listenerChangeMu.Lock()
	defer h.listenerChangeMu.Unlock()

	h.mu.Lock()
	changed := h.ProxyProtocolForce != force
	h.ProxyProtocolForce = force
	h.publishRequestSnapshotLocked()
	saveErr := h.saveConfigLocked()
	hook := h.getProxyProtocolForceChangeHook()
	h.mu.Unlock()
	if event := debugProxyEvent("proxy_protocol_force_set", ""); event != nil {
		event.Bool("enabled", force).Bool("changed", changed).Send()
	}
	if changed && hook != nil {
		hook()
	}
	return saveErr
}

func (h *Handler) GetGatewayListenerConfig() models.GatewayListenerConfig {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.GatewayListener
}

func (h *Handler) SetGatewayListenerConfig(listener models.GatewayListenerConfig) error {
	scope := models.NormalizeGatewayListenerScope(listener.Scope)
	if scope == "" {
		return fmt.Errorf("listener scope must be %q or %q", models.GatewayListenerScopeLoopback, models.GatewayListenerScopeAll)
	}
	listener.Scope = scope

	// Proxy protocol and listener scope both alter the same bound socket. Keep
	// their transitions serialized so a successful scope update cannot race a
	// concurrent proxy-protocol rebind.
	h.listenerChangeMu.Lock()
	defer h.listenerChangeMu.Unlock()

	h.mu.RLock()
	previous := h.GatewayListener
	changed := previous.Scope != listener.Scope
	hook := h.getGatewayListenerConfigChangeHook()
	h.mu.RUnlock()
	if !changed {
		return nil
	}

	if hook != nil {
		if err := hook(listener); err != nil {
			return fmt.Errorf("apply gateway listener scope %q: %w", listener.Scope, err)
		}
	}

	h.mu.Lock()
	h.GatewayListener = listener
	saveErr := h.persistGatewayListenerConfigLocked(listener)
	if saveErr != nil {
		h.GatewayListener = previous
	}
	h.mu.Unlock()
	if saveErr != nil {
		if hook != nil {
			if rollbackErr := hook(previous); rollbackErr != nil {
				return fmt.Errorf(
					"persist gateway listener scope %q: %w; restore runtime listener scope %q: %v",
					listener.Scope,
					saveErr,
					previous.Scope,
					rollbackErr,
				)
			}
		}
		return fmt.Errorf("persist gateway listener scope %q: %w", listener.Scope, saveErr)
	}
	if event := debugProxyEvent("gateway_listener_scope_set", ""); event != nil {
		event.Str("scope", listener.Scope).Bool("changed", changed).Send()
	}
	return nil
}

func (h *Handler) evaluateReverseProxyThrottleRequest(isAuthRoute bool, matchedHostRule *models.HostRule, matchedHostLocation *models.HostLocation, matchedRule *models.Rule, clientIP string, now time.Time) reverseProxyThrottleDecision {
	if !isAuthRoute && matchedHostRule == nil && matchedRule == nil {
		return reverseProxyThrottleDecision{Allowed: true}
	}
	if h.reverseProxyThrottle == nil {
		return reverseProxyThrottleDecision{Allowed: true}
	}
	h.mu.RLock()
	exemptRuntime := h.reverseProxyThrottleExempt
	h.mu.RUnlock()
	if exemptRuntime != nil && exemptRuntime.shouldBypass(clientIP) {
		return reverseProxyThrottleDecision{Allowed: true}
	}
	return h.reverseProxyThrottle.evaluate(clientIP, now)
}

func (h *Handler) allowReverseProxyRequest(
	w http.ResponseWriter,
	r *http.Request,
	clientIP string,
	isAuthRoute bool,
	matchedHostRule *models.HostRule,
	matchedHostLocation *models.HostLocation,
	matchedRule *models.Rule,
	requestID string,
) bool {
	checkedAt := time.Now()
	decision := h.evaluateReverseProxyThrottleRequest(
		isAuthRoute,
		matchedHostRule,
		matchedHostLocation,
		matchedRule,
		clientIP,
		checkedAt,
	)
	routeType := classifyReverseProxyRouteType(r.URL.Path, isAuthRoute, matchedHostRule, matchedHostLocation, matchedRule)
	if !decision.Allowed {
		if event := debugProxyEvent("throttle_blocked", requestID); event != nil {
			event.Str("client_ip", logger.SanitizeLogString(clientIP)).
				Bool("newly_blocked", decision.NewlyBlocked).
				Time("blocked_until", decision.BlockedUntil).
				Str("route_type", routeType).
				Send()
		}
		if decision.NewlyBlocked {
			h.enqueueGatewayThrottleBlockedEvent(gatewayThrottleBlockedEvent{
				ClientIP:     clientIP,
				BlockedUntil: decision.BlockedUntil,
				Config:       decision.Config,
				RouteType:    routeType,
				Host:         r.Host,
				RequestPath:  r.URL.Path,
				IsAuthRoute:  isAuthRoute,
				HappenedAt:   checkedAt,
			})
		}
		suppressAccessLog(w)
		h.abortConnection(w)
		return false
	}
	if event := debugProxyEvent("throttle_allowed", requestID); event != nil {
		event.Str("client_ip", logger.SanitizeLogString(clientIP)).
			Str("route_type", routeType).
			Send()
	}
	return true
}

func classifyReverseProxyRouteType(requestPath string, isAuthRoute bool, matchedHostRule *models.HostRule, matchedHostLocation *models.HostLocation, matchedRule *models.Rule) string {
	switch {
	case isAuthRoute:
		return "auth_proxy"
	case requestPath == "/__select__":
		return "select"
	case matchedHostRule != nil && matchedHostLocation != nil:
		return "host_location"
	case matchedHostRule != nil:
		return "host_rule"
	case matchedRule != nil:
		return "path_rule"
	default:
		return "not_found"
	}
}

func wafRouteContext(r *http.Request, snapshot requestSnapshot, isAuthRoute bool, matchedHostRule *models.HostRule, matchedHostLocation *models.HostLocation, matchedRule *models.Rule) (string, string, string) {
	requestPath := ""
	if r != nil && r.URL != nil {
		requestPath = r.URL.Path
	}
	routeType := classifyReverseProxyRouteType(requestPath, isAuthRoute, matchedHostRule, matchedHostLocation, matchedRule)
	switch {
	case isAuthRoute:
		upstream := ""
		if snapshot.authConfig.AuthPort > 0 {
			upstream = localServiceBaseURL(snapshot.authConfig.AuthPort)
		}
		return routeType, requestPath, upstream
	case requestPath == "/__select__":
		return routeType, requestPath, ""
	case matchedHostRule != nil && matchedHostLocation != nil:
		upstream := ""
		if matchedHostLocation.Action == models.HostLocationActionProxy {
			upstream = matchedHostLocation.Target
		}
		return routeType, hostLocationRouteKey(matchedHostRule, matchedHostLocation), upstream
	case matchedHostRule != nil:
		return routeType, matchedHostRule.Host, matchedHostRule.Target
	case matchedRule != nil:
		return routeType, matchedRule.Path, matchedRule.Target
	default:
		return routeType, requestPath, ""
	}
}

func gatewayThrottleDedupeTTL(now time.Time, blockedUntil time.Time, fallback int) int {
	if blockedUntil.After(now) {
		ttlSeconds := int(time.Until(blockedUntil).Seconds()) + 60
		if ttlSeconds > 0 {
			return ttlSeconds
		}
	}
	if fallback > 0 {
		return fallback + 60
	}
	return 60
}

func gatewayThrottleDedupeKey(ip string, blockedUntil time.Time) string {
	const prefix = "gateway-throttle:"
	unix := blockedUntil.Unix()
	var stack [len(prefix) + 64 + 1 + 20]byte
	buf := stack[:0]
	buf = append(buf, prefix...)
	buf = append(buf, ip...)
	buf = append(buf, ':')
	buf = strconv.AppendInt(buf, unix, 10)
	return string(buf)
}

const gatewayThrottleEventQueueSize = 64

type gatewayThrottleBlockedEvent struct {
	ClientIP     string
	BlockedUntil time.Time
	Config       models.ReverseProxyThrottleConfig
	RouteType    string
	Host         string
	RequestPath  string
	IsAuthRoute  bool
	HappenedAt   time.Time
}

func (h *Handler) startGatewayThrottleEventWorker() {
	if h == nil || h.systemEventClient == nil {
		return
	}
	if h.throttleEventQueue == nil {
		h.throttleEventQueue = make(chan gatewayThrottleBlockedEvent, gatewayThrottleEventQueueSize)
	}
	go func(queue <-chan gatewayThrottleBlockedEvent) {
		for event := range queue {
			h.emitGatewayThrottleBlockedEvent(event)
		}
	}(h.throttleEventQueue)
}

func (h *Handler) enqueueGatewayThrottleBlockedEvent(event gatewayThrottleBlockedEvent) {
	if h == nil || h.systemEventClient == nil || h.throttleEventQueue == nil {
		return
	}
	select {
	case h.throttleEventQueue <- event:
	default:
		log.Printf("Dropping gateway throttle event for %s: event queue full", normalizeClientIP(event.ClientIP))
	}
}

func (h *Handler) emitGatewayThrottleBlockedEvent(args gatewayThrottleBlockedEvent) {
	client := h.systemEventClient
	if client == nil {
		return
	}

	normalizedIP := normalizeClientIP(args.ClientIP)
	if normalizedIP == "" {
		normalizedIP = strings.TrimSpace(args.ClientIP)
	}
	if normalizedIP == "" {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := client.Publish(ctx, 0, events.SystemEventPublishInput{
		Type:             events.FnEventGatewayThrottleBlocked,
		Source:           events.SystemEventSourceGoReauthProxy,
		Level:            events.FnEventLevelWarn,
		HappenedAt:       args.HappenedAt.UTC().Format(time.RFC3339Nano),
		DedupeKey:        gatewayThrottleDedupeKey(normalizedIP, args.BlockedUntil),
		DedupeTTLSeconds: gatewayThrottleDedupeTTL(args.HappenedAt, args.BlockedUntil, args.Config.BlockSeconds),
		Subject: &events.SystemEventSubject{
			Kind: events.SystemEventSubjectKindIP,
			ID:   normalizedIP,
		},
		Payload: events.GatewayThrottleBlockedPayload{
			IP:                normalizedIP,
			BlockedUntil:      args.BlockedUntil.UTC().Format(time.RFC3339Nano),
			BlockSeconds:      args.Config.BlockSeconds,
			RequestsPerSecond: args.Config.RequestsPerSecond,
			Burst:             args.Config.Burst,
			RouteType:         args.RouteType,
			Host:              args.Host,
			Path:              args.RequestPath,
			IsAuthRoute:       args.IsAuthRoute,
		},
	})
	if err != nil {
		log.Printf("Failed to publish gateway throttle event for %s: %v", normalizedIP, err)
	}
}

func (h *Handler) SetSSLDeployment(config models.SSLConfig) error {
	normalized, err := normalizeSSLConfig(config)
	if err != nil {
		if event := debugProxyEvent("ssl_deployment_invalid", ""); event != nil {
			event.Str("error", logger.SanitizeLogString(err.Error())).
				Str("deployment_mode", string(config.DeploymentMode)).
				Int("certificate_count", len(config.Certificates)).
				Send()
		}
		return err
	}
	bundle, err := newSSLRuntimeBundle(normalized)
	if err != nil {
		if event := debugProxyEvent("ssl_deployment_load_failed", ""); event != nil {
			event.Str("error", logger.SanitizeLogString(err.Error())).
				Str("deployment_mode", string(normalized.DeploymentMode)).
				Int("certificate_count", len(normalized.Certificates)).
				Send()
		}
		return err
	}

	h.mu.Lock()
	h.sslBundle.Store(bundle)
	h.sslConfig = normalized
	saveErr := h.saveConfigLocked()
	hook := h.getSSLChangeHook()
	h.mu.Unlock()
	if hook != nil {
		hook()
	}
	if saveErr != nil {
		return saveErr
	}
	if event := debugProxyEvent("ssl_deployment_set", ""); event != nil {
		event.Str("deployment_mode", string(normalized.DeploymentMode)).
			Int("certificate_count", len(normalized.Certificates)).
			Bool("enabled", len(normalized.Certificates) > 0).
			Send()
	}
	return nil
}

func (h *Handler) SetSSLCertificate(cert *tls.Certificate, certPEM, keyPEM string) {
	if cert == nil {
		_ = h.SetSSLDeployment(models.SSLConfig{})
		return
	}
	normalizedCertPEM, normalizedKeyPEM, err := validateLegacySSLPair(certPEM, keyPEM)
	if err != nil {
		log.Printf("Failed to set legacy SSL certificate: %v", err)
		return
	}
	if err := h.SetSSLDeployment(buildLegacySSLConfig(normalizedCertPEM, normalizedKeyPEM)); err != nil {
		log.Printf("Failed to set legacy SSL certificate: %v", err)
	}
}

func (h *Handler) SetSSLCertificatePEM(certPEM, keyPEM string) error {
	normalizedCertPEM, normalizedKeyPEM, err := validateLegacySSLPair(certPEM, keyPEM)
	if err != nil {
		return err
	}
	return h.SetSSLDeployment(buildLegacySSLConfig(normalizedCertPEM, normalizedKeyPEM))
}

func (h *Handler) getSSLBundle() *sslRuntimeBundle {
	val := h.sslBundle.Load()
	if val == nil {
		return newEmptySSLRuntimeBundle(models.SSLDeploymentModeSingleActive)
	}
	bundle, _ := val.(*sslRuntimeBundle)
	if bundle == nil {
		return newEmptySSLRuntimeBundle(models.SSLDeploymentModeSingleActive)
	}
	return bundle
}

func (h *Handler) GetSSLCertificate() *tls.Certificate {
	return h.getSSLBundle().certificateForServerName("")
}

func (h *Handler) GetCertificate(info *tls.ClientHelloInfo) *tls.Certificate {
	if info == nil {
		return h.GetSSLCertificate()
	}
	return h.getSSLBundle().certificateForServerName(info.ServerName)
}

// GetHostProtocolMode returns the immutable host-rule snapshot used by a new
// TLS handshake. Unknown SNI names retain the historical auto behavior.
func (h *Handler) GetHostProtocolMode(serverName string) string {
	host := normalizeRequestHost(serverName)
	if host == "" {
		return models.HostProtocolModeAuto
	}
	snapshot := h.snapshotForRequest()
	rule := snapshot.hostRulesByHost[host]
	if rule == nil {
		return models.HostProtocolModeAuto
	}
	return models.NormalizeHostProtocolMode(rule.ProtocolMode)
}

func (h *Handler) HasSSLCertificates() bool {
	return h.getSSLBundle().hasCertificates()
}

func (h *Handler) GetSSLDeployment() models.SSLConfig {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return copySSLConfig(h.sslConfig)
}

func (h *Handler) GetSSLInfo() models.SSLInfo {
	bundle := h.getSSLBundle()
	return copySSLInfo(models.SSLInfo{
		Enabled:        bundle.hasCertificates(),
		DeploymentMode: bundle.mode,
		Certificates:   bundle.certificates,
	})
}

func (h *Handler) ClearSSLCertificate() error {
	return h.SetSSLDeployment(models.SSLConfig{})
}

func (h *Handler) validateRule(newRule models.Rule) error {
	if newRule.Path == "/" || newRule.Path == "" {
		return fmt.Errorf("cannot add rule for root path '/' or empty path")
	}
	if newRule.Target == "" {
		return fmt.Errorf("cannot add rule with empty target")
	}
	if newRule.Path == "/s" || newRule.Path == "/s/" {
		return fmt.Errorf("cannot add rule for reserved share path '/s' or '/s/'")
	}
	if strings.HasPrefix(newRule.Path, "/__") || strings.HasPrefix(newRule.Path, "__") {
		return fmt.Errorf("cannot add rule for reserved path starting with '__'")
	}
	if strings.HasSuffix(newRule.Path, "/") {
		return fmt.Errorf("path cannot end with a slash '/'")
	}
	if err := h.checkSafeTarget(newRule.Target); err != nil {
		return fmt.Errorf("invalid target: %v", err)
	}
	return nil
}

func (h *Handler) normalizeRules(rules []models.Rule) ([]models.Rule, error) {
	normalized := make([]models.Rule, 0, len(rules))
	indexByPath := make(map[string]int, len(rules))
	for _, rule := range rules {
		if err := h.validateRule(rule); err != nil {
			return nil, err
		}
		if idx, exists := indexByPath[rule.Path]; exists {
			normalized[idx] = rule
			continue
		}
		indexByPath[rule.Path] = len(normalized)
		normalized = append(normalized, rule)
	}
	return normalized, nil
}

func (h *Handler) AddRule(newRule models.Rule) error {
	if err := h.validateRule(newRule); err != nil {
		return err
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	updated := false
	nextRules := make([]models.Rule, 0, len(h.Rules)+1)
	for _, rule := range h.Rules {
		if rule.Path == newRule.Path && !updated {
			nextRules = append(nextRules, newRule)
			updated = true
			continue
		}
		nextRules = append(nextRules, rule)
	}
	if !updated {
		nextRules = append(nextRules, newRule)
	}
	h.Rules = nextRules
	h.publishRequestSnapshotLocked()
	if err := h.saveConfigLocked(); err != nil {
		return err
	}
	if event := debugProxyEvent("path_rule_upserted", ""); event != nil {
		event.Str("path", logger.SanitizeLogString(newRule.Path)).
			Str("target", logger.SanitizeURL(newRule.Target)).
			Bool("updated", updated).
			Bool("use_auth", newRule.UseAuth).
			Int("path_rule_count", len(h.Rules)).
			Send()
	}
	return nil
}

func (h *Handler) SetRules(rules []models.Rule) error {
	normalized, err := h.normalizeRules(rules)
	if err != nil {
		return err
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	h.Rules = normalized
	h.publishRequestSnapshotLocked()
	if err := h.saveConfigLocked(); err != nil {
		return err
	}
	if event := debugProxyEvent("path_rules_set", ""); event != nil {
		event.Int("path_rule_count", len(normalized)).
			Interface("path_rules", debugRuleSummaries(normalized)).
			Send()
	}
	return nil
}

func (h *Handler) checkSafeTarget(target string) error {
	u, _, err := parseReverseProxyTargetURLs(target)
	if err != nil {
		return err
	}
	hostname := u.Hostname()
	port := u.Port()

	if hostname == "" {
		return fmt.Errorf("target must include a valid hostname")
	}

	if hostname == "localhost" || hostname == "127.0.0.1" || hostname == "::1" {
		if port == strconv.Itoa(h.AdminPort) {
			return fmt.Errorf("cannot target local admin port %d", h.AdminPort)
		}
	}
	return nil
}

func parseReverseProxyTargetURLs(target string) (*url.URL, *url.URL, error) {
	targetURL, err := parseReverseProxyTargetURL(target)
	if err != nil {
		return nil, nil, err
	}
	return targetURL, reverseProxyTransportURL(targetURL), nil
}

func compileReverseProxyTargetRuntime(target string) reverseProxyTargetRuntime {
	targetURL, transportURL, err := parseReverseProxyTargetURLs(target)
	if err != nil {
		return reverseProxyTargetRuntime{err: err}
	}
	return reverseProxyTargetRuntime{
		targetURL:            targetURL,
		transportURL:         transportURL,
		supportsHTMLFeatures: reverseProxyTargetSupportsHTMLFeatures(targetURL),
	}
}

func reverseProxyTargetRuntimeKey(target string) string {
	return strings.TrimSpace(target)
}

func buildReverseProxyTargetRuntimeMap(rules []models.Rule, hostRules []models.HostRule) map[string]reverseProxyTargetRuntime {
	targetCount := len(rules) + len(hostRules)
	for _, rule := range hostRules {
		targetCount += len(rule.Locations)
	}
	if targetCount == 0 {
		return nil
	}

	targets := make(map[string]reverseProxyTargetRuntime, targetCount)
	addTarget := func(target string) {
		key := reverseProxyTargetRuntimeKey(target)
		if _, exists := targets[key]; exists {
			return
		}
		targets[key] = compileReverseProxyTargetRuntime(target)
	}

	for _, rule := range rules {
		addTarget(rule.Target)
	}
	for _, rule := range hostRules {
		addTarget(rule.Target)
		for _, location := range rule.Locations {
			if location.Action == models.HostLocationActionResponse {
				continue
			}
			addTarget(location.Target)
		}
	}
	return targets
}

func reverseProxyTargetRuntimeFor(snapshot requestSnapshot, target string) reverseProxyTargetRuntime {
	key := reverseProxyTargetRuntimeKey(target)
	if snapshot.targets != nil {
		if runtime, ok := snapshot.targets[key]; ok {
			return runtime
		}
	}
	return compileReverseProxyTargetRuntime(target)
}

func buildToolbarRouteSnapshot(rules []models.Rule, hostRules []models.HostRule, targets map[string]reverseProxyTargetRuntime) ([]models.Rule, []models.HostRule) {
	toolbarRules := make([]models.Rule, 0, len(rules))
	for _, rule := range rules {
		if !targetSupportsToolbarNavigation(rule.Target, targets) {
			continue
		}
		toolbarRules = append(toolbarRules, rule)
	}

	toolbarHostRules := make([]models.HostRule, 0, len(hostRules))
	for _, rule := range hostRules {
		if !targetSupportsToolbarNavigation(rule.Target, targets) {
			continue
		}
		toolbarHostRules = append(toolbarHostRules, rule)
	}
	return toolbarRules, toolbarHostRules
}

func targetSupportsToolbarNavigation(target string, targets map[string]reverseProxyTargetRuntime) bool {
	if strings.TrimSpace(target) == "" {
		return true
	}
	key := reverseProxyTargetRuntimeKey(target)
	if targets != nil {
		if runtime, ok := targets[key]; ok {
			return runtime.err == nil && runtime.supportsHTMLFeatures
		}
	}
	runtime := compileReverseProxyTargetRuntime(target)
	return runtime.err == nil && runtime.supportsHTMLFeatures
}

func parseReverseProxyTargetURL(target string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(target))
	if err != nil {
		return nil, err
	}
	u.Scheme = strings.ToLower(u.Scheme)
	if !isSupportedReverseProxyTargetScheme(u.Scheme) {
		return nil, fmt.Errorf("unsupported target scheme %q", u.Scheme)
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("target must include a valid hostname")
	}
	return u, nil
}

func isSupportedReverseProxyTargetScheme(scheme string) bool {
	switch strings.ToLower(scheme) {
	case "http", "https", "ws", "wss":
		return true
	default:
		return false
	}
}

func reverseProxyTargetSupportsHTMLFeatures(targetURL *url.URL) bool {
	if targetURL == nil {
		return false
	}
	switch strings.ToLower(targetURL.Scheme) {
	case "http", "https":
		return true
	default:
		return false
	}
}

func rawReverseProxyTargetSupportsHTMLFeatures(target string) bool {
	targetURL, err := parseReverseProxyTargetURL(target)
	return err == nil && reverseProxyTargetSupportsHTMLFeatures(targetURL)
}

func snapshotReverseProxyTargetSupportsHTMLFeatures(snapshot requestSnapshot, target string) bool {
	runtime := reverseProxyTargetRuntimeFor(snapshot, target)
	return runtime.err == nil && runtime.supportsHTMLFeatures
}

func reverseProxyTransportURL(targetURL *url.URL) *url.URL {
	if targetURL == nil {
		return nil
	}
	transportURL := *targetURL
	switch strings.ToLower(transportURL.Scheme) {
	case "ws":
		transportURL.Scheme = "http"
	case "wss":
		transportURL.Scheme = "https"
	case "http", "https":
		transportURL.Scheme = strings.ToLower(transportURL.Scheme)
	}
	return &transportURL
}

func parseStreamTarget(target string) (string, int, error) {
	host, port, err := net.SplitHostPort(strings.TrimSpace(target))
	if err != nil {
		return "", 0, fmt.Errorf("target must be in host:port format")
	}

	if strings.TrimSpace(host) == "" {
		return "", 0, fmt.Errorf("target must include a valid hostname")
	}

	portNum, err := strconv.Atoi(port)
	if err != nil || portNum <= 0 || portNum > 65535 {
		return "", 0, fmt.Errorf("target must include a valid port")
	}

	return host, portNum, nil
}

func normalizeStreamProtocol(protocol string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "", models.StreamProtocolTCP:
		return models.StreamProtocolTCP, nil
	case models.StreamProtocolUDP:
		return models.StreamProtocolUDP, nil
	default:
		return "", fmt.Errorf("protocol must be tcp or udp")
	}
}

func streamRuleMapKey(rule models.StreamRule) string {
	return rule.Protocol + "/" + strconv.Itoa(rule.ListenPort)
}

func isLoopbackOrUnspecifiedHost(host string) bool {
	normalizedHost := strings.TrimSpace(strings.Trim(host, "[]"))
	if normalizedHost == "" {
		return false
	}
	if strings.EqualFold(normalizedHost, "localhost") {
		return true
	}

	parsedIP := net.ParseIP(normalizedHost)
	return parsedIP != nil && (parsedIP.IsLoopback() || parsedIP.IsUnspecified())
}

func (h *Handler) reservedStreamPortName(rule models.StreamRule) string {
	if rule.Protocol != models.StreamProtocolTCP {
		return ""
	}

	switch {
	case h.AdminPort > 0 && rule.ListenPort == h.AdminPort:
		return "admin API"
	case h.ProxyPort > 0 && rule.ListenPort == h.ProxyPort:
		return "reverse proxy"
	default:
		return ""
	}
}

func (h *Handler) checkSafeStreamTarget(protocol string, target string) (string, int, error) {
	host, portNum, err := parseStreamTarget(target)
	if err != nil {
		return "", 0, err
	}

	if protocol == models.StreamProtocolTCP && isLoopbackOrUnspecifiedHost(host) {
		if portNum == h.AdminPort {
			return "", 0, fmt.Errorf("cannot target local admin port %d", h.AdminPort)
		}
	}

	return host, portNum, nil
}

func (h *Handler) normalizeStreamRule(newRule models.StreamRule) (models.StreamRule, error) {
	newRule.Target = strings.TrimSpace(newRule.Target)
	var err error
	newRule.Protocol, err = normalizeStreamProtocol(newRule.Protocol)
	if err != nil {
		return models.StreamRule{}, err
	}

	if newRule.ListenPort <= 0 || newRule.ListenPort > 65535 {
		return models.StreamRule{}, fmt.Errorf("listen_port must be between 1 and 65535")
	}
	if reservedName := h.reservedStreamPortName(newRule); reservedName != "" {
		return models.StreamRule{}, fmt.Errorf("listen_port %d is reserved for the %s", newRule.ListenPort, reservedName)
	}
	if newRule.Target == "" {
		return models.StreamRule{}, fmt.Errorf("cannot add stream rule with empty target")
	}
	targetHost, targetPort, err := h.checkSafeStreamTarget(newRule.Protocol, newRule.Target)
	if err != nil {
		return models.StreamRule{}, fmt.Errorf("invalid target: %v", err)
	}
	if newRule.ListenPort == targetPort && isLoopbackOrUnspecifiedHost(targetHost) {
		return models.StreamRule{}, fmt.Errorf("cannot target the same local listen_port %d", newRule.ListenPort)
	}

	return newRule, nil
}

func (h *Handler) RemoveRule(path string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	newRules := make([]models.Rule, 0, len(h.Rules))
	for _, rule := range h.Rules {
		if rule.Path != path {
			newRules = append(newRules, rule)
		}
	}
	h.Rules = newRules
	h.publishRequestSnapshotLocked()
	h.saveConfigLocked()
	if event := debugProxyEvent("path_rule_removed", ""); event != nil {
		event.Str("path", logger.SanitizeLogString(path)).
			Int("path_rule_count", len(h.Rules)).
			Send()
	}
}

func (h *Handler) FlushRules() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.Rules = make([]models.Rule, 0)
	h.publishRequestSnapshotLocked()
	if err := h.saveConfigLocked(); err != nil {
		return err
	}
	if event := debugProxyEvent("path_rules_flushed", ""); event != nil {
		event.Send()
	}
	return nil
}

func (h *Handler) GetRules() []models.Rule {
	h.mu.RLock()
	defer h.mu.RUnlock()

	rules := make([]models.Rule, len(h.Rules))
	copy(rules, h.Rules)
	return rules
}

func hostLocationMapKey(location models.HostLocation) string {
	return location.Match + "\x00" + location.Path
}

func hostLocationRouteKey(hostRule *models.HostRule, location *models.HostLocation) string {
	host := ""
	locationPath := ""
	if hostRule != nil {
		host = hostRule.Host
	}
	if location != nil {
		locationPath = location.Path
	}
	if host == "" {
		return locationPath
	}
	if locationPath == "" {
		return host
	}
	return host + " " + locationPath
}

func normalizeHostLocationResponseHeaders(headers map[string]string) (map[string]string, error) {
	if len(headers) == 0 {
		return map[string]string{}, nil
	}

	normalized := make(map[string]string, len(headers))
	for rawName, value := range headers {
		name := strings.TrimSpace(rawName)
		if name == "" {
			return nil, fmt.Errorf("response header name cannot be empty")
		}
		if !httpguts.ValidHeaderFieldName(name) {
			return nil, fmt.Errorf("invalid response header name %q", rawName)
		}
		switch strings.ToLower(name) {
		case "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
			"proxy-connection", "te", "trailer", "transfer-encoding", "upgrade", "content-length",
			"content-type":
			return nil, fmt.Errorf("response header %q is not configurable", name)
		}
		normalized[http.CanonicalHeaderKey(name)] = value
	}

	return normalized, nil
}

func (h *Handler) normalizeHostLocation(location models.HostLocation) (models.HostLocation, error) {
	rawPath := strings.TrimSpace(location.Path)
	if rawPath == "" {
		return models.HostLocation{}, fmt.Errorf("host location path is required")
	}
	if !strings.HasPrefix(rawPath, "/") {
		return models.HostLocation{}, fmt.Errorf("host location path must start with '/'")
	}
	location.Path = path.Clean(rawPath)
	if location.Path == "/" {
		return models.HostLocation{}, fmt.Errorf("host location path '/' is not allowed")
	}
	if location.Path == "/s" || location.Path == "/s/" {
		return models.HostLocation{}, fmt.Errorf("host location path cannot use reserved share path %q", location.Path)
	}
	if strings.HasPrefix(location.Path, "/__") {
		return models.HostLocation{}, fmt.Errorf("host location path cannot start with reserved prefix '/__'")
	}

	switch strings.TrimSpace(strings.ToLower(location.Match)) {
	case "", models.HostLocationMatchPrefix:
		location.Match = models.HostLocationMatchPrefix
	case models.HostLocationMatchExact:
		location.Match = models.HostLocationMatchExact
	default:
		return models.HostLocation{}, fmt.Errorf("host location match must be exact or prefix")
	}

	switch strings.TrimSpace(strings.ToLower(location.Action)) {
	case "", models.HostLocationActionProxy:
		location.Action = models.HostLocationActionProxy
	case models.HostLocationActionResponse:
		location.Action = models.HostLocationActionResponse
	default:
		return models.HostLocation{}, fmt.Errorf("host location action must be proxy or response")
	}

	switch location.Action {
	case models.HostLocationActionProxy:
		location.Target = strings.TrimSpace(location.Target)
		if location.Target == "" {
			return models.HostLocation{}, fmt.Errorf("host location %s requires target", location.Path)
		}
		if err := h.checkSafeTarget(location.Target); err != nil {
			return models.HostLocation{}, fmt.Errorf("invalid location target for %s: %v", location.Path, err)
		}
		location.Response = models.HostLocationResponse{}
	case models.HostLocationActionResponse:
		location.Target = ""
		if location.Response.Status == 0 {
			location.Response.Status = http.StatusOK
		}
		if location.Response.Status < 100 || location.Response.Status > 599 {
			return models.HostLocation{}, fmt.Errorf("host location response status for %s must be between 100 and 599", location.Path)
		}
		location.Response.ContentType = strings.TrimSpace(location.Response.ContentType)
		if location.Response.ContentType == "" {
			location.Response.ContentType = "text/plain; charset=utf-8"
		}
		headers, err := normalizeHostLocationResponseHeaders(location.Response.Headers)
		if err != nil {
			return models.HostLocation{}, fmt.Errorf("invalid response headers for %s: %v", location.Path, err)
		}
		location.Response.Headers = headers
		location.StripPath = false
		location.RewriteHTML = false
	}

	return location, nil
}

func (h *Handler) normalizeHostLocations(locations []models.HostLocation) ([]models.HostLocation, error) {
	if len(locations) == 0 {
		return nil, nil
	}

	normalized := make([]models.HostLocation, 0, len(locations))
	seen := make(map[string]struct{}, len(locations))
	for _, location := range locations {
		nextLocation, err := h.normalizeHostLocation(location)
		if err != nil {
			return nil, err
		}
		key := hostLocationMapKey(nextLocation)
		if _, exists := seen[key]; exists {
			return nil, fmt.Errorf("duplicate host location %s %s", nextLocation.Match, nextLocation.Path)
		}
		seen[key] = struct{}{}
		normalized = append(normalized, nextLocation)
	}

	return normalized, nil
}

func (h *Handler) normalizeHostRule(newRule models.HostRule) (models.HostRule, error) {
	newRule.Host = normalizeRequestHost(newRule.Host)
	if newRule.Host == "" {
		return models.HostRule{}, fmt.Errorf("cannot add host rule with empty host")
	}
	if strings.Contains(newRule.Host, "/") || strings.Contains(newRule.Host, "*") {
		return models.HostRule{}, fmt.Errorf("host rule must be an exact host without path or wildcard")
	}
	if newRule.Target == "" {
		return models.HostRule{}, fmt.Errorf("cannot add host rule with empty target")
	}
	if err := h.checkSafeTarget(newRule.Target); err != nil {
		return models.HostRule{}, fmt.Errorf("invalid target: %v", err)
	}
	newRule.ProtocolMode = models.NormalizeHostProtocolMode(newRule.ProtocolMode)
	visibility, _, err := normalizeHostRuleVisibility(newRule.Visibility)
	if err != nil {
		return models.HostRule{}, err
	}
	newRule.Visibility = visibility
	advancedAuth, err := normalizeAdvancedAuthConfig(newRule.AdvancedAuth)
	if err != nil {
		return models.HostRule{}, err
	}
	newRule.AdvancedAuth = advancedAuth
	if newRule.AccessMode == "" {
		newRule.AccessMode = "login_first"
	}
	newRule.Title = strings.TrimSpace(newRule.Title)
	newRule.Favicon = strings.TrimSpace(newRule.Favicon)
	availability, err := normalizeHostRuleAvailability(newRule.Availability)
	if err != nil {
		return models.HostRule{}, err
	}
	newRule.Availability = availability
	basicAuth, err := normalizeBasicAuthConfig(newRule.BasicAuth)
	if err != nil {
		return models.HostRule{}, err
	}
	newRule.BasicAuth = basicAuth
	locations, err := h.normalizeHostLocations(newRule.Locations)
	if err != nil {
		return models.HostRule{}, err
	}
	newRule.Locations = locations

	return newRule, nil
}

func normalizeBasicAuthConfig(cfg models.BasicAuthConfig) (models.BasicAuthConfig, error) {
	if !cfg.Enabled {
		return models.BasicAuthConfig{}, nil
	}

	username := strings.TrimSpace(cfg.Username)
	if username == "" || cfg.Password == "" {
		return models.BasicAuthConfig{}, fmt.Errorf("basic auth injection requires username and password")
	}
	if strings.Contains(username, ":") {
		return models.BasicAuthConfig{}, fmt.Errorf("basic auth username cannot contain ':'")
	}

	return models.BasicAuthConfig{
		Enabled:  true,
		Username: username,
		Password: cfg.Password,
	}, nil
}

func applyBasicAuthInjection(out *http.Request, cfg models.BasicAuthConfig) {
	if out == nil || !cfg.Enabled {
		return
	}

	username := strings.TrimSpace(cfg.Username)
	if username == "" || cfg.Password == "" || strings.Contains(username, ":") {
		return
	}

	out.SetBasicAuth(username, cfg.Password)
}

func (h *Handler) AddHostRule(newRule models.HostRule) error {
	protocolModeMissing := strings.TrimSpace(newRule.ProtocolMode) == ""
	visibilityMissing := strings.TrimSpace(newRule.Visibility.Mode) == "" && len(newRule.Visibility.CIDRs) == 0
	newRule, err := h.normalizeHostRule(newRule)
	if err != nil {
		return err
	}

	h.mu.Lock()
	updated := false
	nextRules := make([]models.HostRule, 0, len(h.HostRules)+1)
	for _, rule := range h.HostRules {
		if normalizeRequestHost(rule.Host) == newRule.Host && !updated {
			if protocolModeMissing {
				newRule.ProtocolMode = models.NormalizeHostProtocolMode(rule.ProtocolMode)
			}
			if visibilityMissing {
				newRule.Visibility = rule.Visibility
				newRule.Visibility.CIDRs = append([]string(nil), rule.Visibility.CIDRs...)
			}
			nextRules = append(nextRules, newRule)
			updated = true
			continue
		}
		nextRules = append(nextRules, rule)
	}
	if !updated {
		nextRules = append(nextRules, newRule)
	}
	if newRule.IsDefault {
		for i := range nextRules {
			nextRules[i].IsDefault = normalizeRequestHost(nextRules[i].Host) == newRule.Host
		}
	} else {
		keepFirstDefaultHostRule(nextRules)
	}
	changedProtocolHosts := changedHostProtocolModes(h.HostRules, nextRules)
	if err := h.persistHostRulesLocked(nextRules); err != nil {
		h.mu.Unlock()
		return err
	}
	h.HostRules = nextRules
	h.publishRequestSnapshotLocked()
	hook := h.getHostProtocolModeChangeHook()
	hostRuleCount := len(nextRules)
	h.mu.Unlock()
	if hook != nil && len(changedProtocolHosts) > 0 {
		hook(changedProtocolHosts)
	}
	if event := debugProxyEvent("host_rule_upserted", ""); event != nil {
		event.Str("host", logger.SanitizeLogString(newRule.Host)).
			Str("target", logger.SanitizeURL(newRule.Target)).
			Bool("updated", updated).
			Bool("use_auth", newRule.UseAuth).
			Int("location_count", len(newRule.Locations)).
			Bool("basic_auth_enabled", newRule.BasicAuth.Enabled).
			Int("host_rule_count", hostRuleCount).
			Send()
	}
	return nil
}

func (h *Handler) SetHostRules(rules []models.HostRule) error {
	normalizedRules := make([]models.HostRule, 0, len(rules))
	protocolModeMissing := make([]bool, 0, len(rules))
	visibilityMissing := make([]bool, 0, len(rules))
	indexByHost := make(map[string]int, len(rules))

	for _, rule := range rules {
		modeMissing := strings.TrimSpace(rule.ProtocolMode) == ""
		ruleVisibilityMissing := strings.TrimSpace(rule.Visibility.Mode) == "" && len(rule.Visibility.CIDRs) == 0
		normalizedRule, err := h.normalizeHostRule(rule)
		if err != nil {
			return err
		}

		if idx, exists := indexByHost[normalizedRule.Host]; exists {
			normalizedRules[idx] = normalizedRule
			protocolModeMissing[idx] = modeMissing
			visibilityMissing[idx] = ruleVisibilityMissing
			continue
		}

		indexByHost[normalizedRule.Host] = len(normalizedRules)
		normalizedRules = append(normalizedRules, normalizedRule)
		protocolModeMissing = append(protocolModeMissing, modeMissing)
		visibilityMissing = append(visibilityMissing, ruleVisibilityMissing)
	}
	keepFirstDefaultHostRule(normalizedRules)

	h.mu.Lock()
	existingModes := make(map[string]string, len(h.HostRules))
	existingVisibilities := make(map[string]models.HostRuleVisibility, len(h.HostRules))
	existingAdvancedAuth := make(map[string]models.AdvancedAuthConfig, len(h.HostRules))
	for _, existingRule := range h.HostRules {
		host := normalizeRequestHost(existingRule.Host)
		if host == "" {
			continue
		}
		if _, exists := existingModes[host]; exists {
			continue
		}
		existingModes[host] = models.NormalizeHostProtocolMode(existingRule.ProtocolMode)
		visibility := existingRule.Visibility
		visibility.CIDRs = append([]string(nil), existingRule.Visibility.CIDRs...)
		existingVisibilities[host] = visibility
		existingAdvancedAuth[host] = copyAdvancedAuthConfig(existingRule.AdvancedAuth)
	}
	for i := range normalizedRules {
		if protocolModeMissing[i] {
			if existingMode, exists := existingModes[normalizedRules[i].Host]; exists {
				normalizedRules[i].ProtocolMode = existingMode
			}
		}
		if visibilityMissing[i] {
			if existingVisibility, exists := existingVisibilities[normalizedRules[i].Host]; exists {
				normalizedRules[i].Visibility = existingVisibility
			}
		}
		// Host mapping editors predating advanced authentication omit this
		// field entirely. Preserve an existing policy in that case so an
		// unrelated host edit cannot silently disable a security boundary.
		if isEmptyAdvancedAuthConfig(normalizedRules[i].AdvancedAuth) {
			if existingPolicy, exists := existingAdvancedAuth[normalizedRules[i].Host]; exists && !isEmptyAdvancedAuthConfig(existingPolicy) {
				normalizedRules[i].AdvancedAuth = existingPolicy
			}
		}
	}
	changedProtocolHosts := changedHostProtocolModes(h.HostRules, normalizedRules)
	if err := h.persistHostRulesLocked(normalizedRules); err != nil {
		h.mu.Unlock()
		return err
	}
	h.HostRules = normalizedRules
	h.publishRequestSnapshotLocked()
	hook := h.getHostProtocolModeChangeHook()
	h.mu.Unlock()
	if hook != nil && len(changedProtocolHosts) > 0 {
		hook(changedProtocolHosts)
	}
	if event := debugProxyEvent("host_rules_set", ""); event != nil {
		event.Int("host_rule_count", len(normalizedRules)).
			Interface("host_rules", debugHostRuleSummaries(normalizedRules)).
			Send()
	}
	return nil
}

func (h *Handler) FlushHostRules() error {
	h.mu.Lock()
	changedProtocolHosts := changedHostProtocolModes(h.HostRules, nil)
	nextRules := make([]models.HostRule, 0)
	if err := h.persistHostRulesLocked(nextRules); err != nil {
		h.mu.Unlock()
		return err
	}
	h.HostRules = nextRules
	h.publishRequestSnapshotLocked()
	hook := h.getHostProtocolModeChangeHook()
	h.mu.Unlock()
	if hook != nil && len(changedProtocolHosts) > 0 {
		hook(changedProtocolHosts)
	}
	if event := debugProxyEvent("host_rules_flushed", ""); event != nil {
		event.Send()
	}
	return nil
}

func (h *Handler) GetHostRules() []models.HostRule {
	h.mu.RLock()
	defer h.mu.RUnlock()

	return copyHostRules(h.HostRules)
}

func (h *Handler) ValidateStreamRules(rules []models.StreamRule) ([]models.StreamRule, error) {
	normalized := make([]models.StreamRule, 0, len(rules))
	seenRules := make(map[string]struct{}, len(rules))

	for _, rule := range rules {
		nextRule, err := h.normalizeStreamRule(rule)
		if err != nil {
			return nil, err
		}
		key := streamRuleMapKey(nextRule)
		if _, exists := seenRules[key]; exists {
			return nil, fmt.Errorf("duplicate stream rule for %s", key)
		}
		seenRules[key] = struct{}{}
		normalized = append(normalized, nextRule)
	}

	return normalized, nil
}

func (h *Handler) SetStreamRules(rules []models.StreamRule) error {
	normalized, err := h.ValidateStreamRules(rules)
	if err != nil {
		return err
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	h.StreamRules = normalized
	if err := h.saveConfigLocked(); err != nil {
		return err
	}
	if event := debugProxyEvent("stream_rules_set", ""); event != nil {
		event.Int("stream_rule_count", len(normalized)).
			Interface("stream_rules", debugStreamRuleSummaries(normalized)).
			Send()
	}
	return nil
}

func (h *Handler) FlushStreamRules() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.StreamRules = make([]models.StreamRule, 0)
	if err := h.saveConfigLocked(); err != nil {
		return err
	}
	if event := debugProxyEvent("stream_rules_flushed", ""); event != nil {
		event.Send()
	}
	return nil
}

func (h *Handler) GetStreamRules() []models.StreamRule {
	h.mu.RLock()
	defer h.mu.RUnlock()

	rules := make([]models.StreamRule, len(h.StreamRules))
	copy(rules, h.StreamRules)
	return rules
}

func (h *Handler) GetDefaultRoute() string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.DefaultRoute
}

func (h *Handler) SetDefaultRoute(route string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if route == "" {
		h.DefaultRoute = "/__select__"
	} else {
		h.DefaultRoute = route
	}
	h.publishRequestSnapshotLocked()
	if err := h.saveConfigLocked(); err != nil {
		return err
	}
	if event := debugProxyEvent("default_route_set", ""); event != nil {
		event.Str("route", logger.SanitizeLogString(h.DefaultRoute)).Send()
	}
	return nil
}

func (h *Handler) GetAuthConfig() models.AuthConfig {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.AuthConfig
}

func (h *Handler) GetLoggingConfig() gatewaylog.ConfigInfo {
	if h.gatewayLogManager == nil {
		return gatewaylog.ConfigInfo{
			Enabled: false,
			MaxDays: gatewaylog.DefaultMaxDays,
		}
	}
	return h.gatewayLogManager.GetConfigInfo()
}

func (h *Handler) SetLoggingConfig(cfg models.LoggingConfig) (gatewaylog.ConfigInfo, error) {
	normalized := gatewaylog.NormalizeConfig(cfg)

	h.mu.Lock()
	h.LoggingConfig = normalized
	saveErr := h.saveConfigLocked()
	h.mu.Unlock()
	if event := debugProxyEvent("gateway_logging_config_set", ""); event != nil {
		event.Bool("enabled", normalized.Enabled).
			Int("max_days", normalized.MaxDays).
			Send()
	}

	if h.gatewayLogManager == nil {
		return gatewaylog.ConfigInfo{
			Enabled: normalized.Enabled,
			MaxDays: normalized.MaxDays,
		}, saveErr
	}
	return h.gatewayLogManager.UpdateConfig(normalized), saveErr
}

func (h *Handler) GetLoggingDirectory() gatewaylog.DirectoryInfo {
	if h.gatewayLogManager == nil {
		return gatewaylog.DirectoryInfo{}
	}
	return gatewaylog.DirectoryInfo{LogsDir: h.gatewayLogManager.LogsDir()}
}

func (h *Handler) GetLogDates() (gatewaylog.DatesResult, error) {
	if h.gatewayLogManager == nil {
		return gatewaylog.DatesResult{}, nil
	}
	return h.gatewayLogManager.GetDates()
}

func (h *Handler) QueryLogEntries(date string, page int, limit int, search string, status string, loggedIn string, credential string, cursor string, pagination string) (gatewaylog.QueryResult, error) {
	if h.gatewayLogManager == nil {
		return gatewaylog.QueryResult{}, nil
	}
	return h.gatewayLogManager.Query(date, page, limit, search, status, loggedIn, credential, cursor, pagination)
}

func (h *Handler) DeleteLogDate(date string) (gatewaylog.DeleteResult, error) {
	if h.gatewayLogManager == nil {
		return gatewaylog.DeleteResult{}, nil
	}
	return h.gatewayLogManager.DeleteDate(date)
}

func (h *Handler) ClearGatewayLogs() error {
	if h.gatewayLogManager == nil {
		return nil
	}
	dates, err := h.gatewayLogManager.GetDates()
	if err != nil {
		return err
	}
	for _, date := range dates.Dates {
		if _, err := h.gatewayLogManager.DeleteDate(date); err != nil {
			return err
		}
	}
	return nil
}

func (h *Handler) GetWAFConfig() models.WAFConfig {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.WAFConfig
}

func (h *Handler) GetWAFStatus() proxywaf.Status {
	if h.wafRuntime == nil {
		return proxywaf.Status{}
	}
	return h.wafRuntime.Status()
}

func (h *Handler) SetWAFConfig(cfg models.WAFConfig) (proxywaf.Status, error) {
	if h.wafRuntime == nil {
		return proxywaf.Status{}, fmt.Errorf("WAF runtime is not initialized")
	}
	normalized, err := h.wafRuntime.SetConfig(cfg)
	if err != nil {
		if event := debugProxyEvent("waf_config_set_failed", ""); event != nil {
			event.Bool("enabled", cfg.Enabled).
				Str("mode", logger.SanitizeLogString(cfg.Mode)).
				Str("error", logger.SanitizeLogString(err.Error())).
				Send()
		}
		return h.wafRuntime.Status(), err
	}
	h.mu.Lock()
	h.WAFConfig = normalized
	saveErr := h.saveConfigLocked()
	h.mu.Unlock()
	if saveErr != nil {
		return h.wafRuntime.Status(), saveErr
	}
	if event := debugProxyEvent("waf_config_set", ""); event != nil {
		event.Bool("enabled", normalized.Enabled).
			Str("mode", logger.SanitizeLogString(normalized.Mode)).
			Str("rules_dir", logger.SanitizeLogString(normalized.RulesDir)).
			Int("disabled_host_count", len(normalized.DisabledHosts)).
			Int("disabled_path_prefix_count", len(normalized.DisabledPathPrefixes)).
			Send()
	}
	return h.wafRuntime.Status(), nil
}

func (h *Handler) ValidateWAFBundle(cfg models.WAFConfig, bundleID string, bundlePath string) (proxywaf.ValidationResult, error) {
	if h.wafRuntime == nil {
		return proxywaf.ValidationResult{}, fmt.Errorf("WAF runtime is not initialized")
	}
	result, err := h.wafRuntime.Validate(cfg, bundleID, bundlePath)
	if event := debugProxyEvent("waf_bundle_validate", ""); event != nil {
		event.Bool("ok", result.OK).
			Str("bundle_id", logger.SanitizeLogString(result.BundleID)).
			Str("bundle_path", logger.SanitizeLogString(result.BundlePath)).
			Str("bundle_hash", logger.SanitizeLogString(result.BundleHash)).
			Str("error", logger.SanitizeLogString(result.Error)).
			Send()
	}
	return result, err
}

func (h *Handler) ReloadWAFBundle(cfg models.WAFConfig, bundleID string, bundlePath string) (proxywaf.Status, error) {
	if h.wafRuntime == nil {
		return proxywaf.Status{}, fmt.Errorf("WAF runtime is not initialized")
	}
	status, err := h.wafRuntime.Reload(cfg, bundleID, bundlePath)
	if err != nil {
		if event := debugProxyEvent("waf_bundle_reload_failed", ""); event != nil {
			event.Str("bundle_id", logger.SanitizeLogString(bundleID)).
				Str("bundle_path", logger.SanitizeLogString(bundlePath)).
				Str("error", logger.SanitizeLogString(err.Error())).
				Send()
		}
		return status, err
	}
	normalized := h.wafRuntime.Config()
	h.mu.Lock()
	h.WAFConfig = normalized
	saveErr := h.saveConfigLocked()
	h.mu.Unlock()
	if saveErr != nil {
		return status, saveErr
	}
	if event := debugProxyEvent("waf_bundle_reloaded", ""); event != nil {
		event.Bool("enabled", status.Enabled).
			Bool("loaded", status.Loaded).
			Str("mode", logger.SanitizeLogString(status.Mode)).
			Str("bundle_id", logger.SanitizeLogString(status.BundleID)).
			Str("bundle_hash", logger.SanitizeLogString(status.BundleHash)).
			Send()
	}
	return status, nil
}

func (h *Handler) DrainWAFEvents(limit int) proxywaf.DrainResult {
	if h.wafRuntime == nil {
		return proxywaf.DrainResult{Events: []proxywaf.Event{}}
	}
	return h.wafRuntime.Drain(limit)
}

func (h *Handler) SetAuthConfig(config models.AuthConfig) error {
	if config.AuthPort <= 0 {
		config.AuthPort = 7997
	}
	if config.AuthURL == "" {
		config.AuthURL = "/api/auth/verify"
	}
	if config.LoginURL == "" {
		config.LoginURL = "/login"
	}
	if config.LogoutURL == "" {
		config.LogoutURL = "/api/auth/logout"
	}
	if config.PreflightURL == "" {
		config.PreflightURL = "/api/auth/preflight"
	}
	if config.AuthCacheTTL < 0 {
		config.AuthCacheTTL = 0
	}
	if config.AuthCacheFailTTL < 0 {
		config.AuthCacheFailTTL = 0
	}
	if config.PublicHTTPPort < 0 {
		config.PublicHTTPPort = 0
	}
	if config.PublicHTTPSPort < 0 {
		config.PublicHTTPSPort = 0
	}
	config.PublicAuthBaseURL = strings.TrimSpace(strings.TrimRight(config.PublicAuthBaseURL, "/"))
	config.AuthHost = normalizeRequestHost(config.AuthHost)
	config.NormalizeEdgeClientIPSelection()

	h.mu.Lock()
	defer h.mu.Unlock()
	h.AuthConfig = config
	h.publishRequestSnapshotLocked()
	if err := h.saveConfigLocked(); err != nil {
		return err
	}
	h.clearAuthCache()
	if event := debugProxyEvent("auth_config_set", ""); event != nil {
		event.Interface("auth_config", debugAuthConfigSummary(config)).
			Send()
	}
	return nil
}

func (h *Handler) GetReverseProxyThrottle() models.ReverseProxyThrottleConfig {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.ReverseProxyThrottle
}

func (h *Handler) GetGatewayVisibility() models.GatewayVisibilityConfig {
	h.mu.RLock()
	defer h.mu.RUnlock()

	cidrs := make([]string, len(h.GatewayVisibility.CIDRs))
	copy(cidrs, h.GatewayVisibility.CIDRs)

	return models.GatewayVisibilityConfig{
		Enabled:   h.GatewayVisibility.Enabled,
		CIDRs:     cidrs,
		UpdatedAt: h.GatewayVisibility.UpdatedAt,
	}
}

func (h *Handler) ListGeneralBlacklist(page int, limit int, search string) models.GeneralBlacklistList {
	h.mu.RLock()
	runtime := h.generalBlacklist
	h.mu.RUnlock()

	if runtime == nil {
		return models.GeneralBlacklistList{Items: []models.GeneralBlacklistRecord{}}
	}
	return runtime.list(page, limit, search)
}

func (h *Handler) CheckGeneralBlacklist(ips []string) (models.GeneralBlacklistStatus, error) {
	h.mu.RLock()
	runtime := h.generalBlacklist
	h.mu.RUnlock()

	if runtime == nil {
		runtime = newGeneralBlacklistRuntime(models.GeneralBlacklistConfig{})
	}
	return runtime.status(ips)
}

func (h *Handler) GetGeneralBlacklist() models.GeneralBlacklistConfig {
	h.mu.RLock()
	runtime := h.generalBlacklist
	h.mu.RUnlock()

	if runtime == nil {
		return models.GeneralBlacklistConfig{Items: []models.GeneralBlacklistRecord{}}
	}
	return runtime.getConfig()
}

func (h *Handler) AddGeneralBlacklist(ips []string, source string, comment string) (models.GeneralBlacklistMutationResult, error) {
	h.mu.Lock()
	runtime := h.generalBlacklist
	if runtime == nil {
		runtime = newGeneralBlacklistRuntime(models.GeneralBlacklistConfig{})
		h.generalBlacklist = runtime
	}
	h.mu.Unlock()

	normalized, result, err := runtime.addMany(ips, source, comment, time.Now())
	if err != nil {
		return models.GeneralBlacklistMutationResult{}, err
	}

	h.mu.Lock()
	h.GeneralBlacklist = normalized
	if err := h.saveConfigLocked(); err != nil {
		h.mu.Unlock()
		return models.GeneralBlacklistMutationResult{}, err
	}
	h.mu.Unlock()

	if event := debugProxyEvent("general_blacklist_added", ""); event != nil {
		event.Int("added", result.Added).
			Int("updated", result.Updated).
			Int("total", result.Total).
			Str("source", logger.SanitizeLogString(normalizeGeneralBlacklistSource(source))).
			Send()
	}
	return result, nil
}

func (h *Handler) RemoveGeneralBlacklist(ips []string) (models.GeneralBlacklistMutationResult, error) {
	h.mu.Lock()
	runtime := h.generalBlacklist
	if runtime == nil {
		runtime = newGeneralBlacklistRuntime(models.GeneralBlacklistConfig{})
		h.generalBlacklist = runtime
	}
	h.mu.Unlock()

	normalized, result, err := runtime.removeMany(ips)
	if err != nil {
		return models.GeneralBlacklistMutationResult{}, err
	}

	h.mu.Lock()
	h.GeneralBlacklist = normalized
	if err := h.saveConfigLocked(); err != nil {
		h.mu.Unlock()
		return models.GeneralBlacklistMutationResult{}, err
	}
	h.mu.Unlock()

	if event := debugProxyEvent("general_blacklist_removed", ""); event != nil {
		event.Int("removed", result.Removed).
			Int("total", result.Total).
			Send()
	}
	return result, nil
}

func (h *Handler) GetForwardedHeadersConfig() models.ForwardedHeadersConfig {
	h.mu.RLock()
	defer h.mu.RUnlock()

	omitTargets := make([]string, len(h.ForwardedHeaders.OmitTargets))
	copy(omitTargets, h.ForwardedHeaders.OmitTargets)

	return models.ForwardedHeadersConfig{
		Enabled:     h.ForwardedHeaders.Enabled,
		OmitTargets: omitTargets,
		UpdatedAt:   h.ForwardedHeaders.UpdatedAt,
	}
}

func (h *Handler) GetPreserveHostConfig() models.PreserveHostConfig {
	h.mu.RLock()
	defer h.mu.RUnlock()

	omitTargets := make([]string, len(h.PreserveHost.OmitTargets))
	copy(omitTargets, h.PreserveHost.OmitTargets)

	return models.PreserveHostConfig{
		Enabled:     h.PreserveHost.Enabled,
		OmitTargets: omitTargets,
		UpdatedAt:   h.PreserveHost.UpdatedAt,
	}
}

func (h *Handler) GetCrawlerBlockerConfig() models.CrawlerBlockerConfig {
	h.mu.RLock()
	defer h.mu.RUnlock()

	return h.CrawlerBlocker
}

func (h *Handler) GetFnosPortIconHijackConfig() models.FnosPortIconHijackConfig {
	h.mu.RLock()
	defer h.mu.RUnlock()

	return h.FnosPortIconHijack
}

func (h *Handler) GetReverseProxyThrottleExemptIPs() models.ReverseProxyThrottleExemptIPsRuntime {
	h.mu.RLock()
	runtime := h.reverseProxyThrottleExempt
	h.mu.RUnlock()

	if runtime == nil {
		return models.ReverseProxyThrottleExemptIPsRuntime{
			Enabled:   false,
			IPs:       []string{},
			CIDRs:     []string{},
			UpdatedAt: "",
		}
	}

	return runtime.getConfig()
}

func (h *Handler) IsClientIPVisible(clientIP string) bool {
	h.mu.RLock()
	visibility := h.gatewayVisibility
	h.mu.RUnlock()

	if visibility == nil {
		return true
	}
	return visibility.contains(clientIP)
}

func (h *Handler) IsClientIPVisibleForHost(clientIP string, rule *models.HostRule, snapshot requestSnapshot) bool {
	h.mu.RLock()
	visibility := h.gatewayVisibility
	h.mu.RUnlock()

	if visibility == nil {
		return true
	}
	if rule == nil || normalizeRequestHost(rule.Host) == normalizeRequestHost(snapshot.authConfig.AuthHost) {
		return visibility.contains(clientIP)
	}
	if rule.Visibility.Mode == models.HostVisibilityModeDisabled {
		return true
	}
	if rule.Visibility.Mode != models.HostVisibilityModeCustom {
		return visibility.contains(clientIP)
	}
	host := normalizeRequestHost(rule.Host)
	prefixes, ok := snapshot.hostVisibility[host]
	if !ok {
		return visibility.contains(clientIP)
	}
	return visibility.containsPrefixes(clientIP, prefixes, true)
}

func (h *Handler) GetGeneralBlacklistRecordForClientIP(clientIP string) (models.GeneralBlacklistRecord, bool) {
	h.mu.RLock()
	runtime := h.generalBlacklist
	h.mu.RUnlock()

	if runtime == nil {
		return models.GeneralBlacklistRecord{}, false
	}
	return runtime.contains(clientIP)
}

func (h *Handler) SetReverseProxyThrottle(cfg models.ReverseProxyThrottleConfig) error {
	normalized := normalizeReverseProxyThrottleConfig(cfg)

	h.mu.Lock()
	h.ReverseProxyThrottle = normalized
	saveErr := h.saveConfigLocked()
	throttle := h.reverseProxyThrottle
	h.mu.Unlock()

	if throttle == nil {
		h.mu.Lock()
		if h.reverseProxyThrottle == nil {
			h.reverseProxyThrottle = newReverseProxyThrottle(normalized)
			throttle = h.reverseProxyThrottle
		} else {
			throttle = h.reverseProxyThrottle
		}
		h.mu.Unlock()
	}
	if throttle != nil {
		throttle.updateConfig(normalized)
	}
	if event := debugProxyEvent("reverse_proxy_throttle_set", ""); event != nil {
		event.Bool("enabled", normalized.Enabled).
			Int("requests_per_second", normalized.RequestsPerSecond).
			Int("burst", normalized.Burst).
			Int("block_seconds", normalized.BlockSeconds).
			Send()
	}
	return saveErr
}

func (h *Handler) SetGatewayVisibility(cfg models.GatewayVisibilityConfig) error {
	normalized, prefixes, err := normalizeGatewayVisibilityConfig(cfg)
	if err != nil {
		return err
	}

	h.mu.Lock()
	h.GatewayVisibility = normalized
	saveErr := h.saveConfigLocked()
	visibility := h.gatewayVisibility
	if visibility == nil {
		visibility = &gatewayVisibility{}
		h.gatewayVisibility = visibility
	}
	h.mu.Unlock()
	if saveErr != nil {
		return saveErr
	}

	visibility.mu.Lock()
	visibility.config = normalized
	visibility.prefixes = prefixes
	visibility.mu.Unlock()

	if event := debugProxyEvent("gateway_visibility_set", ""); event != nil {
		event.Bool("enabled", normalized.Enabled).
			Int("cidr_count", len(normalized.CIDRs)).
			Str("updated_at", logger.SanitizeLogString(normalized.UpdatedAt)).
			Send()
	}
	return nil
}

func (h *Handler) SetForwardedHeadersConfig(cfg models.ForwardedHeadersConfig) error {
	normalized, _ := normalizeForwardedHeadersConfig(cfg)

	h.mu.Lock()
	h.ForwardedHeaders = normalized
	saveErr := h.saveConfigLocked()
	forwardedHeaders := h.forwardedHeaders
	if forwardedHeaders == nil {
		forwardedHeaders = newForwardedHeadersConfig(normalized)
		h.forwardedHeaders = forwardedHeaders
	}
	h.mu.Unlock()
	if saveErr != nil {
		return saveErr
	}

	forwardedHeaders.updateConfig(normalized)
	if event := debugProxyEvent("forwarded_headers_config_set", ""); event != nil {
		event.Bool("enabled", normalized.Enabled).
			Int("omit_target_count", len(normalized.OmitTargets)).
			Str("updated_at", logger.SanitizeLogString(normalized.UpdatedAt)).
			Send()
	}
	return nil
}

func (h *Handler) SetPreserveHostConfig(cfg models.PreserveHostConfig) error {
	normalized, _ := normalizePreserveHostConfig(cfg)

	h.mu.Lock()
	h.PreserveHost = normalized
	saveErr := h.saveConfigLocked()
	preserveHost := h.preserveHost
	if preserveHost == nil {
		preserveHost = newPreserveHostConfig(normalized)
		h.preserveHost = preserveHost
	}
	h.mu.Unlock()
	if saveErr != nil {
		return saveErr
	}

	preserveHost.updateConfig(normalized)
	if event := debugProxyEvent("preserve_host_config_set", ""); event != nil {
		event.Bool("enabled", normalized.Enabled).
			Int("omit_target_count", len(normalized.OmitTargets)).
			Str("updated_at", logger.SanitizeLogString(normalized.UpdatedAt)).
			Send()
	}
	return nil
}

func (h *Handler) SetCrawlerBlockerConfig(cfg models.CrawlerBlockerConfig) (models.CrawlerBlockerConfig, error) {
	normalized := normalizeCrawlerBlockerConfig(cfg)

	h.mu.Lock()
	h.CrawlerBlocker = normalized
	saveErr := h.saveConfigLocked()
	h.mu.Unlock()
	if saveErr != nil {
		return normalized, saveErr
	}

	if event := debugProxyEvent("crawler_blocker_config_set", ""); event != nil {
		event.Bool("enabled", normalized.Enabled).
			Str("updated_at", logger.SanitizeLogString(normalized.UpdatedAt)).
			Send()
	}
	return normalized, nil
}

func (h *Handler) GetGatewayPortalConfig() models.GatewayPortalConfig {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return models.NormalizeGatewayPortalConfig(h.GatewayPortal)
}

func (h *Handler) SetGatewayPortalConfig(cfg models.GatewayPortalConfig) (models.GatewayPortalConfig, error) {
	normalized := models.NormalizeGatewayPortalConfig(cfg)

	h.mu.Lock()
	h.GatewayPortal = normalized
	h.publishRequestSnapshotLocked()
	saveErr := h.saveConfigLocked()
	h.mu.Unlock()
	if saveErr != nil {
		return normalized, saveErr
	}
	if event := debugProxyEvent("gateway_portal_config_set", ""); event != nil {
		event.Bool("enabled", normalized.Enabled).
			Str("display_style", logger.SanitizeLogString(normalized.DisplayStyle)).
			Str("icon_drag_mode", logger.SanitizeLogString(normalized.IconDragMode)).
			Bool("show_app_icon", normalized.ShowAppIcon).
			Send()
	}

	return normalized, nil
}

func (h *Handler) GetGatewayUnmatchedRouteConfig() models.GatewayUnmatchedRouteConfig {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return models.NormalizeGatewayUnmatchedRouteConfig(h.GatewayUnmatchedRoute)
}

func (h *Handler) SetGatewayUnmatchedRouteConfig(cfg models.GatewayUnmatchedRouteConfig) (models.GatewayUnmatchedRouteConfig, error) {
	normalized := models.NormalizeGatewayUnmatchedRouteConfig(cfg)

	h.mu.Lock()
	previous := h.GatewayUnmatchedRoute
	h.GatewayUnmatchedRoute = normalized
	h.publishRequestSnapshotLocked()
	saveErr := h.saveConfigLocked()
	if saveErr != nil {
		h.GatewayUnmatchedRoute = previous
		h.publishRequestSnapshotLocked()
	}
	h.mu.Unlock()
	if saveErr != nil {
		return normalized, saveErr
	}
	if event := debugProxyEvent("gateway_unmatched_route_config_set", ""); event != nil {
		event.Str("behavior", normalized.Behavior).Send()
	}

	return normalized, nil
}

func (h *Handler) SetFnosPortIconHijackConfig(cfg models.FnosPortIconHijackConfig) (models.FnosPortIconHijackConfig, error) {
	normalized := models.FnosPortIconHijackConfig{
		Enabled:   cfg.Enabled,
		UpdatedAt: strings.TrimSpace(cfg.UpdatedAt),
	}

	h.mu.Lock()
	h.FnosPortIconHijack = normalized
	saveErr := h.saveConfigLocked()
	h.mu.Unlock()
	if saveErr != nil {
		return normalized, saveErr
	}
	if event := debugProxyEvent("fnos_port_icon_hijack_config_set", ""); event != nil {
		event.Bool("enabled", normalized.Enabled).
			Str("updated_at", logger.SanitizeLogString(normalized.UpdatedAt)).
			Send()
	}

	return normalized, nil
}

func (h *Handler) SetReverseProxyThrottleExemptIPs(cfg models.ReverseProxyThrottleExemptIPsRuntime) {
	h.mu.Lock()
	runtime := h.reverseProxyThrottleExempt
	if runtime == nil {
		runtime = newReverseProxyThrottleExemptIPsRuntime(
			models.ReverseProxyThrottleExemptIPsRuntime{},
		)
		h.reverseProxyThrottleExempt = runtime
	}
	h.mu.Unlock()

	runtime.updateConfig(cfg)
	normalized := runtime.getConfig()
	if event := debugProxyEvent("reverse_proxy_throttle_exempt_ips_set", ""); event != nil {
		event.Bool("enabled", normalized.Enabled).
			Int("ip_count", len(normalized.IPs)).
			Int("cidr_count", len(normalized.CIDRs)).
			Str("updated_at", logger.SanitizeLogString(normalized.UpdatedAt)).
			Send()
	}
}

func (h *Handler) GetCommonLocationExemptions() models.CommonLocationExemptionsRuntime {
	h.mu.RLock()
	runtime := h.commonLocationExemptions
	h.mu.RUnlock()

	if runtime == nil {
		return models.CommonLocationExemptionsRuntime{
			Enabled:    false,
			WAFEnabled: false,
			CIDRs:      []string{},
			UpdatedAt:  "",
		}
	}

	return runtime.getConfig()
}

func (h *Handler) SetCommonLocationExemptions(cfg models.CommonLocationExemptionsRuntime) {
	h.mu.Lock()
	runtime := h.commonLocationExemptions
	if runtime == nil {
		runtime = newCommonLocationExemptionsRuntime(
			models.CommonLocationExemptionsRuntime{},
		)
		h.commonLocationExemptions = runtime
	}
	h.mu.Unlock()

	runtime.updateConfig(cfg)
	normalized := runtime.getConfig()
	if event := debugProxyEvent("common_location_exemptions_set", ""); event != nil {
		event.Bool("enabled", normalized.Enabled).
			Bool("waf_enabled", normalized.WAFEnabled).
			Int("cidr_count", len(normalized.CIDRs)).
			Str("updated_at", logger.SanitizeLogString(normalized.UpdatedAt)).
			Send()
	}
}

type TrafficStats struct {
	TotalIn     uint64             `json:"total_in"`
	TotalOut    uint64             `json:"total_out"`
	ActiveConns int64              `json:"active_conns"`
	Error5xx    uint64             `json:"error_5xx"`
	ByHost      []HostTrafficStats `json:"by_host,omitempty"`
}

type HostTrafficStats struct {
	Host          string `json:"host"`
	TotalIn       uint64 `json:"total_in"`
	TotalOut      uint64 `json:"total_out"`
	Error5xx      uint64 `json:"error_5xx"`
	ActiveIPCount int    `json:"active_ip_count"`
}

type HostActiveIPStats struct {
	IP          string    `json:"ip"`
	LastSeenAt  time.Time `json:"last_seen_at"`
	ActiveConns int64     `json:"active_conns"`
}

type HostActiveIPsStats struct {
	Host          string              `json:"host"`
	WindowSeconds int                 `json:"window_seconds"`
	Items         []HostActiveIPStats `json:"items"`
}

type hostTrafficCounters struct {
	totalIn                     atomic.Uint64
	totalOut                    atomic.Uint64
	error5xx                    atomic.Uint64
	activeIPs                   sync.Map
	activeIPEntries             atomic.Int64
	activeIPLastCleanupUnixNano atomic.Int64
}

type hostActiveIPRecord struct {
	ip               string
	lastSeenUnixNano atomic.Int64
	activeConns      atomic.Int64
}

func normalizeTrafficHost(host string) string {
	return strings.TrimSuffix(normalizeRequestHost(host), ".")
}

const (
	hostActiveIPWindow          = 2 * time.Minute
	hostActiveIPCleanupInterval = 30 * time.Second
	hostActiveIPMaxItems        = 256
	hostActiveIPHardLimit       = 4096
)

func (c *hostTrafficCounters) deleteActiveIP(key any) {
	if c == nil {
		return
	}
	if _, loaded := c.activeIPs.LoadAndDelete(key); loaded {
		if c.activeIPEntries.Add(-1) < 0 {
			c.activeIPEntries.Store(0)
		}
	}
}

func (c *hostTrafficCounters) cleanupActiveIPs(now time.Time) {
	if c == nil {
		return
	}
	cutoff := now.Add(-hostActiveIPWindow).UnixNano()
	c.activeIPs.Range(func(key, value any) bool {
		record, ok := value.(*hostActiveIPRecord)
		if !ok || record == nil {
			c.deleteActiveIP(key)
			return true
		}
		lastSeen := record.lastSeenUnixNano.Load()
		activeConns := record.activeConns.Load()
		if activeConns <= 0 && lastSeen < cutoff {
			c.deleteActiveIP(key)
		}
		return true
	})
	c.enforceActiveIPLimit()
}

func (c *hostTrafficCounters) cleanupActiveIPsIfNeeded(now time.Time) {
	if c == nil {
		return
	}
	nowUnixNano := now.UnixNano()
	lastCleanup := c.activeIPLastCleanupUnixNano.Load()
	if lastCleanup > 0 && nowUnixNano-lastCleanup < int64(hostActiveIPCleanupInterval) {
		return
	}
	if !c.activeIPLastCleanupUnixNano.CompareAndSwap(lastCleanup, nowUnixNano) {
		return
	}
	c.cleanupActiveIPs(now)
}

func (c *hostTrafficCounters) enforceActiveIPLimit() {
	if c == nil || c.activeIPEntries.Load() <= hostActiveIPHardLimit {
		return
	}
	type activeIPCandidate struct {
		key         any
		lastSeen    int64
		activeConns int64
	}
	candidates := make([]activeIPCandidate, 0)
	c.activeIPs.Range(func(key, value any) bool {
		record, ok := value.(*hostActiveIPRecord)
		if !ok || record == nil {
			candidates = append(candidates, activeIPCandidate{key: key})
			return true
		}
		candidates = append(candidates, activeIPCandidate{
			key:         key,
			lastSeen:    record.lastSeenUnixNano.Load(),
			activeConns: record.activeConns.Load(),
		})
		return true
	})
	sort.Slice(candidates, func(i, j int) bool {
		if (candidates[i].activeConns <= 0) != (candidates[j].activeConns <= 0) {
			return candidates[i].activeConns <= 0
		}
		return candidates[i].lastSeen < candidates[j].lastSeen
	})
	for _, candidate := range candidates {
		if c.activeIPEntries.Load() <= hostActiveIPHardLimit {
			return
		}
		c.deleteActiveIP(candidate.key)
	}
}

func (c *hostTrafficCounters) markActiveIP(clientIP string, now time.Time) *hostActiveIPRecord {
	if c == nil {
		return nil
	}
	ip := normalizeIPAddress(clientIP)
	if ip == "" {
		return nil
	}

	c.cleanupActiveIPsIfNeeded(now)
	record, loaded := c.activeIPs.Load(ip)
	activeRecord, ok := record.(*hostActiveIPRecord)
	if !loaded || !ok || activeRecord == nil {
		candidate := &hostActiveIPRecord{ip: ip}
		actual, wasLoaded := c.activeIPs.LoadOrStore(ip, candidate)
		loaded = wasLoaded
		if existing, valid := actual.(*hostActiveIPRecord); valid && existing != nil {
			activeRecord = existing
		} else {
			activeRecord = candidate
		}
	}

	activeRecord.lastSeenUnixNano.Store(now.UnixNano())
	activeRecord.activeConns.Add(1)
	if !loaded {
		if c.activeIPEntries.Add(1) > hostActiveIPHardLimit {
			c.cleanupActiveIPs(now)
		}
	}

	return activeRecord
}

func releaseHostActiveIP(record *hostActiveIPRecord, now time.Time) {
	if record == nil {
		return
	}
	record.lastSeenUnixNano.Store(now.UnixNano())
	if record.activeConns.Add(-1) < 0 {
		record.activeConns.Store(0)
	}
}

func (c *hostTrafficCounters) activeIPCount(now time.Time) int {
	if c == nil {
		return 0
	}
	c.cleanupActiveIPs(now)

	cutoff := now.Add(-hostActiveIPWindow).UnixNano()
	count := 0
	c.activeIPs.Range(func(key, value any) bool {
		record, ok := value.(*hostActiveIPRecord)
		if !ok || record == nil {
			c.deleteActiveIP(key)
			return true
		}
		lastSeen := record.lastSeenUnixNano.Load()
		activeConns := record.activeConns.Load()
		if activeConns <= 0 && lastSeen < cutoff {
			c.deleteActiveIP(key)
			return true
		}
		if lastSeen > 0 {
			count++
		}
		return true
	})
	return count
}

func (c *hostTrafficCounters) activeIPStats(now time.Time) []HostActiveIPStats {
	if c == nil {
		return []HostActiveIPStats{}
	}
	c.cleanupActiveIPs(now)

	cutoff := now.Add(-hostActiveIPWindow).UnixNano()
	items := make([]HostActiveIPStats, 0)
	c.activeIPs.Range(func(key, value any) bool {
		record, ok := value.(*hostActiveIPRecord)
		if !ok || record == nil {
			c.deleteActiveIP(key)
			return true
		}

		lastSeen := record.lastSeenUnixNano.Load()
		activeConns := record.activeConns.Load()
		if activeConns <= 0 && lastSeen < cutoff {
			c.deleteActiveIP(key)
			return true
		}
		if lastSeen <= 0 {
			return true
		}

		items = append(items, HostActiveIPStats{
			IP:          record.ip,
			LastSeenAt:  time.Unix(0, lastSeen).UTC(),
			ActiveConns: activeConns,
		})
		return true
	})

	sort.Slice(items, func(i, j int) bool {
		if items[i].LastSeenAt.Equal(items[j].LastSeenAt) {
			return items[i].IP < items[j].IP
		}
		return items[i].LastSeenAt.After(items[j].LastSeenAt)
	})
	if len(items) > hostActiveIPMaxItems {
		items = items[:hostActiveIPMaxItems]
	}
	return items
}

func (h *Handler) lookupHostTrafficCounters(host string) (*hostTrafficCounters, string) {
	normalizedHost := normalizeTrafficHost(host)
	if normalizedHost == "" {
		return nil, ""
	}
	value, ok := h.trafficByHost.Load(normalizedHost)
	if !ok {
		return nil, normalizedHost
	}
	counters, ok := value.(*hostTrafficCounters)
	if !ok || counters == nil {
		return nil, normalizedHost
	}
	return counters, normalizedHost
}

func (h *Handler) getHostTrafficCounters(host string) *hostTrafficCounters {
	normalizedHost := normalizeTrafficHost(host)
	if normalizedHost == "" {
		return nil
	}
	if value, ok := h.trafficByHost.Load(normalizedHost); ok {
		if counters, ok := value.(*hostTrafficCounters); ok {
			return counters
		}
	}
	counters := &hostTrafficCounters{}
	actual, _ := h.trafficByHost.LoadOrStore(normalizedHost, counters)
	if existing, ok := actual.(*hostTrafficCounters); ok {
		return existing
	}
	return counters
}

func (h *Handler) activeTrafficHosts() map[string]struct{} {
	h.mu.RLock()
	defer h.mu.RUnlock()

	hosts := make(map[string]struct{}, len(h.HostRules))
	for _, rule := range h.HostRules {
		host := normalizeTrafficHost(rule.Host)
		if host == "" {
			continue
		}
		hosts[host] = struct{}{}
	}
	return hosts
}

func (h *Handler) GetTrafficStats(timestamp time.Time) TrafficStats {
	byHost := make([]HostTrafficStats, 0)
	activeHosts := h.activeTrafficHosts()
	h.trafficByHost.Range(func(key, value any) bool {
		host, ok := key.(string)
		if !ok || host == "" {
			return true
		}
		if _, ok := activeHosts[host]; !ok {
			h.trafficByHost.Delete(host)
			return true
		}
		counters, ok := value.(*hostTrafficCounters)
		if !ok || counters == nil {
			return true
		}
		byHost = append(byHost, HostTrafficStats{
			Host:          host,
			TotalIn:       counters.totalIn.Load(),
			TotalOut:      counters.totalOut.Load(),
			Error5xx:      counters.error5xx.Load(),
			ActiveIPCount: counters.activeIPCount(timestamp),
		})
		return true
	})
	sort.Slice(byHost, func(i, j int) bool {
		return byHost[i].Host < byHost[j].Host
	})

	return TrafficStats{
		TotalIn:     h.trafficTotalIn.Load(),
		TotalOut:    h.trafficTotalOut.Load(),
		ActiveConns: h.activeLoggedInCount(timestamp),
		Error5xx:    h.trafficError5xx.Load(),
		ByHost:      byHost,
	}
}

func (h *Handler) GetHostActiveIPs(host string, timestamp time.Time) HostActiveIPsStats {
	normalizedHost := normalizeTrafficHost(host)
	result := HostActiveIPsStats{
		Host:          normalizedHost,
		WindowSeconds: int(hostActiveIPWindow.Seconds()),
		Items:         []HostActiveIPStats{},
	}
	if normalizedHost == "" {
		return result
	}

	activeHosts := h.activeTrafficHosts()
	if _, ok := activeHosts[normalizedHost]; !ok {
		h.trafficByHost.Delete(normalizedHost)
		return result
	}

	counters, _ := h.lookupHostTrafficCounters(normalizedHost)
	if counters == nil {
		return result
	}

	result.Items = counters.activeIPStats(timestamp)
	return result
}

func (h *Handler) AddStreamTraffic(bytesIn, bytesOut uint64, status int) {
	if bytesIn > 0 {
		h.trafficTotalIn.Add(bytesIn)
	}
	if bytesOut > 0 {
		h.trafficTotalOut.Add(bytesOut)
	}
	if status >= 500 {
		h.trafficError5xx.Add(1)
	}
}

func (h *Handler) LogGatewayEntry(entry gatewaylog.Entry) {
	if h.gatewayLogManager != nil {
		h.gatewayLogManager.Log(entry)
	}
}

const loggedInActiveWindow = 2 * time.Minute
const loggedInActiveCleanupInterval = 30 * time.Second
const loggedInActiveMaxEntries = 8192
const proxyPathCookieName = "__proxy_path"
const defaultCookieMaxNum = 3000
const canonicalCookieIdentityStackPairs = 8

type canonicalCookiePair struct {
	name  string
	value string
}

func canonicalCookieIdentity(r *http.Request) string {
	if r == nil {
		return ""
	}

	headers := r.Header.Values("Cookie")
	if len(headers) == 0 || !cookieHeaderValuesWithinDefaultLimit(headers) {
		return ""
	}

	var stackPairs [canonicalCookieIdentityStackPairs]canonicalCookiePair
	pairs := stackPairs[:0]
	for _, header := range headers {
		pairs = appendCanonicalCookieIdentityPairs(pairs, header)
	}
	if len(pairs) == 0 {
		return ""
	}
	if len(pairs) == 1 {
		return pairs[0].name + "=" + pairs[0].value
	}

	sortCanonicalCookiePairs(pairs)

	var b strings.Builder
	b.Grow(canonicalCookieIdentitySize(pairs))
	for i, pair := range pairs {
		if i > 0 {
			b.WriteByte(';')
		}
		b.WriteString(pair.name)
		b.WriteByte('=')
		b.WriteString(pair.value)
	}
	return b.String()
}

func canonicalCookieIdentityKey(r *http.Request) (string, bool) {
	if r == nil {
		return "", false
	}

	headers := r.Header.Values("Cookie")
	if len(headers) == 0 || !cookieHeaderValuesWithinDefaultLimit(headers) {
		return "", false
	}

	var stackPairs [canonicalCookieIdentityStackPairs]canonicalCookiePair
	pairs := stackPairs[:0]
	for _, header := range headers {
		pairs = appendCanonicalCookieIdentityPairs(pairs, header)
	}
	if len(pairs) == 0 {
		return "", false
	}

	var stack [authCacheHashBufferSize]byte
	buf := stack[:0]
	buf = append(buf, identitySourceCookiePrefix...)
	if len(pairs) == 1 {
		buf = appendCanonicalCookiePairBytes(buf, pairs[0])
	} else {
		sortCanonicalCookiePairs(pairs)
		buf = appendCanonicalCookiePairsBytes(buf, pairs)
	}
	return sha256HexBytes(buf), true
}

func appendCanonicalCookiePairsBytes(buf []byte, pairs []canonicalCookiePair) []byte {
	for i, pair := range pairs {
		if i > 0 {
			buf = append(buf, ';')
		}
		buf = appendCanonicalCookiePairBytes(buf, pair)
	}
	return buf
}

func appendCanonicalCookieIdentityPairs(pairs []canonicalCookiePair, header string) []canonicalCookiePair {
	for {
		part, rest, more := strings.Cut(header, ";")
		name, value, ok := parseCanonicalCookiePart(strings.TrimSpace(part))
		if ok && name != proxyPathCookieName && value != "" {
			pairs = append(pairs, canonicalCookiePair{name: name, value: value})
		}
		if !more {
			return pairs
		}
		header = rest
	}
}

func appendCanonicalCookiePairBytes(buf []byte, pair canonicalCookiePair) []byte {
	buf = append(buf, pair.name...)
	buf = append(buf, '=')
	buf = append(buf, pair.value...)
	return buf
}

func sortCanonicalCookiePairs(pairs []canonicalCookiePair) {
	for i := 1; i < len(pairs); i++ {
		pair := pairs[i]
		j := i - 1
		for ; j >= 0 && canonicalCookiePairLess(pair, pairs[j]); j-- {
			pairs[j+1] = pairs[j]
		}
		pairs[j+1] = pair
	}
}

func canonicalCookiePairLess(a, b canonicalCookiePair) bool {
	if a.name == b.name {
		return a.value < b.value
	}
	return a.name < b.name
}

func parseCanonicalCookiePart(part string) (string, string, bool) {
	if part == "" {
		return "", "", false
	}
	name, rawValue, _ := strings.Cut(part, "=")
	name = strings.TrimSpace(name)
	if name == "" || !httpguts.ValidHeaderFieldName(name) {
		return "", "", false
	}
	value, ok := parseCanonicalCookieValue(rawValue)
	if !ok {
		return "", "", false
	}
	return name, value, true
}

func parseCanonicalCookieValue(raw string) (string, bool) {
	if len(raw) > 1 && raw[0] == '"' && raw[len(raw)-1] == '"' {
		raw = raw[1 : len(raw)-1]
	}
	for i := 0; i < len(raw); i++ {
		if !validCanonicalCookieValueByte(raw[i]) {
			return "", false
		}
	}
	return raw, true
}

func validCanonicalCookieValueByte(b byte) bool {
	return 0x20 <= b && b < 0x7f && b != '"' && b != ';' && b != '\\'
}

func cookieHeaderValuesWithinDefaultLimit(headers []string) bool {
	if len(headers) == 0 {
		return true
	}
	totalLen := 0
	for _, header := range headers {
		totalLen += len(header)
	}
	if totalLen+len(headers) <= defaultCookieMaxNum {
		return true
	}

	count := 0
	for _, header := range headers {
		count += strings.Count(header, ";") + 1
		if count > defaultCookieMaxNum {
			return false
		}
	}
	return true
}

func canonicalCookieIdentitySize(pairs []canonicalCookiePair) int {
	if len(pairs) == 0 {
		return 0
	}
	size := len(pairs) - 1
	for _, pair := range pairs {
		size += len(pair.name) + 1 + len(pair.value)
	}
	return size
}

func activeIdentityKey(r *http.Request, clientIP string) string {
	if cookieKey, ok := canonicalCookieIdentityKey(r); ok {
		return cookieKey
	} else if auth := r.Header.Get("Authorization"); auth != "" {
		return activeIdentityKeyFromParts(identitySourceAuthPrefix, auth)
	} else if clientIP != "" {
		return activeIdentityKeyFromParts(identitySourceIPPrefix, clientIP)
	} else {
		return ""
	}
}

func activeIdentityKeyFromSource(src string) string {
	if strings.TrimSpace(src) == "" {
		return ""
	}
	return sha256HexString(src)
}

func activeIdentityKeyFromClientIP(clientIP string) string {
	clientIP = strings.TrimSpace(clientIP)
	if clientIP == "" {
		return ""
	}
	return activeIdentityKeyFromParts(identitySourceIPPrefix, clientIP)
}

func (h *Handler) storeLoggedInActive(key string, now time.Time) {
	if key == "" {
		return
	}
	nowUnixNano := now.UnixNano()
	if _, loaded := h.loggedInActive.LoadOrStore(key, nowUnixNano); loaded {
		h.loggedInActive.Store(key, nowUnixNano)
	} else if h.loggedInActiveCount.Add(1) > loggedInActiveMaxEntries {
		h.cleanupLoggedInActive(now)
	}
	h.cleanupLoggedInActiveIfNeeded(now)
}

func (h *Handler) markLoggedInActive(r *http.Request, clientIP string, now time.Time) {
	h.storeLoggedInActive(activeIdentityKey(r, clientIP), now)
}

func (h *Handler) MarkLoggedInActiveByClientIP(clientIP string, now time.Time) {
	h.storeLoggedInActive(activeIdentityKeyFromClientIP(clientIP), now)
}

func (h *Handler) activeLoggedInCount(now time.Time) int64 {
	h.cleanupLoggedInActive(now)
	return h.loggedInActiveCount.Load()
}

func (h *Handler) cleanupLoggedInActiveIfNeeded(now time.Time) {
	nowUnixNano := now.UnixNano()
	lastCleanup := h.loggedInActiveCleanupNano.Load()
	if lastCleanup > 0 && nowUnixNano-lastCleanup < int64(loggedInActiveCleanupInterval) {
		return
	}
	if !h.loggedInActiveCleanupNano.CompareAndSwap(lastCleanup, nowUnixNano) {
		return
	}
	h.cleanupLoggedInActive(now)
}

func (h *Handler) cleanupLoggedInActive(now time.Time) {
	cutoff := now.Add(-loggedInActiveWindow).UnixNano()
	h.loggedInActive.Range(func(key, value any) bool {
		ts, ok := value.(int64)
		if !ok || ts < cutoff {
			h.deleteLoggedInActive(key)
			return true
		}
		return true
	})
	h.enforceLoggedInActiveLimit()
}

func (h *Handler) deleteLoggedInActive(key any) {
	if _, loaded := h.loggedInActive.LoadAndDelete(key); loaded {
		if h.loggedInActiveCount.Add(-1) < 0 {
			h.loggedInActiveCount.Store(0)
		}
	}
}

func (h *Handler) enforceLoggedInActiveLimit() {
	if h.loggedInActiveCount.Load() <= loggedInActiveMaxEntries {
		return
	}
	type loggedInActiveCandidate struct {
		key any
		ts  int64
	}
	candidates := make([]loggedInActiveCandidate, 0)
	h.loggedInActive.Range(func(key, value any) bool {
		ts, _ := value.(int64)
		candidates = append(candidates, loggedInActiveCandidate{key: key, ts: ts})
		return true
	})
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].ts < candidates[j].ts
	})
	for _, candidate := range candidates {
		if h.loggedInActiveCount.Load() <= loggedInActiveMaxEntries {
			return
		}
		h.deleteLoggedInActive(candidate.key)
	}
}

type requestTrafficMetrics struct {
	inBytes         uint64
	outBytes        uint64
	pendingInBytes  uint64
	pendingOutBytes uint64
	statusCode      int
	wroteHeader     bool
	host            string
	hostTraffic     *hostTrafficCounters
	activeIPRecord  *hostActiveIPRecord
}

func (m *requestTrafficMetrics) bindHost(handler *Handler, host string) {
	if m == nil || handler == nil {
		return
	}
	normalizedHost := normalizeTrafficHost(host)
	if normalizedHost == "" || normalizedHost == m.host {
		return
	}
	m.host = normalizedHost
	m.hostTraffic = handler.getHostTrafficCounters(normalizedHost)
}

func (m *requestTrafficMetrics) markActiveIP(clientIP string, now time.Time) {
	if m == nil || m.hostTraffic == nil {
		return
	}
	m.activeIPRecord = m.hostTraffic.markActiveIP(clientIP, now)
}

func (m *requestTrafficMetrics) releaseActiveIP(now time.Time) {
	if m == nil {
		return
	}
	releaseHostActiveIP(m.activeIPRecord, now)
	m.activeIPRecord = nil
}

func (m *requestTrafficMetrics) flushIn(handler *Handler) {
	if m == nil || m.pendingInBytes == 0 {
		return
	}
	bytes := m.pendingInBytes
	m.pendingInBytes = 0
	if handler != nil {
		handler.trafficTotalIn.Add(bytes)
	}
	if m.hostTraffic != nil {
		m.hostTraffic.totalIn.Add(bytes)
	}
}

func (m *requestTrafficMetrics) flushOut(handler *Handler) {
	if m == nil || m.pendingOutBytes == 0 {
		return
	}
	bytes := m.pendingOutBytes
	m.pendingOutBytes = 0
	if handler != nil {
		handler.trafficTotalOut.Add(bytes)
	}
	if m.hostTraffic != nil {
		m.hostTraffic.totalOut.Add(bytes)
	}
}

func (m *requestTrafficMetrics) flush(handler *Handler) {
	m.flushIn(handler)
	m.flushOut(handler)
}

func (m *requestTrafficMetrics) addIn(handler *Handler, bytes uint64) {
	if m == nil || bytes == 0 {
		return
	}
	m.inBytes += bytes
	m.pendingInBytes += bytes
	if m.pendingInBytes >= trafficCounterFlushBytes {
		m.flushIn(handler)
	}
}

func (m *requestTrafficMetrics) addOut(handler *Handler, bytes uint64) {
	if m == nil || bytes == 0 {
		return
	}
	m.outBytes += bytes
	m.pendingOutBytes += bytes
	if m.pendingOutBytes >= trafficCounterFlushBytes {
		m.flushOut(handler)
	}
}

func (m *requestTrafficMetrics) add5xx() {
	if m == nil || m.hostTraffic == nil {
		return
	}
	m.hostTraffic.error5xx.Add(1)
}

type trafficReadCloser struct {
	io.ReadCloser
	handler *Handler
	metrics *requestTrafficMetrics
}

func (trc *trafficReadCloser) Read(p []byte) (int, error) {
	n, err := trc.ReadCloser.Read(p)
	if n > 0 {
		trc.metrics.addIn(trc.handler, uint64(n))
	}
	return n, err
}

type trafficResponseWriter struct {
	http.ResponseWriter
	handler       *Handler
	metrics       *requestTrafficMetrics
	skipAccessLog bool
}

func (tw *trafficResponseWriter) WriteHeader(statusCode int) {
	if !tw.metrics.wroteHeader {
		tw.metrics.wroteHeader = true
		tw.metrics.statusCode = statusCode
	}
	tw.ResponseWriter.WriteHeader(statusCode)
}

func (tw *trafficResponseWriter) Write(p []byte) (int, error) {
	if !tw.metrics.wroteHeader {
		tw.WriteHeader(http.StatusOK)
	}
	n, err := tw.ResponseWriter.Write(p)
	if n > 0 {
		tw.metrics.addOut(tw.handler, uint64(n))
	}
	return n, err
}

func (tw *trafficResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := tw.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	return hj.Hijack()
}

func (tw *trafficResponseWriter) Flush() {
	if fl, ok := tw.ResponseWriter.(http.Flusher); ok {
		fl.Flush()
	}
}

func (tw *trafficResponseWriter) Push(target string, opts *http.PushOptions) error {
	ps, ok := tw.ResponseWriter.(http.Pusher)
	if !ok {
		return http.ErrNotSupported
	}
	return ps.Push(target, opts)
}

func (tw *trafficResponseWriter) SuppressAccessLog() {
	tw.skipAccessLog = true
}

type accessLogSuppressor interface {
	SuppressAccessLog()
}

func suppressAccessLog(w http.ResponseWriter) {
	if suppressor, ok := w.(accessLogSuppressor); ok {
		suppressor.SuppressAccessLog()
	}
}

func wrapRequestBodyForTraffic(r *http.Request, h *Handler, metrics *requestTrafficMetrics) {
	if r == nil || r.Body == nil {
		return
	}
	if _, ok := r.Body.(*trafficReadCloser); ok {
		return
	}
	r.Body = &trafficReadCloser{ReadCloser: r.Body, handler: h, metrics: metrics}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	requestID := ""
	if logger.DebugEnabled() {
		requestID = logger.NextDebugRequestID()
	}
	metrics := &requestTrafficMetrics{statusCode: http.StatusOK}
	accessEntry := gatewaylog.Entry{
		Method:          r.Method,
		Scheme:          requestScheme(r),
		Host:            r.Host,
		Path:            r.URL.Path,
		Query:           r.URL.RawQuery,
		RequestURI:      r.URL.RequestURI(),
		Protocol:        r.Proto,
		Status:          http.StatusOK,
		RemoteAddr:      r.RemoteAddr,
		UserAgent:       r.UserAgent(),
		Referer:         r.Referer(),
		TLS:             r.TLS != nil,
		WebSocket:       strings.EqualFold(r.Header.Get("Upgrade"), "websocket"),
		AliRealClientIP: strings.TrimSpace(r.Header.Get("Ali-Real-Client-IP")),
		EOConnectingIP:  strings.TrimSpace(r.Header.Get("EO-Connecting-IP")),
		XForwardedFor:   firstForwardedValue(r.Header.Get("X-Forwarded-For")),
		XRealIP:         strings.TrimSpace(r.Header.Get("X-Real-IP")),
	}
	var clientIP string
	loggedStatusCode := 0

	tw := &trafficResponseWriter{ResponseWriter: w, handler: h, metrics: metrics}
	w = tw
	if event := debugProxyEvent("request_start", requestID); event != nil {
		event.Str("method", r.Method).
			Str("scheme", requestScheme(r)).
			Str("host", logger.SanitizeLogString(r.Host)).
			Str("path", logger.SanitizeLogString(r.URL.Path)).
			Str("query", logger.SanitizeURL("?"+r.URL.RawQuery)).
			Str("request_uri", logger.SanitizeURL(r.URL.RequestURI())).
			Str("protocol", r.Proto).
			Str("remote_addr", logger.SanitizeLogString(r.RemoteAddr)).
			Bool("tls", r.TLS != nil).
			Bool("websocket", strings.EqualFold(r.Header.Get("Upgrade"), "websocket")).
			Interface("headers", logger.SanitizeHeader(r.Header)).
			Send()
	}

	defer func() {
		rec := recover()
		metrics.releaseActiveIP(time.Now())
		metrics.flush(h)
		if metrics.statusCode >= 500 {
			h.trafficError5xx.Add(1)
			metrics.add5xx()
		}
		accessEntry.Path = r.URL.Path
		accessEntry.Query = r.URL.RawQuery
		accessEntry.RequestURI = r.URL.RequestURI()
		accessEntry.BytesIn = metrics.inBytes
		accessEntry.BytesOut = metrics.outBytes
		accessEntry.DurationMs = time.Since(start).Milliseconds()
		if loggedStatusCode > 0 {
			accessEntry.Status = loggedStatusCode
		} else {
			accessEntry.Status = metrics.statusCode
		}
		if diagnostics.Enabled() {
			diagnostics.ObserveHTTPRequest(time.Since(start), accessEntry.Status)
		}
		if clientIP != "" {
			accessEntry.RemoteIP = clientIP
		}
		if !tw.skipAccessLog && h.gatewayLogManager != nil {
			h.gatewayLogManager.Log(accessEntry)
		}
		if event := debugProxyEvent("request_end", requestID); event != nil {
			event.Str("method", r.Method).
				Str("host", logger.SanitizeLogString(accessEntry.Host)).
				Str("path", logger.SanitizeLogString(accessEntry.Path)).
				Str("route_type", accessEntry.RouteType).
				Str("route_key", logger.SanitizeLogString(accessEntry.RouteKey)).
				Str("upstream", logger.SanitizeURL(accessEntry.Upstream)).
				Int("status", accessEntry.Status).
				Int64("duration_ms", accessEntry.DurationMs).
				Uint64("bytes_in", accessEntry.BytesIn).
				Uint64("bytes_out", accessEntry.BytesOut).
				Str("remote_ip", logger.SanitizeLogString(accessEntry.RemoteIP)).
				Bool("logged_in", accessEntry.LoggedIn).
				Bool("auth_required", accessEntry.AuthRequired).
				Str("auth_decision", accessEntry.AuthDecision).
				Bool("matched", accessEntry.Matched).
				Bool("access_log_suppressed", tw.skipAccessLog).
				Bool("panic", rec != nil).
				Send()
		}
		if rec != nil {
			panic(rec)
		}
	}()

	snapshot := h.snapshotForRequest()
	originalPath := r.URL.Path
	cleanedPath := path.Clean(r.URL.Path)
	if strings.HasSuffix(r.URL.Path, "/") && cleanedPath != "/" {
		cleanedPath += "/"
	}
	r.URL.Path = cleanedPath
	if originalPath != cleanedPath {
		// RawPath can retain the pre-normalization dot segments and is used by
		// RequestURI() when constructing the auth-bridge context. Drop it so
		// Rust evaluates the same canonical path as the gateway rule engine.
		r.URL.RawPath = ""
		if event := debugProxyEvent("path_normalized", requestID); event != nil {
			event.Str("original_path", logger.SanitizeLogString(originalPath)).
				Str("cleaned_path", logger.SanitizeLogString(cleanedPath)).
				Send()
		}
	}

	clientIP = resolveClientIP(r, snapshot.authConfig, snapshot.proxyProtocolForce)
	accessEntry.RemoteIP = clientIP
	if event := debugProxyEvent("client_ip_resolved", requestID); event != nil {
		event.Str("client_ip", logger.SanitizeLogString(clientIP)).
			Bool("proxy_protocol_force", snapshot.proxyProtocolForce).
			Bool("edge_client_ip_active", snapshot.authConfig.EdgeClientIPActive()).
			Str("x_forwarded_for", logger.SanitizeLogString(firstForwardedValue(r.Header.Get("X-Forwarded-For")))).
			Str("x_real_ip", logger.SanitizeLogString(r.Header.Get("X-Real-IP"))).
			Str("ali_real_client_ip", logger.SanitizeLogString(r.Header.Get("Ali-Real-Client-IP"))).
			Str("eo_connecting_ip", logger.SanitizeLogString(r.Header.Get("EO-Connecting-IP"))).
			Send()
	}

	crawlerBlocker := h.GetCrawlerBlockerConfig()
	if crawlerBlocker.Enabled {
		if isCrawlerBlockerRobotsPath(r.URL.Path) {
			accessEntry.RouteType = "crawler_blocker"
			accessEntry.RouteKey = crawlerBlockerRobotsPath
			accessEntry.AuthDecision = "robots_txt_served"
			accessEntry.Matched = true
			if event := debugProxyEvent("crawler_blocker_robots_served", requestID); event != nil {
				event.Str("path", logger.SanitizeLogString(r.URL.Path)).Send()
			}
			serveCrawlerBlockerRobots(w)
			return
		}

		if isCrawlerBlockerUserAgent(r.UserAgent()) {
			accessEntry.RouteType = "crawler_blocker"
			accessEntry.RouteKey = "user_agent"
			accessEntry.AuthDecision = "crawler_blocked"
			accessEntry.Matched = true
			loggedStatusCode = http.StatusForbidden
			if event := debugProxyEvent("crawler_blocker_blocked", requestID); event != nil {
				event.Str("client_ip", logger.SanitizeLogString(clientIP)).
					Str("user_agent", logger.SanitizeLogString(r.UserAgent())).
					Send()
			}
			serveCrawlerBlockerForbidden(w)
			return
		}
	}

	if blacklistRecord, blocked := h.GetGeneralBlacklistRecordForClientIP(clientIP); blocked {
		accessEntry.RouteType = "general_blacklist"
		accessEntry.RouteKey = blacklistRecord.IP
		accessEntry.AuthDecision = "general_blacklist_blocked"
		accessEntry.GeneralBlacklistBlocked = true
		accessEntry.Matched = true
		loggedStatusCode = 499
		if event := debugProxyEvent("general_blacklist_blocked", requestID); event != nil {
			event.Str("client_ip", logger.SanitizeLogString(clientIP)).
				Str("source", logger.SanitizeLogString(blacklistRecord.Source)).
				Str("comment", logger.SanitizeLogString(blacklistRecord.Comment)).
				Send()
		}
		h.abortConnection(w)
		return
	}

	matchedHostRule := matchHostRule(r, snapshot)
	if !h.IsClientIPVisibleForHost(clientIP, matchedHostRule, snapshot) {
		accessEntry.RouteType = "visibility"
		accessEntry.RouteKey = "cidr"
		accessEntry.AuthDecision = "visibility_denied"
		loggedStatusCode = 499
		if event := debugProxyEvent("visibility_denied", requestID); event != nil {
			event.Str("client_ip", logger.SanitizeLogString(clientIP)).Send()
		}
		h.abortConnection(w)
		return
	}

	http1Required := isHTTP1OnlyHostOverHTTP2(r, matchedHostRule)
	http2Required := isHTTP2OnlyHostOverHTTP1(r, matchedHostRule)
	if http1Required || http2Required {
		if !h.allowReverseProxyRequest(w, r, clientIP, false, matchedHostRule, nil, nil, requestID) {
			return
		}
		metrics.bindHost(h, matchedHostRule.Host)
		accessEntry.RouteType = "protocol_misdirected"
		accessEntry.RouteKey = matchedHostRule.Host
		accessEntry.Upstream = matchedHostRule.Target
		accessEntry.Matched = true
		requiredProtocol := models.HostProtocolModeHTTP1
		if http2Required {
			requiredProtocol = models.HostProtocolModeHTTP2
		}
		accessEntry.AuthDecision = requiredProtocol + "_required"
		loggedStatusCode = http.StatusMisdirectedRequest
		if event := debugProxyEvent("protocol_misdirected", requestID); event != nil {
			event.Str("host", logger.SanitizeLogString(matchedHostRule.Host)).
				Str("sni", logger.SanitizeLogString(r.TLS.ServerName)).
				Str("negotiated_protocol", logger.SanitizeLogString(r.TLS.NegotiatedProtocol)).
				Str("required_protocol", requiredProtocol).
				Send()
		}
		serveProtocolMisdirectedRequest(w, r, http2Required)
		return
	}

	if response.IsFaviconPath(r.URL.Path) {
		accessEntry.RouteType = "favicon"
		accessEntry.RouteKey = r.URL.Path
		accessEntry.Matched = true
		if event := debugProxyEvent("favicon_served", requestID); event != nil {
			event.Str("path", logger.SanitizeLogString(r.URL.Path)).Send()
		}
		response.ServeFavicon(w, r)
		return
	}

	if response.IsToolbarAssetPath(r.URL.Path) {
		accessEntry.RouteType = "toolbar_asset"
		accessEntry.RouteKey = r.URL.Path
		accessEntry.Matched = true
		response.ServeToolbarAsset(w, r)
		return
	}

	isSelectRoute := r.URL.Path == "/__select__"
	isAuthRoute := strings.HasPrefix(r.URL.Path, "/__auth__/")
	matchedHostLocation := matchHostLocation(r, matchedHostRule)
	if matchedHostRule != nil {
		metrics.bindHost(h, matchedHostRule.Host)
		metrics.markActiveIP(clientIP, time.Now())
	}
	accessMode := ""
	if matchedHostRule != nil {
		accessMode = matchedHostRule.AccessMode
	}
	authContextAccessMode := ""
	if matchedHostRule != nil && matchedHostRule.UseAuth {
		authContextAccessMode = accessMode
	}
	var requestAuth *requestAuthContext
	if matchedHostRule != nil {
		availability := evaluateHostRuleAvailability(matchedHostRule, start)
		if !availability.Available {
			accessEntry.RouteType = "host_unavailable"
			accessEntry.RouteKey = matchedHostRule.Host
			accessEntry.Upstream = matchedHostRule.Target
			accessEntry.Matched = true
			accessEntry.AuthDecision = availability.Reason
			accessEntry.AccessMode = accessMode
			loggedStatusCode = http.StatusServiceUnavailable
			if event := debugProxyEvent("host_unavailable", requestID); event != nil {
				event.Str("host", logger.SanitizeLogString(matchedHostRule.Host)).
					Str("reason", logger.SanitizeLogString(availability.Reason)).
					Str("window", logger.SanitizeLogString(availability.Window)).
					Send()
			}
			response.HostUnavailable(w, r, response.HostUnavailableOptions{
				Reason: availability.Reason,
				Window: availability.Window,
			})
			return
		}
	}

	matchedRule, needsSlashRedirect := matchRule(r, snapshot)
	if matchedHostRule != nil {
		matchedRule = nil
		needsSlashRedirect = ""
	}

	resetUnmatchedConnection := snapshot.unmatchedRoute.Behavior ==
		models.GatewayUnmatchedRouteBehaviorResetConnection
	if !resetUnmatchedConnection && matchedRule == nil && needsSlashRedirect == "" && matchedHostRule == nil && !isSelectRoute && !isAuthRoute {
		defaultHostRule := snapshot.defaultHostRule
		if defaultHostRule != nil && !hostRuleAvailableNow(defaultHostRule, start) {
			defaultHostRule = nil
		}
		if redirectURL := buildDefaultHostRuleRedirectURL(r, defaultHostRule); redirectURL != "" {
			accessEntry.RouteType = "default_host_redirect"
			accessEntry.RouteKey = defaultHostRule.Host
			accessEntry.Upstream = defaultHostRule.Target
			accessEntry.Matched = true
			accessEntry.AuthDecision = "redirected"
			if event := debugProxyEvent("default_host_redirect", requestID); event != nil {
				event.Str("host", logger.SanitizeLogString(defaultHostRule.Host)).
					Str("target", logger.SanitizeURL(redirectURL)).
					Send()
			}
			status := http.StatusFound
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				status = http.StatusTemporaryRedirect
			}
			http.Redirect(w, r, redirectURL, status)
			return
		}
	}

	if matchedRule == nil && snapshot.defaultRule != nil {
		matchedRule = snapshot.defaultRule
	}
	if resetUnmatchedConnection && matchedRule == nil && needsSlashRedirect == "" &&
		matchedHostRule == nil && !isSelectRoute && !isAuthRoute {
		accessEntry.RouteType = "unmatched_route_blocked"
		accessEntry.RouteKey = requestHostForRouting(r)
		accessEntry.AuthDecision = "connection_reset"
		accessEntry.Matched = false
		loggedStatusCode = 499
		if event := debugProxyEvent("unmatched_route_blocked", requestID); event != nil {
			event.Str("host", logger.SanitizeLogString(accessEntry.RouteKey)).
				Str("path", logger.SanitizeLogString(r.URL.Path)).
				Send()
		}
		h.abortConnection(w)
		return
	}
	if event := debugProxyEvent("route_match_evaluated", requestID); event != nil {
		event.Bool("select_route", isSelectRoute).
			Bool("auth_route", isAuthRoute).
			Bool("host_rule_matched", matchedHostRule != nil).
			Bool("host_location_matched", matchedHostLocation != nil).
			Bool("path_rule_matched", matchedRule != nil).
			Str("needs_slash_redirect", logger.SanitizeLogString(needsSlashRedirect)).
			Str("host_rule", func() string {
				if matchedHostRule == nil {
					return ""
				}
				return logger.SanitizeLogString(matchedHostRule.Host)
			}()).
			Str("path_rule", func() string {
				if matchedRule == nil {
					return ""
				}
				return logger.SanitizeLogString(matchedRule.Path)
			}()).
			Send()
	}
	if !h.allowReverseProxyRequest(w, r, clientIP, isAuthRoute, matchedHostRule, matchedHostLocation, matchedRule, requestID) {
		return
	}
	wafRouteType, wafRouteKey, wafUpstream := wafRouteContext(r, snapshot, isAuthRoute, matchedHostRule, matchedHostLocation, matchedRule)
	wafRuntime := h.wafRuntime
	if wafRuntime != nil && wafRuntime.Active() {
		h.mu.RLock()
		commonLocationExemptions := h.commonLocationExemptions
		h.mu.RUnlock()
		wafBypassedByCommonLocation := commonLocationExemptions != nil && commonLocationExemptions.shouldBypassWAF(clientIP)
		if !wafBypassedByCommonLocation {
			decision := wafRuntime.Evaluate(r, proxywaf.EvaluateContext{
				ClientIP:   clientIP,
				RouteType:  wafRouteType,
				RouteKey:   wafRouteKey,
				Upstream:   wafUpstream,
				Scheme:     requestScheme(r),
				RemoteAddr: r.RemoteAddr,
			})
			if event := debugProxyEvent("waf_evaluated", requestID); event != nil {
				event.Bool("enabled", decision.Enabled).
					Bool("allowed", decision.Allowed).
					Str("mode", decision.Mode).
					Str("action", decision.Action).
					Int("status", decision.Status).
					Str("trace_id", decision.TraceID).
					Ints("rule_ids", decision.RuleIDs).
					Str("route_type", wafRouteType).
					Str("route_key", logger.SanitizeLogString(wafRouteKey)).
					Str("upstream", logger.SanitizeURL(wafUpstream)).
					Send()
			}
			if decision.Enabled && decision.TraceID != "" {
				accessEntry.WAFTraceID = decision.TraceID
				accessEntry.WAFMode = decision.Mode
				accessEntry.WAFRuleIDs = decision.RuleIDs
				accessEntry.WAFAction = decision.Action
				accessEntry.WAFBundle = decision.BundleID
			}
			if !decision.Allowed {
				accessEntry.Matched = true
				accessEntry.RouteType = wafRouteType
				accessEntry.RouteKey = wafRouteKey
				accessEntry.Upstream = wafUpstream
				accessEntry.AuthDecision = "waf_blocked"
				accessEntry.WAFBlocked = true
				loggedStatusCode = decision.Status
				response.WAFBlocked(w, r, response.WAFBlockPageOptions{
					Status:  decision.Status,
					TraceID: decision.TraceID,
				})
				return
			}
		}
	}
	if matchedHostRule != nil && matchedHostRule.UseAuth && !isAuthRoute && !isSelectRoute &&
		normalizeRequestHost(matchedHostRule.Host) != normalizeRequestHost(snapshot.authConfig.AuthHost) {
		host := normalizeRequestHost(matchedHostRule.Host)
		withAdvancedAuthPolicyVersion(r, matchedHostRule.AdvancedAuth.PolicyVersion)
		if policy := snapshot.advancedAuth[host]; policy != nil {
			diagnostics.RecordSubdomainRuleEvaluation()
			if ruleMatch := policy.evaluate(r, clientIP); ruleMatch != nil {
				diagnostics.RecordSubdomainRuleMatch()
				ruleMatch.host = host
				withAdvancedAuthRuleMatch(r, ruleMatch)
			}
		}
	}
	wrapRequestBodyForTraffic(r, h, metrics)
	isMatch := isSelectRoute || isAuthRoute || matchedHostRule != nil || matchedRule != nil || r.URL.Path == "/"
	accessEntry.Matched = isMatch
	accessEntry.AccessMode = accessMode
	var preparedAuth *authCheckExecution
	if shouldRunPreflightForRoute(isSelectRoute, isAuthRoute, matchedHostRule, matchedRule) {
		if strings.TrimSpace(snapshot.authConfig.AuthURL) != "" {
			requestAuth = newRequestAuthContext(r, clientIP, authContextAccessMode)
		}
		preflight := preflightDecision{}
		verifyRequired := strings.TrimSpace(snapshot.authConfig.AuthURL) != "" && !isAuthRoute &&
			(isSelectRoute || (matchedHostRule != nil && matchedHostRule.UseAuth) || (matchedRule != nil && matchedRule.UseAuth))
		if verifyRequired {
			if combined, used := h.executeCombinedHTTPAuth(r, snapshot.authConfig, clientIP, authContextAccessMode, isMatch, requestID, requestAuth); used {
				preflight = combined.preflight
				preparedAuth = &combined.auth
			} else {
				preflight = h.runPreflight(r, snapshot.authConfig, clientIP, isMatch, accessMode, requestID, requestAuth)
			}
		} else {
			preflight = h.runPreflight(r, snapshot.authConfig, clientIP, isMatch, accessMode, requestID, requestAuth)
		}
		if preflight.accessDeniedReason != "" {
			if isAuthRoute {
				if event := debugProxyEvent("preflight_access_denied_ignored_auth_route", requestID); event != nil {
					event.Str("client_ip", logger.SanitizeLogString(clientIP)).
						Str("reason", logger.SanitizeLogString(preflight.accessDeniedReason)).
						Str("path", logger.SanitizeLogString(r.URL.Path)).
						Send()
				}
			} else {
				accessEntry.RouteType = "preflight"
				accessEntry.AuthDecision = "access_denied"
				accessEntry.LoggedIn = preflight.credentialIdentity.hasCredential()
				applyAuthCredentialIdentityToLogEntry(&accessEntry, preflight.credentialIdentity)
				loggedStatusCode = http.StatusForbidden
				if event := debugProxyEvent("preflight_access_denied", requestID); event != nil {
					event.Str("client_ip", logger.SanitizeLogString(clientIP)).
						Str("reason", logger.SanitizeLogString(preflight.accessDeniedReason)).
						Str("credential_id", logger.SanitizeLogString(preflight.credentialIdentity.credentialID)).
						Str("linked_totp_id", logger.SanitizeLogString(preflight.credentialIdentity.linkedTOTPID)).
						Bool("matched", isMatch).
						Str("access_mode", accessMode).
						Send()
				}
				response.AccessDenied(w, r)
				return
			}
		}
		if preflight.deny {
			accessEntry.RouteType = "preflight"
			accessEntry.AuthDecision = "denied"
			loggedStatusCode = 499
			suppressAccessLog(w)
			if event := debugProxyEvent("preflight_denied", requestID); event != nil {
				event.Str("client_ip", logger.SanitizeLogString(clientIP)).
					Bool("matched", isMatch).
					Str("access_mode", accessMode).
					Send()
			}
			h.abortConnection(w)
			return
		}
		if preflight.redirectLocation != "" {
			accessEntry.RouteType = "preflight"
			accessEntry.AuthDecision = "redirected"
			if event := debugProxyEvent("preflight_redirected", requestID); event != nil {
				event.Str("redirect_location", logger.SanitizeURL(preflight.redirectLocation)).
					Bool("matched", isMatch).
					Str("access_mode", accessMode).
					Send()
			}
			applyNoStoreCacheHeaders(w.Header())
			http.Redirect(w, r, preflight.redirectLocation, http.StatusFound)
			return
		}
		if event := debugProxyEvent("preflight_allowed", requestID); event != nil {
			event.Bool("matched", isMatch).
				Str("access_mode", accessMode).
				Send()
		}
	} else {
		if event := debugProxyEvent("preflight_skipped_auth_not_required", requestID); event != nil {
			event.Bool("matched", isMatch).
				Str("access_mode", accessMode).
				Send()
		}
	}
	if needsSlashRedirect != "" {
		accessEntry.RouteType = "slash_redirect"
		accessEntry.RouteKey = needsSlashRedirect
		newPath := needsSlashRedirect
		if r.URL.RawQuery != "" {
			newPath += "?" + r.URL.RawQuery
		}
		if event := debugProxyEvent("slash_redirect", requestID); event != nil {
			event.Str("target", logger.SanitizeURL(newPath)).Send()
		}
		http.Redirect(w, r, newPath, http.StatusMovedPermanently)
		return
	}
	if isSelectRoute {
		accessEntry.RouteType = "select"
		accessEntry.RouteKey = r.URL.Path
		accessEntry.AuthRequired = true
		authResult := h.handleSelectRoute(w, r, snapshot, clientIP, requestID, requestAuth, preparedAuth)
		applyAuthResultToLogEntry(&accessEntry, authResult)
		if event := debugProxyEvent("select_route_served", requestID); event != nil {
			event.Bool("auth_required", accessEntry.AuthRequired).
				Bool("authenticated", authResult.authenticated).
				Str("auth_decision", authResult.decision).
				Send()
		}
		return
	}
	if isAuthRoute {
		accessEntry.RouteType = "auth_proxy"
		accessEntry.RouteKey = r.URL.Path
		if snapshot.authConfig.AuthPort > 0 {
			accessEntry.Upstream = localServiceBaseURL(snapshot.authConfig.AuthPort)
		}
		accessEntry.AuthDecision = "proxy"
		if event := debugProxyEvent("auth_proxy_route", requestID); event != nil {
			event.Str("path", logger.SanitizeLogString(r.URL.Path)).
				Str("upstream", logger.SanitizeURL(accessEntry.Upstream)).
				Send()
		}
		h.handleAuthProxyRoute(w, r, snapshot, clientIP)
		return
	}
	if matchedHostRule != nil {
		accessEntry.RouteType = "host_rule"
		accessEntry.RouteKey = matchedHostRule.Host
		accessEntry.Upstream = matchedHostRule.Target
		authUpstreamTarget := matchedHostRule.Target
		toolbarProbeTarget := matchedHostRule.Target
		if matchedHostLocation != nil {
			accessEntry.RouteType = "host_location"
			accessEntry.RouteKey = hostLocationRouteKey(matchedHostRule, matchedHostLocation)
			if matchedHostLocation.Action == models.HostLocationActionProxy {
				accessEntry.Upstream = matchedHostLocation.Target
				authUpstreamTarget = matchedHostLocation.Target
				toolbarProbeTarget = matchedHostLocation.Target
			} else {
				accessEntry.Upstream = ""
				toolbarProbeTarget = ""
			}
		}
		accessEntry.AuthRequired = matchedHostRule.UseAuth && snapshot.authConfig.AuthURL != ""
		authResult := authCheckResult{allowed: true, decision: "not_required"}
		if accessEntry.AuthRequired {
			authResult = h.checkAuth(w, r, snapshot.authConfig, clientIP, matchedHostRule.AccessMode, authUpstreamTarget, requestID, requestAuth, preparedAuth)
			applyAuthResultToLogEntry(&accessEntry, authResult)
			if !authResult.allowed {
				if authResult.decision == "denied" {
					loggedStatusCode = 499
				}
				if event := debugProxyEvent("host_auth_rejected", requestID); event != nil {
					event.Str("host", logger.SanitizeLogString(matchedHostRule.Host)).
						Str("auth_decision", authResult.decision).
						Send()
				}
				return
			}
		} else if !matchedHostRule.SuppressToolbar && snapshotReverseProxyTargetSupportsHTMLFeatures(snapshot, toolbarProbeTarget) && shouldProbeAuthForToolbar(r, snapshot.authConfig, snapshot.gatewayPortal) {
			if requestAuth == nil {
				requestAuth = newRequestAuthContext(r, clientIP, "")
			}
			authResult = h.checkAuthForToolbar(w, r, snapshot.authConfig, clientIP, requestID, requestAuth)
			applyAuthResultToLogEntry(&accessEntry, authResult)
		} else {
			accessEntry.AuthDecision = authResult.decision
		}
		applyAuthResultToLogEntry(&accessEntry, authResult)
		if matchedHostLocation != nil {
			if event := debugProxyEvent("host_location_selected", requestID); event != nil {
				event.Str("route_key", logger.SanitizeLogString(hostLocationRouteKey(matchedHostRule, matchedHostLocation))).
					Str("action", logger.SanitizeLogString(matchedHostLocation.Action)).
					Str("upstream", logger.SanitizeURL(accessEntry.Upstream)).
					Bool("auth_required", accessEntry.AuthRequired).
					Bool("authenticated", authResult.authenticated).
					Str("auth_decision", authResult.decision).
					Send()
			}
			switch matchedHostLocation.Action {
			case models.HostLocationActionResponse:
				serveHostLocationResponse(w, *matchedHostLocation)
			case models.HostLocationActionProxy:
				h.proxyToHostLocationTarget(w, r, snapshot, *matchedHostRule, *matchedHostLocation, clientIP, authResult, requestID)
			default:
				response.HTMLWithSelectLink(w, r, errors.CodeProxyTargetInvalid, "Invalid host location configuration", snapshot.rules, authResult.authenticated)
			}
			return
		}
		if event := debugProxyEvent("host_rule_selected", requestID); event != nil {
			event.Str("host", logger.SanitizeLogString(matchedHostRule.Host)).
				Str("upstream", logger.SanitizeURL(matchedHostRule.Target)).
				Bool("auth_required", accessEntry.AuthRequired).
				Bool("authenticated", authResult.authenticated).
				Str("auth_decision", authResult.decision).
				Send()
		}
		h.proxyToHostTarget(w, r, snapshot, *matchedHostRule, clientIP, authResult, requestID)
		return
	}
	if matchedRule == nil {
		accessEntry.RouteType = "not_found"
		accessEntry.RouteKey = r.URL.Path
		accessEntry.AuthDecision = "not_required"
		authResult := authCheckResult{allowed: true, decision: "not_required"}
		if r.URL.Path != "/" &&
			strings.TrimSpace(snapshot.authConfig.AuthURL) != "" &&
			requestHasExplicitAuthIdentity(r) {
			if requestAuth == nil {
				requestAuth = newRequestAuthContext(r, clientIP, "")
			}
			authResult = h.checkAuthForToolbar(w, r, snapshot.authConfig, clientIP, requestID, requestAuth)
			applyAuthResultToLogEntry(&accessEntry, authResult)
		}
		if event := debugProxyEvent("route_not_found", requestID); event != nil {
			event.Str("path", logger.SanitizeLogString(r.URL.Path)).
				Bool("authenticated", authResult.authenticated).
				Send()
		}
		h.handleNoMatchRoute(w, r, snapshot, authResult.authenticated)
		return
	}
	accessEntry.RouteType = "path_rule"
	accessEntry.RouteKey = matchedRule.Path
	accessEntry.Upstream = matchedRule.Target
	accessEntry.AuthRequired = matchedRule.UseAuth && snapshot.authConfig.AuthURL != ""
	if snapshotReverseProxyTargetSupportsHTMLFeatures(snapshot, matchedRule.Target) && matchedRule.UseRootMode && matchedRule.Path != "/" && strings.HasPrefix(r.URL.Path, matchedRule.Path) {
		accessEntry.AuthDecision = "root_mode_redirect"
		http.SetCookie(w, &http.Cookie{
			Name:  proxyPathCookieName,
			Value: matchedRule.Path,
			Path:  "/",
		})
		if event := debugProxyEvent("root_mode_redirect", requestID); event != nil {
			event.Str("path_rule", logger.SanitizeLogString(matchedRule.Path)).Send()
		}
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	authResult := authCheckResult{allowed: true, decision: "not_required"}
	if accessEntry.AuthRequired {
		authResult = h.checkAuth(w, r, snapshot.authConfig, clientIP, "", matchedRule.Target, requestID, requestAuth, preparedAuth)
		applyAuthResultToLogEntry(&accessEntry, authResult)
		if !authResult.allowed {
			if authResult.decision == "denied" {
				loggedStatusCode = 499
			}
			if event := debugProxyEvent("path_auth_rejected", requestID); event != nil {
				event.Str("path_rule", logger.SanitizeLogString(matchedRule.Path)).
					Str("auth_decision", authResult.decision).
					Send()
			}
			return
		}
	} else if snapshotReverseProxyTargetSupportsHTMLFeatures(snapshot, matchedRule.Target) && shouldProbeAuthForToolbar(r, snapshot.authConfig, snapshot.gatewayPortal) {
		if requestAuth == nil {
			requestAuth = newRequestAuthContext(r, clientIP, "")
		}
		authResult = h.checkAuthForToolbar(w, r, snapshot.authConfig, clientIP, requestID, requestAuth)
		applyAuthResultToLogEntry(&accessEntry, authResult)
	} else {
		accessEntry.AuthDecision = authResult.decision
	}
	applyAuthResultToLogEntry(&accessEntry, authResult)
	if event := debugProxyEvent("path_rule_selected", requestID); event != nil {
		event.Str("path_rule", logger.SanitizeLogString(matchedRule.Path)).
			Str("upstream", logger.SanitizeURL(matchedRule.Target)).
			Bool("auth_required", accessEntry.AuthRequired).
			Bool("authenticated", authResult.authenticated).
			Str("auth_decision", authResult.decision).
			Send()
	}
	h.proxyToRuleTarget(w, r, snapshot, *matchedRule, clientIP, authResult, requestID)
}

func filterSelectHostRulesByAuthScope(hostRules []models.HostRule, authResult authCheckResult) []models.HostRule {
	if !authResult.subdomainAccessCustom {
		return hostRules
	}
	if len(hostRules) == 0 || len(authResult.allowedSubdomainHosts) == 0 {
		return nil
	}
	filtered := make([]models.HostRule, 0, len(hostRules))
	for _, rule := range hostRules {
		host := normalizeRequestHost(rule.Host)
		if host == "" {
			continue
		}
		if _, ok := authResult.allowedSubdomainHosts[host]; ok {
			filtered = append(filtered, rule)
		}
	}
	return filtered
}

func (h *Handler) handleSelectRoute(w http.ResponseWriter, r *http.Request, snapshot requestSnapshot, clientIP string, requestID string, requestAuth *requestAuthContext, prepared *authCheckExecution) authCheckResult {
	authResult := h.checkAuth(w, r, snapshot.authConfig, clientIP, "", "", requestID, requestAuth, prepared)
	if !authResult.allowed {
		return authResult
	}
	if !authResult.authenticated {
		applyNoStoreCacheHeaders(w.Header())
		http.Redirect(w, r, authLoginRedirectLocation(snapshot.authConfig, r), http.StatusFound)
		return authCheckResult{decision: "redirected"}
	}

	applyNoStoreCacheHeaders(w.Header())
	availableHostRules := filterAvailableHostRules(snapshot.toolbarHostRules, time.Now())
	response.SelectPageWithPrefilteredRoutes(
		w,
		r,
		snapshot.toolbarRules,
		filterSelectHostRulesByAuthScope(availableHostRules, authResult),
		snapshot.gatewayPortal,
	)
	return authResult
}

func (h *Handler) handleAuthProxyRoute(w http.ResponseWriter, r *http.Request, snapshot requestSnapshot, clientIP string) bool {
	if !strings.HasPrefix(r.URL.Path, "/__auth__/") {
		return false
	}

	if snapshot.authConfig.AuthPort <= 0 {
		response.HTML(w, r, errors.CodeInternal, "Authentication service is not configured", nil)
		return true
	}
	targetURL := localServiceTargetURL(snapshot.authConfig.AuthPort)

	proxyPath := r.URL.Path
	switch r.URL.Path {
	case "/__auth__/login":
		proxyPath = snapshot.authConfig.LoginURL
		if proxyPath == "" {
			proxyPath = "/login"
		}
		if redirectTarget := buildInternalAuthLoginRedirect(proxyPath, r.URL.RawQuery); redirectTarget != "" {
			applyNoStoreCacheHeaders(w.Header())
			http.Redirect(w, r, redirectTarget, http.StatusFound)
			return true
		}
	case "/__auth__/logout", "/__auth__/api/auth/logout":
		proxyPath = snapshot.authConfig.LogoutURL
		if proxyPath == "" {
			proxyPath = "/api/auth/logout"
		}
	case "/__auth__/oidc/bind", "/__auth__/oidc/bind/":
		proxyPath = "/api/auth/oidc/bind"
	default:
		rawProxyPath := strings.TrimPrefix(r.URL.Path, "/__auth__")
		proxyPath = path.Clean(ensureLeadingSlash(rawProxyPath))
	}

	targetURL.Path = singleJoiningSlash(targetURL.Path, proxyPath)

	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	proxy.BufferPool = sharedProxyBufferPool
	transport := h.proxyTransport
	if transport == nil {
		transport = newProxyTransport()
	}
	proxy.Transport = transport

	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		applyInternalAuthProxyHeaders(req, r, targetURL, clientIP, snapshot.authConfig)
	}
	proxy.ModifyResponse = func(resp *http.Response) error {
		setCookies := resp.Header.Values("Set-Cookie")
		if shouldDisableAuthResponseCaching(proxyPath) || len(setCookies) > 0 {
			applyNoStoreCacheHeaders(resp.Header)
		}
		h.authCacheInvalidateForSetCookieMutation(r, clientIP, setCookies)
		return nil
	}

	serveReverseProxyWithResponseCoalescing(proxy, w, r)
	return true
}

func matchRuleFromProxyPathCookie(r *http.Request, snapshot requestSnapshot) *models.Rule {
	cookie, err := r.Cookie(proxyPathCookieName)
	if err != nil || cookie.Value == "" {
		return nil
	}

	if rule, ok := snapshot.rulesByPath[cookie.Value]; ok {
		return rule
	}

	for i := range snapshot.rules {
		rule := &snapshot.rules[i]
		if cookie.Value == rule.Path {
			return rule
		}
	}

	return nil
}

func addProxyPathCookieIfChanged(resp *http.Response, r *http.Request, proxyPath string) {
	if resp == nil || strings.TrimSpace(proxyPath) == "" {
		return
	}
	if resp.Header == nil {
		resp.Header = http.Header{}
	}
	stripProxyPathSetCookies(resp.Header)
	if r != nil {
		if cookie, err := r.Cookie(proxyPathCookieName); err == nil && cookie.Value == proxyPath {
			return
		}
	}
	cookie := &http.Cookie{
		Name:  proxyPathCookieName,
		Value: proxyPath,
		Path:  "/",
	}
	resp.Header.Add("Set-Cookie", cookie.String())
}

func stripProxyPathSetCookies(headers http.Header) {
	if headers == nil {
		return
	}
	values := headers.Values("Set-Cookie")
	if len(values) == 0 {
		return
	}

	headers.Del("Set-Cookie")
	for _, value := range values {
		if isProxyPathSetCookie(value) {
			continue
		}
		headers.Add("Set-Cookie", value)
	}
}

func isProxyPathSetCookie(value string) bool {
	if cookie, err := http.ParseSetCookie(value); err == nil {
		return cookie.Name == proxyPathCookieName
	}
	name, _, ok := strings.Cut(value, "=")
	return ok && strings.TrimSpace(name) == proxyPathCookieName
}

func requestHostForRouting(r *http.Request) string {
	host := normalizeRequestHost(r.Host)
	if forwardedHost := normalizeRequestHost(r.Header.Get("X-Forwarded-Host")); forwardedHost != "" {
		host = forwardedHost
	}
	return host
}

func buildDefaultHostRuleRedirectURL(r *http.Request, defaultHostRule *models.HostRule) string {
	if r == nil || r.URL == nil || defaultHostRule == nil {
		return ""
	}
	defaultHost := normalizeRequestHost(defaultHostRule.Host)
	if defaultHost == "" || requestHostForRouting(r) == defaultHost {
		return ""
	}

	scheme := requestScheme(r)
	rawHost := firstForwardedValue(r.Header.Get("X-Forwarded-Host"))
	if rawHost == "" {
		rawHost = r.Host
	}
	_, port := splitRequestHostPort(rawHost)
	path := r.URL.Path
	if path == "" {
		path = "/"
	}

	redirectURL := url.URL{
		Scheme:   scheme,
		Host:     formatURLHost(defaultHost, port, scheme),
		Path:     path,
		RawQuery: r.URL.RawQuery,
	}
	if redirectURL.Host == "" {
		return ""
	}
	return redirectURL.String()
}

func matchHostRule(r *http.Request, snapshot requestSnapshot) *models.HostRule {
	if len(snapshot.hostRules) == 0 && len(snapshot.hostRulesByHost) == 0 {
		return nil
	}

	host := requestHostForRouting(r)
	if host == "" {
		return nil
	}

	if rule, ok := snapshot.hostRulesByHost[host]; ok {
		return rule
	}

	for i := range snapshot.hostRules {
		rule := &snapshot.hostRules[i]
		if normalizeRequestHost(rule.Host) == host {
			return rule
		}
	}

	return nil
}

func matchHostLocation(r *http.Request, hostRule *models.HostRule) *models.HostLocation {
	if r == nil || r.URL == nil || hostRule == nil || len(hostRule.Locations) == 0 {
		return nil
	}

	requestPath := r.URL.Path
	var matchedPrefix *models.HostLocation
	longestPrefix := -1
	for i := range hostRule.Locations {
		location := &hostRule.Locations[i]
		if location.Path == "" {
			continue
		}
		switch location.Match {
		case models.HostLocationMatchExact:
			if requestPath == location.Path {
				return location
			}
		case models.HostLocationMatchPrefix:
			if hostLocationPrefixMatches(requestPath, location.Path) && len(location.Path) > longestPrefix {
				matchedPrefix = location
				longestPrefix = len(location.Path)
			}
		}
	}

	return matchedPrefix
}

func hostLocationPrefixMatches(requestPath string, locationPath string) bool {
	if locationPath == "" {
		return false
	}
	if requestPath == locationPath {
		return true
	}
	if strings.HasSuffix(locationPath, "/") {
		return strings.HasPrefix(requestPath, locationPath)
	}
	return strings.HasPrefix(requestPath, locationPath+"/")
}

func matchRule(r *http.Request, snapshot requestSnapshot) (*models.Rule, string) {
	var matchedRule *models.Rule
	var longestMatch int
	var needsSlashRedirect string
	var rootPathCookieRule *models.Rule

	// When the user returns to "/", prefer the last root-mode selection
	// before falling back to a catch-all "/" rule or the configured default route.
	if r.URL.Path == "/" {
		rootPathCookieRule = matchRuleFromProxyPathCookie(r, snapshot)
	}

	matchedRule, longestMatch = longestPathRuleMatch(r.URL.Path, snapshot)
	if rule, ok := snapshot.rulesByPath[r.URL.Path+"/"]; ok {
		needsSlashRedirect = rule.Path
	} else if len(snapshot.rulesByPath) == 0 {
		for i := range snapshot.rules {
			rule := &snapshot.rules[i]
			if r.URL.Path+"/" == rule.Path {
				needsSlashRedirect = rule.Path
				break
			}
		}
	}

	if matchedRule != nil && matchedRule.Path != "/" && r.URL.Path == matchedRule.Path && !strings.HasSuffix(matchedRule.Path, "/") {
		if r.Method == http.MethodGet {
			needsSlashRedirect = matchedRule.Path + "/"
			matchedRule = nil
		}
	} else if longestMatch == len(r.URL.Path) {
		needsSlashRedirect = ""
	} else if needsSlashRedirect != "" {
		matchedRule = nil
	}

	if rootPathCookieRule != nil && needsSlashRedirect == "" {
		matchedRule = rootPathCookieRule
	}

	if matchedRule == nil && needsSlashRedirect == "" {
		isWebSocket := equalFoldASCIIString(r.Header.Get("Upgrade"), "websocket")
		canUseCookie := r.URL.Path == "/" || r.Header.Get("Referer") != "" || r.Header.Get("Origin") != "" || isWebSocket
		if canUseCookie {
			matchedRule = matchRuleFromProxyPathCookie(r, snapshot)
		}

		if matchedRule == nil {
			referer := r.Header.Get("Referer")
			if referer != "" {
				refURL, err := url.Parse(referer)
				if err == nil {
					matchedRule, _ = longestPathRuleMatch(refURL.Path, snapshot)
				}
			}
		}
	}

	return matchedRule, needsSlashRedirect
}

func longestPathRuleMatch(requestPath string, snapshot requestSnapshot) (*models.Rule, int) {
	rulesByLength := snapshot.rulesByLength
	if len(rulesByLength) == 0 {
		rulesByLength = snapshot.rules
	}
	if len(snapshot.rulesByPath) > 0 && len(requestPath) <= len(rulesByLength)*4 {
		for end := len(requestPath); end > 0; end-- {
			if rule, ok := snapshot.rulesByPath[requestPath[:end]]; ok {
				return rule, len(rule.Path)
			}
		}
		return nil, 0
	}

	for i := range rulesByLength {
		rule := &rulesByLength[i]
		if rule.Path != "" && strings.HasPrefix(requestPath, rule.Path) {
			return rule, len(rule.Path)
		}
	}
	return nil, 0
}

func (h *Handler) handleNoMatchRoute(w http.ResponseWriter, r *http.Request, snapshot requestSnapshot, authenticated bool) {
	if r.URL.Path == "/" {
		if len(snapshot.rules) == 0 && len(snapshot.hostRules) == 0 {
			response.Welcome(w, r, nil)
			return
		}
		if len(snapshot.rules) > 0 {
			http.Redirect(w, r, "/__select__", http.StatusFound)
			return
		}
	}
	response.RouteNotFound(w, r, snapshot.rules, authenticated)
}

func serveHostLocationResponse(w http.ResponseWriter, location models.HostLocation) {
	for name, value := range location.Response.Headers {
		w.Header().Set(name, value)
	}
	contentType := strings.TrimSpace(location.Response.ContentType)
	if contentType == "" {
		contentType = "text/plain; charset=utf-8"
	}
	status := location.Response.Status
	if status == 0 {
		status = http.StatusOK
	}
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(status)
	_, _ = io.WriteString(w, location.Response.Body)
}

func (h *Handler) proxyToHostLocationTarget(w http.ResponseWriter, r *http.Request, snapshot requestSnapshot, matchedRule models.HostRule, location models.HostLocation, clientIP string, authResult authCheckResult, requestID string) {
	targetRuntime := reverseProxyTargetRuntimeFor(snapshot, location.Target)
	if targetRuntime.err != nil {
		if event := debugProxyEvent("reverse_proxy_target_invalid", requestID); event != nil {
			event.Str("route_type", "host_location").
				Str("route_key", logger.SanitizeLogString(hostLocationRouteKey(&matchedRule, &location))).
				Str("target", logger.SanitizeURL(location.Target)).
				Str("error", logger.SanitizeLogString(targetRuntime.err.Error())).
				Send()
		}
		response.HTMLWithSelectLink(w, r, errors.CodeProxyTargetInvalid, "Invalid target URL configuration", snapshot.rules, authResult.authenticated)
		return
	}
	targetURL := targetRuntime.targetURL
	transportTargetURL := targetRuntime.transportURL

	transport := h.proxyTransport
	if transport == nil {
		transport = newProxyTransport()
	}
	targetSupportsHTMLFeatures := targetRuntime.supportsHTMLFeatures
	omitForwardedHeaders := h.shouldOmitForwardedHeaders(transportTargetURL)
	preserveHost := matchedRule.PreserveHost && !h.shouldOmitPreserveHost(transportTargetURL)
	gatewayPortalEnabled := snapshot.gatewayPortal.Enabled
	suppressToolbarForUA := response.ShouldSuppressToolbarForUserAgent(r.UserAgent())
	toolbarCandidate := targetSupportsHTMLFeatures && gatewayPortalEnabled && authResult.authenticated && !matchedRule.SuppressToolbar && !authResult.suppressToolbar && !suppressToolbarForUA
	isAuthHostProxy := snapshot.authConfig.AuthHost != "" && normalizeRequestHost(matchedRule.Host) == snapshot.authConfig.AuthHost
	if event := debugProxyEvent("reverse_proxy_start", requestID); event != nil {
		event.Str("route_type", "host_location").
			Str("route_key", logger.SanitizeLogString(hostLocationRouteKey(&matchedRule, &location))).
			Str("target", logger.SanitizeURL(targetURL.String())).
			Str("transport_target", logger.SanitizeURL(transportTargetURL.String())).
			Bool("omit_forwarded_headers", omitForwardedHeaders).
			Bool("preserve_host", preserveHost).
			Bool("strip_path", location.StripPath).
			Bool("rewrite_html", targetSupportsHTMLFeatures && location.RewriteHTML).
			Bool("toolbar_candidate", toolbarCandidate).
			Send()
	}

	proxy := &httputil.ReverseProxy{
		Transport:  transport,
		BufferPool: sharedProxyBufferPool,
		Rewrite: func(pr *httputil.ProxyRequest) {
			applyForwardedHeaderPolicy(pr.Out, pr.In, clientIP, omitForwardedHeaders)
			copyUserAgentHeader(pr.Out, pr.In)
			stripAdvancedAuthGrantCookie(pr.Out.Header)
			pr.SetURL(transportTargetURL)
			applyBasicAuthInjection(pr.Out, matchedRule.BasicAuth)
			applyUpstreamPrivateIPv4HintHeader(pr.Out, transportTargetURL)
			applyPreserveHostPolicy(pr.Out, pr.In, transportTargetURL, preserveHost)
			h.maybePrepareFnosPortIconHijackHTTPProxyRequest(pr.Out)
			applyReverseProxyRoutePath(pr.Out.URL, reverseProxyRoutePathOptions{
				targetURL:  transportTargetURL,
				incoming:   pr.In.URL,
				stripPath:  location.StripPath,
				pathPrefix: location.Path,
			})

			if !preserveHost {
				if origin := pr.In.Header.Get("Origin"); origin != "" {
					pr.Out.Header.Set("Origin", transportTargetURL.Scheme+"://"+transportTargetURL.Host)
				}
				if referer := pr.In.Header.Get("Referer"); referer != "" {
					ref, err := url.Parse(referer)
					if err == nil {
						ref.Scheme = transportTargetURL.Scheme
						ref.Host = transportTargetURL.Host
						ref.Path = path.Clean(ref.Path)
						applyReverseProxyRoutePath(ref, reverseProxyRoutePathOptions{
							targetURL:  transportTargetURL,
							incoming:   ref,
							stripPath:  location.StripPath,
							pathPrefix: location.Path,
						})
						pr.Out.Header.Set("Referer", ref.String())
					}
				}
			}

			if (targetSupportsHTMLFeatures && location.RewriteHTML) || toolbarCandidate {
				pr.Out.Header.Del("Accept-Encoding")
			}
			if event := debugProxyEvent("reverse_proxy_rewrite", requestID); event != nil {
				event.Str("route_type", "host_location").
					Str("target_url", logger.SanitizeURL(pr.Out.URL.String())).
					Str("out_host", logger.SanitizeLogString(pr.Out.Host)).
					Interface("out_header_names", logger.SanitizedHeaderNames(pr.Out.Header)).
					Send()
			}
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if event := debugProxyEvent("reverse_proxy_error", requestID); event != nil {
				event.Str("route_type", "host_location").
					Str("target", logger.SanitizeURL(targetURL.String())).
					Str("error", logger.SanitizeLogString(err.Error())).
					Send()
			}
			log.Printf("Host location proxy error: %v", err)
			response.HTMLWithSelectLink(w, r, errors.CodeProxyTimeout, "Upstream unavailable: "+err.Error(), snapshot.rules, authResult.authenticated)
		},
	}

	proxy.ModifyResponse = func(resp *http.Response) error {
		stripAdvancedAuthGrantSetCookies(resp.Header)
		if isAuthHostProxy {
			setCookies := resp.Header.Values("Set-Cookie")
			if shouldDisableAuthResponseCaching(r.URL.Path) || len(setCookies) > 0 {
				applyNoStoreCacheHeaders(resp.Header)
			}
			h.authCacheInvalidateForSetCookieMutation(r, clientIP, setCookies)
		}
		if err := h.maybeRewriteFnosPortIconHijackHTTPResponse(resp, snapshot.hostRules); err != nil {
			return err
		}

		needsRewrite := targetSupportsHTMLFeatures && location.RewriteHTML
		needsToolbar := toolbarCandidate
		if event := debugProxyEvent("reverse_proxy_response", requestID); event != nil {
			event.Str("route_type", "host_location").
				Int("status", resp.StatusCode).
				Str("content_type", logger.SanitizeLogString(resp.Header.Get("Content-Type"))).
				Bool("rewrite_html", needsRewrite).
				Bool("toolbar", needsToolbar).
				Int64("content_length", resp.ContentLength).
				Interface("response_headers", logger.SanitizeHeader(resp.Header)).
				Send()
		}
		if !needsRewrite && !needsToolbar {
			return nil
		}

		if needsRewrite {
			if locationHeader := resp.Header.Get("Location"); locationHeader != "" {
				if strings.HasPrefix(locationHeader, "/") {
					resp.Header.Set("Location", location.Path+locationHeader)
				}
			}
		}

		return maybeMutateHTMLProxyResponse(resp, htmlResponseMutationOptions{
			rewrite:       needsRewrite,
			rewritePrefix: strings.TrimSuffix(location.Path, "/"),
			toolbar:       needsToolbar,
			toolbarHTML: func() string {
				return response.GenerateToolbarWithPrefilteredHostsForRequest(
					r,
					snapshot.toolbarRules,
					filterAvailableHostRules(snapshot.toolbarHostRules, time.Now()),
					r.URL.Path,
					matchedRule.Host,
					snapshot.authConfig.AuthHost,
					snapshot.gatewayPortal,
				)
			},
			requestID: requestID,
			routeType: "host_location",
			routeKey:  hostLocationRouteKey(&matchedRule, &location),
		})
	}

	if h.maybeProxyFnosPortIconHijackWebSocket(w, r, fnosPortIconHijackWebSocketOptions{
		targetURL:            transportTargetURL,
		hostRules:            snapshot.hostRules,
		clientIP:             clientIP,
		omitForwardedHeaders: omitForwardedHeaders,
		preserveHost:         preserveHost,
		basicAuth:            matchedRule.BasicAuth,
		rewriteOriginReferer: !preserveHost,
		stripPath:            location.StripPath,
		pathPrefix:           location.Path,
	}) {
		return
	}

	serveReverseProxyWithResponseCoalescing(proxy, w, r)
}

func (h *Handler) proxyToHostTarget(w http.ResponseWriter, r *http.Request, snapshot requestSnapshot, matchedRule models.HostRule, clientIP string, authResult authCheckResult, requestID string) {
	targetRuntime := reverseProxyTargetRuntimeFor(snapshot, matchedRule.Target)
	if targetRuntime.err != nil {
		if event := debugProxyEvent("reverse_proxy_target_invalid", requestID); event != nil {
			event.Str("route_type", "host_rule").
				Str("route_key", logger.SanitizeLogString(matchedRule.Host)).
				Str("target", logger.SanitizeURL(matchedRule.Target)).
				Str("error", logger.SanitizeLogString(targetRuntime.err.Error())).
				Send()
		}
		response.HTMLWithSelectLink(w, r, errors.CodeProxyTargetInvalid, "Invalid target URL configuration", snapshot.rules, authResult.authenticated)
		return
	}
	targetURL := targetRuntime.targetURL
	transportTargetURL := targetRuntime.transportURL

	transport := h.proxyTransport
	if transport == nil {
		transport = newProxyTransport()
	}
	targetSupportsHTMLFeatures := targetRuntime.supportsHTMLFeatures
	omitForwardedHeaders := h.shouldOmitForwardedHeaders(transportTargetURL)
	preserveHost := matchedRule.PreserveHost && !h.shouldOmitPreserveHost(transportTargetURL)
	gatewayPortalEnabled := snapshot.gatewayPortal.Enabled
	suppressToolbarForUA := response.ShouldSuppressToolbarForUserAgent(r.UserAgent())
	toolbarCandidate := targetSupportsHTMLFeatures && gatewayPortalEnabled && authResult.authenticated && !matchedRule.SuppressToolbar && !authResult.suppressToolbar && !suppressToolbarForUA
	isAuthHostProxy := snapshot.authConfig.AuthHost != "" && normalizeRequestHost(matchedRule.Host) == snapshot.authConfig.AuthHost
	if event := debugProxyEvent("reverse_proxy_start", requestID); event != nil {
		event.Str("route_type", "host_rule").
			Str("route_key", logger.SanitizeLogString(matchedRule.Host)).
			Str("target", logger.SanitizeURL(targetURL.String())).
			Str("transport_target", logger.SanitizeURL(transportTargetURL.String())).
			Bool("omit_forwarded_headers", omitForwardedHeaders).
			Bool("preserve_host", preserveHost).
			Bool("toolbar_candidate", toolbarCandidate).
			Send()
	}

	proxy := &httputil.ReverseProxy{
		Transport:  transport,
		BufferPool: sharedProxyBufferPool,
		Rewrite: func(pr *httputil.ProxyRequest) {
			applyForwardedHeaderPolicy(pr.Out, pr.In, clientIP, omitForwardedHeaders)
			copyUserAgentHeader(pr.Out, pr.In)
			stripAdvancedAuthGrantCookie(pr.Out.Header)
			pr.SetURL(transportTargetURL)
			applyBasicAuthInjection(pr.Out, matchedRule.BasicAuth)
			applyUpstreamPrivateIPv4HintHeader(pr.Out, transportTargetURL)
			applyPreserveHostPolicy(pr.Out, pr.In, transportTargetURL, preserveHost)
			h.maybePrepareFnosPortIconHijackHTTPProxyRequest(pr.Out)

			if !preserveHost {
				if origin := pr.In.Header.Get("Origin"); origin != "" {
					pr.Out.Header.Set("Origin", transportTargetURL.Scheme+"://"+transportTargetURL.Host)
				}
				if referer := pr.In.Header.Get("Referer"); referer != "" {
					ref, err := url.Parse(referer)
					if err == nil {
						ref.Scheme = transportTargetURL.Scheme
						ref.Host = transportTargetURL.Host
						pr.Out.Header.Set("Referer", ref.String())
					}
				}
			}

			if toolbarCandidate {
				pr.Out.Header.Del("Accept-Encoding")
			}
			if event := debugProxyEvent("reverse_proxy_rewrite", requestID); event != nil {
				event.Str("route_type", "host_rule").
					Str("target_url", logger.SanitizeURL(pr.Out.URL.String())).
					Str("out_host", logger.SanitizeLogString(pr.Out.Host)).
					Interface("out_header_names", logger.SanitizedHeaderNames(pr.Out.Header)).
					Send()
			}
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if event := debugProxyEvent("reverse_proxy_error", requestID); event != nil {
				event.Str("route_type", "host_rule").
					Str("target", logger.SanitizeURL(targetURL.String())).
					Str("error", logger.SanitizeLogString(err.Error())).
					Send()
			}
			log.Printf("Host proxy error: %v", err)
			response.HTMLWithSelectLink(w, r, errors.CodeProxyTimeout, "Upstream unavailable: "+err.Error(), snapshot.rules, authResult.authenticated)
		},
	}

	proxy.ModifyResponse = func(resp *http.Response) error {
		stripAdvancedAuthGrantSetCookies(resp.Header)
		if isAuthHostProxy {
			setCookies := resp.Header.Values("Set-Cookie")
			if shouldDisableAuthResponseCaching(r.URL.Path) || len(setCookies) > 0 {
				applyNoStoreCacheHeaders(resp.Header)
			}
			h.authCacheInvalidateForSetCookieMutation(r, clientIP, setCookies)
		}
		if err := h.maybeRewriteFnosPortIconHijackHTTPResponse(resp, snapshot.hostRules); err != nil {
			return err
		}

		needsToolbar := toolbarCandidate
		if event := debugProxyEvent("reverse_proxy_response", requestID); event != nil {
			event.Str("route_type", "host_rule").
				Int("status", resp.StatusCode).
				Str("content_type", logger.SanitizeLogString(resp.Header.Get("Content-Type"))).
				Bool("toolbar", needsToolbar).
				Int64("content_length", resp.ContentLength).
				Interface("response_headers", logger.SanitizeHeader(resp.Header)).
				Send()
		}
		if !needsToolbar {
			return nil
		}

		return maybeMutateHTMLProxyResponse(resp, htmlResponseMutationOptions{
			toolbar: needsToolbar,
			toolbarHTML: func() string {
				return response.GenerateToolbarWithPrefilteredHostsForRequest(
					r,
					snapshot.toolbarRules,
					filterAvailableHostRules(snapshot.toolbarHostRules, time.Now()),
					r.URL.Path,
					matchedRule.Host,
					snapshot.authConfig.AuthHost,
					snapshot.gatewayPortal,
				)
			},
			requestID: requestID,
			routeType: "host_rule",
			routeKey:  matchedRule.Host,
		})
	}

	if h.maybeProxyFnosPortIconHijackWebSocket(w, r, fnosPortIconHijackWebSocketOptions{
		targetURL:            transportTargetURL,
		hostRules:            snapshot.hostRules,
		clientIP:             clientIP,
		omitForwardedHeaders: omitForwardedHeaders,
		preserveHost:         preserveHost,
		basicAuth:            matchedRule.BasicAuth,
		rewriteOriginReferer: !preserveHost,
		stripPath:            false,
		pathPrefix:           "",
	}) {
		return
	}

	serveReverseProxyWithResponseCoalescing(proxy, w, r)
}

func (h *Handler) proxyToRuleTarget(w http.ResponseWriter, r *http.Request, snapshot requestSnapshot, matchedRule models.Rule, clientIP string, authResult authCheckResult, requestID string) {
	targetRuntime := reverseProxyTargetRuntimeFor(snapshot, matchedRule.Target)
	if targetRuntime.err != nil {
		if event := debugProxyEvent("reverse_proxy_target_invalid", requestID); event != nil {
			event.Str("route_type", "path_rule").
				Str("route_key", logger.SanitizeLogString(matchedRule.Path)).
				Str("target", logger.SanitizeURL(matchedRule.Target)).
				Str("error", logger.SanitizeLogString(targetRuntime.err.Error())).
				Send()
		}
		response.HTMLWithSelectLink(w, r, errors.CodeProxyTargetInvalid, "Invalid target URL configuration", snapshot.rules, authResult.authenticated)
		return
	}
	targetURL := targetRuntime.targetURL
	transportTargetURL := targetRuntime.transportURL

	transport := h.proxyTransport
	if transport == nil {
		transport = newProxyTransport()
	}
	targetSupportsHTMLFeatures := targetRuntime.supportsHTMLFeatures
	preserveHost := !h.shouldOmitPreserveHost(transportTargetURL)
	gatewayPortalEnabled := snapshot.gatewayPortal.Enabled
	suppressToolbarForUA := response.ShouldSuppressToolbarForUserAgent(r.UserAgent())
	toolbarCandidate := targetSupportsHTMLFeatures && gatewayPortalEnabled && authResult.authenticated && !authResult.suppressToolbar && !suppressToolbarForUA
	if event := debugProxyEvent("reverse_proxy_start", requestID); event != nil {
		event.Str("route_type", "path_rule").
			Str("route_key", logger.SanitizeLogString(matchedRule.Path)).
			Str("target", logger.SanitizeURL(targetURL.String())).
			Str("transport_target", logger.SanitizeURL(transportTargetURL.String())).
			Bool("preserve_host", preserveHost).
			Bool("strip_path", matchedRule.StripPath).
			Bool("rewrite_html", targetSupportsHTMLFeatures && matchedRule.RewriteHTML).
			Bool("toolbar_candidate", toolbarCandidate).
			Send()
	}
	proxy := &httputil.ReverseProxy{
		Transport:  transport,
		BufferPool: sharedProxyBufferPool,
		Rewrite: func(pr *httputil.ProxyRequest) {
			applyForwardedHeaderPolicy(pr.Out, pr.In, clientIP, false)
			copyUserAgentHeader(pr.Out, pr.In)
			stripAdvancedAuthGrantCookie(pr.Out.Header)
			scopeDockerAdminPanelRequestCookie(pr.Out, matchedRule.Path)
			pr.SetURL(transportTargetURL)
			applyUpstreamPrivateIPv4HintHeader(pr.Out, transportTargetURL)
			applyPreserveHostPolicy(pr.Out, pr.In, transportTargetURL, preserveHost)
			applyReverseProxyRoutePath(pr.Out.URL, reverseProxyRoutePathOptions{
				targetURL:  transportTargetURL,
				incoming:   pr.In.URL,
				stripPath:  matchedRule.StripPath,
				pathPrefix: matchedRule.Path,
			})

			if !preserveHost {
				if origin := pr.In.Header.Get("Origin"); origin != "" {
					pr.Out.Header.Set("Origin", transportTargetURL.Scheme+"://"+transportTargetURL.Host)
				}
				if referer := pr.In.Header.Get("Referer"); referer != "" {
					ref, err := url.Parse(referer)
					if err == nil {
						ref.Scheme = transportTargetURL.Scheme
						ref.Host = transportTargetURL.Host
						ref.Path = path.Clean(ref.Path)
						applyReverseProxyRoutePath(ref, reverseProxyRoutePathOptions{
							targetURL:  transportTargetURL,
							incoming:   ref,
							stripPath:  matchedRule.StripPath,
							pathPrefix: matchedRule.Path,
						})

						pr.Out.Header.Set("Referer", ref.String())
					}
				}
			}

			if (targetSupportsHTMLFeatures && matchedRule.RewriteHTML) || toolbarCandidate {
				pr.Out.Header.Del("Accept-Encoding")
			}
			h.maybePrepareFnosPortIconHijackHTTPProxyRequest(pr.Out)
			if event := debugProxyEvent("reverse_proxy_rewrite", requestID); event != nil {
				event.Str("route_type", "path_rule").
					Str("target_url", logger.SanitizeURL(pr.Out.URL.String())).
					Str("out_host", logger.SanitizeLogString(pr.Out.Host)).
					Interface("out_header_names", logger.SanitizedHeaderNames(pr.Out.Header)).
					Send()
			}
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if event := debugProxyEvent("reverse_proxy_error", requestID); event != nil {
				event.Str("route_type", "path_rule").
					Str("target", logger.SanitizeURL(targetURL.String())).
					Str("error", logger.SanitizeLogString(err.Error())).
					Send()
			}
			log.Printf("Proxy error: %v", err)
			response.HTMLWithSelectLink(w, r, errors.CodeProxyTimeout, "Upstream unavailable: "+err.Error(), snapshot.rules, authResult.authenticated)
		},
	}

	proxy.ModifyResponse = func(resp *http.Response) error {
		stripAdvancedAuthGrantSetCookies(resp.Header)
		scopeDockerAdminPanelResponseCookie(resp, matchedRule.Path)
		addProxyPathCookieIfChanged(resp, r, matchedRule.Path)
		if err := h.maybeRewriteFnosPortIconHijackHTTPResponse(resp, snapshot.hostRules); err != nil {
			return err
		}

		needsRewrite := targetSupportsHTMLFeatures && matchedRule.RewriteHTML && !matchedRule.UseRootMode
		needsToolbar := toolbarCandidate
		if event := debugProxyEvent("reverse_proxy_response", requestID); event != nil {
			event.Str("route_type", "path_rule").
				Int("status", resp.StatusCode).
				Str("content_type", logger.SanitizeLogString(resp.Header.Get("Content-Type"))).
				Bool("rewrite_html", needsRewrite).
				Bool("toolbar", needsToolbar).
				Int64("content_length", resp.ContentLength).
				Interface("response_headers", logger.SanitizeHeader(resp.Header)).
				Send()
		}
		if !needsRewrite && !needsToolbar {
			return nil
		}

		if needsRewrite {
			if location := resp.Header.Get("Location"); location != "" {
				if strings.HasPrefix(location, "/") {
					resp.Header.Set("Location", matchedRule.Path+location)
				}
			}
		}

		return maybeMutateHTMLProxyResponse(resp, htmlResponseMutationOptions{
			rewrite:       needsRewrite,
			rewritePrefix: strings.TrimSuffix(matchedRule.Path, "/"),
			toolbar:       needsToolbar,
			toolbarHTML: func() string {
				return response.GenerateToolbarWithPrefilteredHostsForRequest(r, snapshot.toolbarRules, nil, matchedRule.Path, "", "", snapshot.gatewayPortal)
			},
			requestID: requestID,
			routeType: "path_rule",
			routeKey:  matchedRule.Path,
		})
	}

	if h.maybeProxyFnosPortIconHijackWebSocket(w, r, fnosPortIconHijackWebSocketOptions{
		targetURL:            transportTargetURL,
		hostRules:            snapshot.hostRules,
		clientIP:             clientIP,
		omitForwardedHeaders: false,
		preserveHost:         preserveHost,
		rewriteOriginReferer: !preserveHost,
		stripPath:            matchedRule.StripPath,
		pathPrefix:           matchedRule.Path,
	}) {
		return
	}

	serveReverseProxyWithResponseCoalescing(proxy, w, r)
}

var (
	htmlRewriteHrefPattern   = []byte(`href="/`)
	htmlRewriteSrcPattern    = []byte(`src="/`)
	htmlRewriteActionPattern = []byte(`action="/`)
	htmlRewriteBasePattern   = []byte(`<base href="/">`)
	htmlRewriteSlashTail     = []byte(`/`)
	htmlRewriteBaseTail      = []byte(`/">`)
	htmlBodyCloseMarker      = []byte(`</body>`)
	htmlStartMarker          = []byte(`<html`)
	htmlHeadMarker           = []byte(`<head`)
	htmlBodyStartMarker      = []byte(`<body`)
	htmlDoctypeMarker        = []byte(`<!doctype`)
)

const (
	htmlProxyMutationBodyLimitBytes int64 = 2 * 1024 * 1024
	htmlToolbarStreamChunkSize            = 32 * 1024
	htmlToolbarStreamTailBytes            = len("<!doctype") - 1
	htmlToolbarStreamMaxSegments          = 5
)

var htmlToolbarStreamBufferPool = newProxyBufferPool(htmlToolbarStreamChunkSize)

type htmlResponseMutationOptions struct {
	rewrite       bool
	rewritePrefix string
	toolbar       bool
	toolbarHTML   func() string
	requestID     string
	routeType     string
	routeKey      string
}

type prependReadCloser struct {
	reader io.Reader
	closer io.Closer
}

func (rc *prependReadCloser) Read(p []byte) (int, error) {
	return rc.reader.Read(p)
}

func (rc *prependReadCloser) Close() error {
	if rc.closer == nil {
		return nil
	}
	return rc.closer.Close()
}

func maybeMutateHTMLProxyResponse(resp *http.Response, opts htmlResponseMutationOptions) error {
	if !opts.rewrite && !opts.toolbar {
		return nil
	}
	if resp == nil {
		logHTMLProxyMutation(opts, nil, "skipped", "no_response", 0, 0)
		return nil
	}
	if !isHTMLContentType(resp.Header.Get("Content-Type")) {
		logHTMLProxyMutation(opts, resp, "skipped", "not_html", 0, 0)
		return nil
	}
	if resp.Body == nil {
		logHTMLProxyMutation(opts, resp, "skipped", "no_body", 0, 0)
		return nil
	}
	if opts.toolbar && !opts.rewrite {
		toolbarHTML := ""
		if opts.toolbarHTML != nil {
			toolbarHTML = opts.toolbarHTML()
		}
		if toolbarHTML == "" {
			logHTMLProxyMutation(opts, resp, "skipped", "empty_toolbar", 0, 0)
			return nil
		}
		resp.Body = newStreamingToolbarReadCloser(resp.Body, toolbarHTML)
		resp.ContentLength = -1
		resp.Header.Del("Content-Length")
		logHTMLProxyMutation(opts, resp, "streaming", "", 0, 0)
		return nil
	}

	bodyBytes, skipReason, err := readHTMLProxyMutationBody(resp, htmlProxyMutationBodyLimitBytes)
	if err != nil {
		return err
	}
	if skipReason != "" {
		logHTMLProxyMutation(opts, resp, "skipped", skipReason, 0, 0)
		return nil
	}

	originalLen := len(bodyBytes)
	toolbarHTML := ""
	if opts.toolbar {
		if opts.toolbarHTML != nil {
			toolbarHTML = opts.toolbarHTML()
		}
	}
	bodyBytes = mutateHTMLProxyBody(bodyBytes, opts.rewrite, opts.rewritePrefix, toolbarHTML)

	resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	resp.ContentLength = int64(len(bodyBytes))
	resp.Header.Set("Content-Length", strconv.Itoa(len(bodyBytes)))
	logHTMLProxyMutation(opts, resp, "applied", "", originalLen, len(bodyBytes))
	return nil
}

func readHTMLProxyMutationBody(resp *http.Response, limit int64) ([]byte, string, error) {
	if resp == nil || resp.Body == nil {
		return nil, "no_body", nil
	}
	if resp.ContentLength > limit {
		return nil, "content_length_exceeds_limit", nil
	}

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, "", err
	}
	if int64(len(bodyBytes)) > limit {
		resp.Body = &prependReadCloser{
			reader: io.MultiReader(bytes.NewReader(bodyBytes), resp.Body),
			closer: resp.Body,
		}
		return nil, "stream_exceeds_limit", nil
	}

	_ = resp.Body.Close()
	return bodyBytes, "", nil
}

func logHTMLProxyMutation(opts htmlResponseMutationOptions, resp *http.Response, outcome string, reason string, originalBytes int, mutatedBytes int) {
	if event := debugProxyEvent("html_response_mutation", opts.requestID); event != nil {
		contentLength := int64(-1)
		contentType := ""
		if resp != nil {
			contentLength = resp.ContentLength
			contentType = resp.Header.Get("Content-Type")
		}
		event.Str("route_type", opts.routeType).
			Str("route_key", logger.SanitizeLogString(opts.routeKey)).
			Str("outcome", outcome).
			Str("reason", reason).
			Bool("rewrite_html", opts.rewrite).
			Bool("toolbar", opts.toolbar).
			Str("content_type", logger.SanitizeLogString(contentType)).
			Int64("content_length", contentLength).
			Int64("limit_bytes", htmlProxyMutationBodyLimitBytes).
			Int("original_bytes", originalBytes).
			Int("mutated_bytes", mutatedBytes).
			Send()
	}
}

type toolbarStreamSegment struct {
	data   []byte
	text   string
	offset int
}

type streamingToolbarReadCloser struct {
	source  io.ReadCloser
	toolbar string
	scratch []byte

	pending     [htmlToolbarStreamTailBytes]byte
	emitPrefix  [htmlToolbarStreamTailBytes]byte
	pendingLen  int
	segments    [htmlToolbarStreamMaxSegments]toolbarStreamSegment
	segmentNext int
	segmentLen  int

	injected        bool
	sawHTML         bool
	readError       error
	scratchReleased bool
}

func newStreamingToolbarReadCloser(source io.ReadCloser, toolbarHTML string) io.ReadCloser {
	scratch := htmlToolbarStreamBufferPool.Get()
	if len(scratch) < htmlToolbarStreamChunkSize {
		scratch = make([]byte, htmlToolbarStreamChunkSize)
	}
	return &streamingToolbarReadCloser{
		source:  source,
		toolbar: toolbarHTML,
		scratch: scratch[:htmlToolbarStreamChunkSize],
	}
}

func (rc *streamingToolbarReadCloser) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		if n := rc.readSegments(p); n > 0 {
			return n, nil
		}
		if rc.readError != nil {
			rc.releaseScratch()
			return 0, rc.readError
		}
		rc.readMore()
	}
}

func (rc *streamingToolbarReadCloser) Close() error {
	if rc == nil {
		return nil
	}
	rc.releaseScratch()
	if rc.source == nil {
		return nil
	}
	source := rc.source
	rc.source = nil
	return source.Close()
}

func (rc *streamingToolbarReadCloser) releaseScratch() {
	if rc == nil || rc.scratchReleased {
		return
	}
	rc.scratchReleased = true
	if rc.scratch != nil {
		htmlToolbarStreamBufferPool.Put(rc.scratch)
		rc.scratch = nil
	}
}

func (rc *streamingToolbarReadCloser) readSegments(p []byte) int {
	for rc.segmentNext < rc.segmentLen {
		segment := &rc.segments[rc.segmentNext]
		var n int
		if segment.data != nil {
			n = copy(p, segment.data[segment.offset:])
			if segment.offset+n == len(segment.data) {
				rc.segmentNext++
			} else {
				segment.offset += n
			}
		} else {
			n = copy(p, segment.text[segment.offset:])
			if segment.offset+n == len(segment.text) {
				rc.segmentNext++
			} else {
				segment.offset += n
			}
		}
		if n > 0 {
			return n
		}
	}
	return 0
}

func (rc *streamingToolbarReadCloser) readMore() {
	rc.segmentNext = 0
	rc.segmentLen = 0
	if rc.source == nil {
		rc.finish()
		rc.readError = io.EOF
		return
	}

	n, err := rc.source.Read(rc.scratch)
	if n > 0 {
		rc.process(rc.scratch[:n])
	}
	if err == io.EOF {
		rc.finish()
		rc.readError = io.EOF
		return
	}
	if err != nil {
		rc.flushPending()
		rc.readError = err
	}
}

func (rc *streamingToolbarReadCloser) process(chunk []byte) {
	if rc.injected {
		rc.appendBytes(chunk)
		return
	}

	oldPendingLen := rc.pendingLen
	copy(rc.emitPrefix[:oldPendingLen], rc.pending[:oldPendingLen])
	oldPending := rc.emitPrefix[:oldPendingLen]
	if !rc.sawHTML && containsAnyHTMLMarkerAcrossChunks(oldPending, chunk) {
		rc.sawHTML = true
	}

	if idx := indexFoldASCIIChunks(oldPending, chunk, htmlBodyCloseMarker); idx >= 0 {
		rc.appendLogicalRange(oldPending, chunk, 0, idx)
		rc.appendString(rc.toolbar)
		rc.appendLogicalRange(oldPending, chunk, idx, len(oldPending)+len(chunk))
		rc.pendingLen = 0
		rc.injected = true
		return
	}

	totalLen := len(oldPending) + len(chunk)
	keepLen := min(totalLen, htmlToolbarStreamTailBytes)
	flushLen := totalLen - keepLen
	rc.appendLogicalRange(oldPending, chunk, 0, flushLen)
	rc.copyLogicalRangeToPending(oldPending, chunk, flushLen, totalLen)
}

func (rc *streamingToolbarReadCloser) appendLogicalRange(prefix []byte, chunk []byte, start int, end int) {
	if start >= end {
		return
	}
	if start < len(prefix) {
		prefixEnd := min(end, len(prefix))
		rc.appendBytes(prefix[start:prefixEnd])
	}
	if end > len(prefix) {
		chunkStart := max(0, start-len(prefix))
		rc.appendBytes(chunk[chunkStart : end-len(prefix)])
	}
}

func (rc *streamingToolbarReadCloser) copyLogicalRangeToPending(prefix []byte, chunk []byte, start int, end int) {
	rc.pendingLen = 0
	if start >= end {
		return
	}
	if start < len(prefix) {
		prefixEnd := min(end, len(prefix))
		rc.pendingLen += copy(rc.pending[rc.pendingLen:], prefix[start:prefixEnd])
	}
	if end > len(prefix) {
		chunkStart := max(0, start-len(prefix))
		rc.pendingLen += copy(rc.pending[rc.pendingLen:], chunk[chunkStart:end-len(prefix)])
	}
}

func (rc *streamingToolbarReadCloser) appendBytes(data []byte) {
	if len(data) == 0 {
		return
	}
	rc.segments[rc.segmentLen] = toolbarStreamSegment{data: data}
	rc.segmentLen++
}

func (rc *streamingToolbarReadCloser) appendString(text string) {
	if text == "" {
		return
	}
	rc.segments[rc.segmentLen] = toolbarStreamSegment{text: text}
	rc.segmentLen++
}

func (rc *streamingToolbarReadCloser) finish() {
	if rc.injected {
		return
	}
	rc.flushPending()
	if rc.sawHTML && rc.toolbar != "" {
		rc.appendString(rc.toolbar)
		rc.injected = true
	}
}

func (rc *streamingToolbarReadCloser) flushPending() {
	if rc.pendingLen == 0 {
		return
	}
	rc.appendBytes(rc.pending[:rc.pendingLen])
	rc.pendingLen = 0
}

func containsAnyHTMLMarkerAcrossChunks(prefix []byte, chunk []byte) bool {
	if containsAnyHTMLMarkerFoldASCII(chunk) {
		return true
	}
	if len(prefix) == 0 {
		return false
	}

	var boundary [htmlToolbarStreamTailBytes * 2]byte
	n := copy(boundary[:], prefix)
	n += copy(boundary[n:], chunk[:min(len(chunk), htmlToolbarStreamTailBytes)])
	return containsAnyHTMLMarkerFoldASCII(boundary[:n])
}

func indexFoldASCIIChunks(prefix []byte, chunk []byte, marker []byte) int {
	if idx := indexFoldASCII(prefix, marker); idx >= 0 {
		return idx
	}
	if len(prefix) > 0 && len(marker) > 1 {
		start := max(0, len(prefix)-len(marker)+1)
		totalLen := len(prefix) + len(chunk)
		for i := start; i < len(prefix) && i+len(marker) <= totalLen; i++ {
			matched := true
			for j := range marker {
				position := i + j
				var value byte
				if position < len(prefix) {
					value = prefix[position]
				} else {
					value = chunk[position-len(prefix)]
				}
				if lowerASCII(value) != lowerASCII(marker[j]) {
					matched = false
					break
				}
			}
			if matched {
				return i
			}
		}
	}
	if idx := indexFoldASCII(chunk, marker); idx >= 0 {
		return len(prefix) + idx
	}
	return -1
}

func mutateHTMLProxyBody(body []byte, rewrite bool, prefix string, toolbarHTML string) []byte {
	if len(body) == 0 {
		return body
	}
	if !rewrite || prefix == "" {
		return injectToolbarIntoHTMLBytes(body, toolbarHTML)
	}

	insertAt := -1
	appendToolbarAtEnd := false
	if toolbarHTML != "" {
		if idx := lastIndexFoldASCII(body, htmlBodyCloseMarker); idx >= 0 {
			insertAt = idx
		} else {
			appendToolbarAtEnd = containsAnyHTMLMarkerFoldASCII(body)
		}
	}

	var out []byte
	last := 0
	for i := 0; i < len(body); {
		if i == insertAt {
			if out == nil {
				out = make([]byte, 0, len(body)+len(toolbarHTML)+htmlRewriteExtraCapacity(len(body), len(prefix)))
			}
			out = append(out, body[last:i]...)
			out = append(out, toolbarHTML...)
			last = i
			insertAt = -1
			continue
		}

		oldLen, headLen, tail := htmlAbsolutePathReplacement(body[i:])
		if oldLen == 0 {
			i++
			continue
		}
		if out == nil {
			out = make([]byte, 0, len(body)+len(toolbarHTML)+htmlRewriteExtraCapacity(len(body), len(prefix)))
		}
		out = append(out, body[last:i]...)
		out = append(out, body[i:i+headLen]...)
		out = append(out, prefix...)
		out = append(out, tail...)
		i += oldLen
		last = i
	}

	if out == nil {
		if appendToolbarAtEnd {
			out = make([]byte, 0, len(body)+len(toolbarHTML))
			out = append(out, body...)
			out = append(out, toolbarHTML...)
			return out
		}
		return body
	}
	out = append(out, body[last:]...)
	if insertAt >= 0 {
		out = append(out, toolbarHTML...)
	}
	if appendToolbarAtEnd {
		out = append(out, toolbarHTML...)
	}
	return out
}

func rewriteHTMLAbsolutePaths(body []byte, prefix string) []byte {
	if len(body) == 0 || prefix == "" {
		return body
	}

	var out []byte
	last := 0
	for i := 0; i < len(body); {
		oldLen, headLen, tail := htmlAbsolutePathReplacement(body[i:])
		if oldLen == 0 {
			i++
			continue
		}
		if out == nil {
			out = make([]byte, 0, len(body)+htmlRewriteExtraCapacity(len(body), len(prefix)))
		}
		out = append(out, body[last:i]...)
		out = append(out, body[i:i+headLen]...)
		out = append(out, prefix...)
		out = append(out, tail...)
		i += oldLen
		last = i
	}
	if out == nil {
		return body
	}
	out = append(out, body[last:]...)
	return out
}

func htmlRewriteExtraCapacity(bodyLen int, prefixLen int) int {
	if prefixLen <= 0 {
		return 0
	}
	extra := prefixLen * 16
	if quarter := bodyLen / 4; quarter > extra {
		extra = quarter
	}
	if maxExtra := prefixLen * 1024; extra > maxExtra {
		extra = maxExtra
	}
	return extra
}

func htmlAbsolutePathReplacement(s []byte) (oldLen int, headLen int, tail []byte) {
	if len(s) == 0 {
		return 0, 0, nil
	}
	switch s[0] {
	case 'h':
		if bytes.HasPrefix(s, htmlRewriteHrefPattern) {
			return len(`href="/`), len(`href="`), htmlRewriteSlashTail
		}
	case 's':
		if bytes.HasPrefix(s, htmlRewriteSrcPattern) {
			return len(`src="/`), len(`src="`), htmlRewriteSlashTail
		}
	case 'a':
		if bytes.HasPrefix(s, htmlRewriteActionPattern) {
			return len(`action="/`), len(`action="`), htmlRewriteSlashTail
		}
	case '<':
		if bytes.HasPrefix(s, htmlRewriteBasePattern) {
			return len(`<base href="/">`), len(`<base href="`), htmlRewriteBaseTail
		}
	}
	return 0, 0, nil
}

func injectToolbarIntoHTMLBytes(body []byte, toolbarHTML string) []byte {
	if toolbarHTML == "" || len(body) == 0 {
		return body
	}

	if idx := lastIndexFoldASCII(body, htmlBodyCloseMarker); idx != -1 {
		out := make([]byte, 0, len(body)+len(toolbarHTML))
		out = append(out, body[:idx]...)
		out = append(out, toolbarHTML...)
		out = append(out, body[idx:]...)
		return out
	}

	if containsAnyHTMLMarkerFoldASCII(body) {
		return append(body, toolbarHTML...)
	}

	return body
}

func containsAnyHTMLMarkerFoldASCII(s []byte) bool {
	for i := 0; i < len(s); i++ {
		if s[i] != '<' {
			continue
		}
		remaining := s[i:]
		if equalFoldASCIIPrefix(remaining, htmlStartMarker) ||
			equalFoldASCIIPrefix(remaining, htmlHeadMarker) ||
			equalFoldASCIIPrefix(remaining, htmlBodyStartMarker) ||
			equalFoldASCIIPrefix(remaining, htmlDoctypeMarker) {
			return true
		}
	}
	return false
}

func equalFoldASCIIPrefix(s []byte, prefix []byte) bool {
	return len(s) >= len(prefix) && equalFoldASCIIBytes(s[:len(prefix)], prefix)
}

func lastIndexFoldASCII(s []byte, substr []byte) int {
	if len(substr) == 0 {
		return len(s)
	}
	if len(substr) > len(s) {
		return -1
	}
	for i := len(s) - len(substr); i >= 0; i-- {
		if equalFoldASCIIBytes(s[i:i+len(substr)], substr) {
			return i
		}
	}
	return -1
}

func indexFoldASCII(s []byte, substr []byte) int {
	if len(substr) == 0 {
		return 0
	}
	if len(substr) > len(s) {
		return -1
	}
	last := len(s) - len(substr)
	for i := 0; i <= last; i++ {
		if equalFoldASCIIBytes(s[i:i+len(substr)], substr) {
			return i
		}
	}
	return -1
}

func equalFoldASCIIBytes(a []byte, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if lowerASCII(a[i]) != lowerASCII(b[i]) {
			return false
		}
	}
	return true
}

func lowerASCII(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

type authCheckErrorPage struct {
	code    int
	title   string
	message string
}

type authCheckPlan struct {
	result             authCheckResult
	setCookies         []string
	redirectLocation   string
	abortConnection    bool
	accessDeniedReason string
	errorPage          *authCheckErrorPage
	cacheScope         pb.AuthCacheScope
}

type authCheckExecution struct {
	entry *authCacheEntry
	plan  authCheckPlan
}

type combinedHTTPAuthExecution struct {
	preflight preflightDecision
	auth      authCheckExecution
	handled   bool
}

func preflightStopsHTTPAuthorization(decision preflightDecision) bool {
	return decision.deny || decision.accessDeniedReason != "" || decision.redirectLocation != ""
}

func (h *Handler) cachedCombinedHTTPAuth(r *http.Request, authConfig models.AuthConfig, now time.Time, preflightLookup preflightCacheLookup, canPreflightLookup bool, authLookup authCacheLookup, canAuthLookup bool) (preflightDecision, bool, authCheckExecution, bool) {
	var preflight preflightDecision
	preflightHit := false
	if canPreflightLookup && preflightCacheTTL(authConfig) > 0 {
		if entry, ok := h.preflightCacheGet(preflightLookup.cacheKey, now); ok {
			if shouldBypassFNAppNegativePreflightCache(r, entry.decision) {
				h.preflightCache.mu.Lock()
				h.preflightCache.deleteEntryLocked(preflightLookup.cacheKey)
				h.preflightCache.mu.Unlock()
			} else {
				preflight = entry.decision
				preflightHit = true
			}
		}
	}

	authExecution := authCheckExecution{}
	authHit := false
	if canAuthLookup && authCacheEnabled(authConfig) {
		if entry, cacheKey, ok := h.cachedAuthEntry(authLookup, now); ok {
			if shouldBypassFNAppUnauthorizedAuthCache(r, entry.result) {
				h.authCache.mu.Lock()
				h.authCache.deleteEntryLocked(cacheKey)
				h.authCache.mu.Unlock()
			} else {
				authExecution.entry = &entry
				authHit = true
			}
		}
	}
	return preflight, preflightHit, authExecution, authHit
}

func (h *Handler) storeCombinedHTTPAuth(r *http.Request, authConfig models.AuthConfig, response *pb.AuthorizeHttpResponse, execution combinedHTTPAuthExecution, preflightLookup preflightCacheLookup, canPreflightLookup bool, authLookup authCacheLookup, canAuthLookup bool) combinedHTTPAuthExecution {
	now := time.Now()
	if canPreflightLookup && response.GetPreflightCacheScope() == pb.AuthCacheScope_AUTH_CACHE_SCOPE_EXACT_REQUEST {
		if ttl := preflightCacheTTL(authConfig); ttl > 0 && !shouldBypassFNAppNegativePreflightCache(r, execution.preflight) {
			h.preflightCacheStore(preflightLookup.cacheKey, preflightCacheEntry{
				decision:    execution.preflight,
				expiresAt:   now.Add(ttl),
				identityKey: preflightLookup.identityKey,
			}, now)
		}
	}

	plan := execution.auth.plan
	if !canAuthLookup || plan.errorPage != nil || len(plan.setCookies) > 0 || shouldBypassFNAppUnauthorizedAuthCache(r, plan.result) {
		return execution
	}
	ttl := authCacheTTL(authConfig, plan.result)
	if ttl <= 0 {
		return execution
	}
	cacheKey := ""
	switch response.GetVerifyCacheScope() {
	case pb.AuthCacheScope_AUTH_CACHE_SCOPE_EXACT_REQUEST:
		cacheKey = authLookup.cacheKey
	case pb.AuthCacheScope_AUTH_CACHE_SCOPE_HOST:
		cacheKey = authLookup.hostCacheKey
	}
	if cacheKey == "" {
		return execution
	}
	entry := authCacheEntry{
		result:           plan.result,
		setCookies:       copySetCookieHeaders(plan.setCookies),
		redirectLocation: plan.redirectLocation,
		abortConnection:  plan.abortConnection,
		expiresAt:        now.Add(ttl),
		identityKey:      authLookup.identityKey,
	}
	h.authCacheStore(cacheKey, entry, now)
	execution.auth = authCheckExecution{entry: &entry}
	return execution
}

func (h *Handler) executeCombinedHTTPAuth(r *http.Request, authConfig models.AuthConfig, clientIP string, accessMode string, isMatch bool, requestID string, requestAuth *requestAuthContext) (combinedHTTPAuthExecution, bool) {
	bridge := h.authBridgeManager()
	if bridge == nil || !bridge.SupportsCapability(rpcbridge.CapabilityAuthorizeHTTPV1) {
		return combinedHTTPAuthExecution{}, false
	}

	preflightLookup, canPreflightLookup := buildPreflightCacheLookup(r, clientIP, accessMode, isMatch)
	authLookup, canAuthLookup := buildAuthCacheLookup(r, clientIP, accessMode)
	resolveCached := func(callRequest *http.Request, preflight preflightDecision, preflightHit bool, authExecution authCheckExecution, authHit bool) (combinedHTTPAuthExecution, bool) {
		switch {
		case preflightHit && (preflightStopsHTTPAuthorization(preflight) || authHit):
			return combinedHTTPAuthExecution{preflight: preflight, auth: authExecution, handled: true}, true
		case preflightHit:
			authExecution = h.executeAuthCheck(callRequest, authConfig, clientIP, accessMode, requestID, requestAuth)
			return combinedHTTPAuthExecution{preflight: preflight, auth: authExecution, handled: true}, true
		case authHit:
			preflight = h.runPreflight(callRequest, authConfig, clientIP, isMatch, accessMode, requestID, requestAuth)
			return combinedHTTPAuthExecution{preflight: preflight, auth: authExecution, handled: true}, true
		default:
			return combinedHTTPAuthExecution{}, false
		}
	}
	preflight, preflightHit, authExecution, authHit := h.cachedCombinedHTTPAuth(r, authConfig, time.Now(), preflightLookup, canPreflightLookup, authLookup, canAuthLookup)
	if !preflightHit && h.preflightSkipUntilUnixNano.Load() > time.Now().UnixNano() {
		if !authHit {
			authExecution = h.executeAuthCheck(r, authConfig, clientIP, accessMode, requestID, requestAuth)
		}
		return combinedHTTPAuthExecution{auth: authExecution, handled: true}, true
	}
	if preflightHit || authHit {
		return resolveCached(r, preflight, preflightHit, authExecution, authHit)
	}

	run := func(callRequest *http.Request) combinedHTTPAuthExecution {
		if preflight, preflightHit, authExecution, authHit := h.cachedCombinedHTTPAuth(callRequest, authConfig, time.Now(), preflightLookup, canPreflightLookup, authLookup, canAuthLookup); preflightHit || authHit {
			if !preflightHit && h.preflightSkipUntilUnixNano.Load() > time.Now().UnixNano() {
				if !authHit {
					authExecution = h.executeAuthCheck(callRequest, authConfig, clientIP, accessMode, requestID, requestAuth)
				}
				return combinedHTTPAuthExecution{auth: authExecution, handled: true}
			}
			if execution, resolved := resolveCached(callRequest, preflight, preflightHit, authExecution, authHit); resolved {
				return execution
			}
		}
		if h.preflightSkipUntilUnixNano.Load() > time.Now().UnixNano() {
			return combinedHTTPAuthExecution{
				auth:    h.executeAuthCheck(callRequest, authConfig, clientIP, accessMode, requestID, requestAuth),
				handled: true,
			}
		}

		start := time.Now()
		ctx, cancel := context.WithTimeout(callRequest.Context(), 5*time.Second)
		defer cancel()
		response, err := bridge.AuthorizeHTTP(ctx, &pb.AuthorizeHttpRequest{
			Context:            requestAuth.proto(false),
			Matched:            isMatch,
			Mode:               pb.HttpAuthMode_HTTP_AUTH_MODE_PREFLIGHT_AND_VERIFY,
			SubdomainRuleMatch: advancedAuthRuleMatchProto(callRequest),
		})
		if err != nil {
			if err == rpcbridge.ErrAuthBridgeCapabilityUnsupported {
				return combinedHTTPAuthExecution{}
			}
			if advancedAuthRuleMatchFromRequest(callRequest) != nil ||
				strings.Contains(callRequest.Header.Get("Cookie"), advancedAuthGrantCookieName+"=") {
				diagnostics.RecordSubdomainGrantStorageError()
			}
			cooldownUntil := time.Now().Add(preflightFailureCooldown).UnixNano()
			h.preflightSkipUntilUnixNano.Store(cooldownUntil)
			if event := debugProxyEvent("authorize_http_request_failed", requestID); event != nil {
				event.Str("error", logger.SanitizeLogString(err.Error())).
					Int64("duration_ms", time.Since(start).Milliseconds()).
					Send()
			}
			return combinedHTTPAuthExecution{auth: canceledAuthCheckExecution(err), handled: true}
		}
		h.preflightSkipUntilUnixNano.Store(0)
		if response.GetPreflight() == nil {
			return combinedHTTPAuthExecution{auth: canceledAuthCheckExecution(fmt.Errorf("auth bridge returned no preflight response")), handled: true}
		}
		execution := combinedHTTPAuthExecution{
			preflight: h.preflightDecisionFromResponse(response.GetPreflight(), requestID, start),
			handled:   true,
		}
		if preflightStopsHTTPAuthorization(execution.preflight) {
			return h.storeCombinedHTTPAuth(callRequest, authConfig, response, execution, preflightLookup, canPreflightLookup, authLookup, canAuthLookup)
		}
		if response.GetVerify() == nil {
			execution.auth = canceledAuthCheckExecution(fmt.Errorf("auth bridge returned no verify response"))
			return execution
		}
		execution.auth.plan = h.authCheckPlanFromResponse(callRequest, authConfig, accessMode, requestID, start, response.GetVerify())
		return h.storeCombinedHTTPAuth(callRequest, authConfig, response, execution, preflightLookup, canPreflightLookup, authLookup, canAuthLookup)
	}

	useSingleflight := advancedAuthRuleMatchFromRequest(r) == nil &&
		((canPreflightLookup && preflightCacheTTL(authConfig) > 0) || (canAuthLookup && authCacheEnabled(authConfig)))
	if !useSingleflight {
		execution := run(r)
		if !execution.handled {
			return combinedHTTPAuthExecution{}, false
		}
		return execution, true
	}

	sharedRequest := r.WithContext(context.WithoutCancel(r.Context()))
	key := "authorize-http:" + preflightLookup.cacheKey + ":" + authLookup.cacheKey
	resultCh := h.authCache.group.DoChan(key, func() (any, error) {
		return run(sharedRequest), nil
	})
	select {
	case result := <-resultCh:
		execution, _ := result.Val.(combinedHTTPAuthExecution)
		if !execution.handled {
			return combinedHTTPAuthExecution{}, false
		}
		return execution, true
	case <-r.Context().Done():
		return combinedHTTPAuthExecution{auth: canceledAuthCheckExecution(r.Context().Err()), handled: true}, true
	}
}

func (h *Handler) performAuthCheck(r *http.Request, authConfig models.AuthConfig, clientIP string, accessMode string, requestID string, requestAuth *requestAuthContext) authCheckPlan {
	if strings.TrimSpace(authConfig.AuthURL) == "" {
		if event := debugProxyEvent("auth_check_missing_auth_url", requestID); event != nil {
			event.Send()
		}
		log.Printf("Auth check requested but AuthURL is not configured")
		return authCheckPlan{
			result: authCheckResult{decision: "error"},
			errorPage: &authCheckErrorPage{
				code:    errors.CodeInternal,
				title:   "Authentication Service Not Configured",
				message: "Authentication Service Not Configured",
			},
		}
	}

	start := time.Now()
	if event := debugProxyEvent("auth_check_start", requestID); event != nil {
		event.Str("transport", "auth_bridge").
			Str("client_ip", logger.SanitizeLogString(clientIP)).
			Str("access_mode", logger.SanitizeLogString(accessMode)).
			Interface("forwarded_headers", logger.SanitizeHeader(http.Header{
				"X-Forwarded-Path":  []string{r.URL.RequestURI()},
				"X-Forwarded-Host":  []string{r.Host},
				"X-Forwarded-Proto": []string{requestScheme(r)},
			})).
			Bool("has_cookie", r.Header.Get("Cookie") != "").
			Bool("has_authorization", r.Header.Get("Authorization") != "").
			Send()
	}

	bridge := h.authBridgeManager()
	if bridge == nil {
		if advancedAuthRuleMatchFromRequest(r) != nil ||
			strings.Contains(r.Header.Get("Cookie"), advancedAuthGrantCookieName+"=") {
			diagnostics.RecordSubdomainGrantStorageError()
		}
		log.Printf("Auth request failed: %v", rpcbridge.ErrAuthBridgeUnavailable)
		return authCheckPlan{
			result: authCheckResult{decision: "error"},
			errorPage: &authCheckErrorPage{
				code:    errors.CodeProxyAuthFailed,
				title:   "Authentication Service Unavailable",
				message: "Authentication Service Unavailable",
			},
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	var resp *pb.VerifyAuthResponse
	var err error
	cacheScope := pb.AuthCacheScope_AUTH_CACHE_SCOPE_EXACT_REQUEST
	supportsCombined := bridge.SupportsCapability(rpcbridge.CapabilityAuthorizeHTTPV1)
	if supportsCombined {
		var combined *pb.AuthorizeHttpResponse
		combined, err = bridge.AuthorizeHTTP(ctx, &pb.AuthorizeHttpRequest{
			Context:            requestAuth.proto(false),
			Mode:               pb.HttpAuthMode_HTTP_AUTH_MODE_VERIFY_ONLY,
			SubdomainRuleMatch: advancedAuthRuleMatchProto(r),
		})
		if err == nil {
			resp = combined.GetVerify()
			cacheScope = combined.GetVerifyCacheScope()
			if resp == nil {
				err = fmt.Errorf("auth bridge returned no verify response")
			}
		}
	}
	if !supportsCombined || err == rpcbridge.ErrAuthBridgeCapabilityUnsupported {
		resp, err = bridge.VerifyAuth(ctx, &pb.VerifyAuthRequest{
			Context: requestAuth.proto(true),
		})
	}
	if err != nil {
		if advancedAuthRuleMatchFromRequest(r) != nil ||
			strings.Contains(r.Header.Get("Cookie"), advancedAuthGrantCookieName+"=") {
			diagnostics.RecordSubdomainGrantStorageError()
		}
		if event := debugProxyEvent("auth_check_request_failed", requestID); event != nil {
			event.Str("transport", "auth_bridge").
				Str("error", logger.SanitizeLogString(err.Error())).
				Int64("duration_ms", time.Since(start).Milliseconds()).
				Send()
		}
		log.Printf("Auth request failed: %v", err)
		return authCheckPlan{
			result: authCheckResult{decision: "error"},
			errorPage: &authCheckErrorPage{
				code:    errors.CodeProxyAuthFailed,
				title:   "Authentication Service Unavailable",
				message: "Authentication Service Unavailable",
			},
		}
	}
	plan := h.authCheckPlanFromResponse(r, authConfig, accessMode, requestID, start, resp)
	plan.cacheScope = cacheScope
	return plan
}

func (h *Handler) authCheckPlanFromResponse(r *http.Request, authConfig models.AuthConfig, accessMode string, requestID string, start time.Time, resp *pb.VerifyAuthResponse) authCheckPlan {
	responseHeaders := protoHeadersToHTTP(resp.GetResponseHeaders())
	setCookies := copySetCookieHeaders(append(copySetCookieHeaders(resp.GetSetCookies()), responseHeaders.Values("Set-Cookie")...))
	statusCode := int(resp.GetStatus())
	if statusCode <= 0 {
		if resp.GetSuccess() {
			statusCode = http.StatusOK
		} else {
			statusCode = http.StatusUnauthorized
		}
	}

	if resp.GetSuccess() {
		subdomainAccessCustom, allowedSubdomainHosts := parseAllowedSubdomainHosts(responseHeaders)
		credentialIdentity := parseAuthCredentialIdentity(responseHeaders)
		isSubdomainRuleGrant := resp.GetGrantKind() == pb.AuthGrantKind_AUTH_GRANT_KIND_SUBDOMAIN_RULE
		authenticated := true
		decision := strings.TrimSpace(resp.GetDecision())
		if isSubdomainRuleGrant {
			authenticated = resp.GetLoginAuthenticated()
			diagnostics.RecordSubdomainGrantState(resp.GetAuthGrantState())
			if decision == "" {
				decision = "subdomain_rule_allowed"
			}
		} else if decision == "" {
			decision = "passed"
		}
		if event := debugProxyEvent("auth_check_end", requestID); event != nil {
			event.Int("status", statusCode).
				Bool("success", true).
				Str("decision", decision).
				Str("credential_method", logger.SanitizeLogString(credentialIdentity.credentialMethod)).
				Str("credential_id", logger.SanitizeLogString(credentialIdentity.credentialID)).
				Str("linked_totp_id", logger.SanitizeLogString(credentialIdentity.linkedTOTPID)).
				Bool("suppress_toolbar", isSubdomainRuleGrant || resp.GetSuppressToolbar() || strings.EqualFold(responseHeaders.Get("X-Reauth-Access-Mode"), "fnos-share")).
				Bool("subdomain_access_custom", subdomainAccessCustom).
				Int("allowed_subdomain_hosts", len(allowedSubdomainHosts)).
				Int("set_cookie_count", len(setCookies)).
				Int64("duration_ms", time.Since(start).Milliseconds()).
				Interface("response_headers", logger.SanitizeHeader(responseHeaders)).
				Send()
		}
		return authCheckPlan{
			result: authCheckResult{
				allowed:               true,
				authenticated:         authenticated,
				suppressToolbar:       isSubdomainRuleGrant || resp.GetSuppressToolbar() || strings.EqualFold(responseHeaders.Get("X-Reauth-Access-Mode"), "fnos-share"),
				decision:              decision,
				subdomainAccessCustom: subdomainAccessCustom,
				allowedSubdomainHosts: allowedSubdomainHosts,
				credentialIdentity:    credentialIdentity,
				authRuleGroupID:       resp.GetAuthRuleGroupId(),
				authGrantState:        resp.GetAuthGrantState(),
				cacheMaxAgeSeconds:    resp.GetCacheMaxAgeSeconds(),
			},
			setCookies: setCookies,
		}
	}
	// A temporary-grant issuance limiter is deliberately fail-closed. Preserve
	// the bridge's 429 and Retry-After instead of converting it to a login
	// redirect or the generic access-denied page.
	if statusCode == http.StatusTooManyRequests {
		diagnostics.RecordSubdomainGrantRateLimited()
		retryAfter := strings.TrimSpace(responseHeaders.Get("Retry-After"))
		return authCheckPlan{
			result: authCheckResult{
				decision:   "rate_limited",
				statusCode: http.StatusTooManyRequests,
				retryAfter: retryAfter,
			},
			setCookies: setCookies,
		}
	}
	authMessage := strings.TrimSpace(resp.GetMessage())
	if advancedAuthRuleMatchFromRequest(r) != nil {
		diagnostics.RecordSubdomainGrantVersionRejected()
	}
	log.Printf("Auth failed: %s", authMessage)
	accessDeniedReason := normalizeReauthAccessDeniedReason(resp.GetAccessDeniedReason())
	if accessDeniedReason == "" {
		accessDeniedReason = normalizeReauthAccessDeniedReason(responseHeaders.Get(reauthAccessDeniedHeader))
	}
	if accessDeniedReason != "" {
		credentialIdentity := parseAuthCredentialIdentity(responseHeaders)
		if event := debugProxyEvent("auth_check_end", requestID); event != nil {
			event.Int("status", statusCode).
				Bool("success", false).
				Str("decision", "access_denied").
				Str("reason", logger.SanitizeLogString(accessDeniedReason)).
				Str("credential_id", logger.SanitizeLogString(credentialIdentity.credentialID)).
				Str("linked_totp_id", logger.SanitizeLogString(credentialIdentity.linkedTOTPID)).
				Str("message", logger.SanitizeLogString(authMessage)).
				Int("set_cookie_count", len(setCookies)).
				Int64("duration_ms", time.Since(start).Milliseconds()).
				Send()
		}
		return authCheckPlan{
			result:             authCheckResult{authenticated: credentialIdentity.hasCredential(), decision: "access_denied", credentialIdentity: credentialIdentity},
			setCookies:         setCookies,
			accessDeniedReason: accessDeniedReason,
		}
	}
	if accessMode == "strict_whitelist" {
		if event := debugProxyEvent("auth_check_end", requestID); event != nil {
			event.Int("status", statusCode).
				Bool("success", false).
				Str("decision", "denied").
				Str("message", logger.SanitizeLogString(authMessage)).
				Int("set_cookie_count", len(setCookies)).
				Int64("duration_ms", time.Since(start).Milliseconds()).
				Send()
		}
		return authCheckPlan{
			result:          authCheckResult{decision: "denied"},
			setCookies:      setCookies,
			abortConnection: true,
		}
	}
	redirectLocation := strings.TrimSpace(resp.GetRedirectLocation())
	if redirectLocation == "" {
		redirectLocation = strings.TrimSpace(responseHeaders.Get("X-Reauth-Redirect-Location"))
	}
	if redirectLocation != "" {
		if strings.HasPrefix(redirectLocation, "/") || strings.HasPrefix(redirectLocation, "http://") || strings.HasPrefix(redirectLocation, "https://") {
			if event := debugProxyEvent("auth_check_end", requestID); event != nil {
				event.Int("status", statusCode).
					Bool("success", false).
					Str("decision", "redirected").
					Str("redirect_location", logger.SanitizeURL(redirectLocation)).
					Str("message", logger.SanitizeLogString(authMessage)).
					Int("set_cookie_count", len(setCookies)).
					Int64("duration_ms", time.Since(start).Milliseconds()).
					Send()
			}
			return authCheckPlan{
				result:           authCheckResult{decision: "redirected"},
				setCookies:       setCookies,
				redirectLocation: redirectLocation,
			}
		}
	}

	loginURL := authLoginRedirectLocation(authConfig, r)

	if event := debugProxyEvent("auth_check_end", requestID); event != nil {
		event.Int("status", statusCode).
			Bool("success", false).
			Str("decision", "redirected").
			Str("redirect_location", logger.SanitizeURL(loginURL)).
			Str("message", logger.SanitizeLogString(authMessage)).
			Int("set_cookie_count", len(setCookies)).
			Int64("duration_ms", time.Since(start).Milliseconds()).
			Send()
	}
	return authCheckPlan{
		result:           authCheckResult{decision: "redirected"},
		setCookies:       setCookies,
		redirectLocation: loginURL,
	}
}

func authLoginRedirectLocation(authConfig models.AuthConfig, r *http.Request) string {
	originalURL := buildPublicRequestURL(r, authConfig, "")
	if originalURL == nil {
		originalURL = &url.URL{
			Scheme:   requestScheme(r),
			Host:     r.Host,
			Path:     r.URL.Path,
			RawQuery: r.URL.RawQuery,
		}
	}

	loginURL := buildPublicAuthLoginURL(authConfig, r, originalURL)
	if loginURL == nil {
		loginURL, _ = url.Parse("/__auth__/login")
		q := loginURL.Query()
		q.Set("redirect_uri", originalURL.String())
		loginURL.RawQuery = q.Encode()
	}
	return loginURL.String()
}

func (h *Handler) applyAuthCheckPlan(w http.ResponseWriter, r *http.Request, plan authCheckPlan, clientIP string, upstreamTarget string) authCheckResult {
	for _, setCookie := range plan.setCookies {
		w.Header().Add("Set-Cookie", setCookie)
	}
	if len(plan.setCookies) > 0 {
		applyNoStoreCacheHeaders(w.Header())
		h.authCacheInvalidateForSetCookieMutation(r, clientIP, plan.setCookies)
	}

	if plan.errorPage != nil {
		applyNoStoreCacheHeaders(w.Header())
		response.HTML(w, r, plan.errorPage.code, plan.errorPage.message, nil)
		return plan.result
	}
	if plan.result.statusCode == http.StatusTooManyRequests {
		applyNoStoreCacheHeaders(w.Header())
		if retryAfter := strings.TrimSpace(plan.result.retryAfter); retryAfter != "" {
			w.Header().Set("Retry-After", retryAfter)
		}
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		return plan.result
	}

	if plan.result.allowed {
		// A subdomain-rule grant is deliberately not a system login. Keep it
		// out of the active-login tracker so logout, portal state, and any
		// login-derived policy continue to see logged_in=false.
		if plan.result.authenticated {
			h.markLoggedInActive(r, clientIP, time.Now())
		}
		return plan.result
	}

	if plan.accessDeniedReason != "" || plan.result.decision == "access_denied" {
		response.AccessDenied(w, r)
		return plan.result
	}

	if h.fnAppMockService != nil {
		handled, err := h.fnAppMockService.handleUnauthorizedRequest(w, r, upstreamTarget)
		if err != nil {
			log.Printf("Failed to serve unauthorized FN App mock response: %v", err)
			return authCheckResult{decision: "error"}
		}
		if handled {
			return authCheckResult{decision: "fn_app_prompt"}
		}
	}

	if plan.abortConnection {
		suppressAccessLog(w)
		h.abortConnection(w)
		return plan.result
	}
	if plan.redirectLocation != "" {
		applyNoStoreCacheHeaders(w.Header())
		http.Redirect(w, r, plan.redirectLocation, http.StatusFound)
		return plan.result
	}
	return plan.result
}

func requestHasExplicitAuthIdentity(r *http.Request) bool {
	if r == nil {
		return false
	}
	headers := r.Header.Values("Cookie")
	if cookieHeaderValuesWithinDefaultLimit(headers) {
		for _, header := range headers {
			if cookieHeaderHasExplicitAuthIdentity(header) {
				return true
			}
		}
	}
	return strings.TrimSpace(r.Header.Get("Authorization")) != ""
}

func cookieHeaderHasExplicitAuthIdentity(header string) bool {
	for {
		part, rest, more := strings.Cut(header, ";")
		if cookiePartHasExplicitAuthIdentity(strings.TrimSpace(part)) {
			return true
		}
		if !more {
			return false
		}
		header = rest
	}
}

func cookiePartHasExplicitAuthIdentity(part string) bool {
	name, rawValue, _ := strings.Cut(part, "=")
	name = strings.TrimSpace(name)
	switch name {
	case authSessionCookieName, authShareSessionCookieName:
	default:
		return false
	}
	value, ok := parseCanonicalCookieValue(rawValue)
	return ok && value != ""
}

func shouldProbeAuthForToolbar(r *http.Request, authConfig models.AuthConfig, portalConfig models.GatewayPortalConfig) bool {
	return strings.TrimSpace(authConfig.AuthURL) != "" &&
		models.NormalizeGatewayPortalConfig(portalConfig).Enabled &&
		requestHasExplicitAuthIdentity(r) &&
		!response.ShouldSuppressToolbarForUserAgent(r.UserAgent())
}

func (h *Handler) cachedAuthEntry(lookup authCacheLookup, now time.Time) (authCacheEntry, string, bool) {
	if entry, ok := h.authCacheGet(lookup.cacheKey, now); ok {
		return entry, lookup.cacheKey, true
	}
	if lookup.hostCacheKey != "" {
		if entry, ok := h.authCacheGet(lookup.hostCacheKey, now); ok {
			return entry, lookup.hostCacheKey, true
		}
	}
	return authCacheEntry{}, "", false
}

func canceledAuthCheckExecution(_ error) authCheckExecution {
	return authCheckExecution{plan: authCheckPlan{
		result: authCheckResult{decision: "error"},
		errorPage: &authCheckErrorPage{
			code:    errors.CodeProxyAuthFailed,
			title:   "Authentication Service Unavailable",
			message: "Authentication Service Unavailable",
		},
	}}
}

func (h *Handler) executeAuthCheck(r *http.Request, authConfig models.AuthConfig, clientIP string, accessMode string, requestID string, requestAuth *requestAuthContext) authCheckExecution {
	now := time.Now()
	useCache := authCacheEnabled(authConfig)
	lookup, canLookup := buildAuthCacheLookup(r, clientIP, accessMode)
	if event := debugProxyEvent("auth_cache_lookup", requestID); event != nil {
		event.Bool("enabled", useCache).
			Bool("can_lookup", canLookup).
			Str("access_mode", logger.SanitizeLogString(accessMode)).
			Send()
	}

	if useCache && canLookup {
		if entry, cacheKey, ok := h.cachedAuthEntry(lookup, now); ok {
			if shouldBypassFNAppUnauthorizedAuthCache(r, entry.result) {
				h.authCache.mu.Lock()
				h.authCache.deleteEntryLocked(cacheKey)
				h.authCache.mu.Unlock()
				if event := debugProxyEvent("auth_cache_bypassed", requestID); event != nil {
					event.Str("reason", "fn_app_unauthorized").Send()
				}
			} else {
				if event := debugProxyEvent("auth_cache_hit", requestID); event != nil {
					event.Str("decision", entry.result.decision).
						Bool("allowed", entry.result.allowed).
						Bool("authenticated", entry.result.authenticated).
						Time("expires_at", entry.expiresAt).
						Send()
				}
				return authCheckExecution{entry: &entry}
			}
		}

		sharedRequest := r.WithContext(context.WithoutCancel(r.Context()))
		resultCh := h.authCache.group.DoChan(lookup.cacheKey, func() (any, error) {
			if entry, cacheKey, ok := h.cachedAuthEntry(lookup, time.Now()); ok {
				if shouldBypassFNAppUnauthorizedAuthCache(r, entry.result) {
					h.authCache.mu.Lock()
					h.authCache.deleteEntryLocked(cacheKey)
					h.authCache.mu.Unlock()
					if event := debugProxyEvent("auth_cache_bypassed", requestID); event != nil {
						event.Str("reason", "fn_app_unauthorized_singleflight").Send()
					}
				} else {
					if event := debugProxyEvent("auth_cache_hit", requestID); event != nil {
						event.Str("decision", entry.result.decision).
							Bool("allowed", entry.result.allowed).
							Bool("authenticated", entry.result.authenticated).
							Time("expires_at", entry.expiresAt).
							Send()
					}
					return authCheckExecution{entry: &entry}, nil
				}
			}

			plan := h.performAuthCheck(sharedRequest, authConfig, clientIP, accessMode, requestID, requestAuth)
			if plan.errorPage == nil && len(plan.setCookies) == 0 {
				if ttl := authCacheTTL(authConfig, plan.result); ttl > 0 {
					cacheKey := ""
					switch plan.cacheScope {
					case pb.AuthCacheScope_AUTH_CACHE_SCOPE_EXACT_REQUEST:
						cacheKey = lookup.cacheKey
					case pb.AuthCacheScope_AUTH_CACHE_SCOPE_HOST:
						cacheKey = lookup.hostCacheKey
					}
					if cacheKey == "" {
						return authCheckExecution{plan: plan}, nil
					}
					entry := authCacheEntry{
						result:           plan.result,
						setCookies:       copySetCookieHeaders(plan.setCookies),
						redirectLocation: plan.redirectLocation,
						abortConnection:  plan.abortConnection,
						expiresAt:        time.Now().Add(ttl),
						identityKey:      lookup.identityKey,
					}
					if !shouldBypassFNAppUnauthorizedAuthCache(r, plan.result) {
						h.authCacheStore(cacheKey, entry, time.Now())
						if event := debugProxyEvent("auth_cache_store", requestID); event != nil {
							event.Str("decision", entry.result.decision).
								Bool("allowed", entry.result.allowed).
								Bool("authenticated", entry.result.authenticated).
								Time("expires_at", entry.expiresAt).
								Send()
						}
					}
					return authCheckExecution{entry: &entry}, nil
				}
			}

			return authCheckExecution{plan: plan}, nil
		})
		select {
		case result := <-resultCh:
			execution, _ := result.Val.(authCheckExecution)
			return execution
		case <-r.Context().Done():
			return canceledAuthCheckExecution(r.Context().Err())
		}
	}

	plan := h.performAuthCheck(r, authConfig, clientIP, accessMode, requestID, requestAuth)
	return authCheckExecution{plan: plan}
}

func (h *Handler) applyToolbarAuthCacheEntry(w http.ResponseWriter, r *http.Request, entry authCacheEntry, clientIP string) authCheckResult {
	for _, setCookie := range entry.setCookies {
		w.Header().Add("Set-Cookie", setCookie)
	}
	if len(entry.setCookies) > 0 {
		applyNoStoreCacheHeaders(w.Header())
		h.authCacheInvalidateForSetCookieMutation(r, clientIP, entry.setCookies)
	}
	if entry.result.allowed && entry.result.authenticated {
		h.markLoggedInActive(r, clientIP, time.Now())
		return entry.result
	}
	return authCheckResult{allowed: true, decision: "not_required"}
}

func (h *Handler) applyToolbarAuthCheckPlan(w http.ResponseWriter, r *http.Request, plan authCheckPlan, clientIP string) authCheckResult {
	for _, setCookie := range plan.setCookies {
		w.Header().Add("Set-Cookie", setCookie)
	}
	if len(plan.setCookies) > 0 {
		applyNoStoreCacheHeaders(w.Header())
		h.authCacheInvalidateForSetCookieMutation(r, clientIP, plan.setCookies)
	}
	if plan.result.allowed && plan.result.authenticated {
		h.markLoggedInActive(r, clientIP, time.Now())
		return plan.result
	}
	return authCheckResult{allowed: true, decision: "not_required"}
}

func (h *Handler) checkAuthForToolbar(w http.ResponseWriter, r *http.Request, authConfig models.AuthConfig, clientIP string, requestID string, requestAuth *requestAuthContext) authCheckResult {
	execution := h.executeAuthCheck(r, authConfig, clientIP, "", requestID, requestAuth)
	if execution.entry != nil {
		return h.applyToolbarAuthCacheEntry(w, r, *execution.entry, clientIP)
	}
	return h.applyToolbarAuthCheckPlan(w, r, execution.plan, clientIP)
}

func (h *Handler) checkAuth(w http.ResponseWriter, r *http.Request, authConfig models.AuthConfig, clientIP string, accessMode string, upstreamTarget string, requestID string, requestAuth *requestAuthContext, prepared *authCheckExecution) authCheckResult {
	execution := authCheckExecution{}
	if prepared != nil {
		execution = *prepared
	} else {
		execution = h.executeAuthCheck(r, authConfig, clientIP, accessMode, requestID, requestAuth)
	}
	if execution.entry != nil {
		return h.applyAuthCacheEntry(w, r, *execution.entry, clientIP, upstreamTarget)
	}
	return h.applyAuthCheckPlan(w, r, execution.plan, clientIP, upstreamTarget)
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

func mergeQueryValues(dst url.Values, src url.Values) {
	for key, values := range src {
		dst.Del(key)
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func applyRequestPortToPublicAuthBase(baseURL *url.URL, r *http.Request, authConfig models.AuthConfig) {
	if authConfig.EdgeClientIPActive() || baseURL == nil || baseURL.Host == "" || baseURL.Port() != "" {
		return
	}

	requestPort := resolvedPublicPort(r, authConfig, baseURL.Scheme, "")
	if requestPort == "" || requestPort == defaultPortForScheme(baseURL.Scheme) {
		return
	}

	hostname := baseURL.Hostname()
	if hostname == "" {
		return
	}

	baseURL.Host = net.JoinHostPort(hostname, requestPort)
}

func buildPublicAuthLoginURL(authConfig models.AuthConfig, r *http.Request, originalURL *url.URL) *url.URL {
	if strings.TrimSpace(authConfig.PublicAuthBaseURL) == "" {
		return nil
	}

	baseURL, err := url.Parse(authConfig.PublicAuthBaseURL)
	if err != nil {
		return nil
	}
	applyRequestPortToPublicAuthBase(baseURL, r, authConfig)

	loginPath := strings.TrimSpace(authConfig.LoginURL)
	if loginPath == "" {
		loginPath = "/login"
	}

	var loginURL *url.URL
	if strings.HasPrefix(loginPath, "/#") || strings.HasPrefix(loginPath, "#") {
		loginURL = baseURL.ResolveReference(&url.URL{})
		if loginURL.Path == "" {
			loginURL.Path = "/"
		}
		loginURL.Fragment = strings.TrimPrefix(strings.TrimPrefix(loginPath, "/"), "#")
	} else {
		loginURL, err = baseURL.Parse(loginPath)
		if err != nil {
			return nil
		}
	}

	q := loginURL.Query()
	q.Set("redirect_uri", originalURL.String())
	loginURL.RawQuery = q.Encode()
	return loginURL
}

func buildInternalAuthLoginRedirect(loginPath string, rawQuery string) string {
	parsedLoginPath, err := url.Parse(strings.TrimSpace(loginPath))
	if err != nil {
		return ""
	}
	if parsedLoginPath.Fragment == "" && parsedLoginPath.RawQuery == "" {
		return ""
	}

	redirectPath := parsedLoginPath.Path
	if redirectPath == "" {
		redirectPath = "/"
	}

	redirectURL := &url.URL{
		Path: singleJoiningSlash("/__auth__", ensureLeadingSlash(redirectPath)),
	}
	query := redirectURL.Query()
	mergeQueryValues(query, parsedLoginPath.Query())
	if requestQuery, err := url.ParseQuery(rawQuery); err == nil {
		mergeQueryValues(query, requestQuery)
	}
	redirectURL.RawQuery = query.Encode()
	redirectURL.Fragment = parsedLoginPath.Fragment
	return redirectURL.String()
}
