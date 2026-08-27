package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	stderrors "errors"
	"fmt"
	"go-reauth-proxy/pkg/config"
	"go-reauth-proxy/pkg/deepmonitor"
	"go-reauth-proxy/pkg/diagnostics"
	"go-reauth-proxy/pkg/errors"
	"go-reauth-proxy/pkg/events"
	"go-reauth-proxy/pkg/gatewaylog"
	"go-reauth-proxy/pkg/grpc/pb"
	compiledipset "go-reauth-proxy/pkg/ipset"
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
	"net/url"
	"os"
	"path"
	"reflect"
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
	proxyCopyBufferSize                = 256 * 1024
	proxyMaxIdleConnections            = 2048
	proxyMaxIdleConnectionsPerHost     = 2048
	proxyIdleConnectionTimeout         = 90 * time.Second
	proxyTLSClientSessionCacheSize     = 256
	trafficCounterFlushBytes           = 1024 * 1024
	maxSignedAuthRequestBodyBytes  int = 4 * 1024 * 1024
)

var errAuthProxyRequestBodyTooLarge = stderrors.New("authentication request body is too large")

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
	wafChangeMu             sync.Mutex
	Rules                   []models.Rule
	HostRules               []models.HostRule
	VisibilityPolicies      map[string]models.CompiledIPSet
	StreamRules             []models.StreamRule
	StreamAccessPolicies    map[string]models.CompiledIPSet
	StreamAvailability      *models.StreamAvailability
	DefaultRoute            string
	AuthConfig              models.AuthConfig
	LoggingConfig           models.LoggingConfig
	AdminPort               int
	ProxyPort               int
	ProxyProtocolForce      bool
	ProxyProtocol           models.GatewayProxyProtocolConfig
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
	routeGeneration         string
	routeIncarnations       map[string]routeIncarnation

	configManager      *config.Manager
	sslConfig          models.SSLConfig
	gatewayLogManager  *gatewaylog.Manager
	deepMonitorManager *deepmonitor.Manager

	trafficTotalIn  atomic.Uint64
	trafficTotalOut atomic.Uint64
	trafficError5xx atomic.Uint64
	trafficByHost   sync.Map
	trafficByStream sync.Map

	fnAppMockService           *fnAppMockService
	loggedInActive             sync.Map
	authBridge                 authBridgeClient
	proxyTransport             *http.Transport
	proxyRoundTripper          http.RoundTripper
	preflightSkipUntilUnixNano atomic.Int64
	authCache                  authStateCache
	preflightCache             preflightStateCache
	loggedInActiveCount        atomic.Int64
	loggedInActiveCleanupNano  atomic.Int64
	reverseProxyThrottle       *reverseProxyThrottle
	reverseProxyThrottleExempt *reverseProxyThrottleExemptIPsRuntime
	trustedClientIPs           *gatewayTrustedClientIPsRuntime
	proxyProtocol              *gatewayProxyProtocolRuntime
	commonLocationExemptions   *commonLocationExemptionsRuntime
	gatewayVisibility          *gatewayVisibility
	compiledVisibilityPolicies map[string]*compiledipset.Set
	generalBlacklist           *generalBlacklistRuntime
	forwardedHeaders           *forwardedHeadersConfig
	preserveHost               *preserveHostConfig
	wafRuntime                 *proxywaf.Runtime
	systemEventClient          *events.Client
	throttleEventQueue         chan gatewayThrottleBlockedEvent
	visibilityEventQueue       chan gatewayVisibilityBlockedEvent
	visibilityDropped          atomic.Uint64
	visibilityDropWarnNano     atomic.Int64
	authHMACSecret             string
}

func (h *Handler) SetAuthBridgeManager(manager *rpcbridge.AuthBridgeManager) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.authBridge = manager
}

func (h *Handler) Close() {
	if h == nil {
		return
	}
	if h.gatewayLogManager != nil {
		h.gatewayLogManager.Close()
	}
	if h.deepMonitorManager != nil {
		h.deepMonitorManager.Close()
	}
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
	hostVisibility     map[string]*compiledipset.Set
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
	routeGeneration    string
	routeIDs           map[string]string
	// Runtime security policies are updated in place under their own locks
	// (pointers are stable for the lifetime of the Handler), so publishing the
	// pointers in the request snapshot keeps the per-request path free of the
	// coarse handler lock while reads always observe the latest policy.
	trustedClientIPs         *gatewayTrustedClientIPsRuntime
	generalBlacklist         *generalBlacklistRuntime
	commonLocationExemptions *commonLocationExemptionsRuntime
	gatewayVisibility        *gatewayVisibility
	crawlerBlocker           models.CrawlerBlockerConfig
}

type routeIncarnation struct {
	signature string
	id        string
}

type reverseProxyTargetRuntime struct {
	targetURL            *url.URL
	transportURL         *url.URL
	transportTarget      string
	policyKey            string
	supportsHTMLFeatures bool
	err                  error
}

type preflightDecision struct {
	deny               bool
	redirectLocation   string
	accessDeniedReason string
	serviceUnavailable bool
	retryAfter         string
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

func pathRouteIncarnationKey(rule *models.Rule) string {
	if rule == nil {
		return ""
	}
	return "path\x00" + rule.Path
}

func hostRouteIncarnationKey(rule *models.HostRule) string {
	if rule == nil {
		return ""
	}
	return "host\x00" + normalizeRequestHost(rule.Host)
}

func hostLocationRouteIncarnationKey(rule *models.HostRule, location *models.HostLocation) string {
	if rule == nil || location == nil {
		return ""
	}
	return hostRouteIncarnationKey(rule) + "\x00location\x00" + location.Match + "\x00" + location.Path
}

func pathRouteIncarnationSignature(rule *models.Rule) string {
	if rule == nil {
		return ""
	}
	return strings.TrimSpace(rule.Target) +
		"\x00strip=" + strconv.FormatBool(rule.StripPath) +
		"\x00root=" + strconv.FormatBool(rule.UseRootMode)
}

func hostRouteIncarnationSignature(rule *models.HostRule) string {
	if rule == nil {
		return ""
	}
	return strings.TrimSpace(rule.Target) +
		"\x00preserve=" + strconv.FormatBool(rule.PreserveHost)
}

func hostLocationRouteIncarnationSignature(
	rule *models.HostRule,
	location *models.HostLocation,
) string {
	if rule == nil || location == nil {
		return ""
	}
	return strings.TrimSpace(location.Target) +
		"\x00action=" + location.Action +
		"\x00strip=" + strconv.FormatBool(location.StripPath) +
		"\x00preserve=" + strconv.FormatBool(rule.PreserveHost)
}

func reconcileRouteIncarnations(
	existing map[string]routeIncarnation,
	rules []models.Rule,
	hostRules []models.HostRule,
) map[string]routeIncarnation {
	next := make(map[string]routeIncarnation, len(rules)+len(hostRules))
	add := func(key string, signature string) {
		if key == "" {
			return
		}
		if current, ok := existing[key]; ok && current.signature == signature && current.id != "" {
			next[key] = current
			return
		}
		next[key] = routeIncarnation{
			signature: signature,
			id:        newRouteGeneration(),
		}
	}
	for i := range rules {
		rule := &rules[i]
		add(pathRouteIncarnationKey(rule), pathRouteIncarnationSignature(rule))
	}
	for i := range hostRules {
		rule := &hostRules[i]
		add(hostRouteIncarnationKey(rule), hostRouteIncarnationSignature(rule))
		for locationIndex := range rule.Locations {
			location := &rule.Locations[locationIndex]
			add(
				hostLocationRouteIncarnationKey(rule, location),
				hostLocationRouteIncarnationSignature(rule, location),
			)
		}
	}
	return next
}

func routeIncarnationIDs(values map[string]routeIncarnation) map[string]string {
	if len(values) == 0 {
		return nil
	}
	result := make(map[string]string, len(values))
	for key, value := range values {
		if value.id != "" {
			result[key] = value.id
		}
	}
	return result
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

	h.mu.Lock()
	h.ensureRouteGenerationLocked()
	h.routeIncarnations = reconcileRouteIncarnations(
		h.routeIncarnations,
		h.Rules,
		h.HostRules,
	)
	s := h.buildRequestSnapshotLocked()
	h.mu.Unlock()
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
	hostVisibility := make(map[string]*compiledipset.Set, len(hostRules))
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
			if policy := h.compiledVisibilityPolicies[rule.Visibility.PolicyID]; policy != nil {
				hostVisibility[host] = policy
			}
		}
		if policy, err := compileAdvancedAuthPolicyWithSets(
			rule.AdvancedAuth,
			h.compiledVisibilityPolicies,
		); err == nil && policy != nil {
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
		rules:                    rules,
		rulesByLength:            rulesByLength,
		rulesByPath:              rulesByPath,
		hostRules:                hostRules,
		hostRulesByHost:          hostRulesByHost,
		hostVisibility:           hostVisibility,
		advancedAuth:             advancedAuth,
		defaultHostRule:          defaultHostRule,
		targets:                  targets,
		toolbarRules:             toolbarRules,
		toolbarHostRules:         toolbarHostRules,
		defaultRoute:             h.DefaultRoute,
		defaultRule:              defaultRule,
		authConfig:               h.AuthConfig,
		gatewayPortal:            models.NormalizeGatewayPortalConfig(h.GatewayPortal),
		unmatchedRoute:           models.NormalizeGatewayUnmatchedRouteConfig(h.GatewayUnmatchedRoute),
		proxyProtocolForce:       h.ProxyProtocolForce,
		routeGeneration:          h.routeGeneration,
		routeIDs:                 routeIncarnationIDs(h.routeIncarnations),
		trustedClientIPs:         h.trustedClientIPs,
		generalBlacklist:         h.generalBlacklist,
		commonLocationExemptions: h.commonLocationExemptions,
		gatewayVisibility:        h.gatewayVisibility,
		crawlerBlocker:           h.CrawlerBlocker,
	}
}

func (h *Handler) publishRequestSnapshotLocked() {
	h.ensureRouteGenerationLocked()
	h.routeIncarnations = reconcileRouteIncarnations(
		h.routeIncarnations,
		h.Rules,
		h.HostRules,
	)
	h.requestState.Store(h.buildRequestSnapshotLocked())
}

func (h *Handler) ensureRouteGenerationLocked() {
	if h.routeGeneration == "" {
		h.routeGeneration = newRouteGeneration()
	}
}

func newRouteGeneration() string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err == nil {
		return hex.EncodeToString(value[:])
	}
	return strconv.FormatInt(time.Now().UnixNano(), 36)
}

func resolveClientIP(r *http.Request, authConfig models.AuthConfig, _ bool) string {
	if isManagedCloudflareTunnelIngress(r) {
		// The managed Tunnel has its own loopback destination, so only
		// Cloudflare's edge-generated client headers are authoritative here.
		// Never fall back to X-Forwarded-For: Cloudflare preserves client-sent
		// XFF values and appends to them, making the first value attacker-owned.
		return resolveManagedCloudflareClientIP(r)
	}

	if requestUsesProxyProtocolClientAddress(r.Context()) {
		return normalizeClientIP(r.RemoteAddr)
	}

	if authConfig.TencentEdgeOneActive() {
		if ip := normalizeIPAddress(r.Header.Get(headerEOConnectingIP)); ip != "" {
			return ip
		}
		if ip := firstForwardedClientIP(r.Header.Get("X-Forwarded-For")); ip != "" {
			return ip
		}
	}

	if authConfig.AliyunESAActive() {
		if ip := normalizeIPAddress(r.Header.Get(headerAliRealClientIP)); ip != "" {
			return ip
		}
		if ip := firstForwardedClientIP(r.Header.Get("X-Forwarded-For")); ip != "" {
			return ip
		}
	}

	// Ordinary direct connections use the socket peer. When PROXY protocol was
	// used, the marked branch above returned its transport-authenticated address.
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

func copyHostRulesForPersistence(rules []models.HostRule) []models.HostRule {
	copied := copyHostRules(rules)
	for i := range copied {
		// These flags record protobuf field presence for compatibility merges.
		// They are deliberately excluded from JSON and therefore must not make
		// an otherwise identical startup payload look like a persisted change.
		copied[i].GroupMetadataSet = false
		copied[i].AdvancedAuthSet = false
		if strings.TrimSpace(copied[i].Visibility.PolicyID) != "" {
			copied[i].Visibility.CIDRs = nil
		}
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
	r.ServiceProfile.EvidenceCodes = append([]string(nil), rule.ServiceProfile.EvidenceCodes...)
	r.ServiceProfile.Metadata = copyStringMap(rule.ServiceProfile.Metadata)
	r.BypassPolicy.Groups = make([]models.StreamBypassGroup, 0, len(rule.BypassPolicy.Groups))
	for _, group := range rule.BypassPolicy.Groups {
		nextGroup := models.StreamBypassGroup{ID: group.ID, Conditions: make([]models.StreamBypassCondition, 0, len(group.Conditions))}
		for _, condition := range group.Conditions {
			condition.CIDRs = append([]string(nil), condition.CIDRs...)
			nextGroup.Conditions = append(nextGroup.Conditions, condition)
		}
		r.BypassPolicy.Groups = append(r.BypassPolicy.Groups, nextGroup)
	}
	return &r
}

func copyStreamRules(rules []models.StreamRule) []models.StreamRule {
	copied := make([]models.StreamRule, 0, len(rules))
	for _, rule := range rules {
		copied = append(copied, *copyStreamRule(rule))
	}
	return copied
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
	transport.MaxIdleConns = proxyMaxIdleConnections
	transport.MaxIdleConnsPerHost = proxyMaxIdleConnectionsPerHost
	transport.IdleConnTimeout = proxyIdleConnectionTimeout
	transport.ForceAttemptHTTP2 = true
	return transport
}

type trackedUpstreamConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *trackedUpstreamConn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		diagnostics.CloseUpstreamConnection()
	}
	return c.Conn.Close()
}

func newProxyTransport() *http.Transport {
	transport := newInternalTransport()
	dialContext := (&net.Dialer{
		Timeout:   6 * time.Second,
		KeepAlive: 30 * time.Second,
	}).DialContext
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		connection, err := dialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		diagnostics.OpenUpstreamConnection()
		return &trackedUpstreamConn{Conn: connection}, nil
	}
	// Hardcode skipping upstream TLS verification for reverse-proxy targets.
	transport.TLSClientConfig = &tls.Config{
		InsecureSkipVerify: true,
		ClientSessionCache: tls.NewLRUClientSessionCache(proxyTLSClientSessionCacheSize),
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
	reauthServiceUnavailableReason    = "auth_service_unavailable"
	authServiceUnavailableMessage     = "Authentication Service Unavailable"
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
	context       *pb.AuthContext
	headers       http.Header
	routeIdentity string
	legacyOnce    sync.Once
}

type routedBackend struct {
	matched    bool
	target     string
	host       string
	routeID    string
	targetSet  bool
	hostSet    bool
	routeIDSet bool
}

func newRoutedBackend(target string, host string) routedBackend {
	return newRoutedBackendWithRouteID(target, host, "")
}

func newRoutedBackendWithRouteID(target string, host string, routeID string) routedBackend {
	return routedBackend{
		matched:    true,
		target:     strings.TrimSpace(target),
		host:       strings.TrimSpace(host),
		routeID:    strings.TrimSpace(routeID),
		targetSet:  true,
		hostSet:    true,
		routeIDSet: true,
	}
}

func (b routedBackend) cacheIdentity() string {
	if !b.matched {
		return "unmatched"
	}
	return "target=" + b.target + "\x00host=" + b.host + "\x00route=" + b.routeID
}

func newRequestAuthContext(r *http.Request, clientIP string, accessMode string, backend routedBackend) *requestAuthContext {
	var normalizedRoutedUpstream *string
	var normalizedRoutedUpstreamHost *string
	var normalizedRoutedUpstreamRouteID *string
	if backend.targetSet {
		normalizedTarget := backend.target
		normalizedRoutedUpstream = &normalizedTarget
	}
	if backend.hostSet {
		normalizedHost := backend.host
		normalizedRoutedUpstreamHost = &normalizedHost
	}
	if backend.routeIDSet {
		normalizedRouteID := backend.routeID
		normalizedRoutedUpstreamRouteID = &normalizedRouteID
	}
	if r == nil {
		return &requestAuthContext{routeIdentity: backend.cacheIdentity(), context: &pb.AuthContext{
			ClientIp:              clientIP,
			AccessMode:            accessMode,
			RoutedUpstream:        normalizedRoutedUpstream,
			RoutedUpstreamHost:    normalizedRoutedUpstreamHost,
			RoutedUpstreamRouteId: normalizedRoutedUpstreamRouteID,
		}}
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
		AccessToken:           r.Header.Get(headerAccessToken),
		AccessTokenHyphenated: r.Header.Get(headerAccessTokenDashed),
		RoutedUpstream:        normalizedRoutedUpstream,
		RoutedUpstreamHost:    normalizedRoutedUpstreamHost,
		RoutedUpstreamRouteId: normalizedRoutedUpstreamRouteID,
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
		context:       context,
		headers:       r.Header,
		routeIdentity: backend.cacheIdentity(),
	}
}

func authRouteIdentityForContext(r *http.Request, requestAuth *requestAuthContext) string {
	if requestAuth != nil && requestAuth.routeIdentity != "" {
		return requestAuth.routeIdentity
	}
	return authRouteIdentityFromRequest(r)
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

func applyInternalAuthProxyHeaders(req *http.Request, source *http.Request, targetURL *url.URL, clientIP string, authConfig models.AuthConfig, hmacSecret string, bodyDigest string) {
	if req == nil {
		return
	}

	if targetURL != nil {
		req.Host = targetURL.Host
		req.URL.Path = targetURL.Path
	}

	req.Header.Set(headerXRealIP, clientIP)
	req.Header.Set("X-Forwarded-For", clientIP)
	if source != nil {
		req.Header.Set("X-Forwarded-Host", source.Host)
		req.Header.Set("X-Forwarded-Proto", requestScheme(source))
	}
	switch {
	case authConfig.TencentEdgeOneActive() && clientIP != "":
		req.Header.Set(headerEOConnectingIP, clientIP)
		req.Header.Del(headerAliRealClientIP)
	case authConfig.AliyunESAActive() && clientIP != "":
		req.Header.Set(headerAliRealClientIP, clientIP)
		req.Header.Del(headerEOConnectingIP)
	default:
		req.Header.Del(headerAliRealClientIP)
		req.Header.Del(headerEOConnectingIP)
	}

	// Strip internal routing hints and any client-supplied real-IP header.
	req.Header.Del("X-Forwarded-Path")
	req.Header.Del("X-Match")
	req.Header.Del("X-Timestamp")
	req.Header.Del("X-Nonce")
	req.Header.Del("X-Signature")
	if strings.TrimSpace(hmacSecret) != "" {
		timestamp := strconv.FormatInt(time.Now().UnixMilli(), 10)
		nonceBytes := make([]byte, 16)
		if _, err := rand.Read(nonceBytes); err == nil {
			nonce := hex.EncodeToString(nonceBytes)
			message := canonicalInternalAuthRequestMessage(
				req.Method,
				req.URL.RequestURI(),
				bodyDigest,
				timestamp,
				nonce,
			)
			mac := hmac.New(sha256.New, []byte(hmacSecret))
			_, _ = mac.Write([]byte(message))
			req.Header.Set("X-Timestamp", timestamp)
			req.Header.Set("X-Nonce", nonce)
			req.Header.Set("X-Signature", hex.EncodeToString(mac.Sum(nil)))
		}
	}
	copyUserAgentHeader(req, source)
}

func canonicalInternalAuthRequestMessage(method string, requestURI string, bodyDigest string, timestamp string, nonce string) string {
	return strings.Join([]string{
		"fn-knock-v1",
		strings.ToUpper(method),
		requestURI,
		bodyDigest,
		timestamp,
		nonce,
	}, "\n")
}

func authProxyRequestBodyDigest(r *http.Request) (string, error) {
	hash := sha256.New()
	if r == nil || r.Body == nil {
		return hex.EncodeToString(hash.Sum(nil)), nil
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, int64(maxSignedAuthRequestBodyBytes)+1))
	if err != nil {
		_ = r.Body.Close()
		return "", err
	}
	_ = r.Body.Close()
	if len(body) > maxSignedAuthRequestBodyBytes {
		return "", errAuthProxyRequestBodyTooLarge
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	_, _ = hash.Write(body)
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func authProxyOriginAllowed(r *http.Request) bool {
	if r == nil || r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
		return true
	}
	if strings.EqualFold(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site")), "cross-site") {
		return false
	}
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	requestOrigin, err := url.Parse(requestScheme(r) + "://" + r.Host)
	if err != nil {
		return false
	}
	return strings.EqualFold(parsed.Scheme, requestOrigin.Scheme) &&
		strings.EqualFold(parsed.Hostname(), requestOrigin.Hostname()) &&
		effectiveOriginPort(parsed) == effectiveOriginPort(requestOrigin)
}

func effectiveOriginPort(value *url.URL) string {
	if port := value.Port(); port != "" {
		return port
	}
	if strings.EqualFold(value.Scheme, "https") {
		return "443"
	}
	return "80"
}

func applyForwardedHeaderPolicy(out *http.Request, in *http.Request, clientIP string, omitForwardedHeaders bool) {
	if out == nil {
		return
	}

	out.Header.Set(headerXRealIP, clientIP)
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

func (h *Handler) shouldOmitForwardedHeadersKey(key string) bool {
	if h == nil || h.forwardedHeaders == nil {
		return false
	}
	return h.forwardedHeaders.shouldOmitKey(key)
}

func (h *Handler) shouldOmitPreserveHost(target *url.URL) bool {
	if h == nil || h.preserveHost == nil {
		return false
	}
	return h.preserveHost.shouldOmit(target)
}

func (h *Handler) shouldOmitPreserveHostKey(key string) bool {
	if h == nil || h.preserveHost == nil {
		return false
	}
	return h.preserveHost.shouldOmitKey(key)
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
	dimensions, canLookup := buildAuthCacheDimensionsWithRouteIdentity(r, clientIP, accessMode, authRouteIdentityForContext(r, requestAuth))
	var lookup preflightCacheLookup
	if canLookup {
		lookup = dimensions.preflightLookup(isMatch)
	}
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
		failure := classifyAuthBridgeFailure(err)
		if event := debugProxyEvent("preflight_request_failed", requestID); event != nil {
			event.Str("cause", failure.cause).
				Time("cooldown_until", time.Unix(0, cooldownUntil)).
				Send()
		}
		log.Printf(
			"Auth bridge preflight failed: cause=%s cooldown=%s",
			failure.cause,
			preflightFailureCooldown,
		)
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
		retryAfter:         strings.TrimSpace(responseHeaders.Get("Retry-After")),
		credentialIdentity: parseAuthCredentialIdentity(responseHeaders),
	}
	rawAccessDeniedReason := strings.TrimSpace(resp.GetAccessDeniedReason())
	if rawAccessDeniedReason == "" {
		rawAccessDeniedReason = strings.TrimSpace(responseHeaders.Get(reauthAccessDeniedHeader))
	}
	decision.serviceUnavailable = strings.EqualFold(rawAccessDeniedReason, reauthServiceUnavailableReason)
	decision.accessDeniedReason = normalizeReauthAccessDeniedReason(rawAccessDeniedReason)
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
			Bool("service_unavailable", decision.serviceUnavailable).
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

func markConnectionResetStatus(w http.ResponseWriter) {
	for depth := 0; w != nil && depth < 16; depth++ {
		if trafficWriter, ok := w.(*trafficResponseWriter); ok {
			if !trafficWriter.metrics.wroteHeader {
				trafficWriter.metrics.statusCode = 499
			}
			return
		}
		unwrapper, ok := w.(interface {
			Unwrap() http.ResponseWriter
		})
		if !ok {
			return
		}
		w = unwrapper.Unwrap()
	}
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
		initialHostRules[i].TargetPathMode = models.NormalizeHostTargetPathMode(initialHostRules[i].TargetPathMode)
		initialHostRules[i].ProtocolMode = models.NormalizeHostProtocolMode(initialHostRules[i].ProtocolMode)
	}
	initialPolicies, initialCompiledPolicies, policyErr :=
		decodeVisibilityPolicies(initialCfg.VisibilityPolicies)
	if policyErr != nil {
		log.Printf("Failed to decode initial visibility policies: %v", policyErr)
		initialPolicies = make(map[string]models.CompiledIPSet)
		initialCompiledPolicies = make(map[string]*compiledipset.Set)
	}
	initialStreamPolicies, _, streamPolicyErr := decodeVisibilityPolicies(initialCfg.StreamAccessPolicies)
	if streamPolicyErr != nil {
		log.Printf("Failed to decode initial stream access policies: %v", streamPolicyErr)
		initialStreamPolicies = make(map[string]models.CompiledIPSet)
	}
	for i := range initialHostRules {
		visibility, err := prepareHostVisibilityPolicy(
			initialHostRules[i].Visibility,
			initialPolicies,
			initialCompiledPolicies,
		)
		if err != nil {
			log.Printf("Failed to prepare initial host visibility for %s: %v", initialHostRules[i].Host, err)
			initialHostRules[i].Visibility = models.HostRuleVisibility{
				Mode:     models.HostVisibilityModeCustom,
				PolicyID: strings.TrimSpace(initialHostRules[i].Visibility.PolicyID),
			}
			continue
		}
		initialHostRules[i].Visibility = visibility
	}
	initialVisibility, initialVisibilitySet, visibilityErr := prepareGatewayVisibilityPolicy(
		initialCfg.Visibility,
		initialPolicies,
		initialCompiledPolicies,
	)
	if visibilityErr != nil {
		log.Printf("Failed to prepare initial gateway visibility: %v", visibilityErr)
		initialVisibility = models.GatewayVisibilityConfig{
			Enabled:   initialCfg.Visibility.Enabled,
			UpdatedAt: strings.TrimSpace(initialCfg.Visibility.UpdatedAt),
		}
		initialVisibilitySet = nil
	}
	pruneVisibilityPolicies(initialHostRules, initialVisibility, initialPolicies, initialCompiledPolicies)

	deepMonitorManager, deepMonitorErr := deepmonitor.NewManager(logsDir)
	if deepMonitorErr != nil {
		log.Printf("Failed to initialize deep monitor storage: %v", deepMonitorErr)
	}
	proxyProtocolRuntime, proxyProtocolErr := newGatewayProxyProtocolRuntime(initialCfg.ProxyProtocol)
	if proxyProtocolErr != nil {
		log.Printf("Failed to load initial PROXY protocol config: %v", proxyProtocolErr)
		proxyProtocolRuntime, _ = newGatewayProxyProtocolRuntime(models.GatewayProxyProtocolConfig{
			TrustedSources: []string{},
		})
	}
	h := &Handler{
		Rules:                      initialCfg.Rules,
		HostRules:                  initialHostRules,
		VisibilityPolicies:         initialPolicies,
		StreamRules:                initialCfg.StreamRules,
		StreamAccessPolicies:       initialStreamPolicies,
		StreamAvailability:         models.CopyDailyAvailability(initialCfg.StreamAvailability),
		DefaultRoute:               initialCfg.DefaultRoute,
		AuthConfig:                 initialCfg.AuthConfig,
		LoggingConfig:              logConfig,
		AdminPort:                  adminPort,
		ProxyPort:                  proxyPort,
		ProxyProtocolForce:         initialCfg.ProxyProtocolForce,
		ProxyProtocol:              proxyProtocolRuntime.getConfig(),
		GatewayListener:            initialCfg.GatewayListener,
		ReverseProxyThrottle:       normalizeReverseProxyThrottleConfig(initialCfg.ReverseProxyThrottle),
		GatewayVisibility:          initialVisibility,
		ForwardedHeaders:           normalizedForwardedHeaders,
		PreserveHost:               normalizedPreserveHost,
		CrawlerBlocker:             normalizeCrawlerBlockerConfig(initialCfg.CrawlerBlocker),
		GatewayPortal:              models.NormalizeGatewayPortalConfig(initialCfg.Portal),
		GatewayUnmatchedRoute:      models.NormalizeGatewayUnmatchedRouteConfig(initialCfg.UnmatchedRoute),
		FnosPortIconHijack:         initialCfg.FnosPortIconHijack,
		GeneralBlacklist:           models.GeneralBlacklistConfig{Items: []models.GeneralBlacklistRecord{}},
		WAFConfig:                  wafConfig,
		configManager:              cfgManager,
		sslConfig:                  copySSLConfig(initialCfg.SSL),
		gatewayLogManager:          gatewaylog.NewManager(logsDir, logConfig),
		deepMonitorManager:         deepMonitorManager,
		fnAppMockService:           newFNAppMockServiceFromEnv(),
		authCache:                  newAuthStateCache(),
		preflightCache:             newPreflightStateCache(),
		generalBlacklist:           newGeneralBlacklistRuntime(initialCfg.GeneralBlacklist),
		proxyProtocol:              proxyProtocolRuntime,
		forwardedHeaders:           newForwardedHeadersConfig(normalizedForwardedHeaders),
		preserveHost:               newPreserveHostConfig(normalizedPreserveHost),
		wafRuntime:                 wafRuntime,
		systemEventClient:          systemEventClient,
		compiledVisibilityPolicies: initialCompiledPolicies,
		authHMACSecret:             strings.TrimSpace(os.Getenv("HMAC_SECRET")),
	}
	h.GeneralBlacklist = h.generalBlacklist.getConfig()
	h.proxyTransport = newProxyTransport()
	h.proxyRoundTripper = deepMonitorTransport{base: h.proxyTransport}
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
	h.trustedClientIPs = newGatewayTrustedClientIPsRuntime(
		models.GatewayTrustedClientIPsRuntime{},
	)
	h.commonLocationExemptions = newCommonLocationExemptionsRuntime(
		models.CommonLocationExemptionsRuntime{
			Enabled:    false,
			WAFEnabled: false,
			CIDRs:      []string{},
			UpdatedAt:  "",
		},
	)
	h.gatewayVisibility = newCompiledGatewayVisibility(initialVisibility, initialVisibilitySet)

	var emptyHook func()
	var emptyProxyProtocolHook func() error
	var emptyProtocolModeHook func([]string)
	h.sslOnChange.Store(emptyHook)
	h.protocolModeOnChange.Store(emptyProtocolModeHook)
	h.proxyProtocolOnChange.Store(emptyProxyProtocolHook)
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
	h.startGatewayVisibilityEventWorker()
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

func (h *Handler) SetProxyProtocolForceChangeHook(hook func() error) {
	h.proxyProtocolOnChange.Store(hook)
}

func (h *Handler) getProxyProtocolForceChangeHook() func() error {
	val := h.proxyProtocolOnChange.Load()
	if val == nil {
		return nil
	}
	hook, _ := val.(func() error)
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

func (h *Handler) saveConfigMutationLocked(update func(*config.AppConfig)) error {
	if h.configManager == nil {
		return nil
	}
	if update == nil {
		return nil
	}
	if err := h.configManager.Update(func(conf *config.AppConfig) error {
		update(conf)
		return nil
	}); err != nil {
		if event := debugProxyEvent("config_save_failed", ""); event != nil {
			event.Str("error", logger.SanitizeLogString(err.Error())).Send()
		}
		log.Printf("Failed to save config: %v", err)
		return err
	}
	if event := debugProxyEvent("config_saved", ""); event != nil {
		event.Int("path_rule_count", len(h.Rules)).
			Int("host_rule_count", len(h.HostRules)).
			Int("stream_rule_count", len(h.StreamRules)).
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
	h.wafChangeMu.Lock()
	defer h.wafChangeMu.Unlock()

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

	wafConfig := resetConfig.WAF
	var preparedWAF proxywaf.PreparedState
	if h.wafRuntime != nil {
		preparedWAF, err = h.wafRuntime.PrepareConfig(wafConfig)
		if err != nil {
			return fmt.Errorf("reset WAF runtime: %w", err)
		}
		wafConfig = preparedWAF.Config()
	}

	resetConfig.Rules = []models.Rule{}
	resetConfig.HostRules = []models.HostRule{}
	resetConfig.VisibilityPolicies = map[string]models.CompiledIPSet{}
	resetConfig.StreamRules = []models.StreamRule{}
	resetConfig.StreamAccessPolicies = map[string]models.CompiledIPSet{}
	resetConfig.StreamAvailability = nil
	resetConfig.ProxyProtocol = models.GatewayProxyProtocolConfig{TrustedSources: []string{}}
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
			return fmt.Errorf("persist reset gateway config: %w", err)
		}
	}

	reverseProxyThrottle := newReverseProxyThrottle(resetConfig.ReverseProxyThrottle)
	generalBlacklist := newGeneralBlacklistRuntime(resetConfig.GeneralBlacklist)
	reverseProxyThrottleExempt := newReverseProxyThrottleExemptIPsRuntime(
		models.ReverseProxyThrottleExemptIPsRuntime{},
	)
	trustedClientIPs := newGatewayTrustedClientIPsRuntime(
		models.GatewayTrustedClientIPsRuntime{},
	)
	proxyProtocol, _ := newGatewayProxyProtocolRuntime(resetConfig.ProxyProtocol)
	commonLocationExemptions := newCommonLocationExemptionsRuntime(
		models.CommonLocationExemptionsRuntime{},
	)

	h.mu.Lock()
	if h.wafRuntime != nil {
		h.wafRuntime.CommitPrepared(preparedWAF)
	}
	h.Rules = []models.Rule{}
	h.HostRules = []models.HostRule{}
	h.VisibilityPolicies = map[string]models.CompiledIPSet{}
	h.StreamRules = []models.StreamRule{}
	h.StreamAccessPolicies = map[string]models.CompiledIPSet{}
	h.StreamAvailability = nil
	h.DefaultRoute = resetConfig.DefaultRoute
	h.AuthConfig = resetConfig.AuthConfig
	h.LoggingConfig = loggingConfig
	h.ProxyProtocolForce = resetConfig.ProxyProtocolForce
	h.ProxyProtocol = resetConfig.ProxyProtocol
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
	h.trustedClientIPs = trustedClientIPs
	h.proxyProtocol = proxyProtocol
	h.commonLocationExemptions = commonLocationExemptions
	h.gatewayVisibility = visibility
	h.compiledVisibilityPolicies = map[string]*compiledipset.Set{}
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
	h.trafficByStream.Range(func(key, _ any) bool {
		h.trafficByStream.Delete(key)
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

func (h *Handler) persistGatewayVisibilityAndPoliciesLocked(
	visibility models.GatewayVisibilityConfig,
	policies map[string]models.CompiledIPSet,
) error {
	if h.configManager == nil {
		return nil
	}
	persistedVisibility := visibility
	persistedVisibility.CIDRs = nil
	persistedVisibility.Policy = nil
	policiesCopy := copyVisibilityPolicies(policies)
	return h.configManager.Update(func(conf *config.AppConfig) error {
		conf.Visibility = persistedVisibility
		conf.VisibilityPolicies = policiesCopy
		return nil
	})
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

func (h *Handler) evaluateReverseProxyThrottleRequest(isAuthRoute bool, matchedHostRule *models.HostRule, matchedHostLocation *models.HostLocation, matchedRule *models.Rule, clientIP string, trustedClientIP bool, now time.Time) reverseProxyThrottleDecision {
	if !isAuthRoute && matchedHostRule == nil && matchedRule == nil {
		return reverseProxyThrottleDecision{Allowed: true}
	}
	if h.reverseProxyThrottle == nil {
		return reverseProxyThrottleDecision{Allowed: true}
	}
	if trustedClientIP {
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
	trustedClientIP bool,
	requestID string,
) bool {
	checkedAt := time.Now()
	decision := h.evaluateReverseProxyThrottleRequest(
		isAuthRoute,
		matchedHostRule,
		matchedHostLocation,
		matchedRule,
		clientIP,
		trustedClientIP,
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

const (
	gatewayVisibilityEventQueueSize        = 64
	gatewayVisibilityEventDedupeKey        = "gateway-visibility:global"
	gatewayVisibilityEventDedupeTTLSeconds = 60
	gatewayVisibilityDropLogInterval       = time.Minute
)

type gatewayVisibilityBlockedEvent struct {
	ClientIP        string
	BlockedAt       time.Time
	Method          string
	Scheme          string
	Host            string
	Path            string
	RouteType       string
	RouteKey        string
	VisibilityScope string
	VisibilityMode  string
}

func (h *Handler) startGatewayVisibilityEventWorker() {
	if h == nil || h.systemEventClient == nil {
		return
	}
	if h.visibilityEventQueue == nil {
		h.visibilityEventQueue = make(chan gatewayVisibilityBlockedEvent, gatewayVisibilityEventQueueSize)
	}
	go func(queue <-chan gatewayVisibilityBlockedEvent) {
		for event := range queue {
			h.emitGatewayVisibilityBlockedEvent(event)
		}
	}(h.visibilityEventQueue)
}

func (h *Handler) enqueueGatewayVisibilityBlockedEvent(event gatewayVisibilityBlockedEvent) {
	if h == nil || h.systemEventClient == nil || h.visibilityEventQueue == nil {
		return
	}
	select {
	case h.visibilityEventQueue <- event:
	default:
		dropped, shouldLog := h.recordDroppedGatewayVisibilityEvent(time.Now())
		if shouldLog {
			log.Printf("Gateway visibility event queue full; dropped %d events", dropped)
		}
	}
}

func (h *Handler) recordDroppedGatewayVisibilityEvent(now time.Time) (uint64, bool) {
	if h == nil {
		return 0, false
	}
	dropped := h.visibilityDropped.Add(1)
	nowNano := now.UnixNano()
	for {
		last := h.visibilityDropWarnNano.Load()
		if last > 0 && nowNano-last < int64(gatewayVisibilityDropLogInterval) {
			return dropped, false
		}
		if h.visibilityDropWarnNano.CompareAndSwap(last, nowNano) {
			return dropped, true
		}
	}
}

func (h *Handler) emitGatewayVisibilityBlockedEvent(args gatewayVisibilityBlockedEvent) {
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
		Type:             events.FnEventGatewayVisibilityBlocked,
		Source:           events.SystemEventSourceGoReauthProxy,
		Level:            events.FnEventLevelWarn,
		HappenedAt:       args.BlockedAt.UTC().Format(time.RFC3339Nano),
		DedupeKey:        gatewayVisibilityEventDedupeKey,
		DedupeTTLSeconds: gatewayVisibilityEventDedupeTTLSeconds,
		Subject: &events.SystemEventSubject{
			Kind: events.SystemEventSubjectKindIP,
			ID:   normalizedIP,
		},
		Tags: []string{"gateway", "visibility", "security"},
		Payload: events.GatewayVisibilityBlockedPayload{
			IP:              normalizedIP,
			BlockedAt:       args.BlockedAt.UTC().Format(time.RFC3339Nano),
			Method:          args.Method,
			Scheme:          args.Scheme,
			Host:            args.Host,
			Path:            args.Path,
			RouteType:       args.RouteType,
			RouteKey:        args.RouteKey,
			VisibilityScope: args.VisibilityScope,
			VisibilityMode:  args.VisibilityMode,
			Status:          499,
		},
	})
	if err != nil {
		log.Printf("Failed to publish gateway visibility event for %s: %v", normalizedIP, err)
	}
}

func (h *Handler) SetSSLDeployment(candidate models.SSLConfig) error {
	normalized, err := normalizeSSLConfig(candidate)
	if err != nil {
		if event := debugProxyEvent("ssl_deployment_invalid", ""); event != nil {
			event.Str("error", logger.SanitizeLogString(err.Error())).
				Str("deployment_mode", string(candidate.DeploymentMode)).
				Int("certificate_count", len(candidate.Certificates)).
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
	previous := h.sslConfig
	h.sslConfig = normalized
	saveErr := h.saveConfigMutationLocked(func(conf *config.AppConfig) {
		conf.SSL = copySSLConfig(h.sslConfig)
		conf.SSLCert, conf.SSLKey = legacySSLPEMFromConfig(h.sslConfig)
	})
	if saveErr != nil {
		h.sslConfig = previous
		h.mu.Unlock()
		return saveErr
	}
	h.sslBundle.Store(bundle)
	hook := h.getSSLChangeHook()
	h.mu.Unlock()
	if hook != nil {
		hook()
	}
	if event := debugProxyEvent("ssl_deployment_set", ""); event != nil {
		event.Str("deployment_mode", string(normalized.DeploymentMode)).
			Int("certificate_count", len(normalized.Certificates)).
			Bool("enabled", len(normalized.Certificates) > 0).
			Send()
	}
	return nil
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
	h.mu.RLock()
	bundle := h.getSSLBundle()
	lanDeployment := models.SSLLANDeploymentInfo{
		Enabled:   h.sslConfig.LANDeployment.Enabled,
		Addresses: append([]string(nil), h.sslConfig.LANDeployment.Addresses...),
	}
	h.mu.RUnlock()
	return copySSLInfo(models.SSLInfo{
		Enabled:        bundle.hasCertificates(),
		DeploymentMode: bundle.mode,
		Certificates:   bundle.certificates,
		LANDeployment:  lanDeployment,
	})
}

func isReservedFnosSharePath(value string) bool {
	return value == "/s" || strings.HasPrefix(value, "/s/")
}

func (h *Handler) validateRule(newRule models.Rule) error {
	if newRule.Path == "/" || newRule.Path == "" {
		return fmt.Errorf("cannot add rule for root path '/' or empty path")
	}
	if newRule.Target == "" {
		return fmt.Errorf("cannot add rule with empty target")
	}
	if isReservedFnosSharePath(newRule.Path) {
		return fmt.Errorf("cannot add rule under reserved share path '/s'")
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
	previous := h.Rules
	if err := h.commitConfigMutationLocked(
		func() { h.Rules = nextRules },
		func() { h.Rules = previous },
		func(conf *config.AppConfig) {
			conf.Rules = append([]models.Rule(nil), h.Rules...)
		},
		h.publishRequestSnapshotLocked,
	); err != nil {
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
	h.clearAuthCache()
	return nil
}

func (h *Handler) SetRules(rules []models.Rule) error {
	normalized, err := h.normalizeRules(rules)
	if err != nil {
		return err
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	previous := h.Rules
	if err := h.commitConfigMutationLocked(
		func() { h.Rules = normalized },
		func() { h.Rules = previous },
		func(conf *config.AppConfig) {
			conf.Rules = append([]models.Rule(nil), h.Rules...)
		},
		h.publishRequestSnapshotLocked,
	); err != nil {
		return err
	}
	if event := debugProxyEvent("path_rules_set", ""); event != nil {
		event.Int("path_rule_count", len(normalized)).
			Interface("path_rules", debugRuleSummaries(normalized)).
			Send()
	}
	h.clearAuthCache()
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
	policyKey, _ := forwardedHeadersTargetKeyForURL(transportURL)
	return reverseProxyTargetRuntime{
		targetURL:            targetURL,
		transportURL:         transportURL,
		transportTarget:      transportURL.String(),
		policyKey:            policyKey,
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

func (h *Handler) RemoveRule(path string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	newRules := make([]models.Rule, 0, len(h.Rules))
	for _, rule := range h.Rules {
		if rule.Path != path {
			newRules = append(newRules, rule)
		}
	}
	previous := h.Rules
	if err := h.commitConfigMutationLocked(
		func() { h.Rules = newRules },
		func() { h.Rules = previous },
		func(conf *config.AppConfig) {
			conf.Rules = append([]models.Rule(nil), h.Rules...)
		},
		h.publishRequestSnapshotLocked,
	); err != nil {
		log.Printf("Failed to remove path rule %q: %v", path, err)
		return
	}
	if event := debugProxyEvent("path_rule_removed", ""); event != nil {
		event.Str("path", logger.SanitizeLogString(path)).
			Int("path_rule_count", len(h.Rules)).
			Send()
	}
	h.clearAuthCache()
}

func (h *Handler) FlushRules() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	nextRules := make([]models.Rule, 0)
	previous := h.Rules
	if err := h.commitConfigMutationLocked(
		func() { h.Rules = nextRules },
		func() { h.Rules = previous },
		func(conf *config.AppConfig) {
			conf.Rules = append([]models.Rule(nil), h.Rules...)
		},
		h.publishRequestSnapshotLocked,
	); err != nil {
		return err
	}
	if event := debugProxyEvent("path_rules_flushed", ""); event != nil {
		event.Send()
	}
	h.clearAuthCache()
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
	if isReservedFnosSharePath(location.Path) {
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
	newRule.TargetPathMode = models.NormalizeHostTargetPathMode(newRule.TargetPathMode)
	newRule.ProtocolMode = models.NormalizeHostProtocolMode(newRule.ProtocolMode)
	newRule.GroupID = strings.TrimSpace(newRule.GroupID)
	newRule.GroupName = strings.TrimSpace(newRule.GroupName)
	visibility, err := normalizeHostRuleVisibility(newRule.Visibility)
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
	targetPathModeMissing := strings.TrimSpace(newRule.TargetPathMode) == ""
	protocolModeMissing := strings.TrimSpace(newRule.ProtocolMode) == ""
	visibilityMissing := strings.TrimSpace(newRule.Visibility.Mode) == "" && len(newRule.Visibility.CIDRs) == 0
	groupMetadataMissing := !newRule.GroupMetadataSet &&
		strings.TrimSpace(newRule.GroupID) == "" &&
		strings.TrimSpace(newRule.GroupName) == ""
	newRule, err := h.normalizeHostRule(newRule)
	if err != nil {
		return err
	}

	h.mu.Lock()
	updated := false
	nextRules := make([]models.HostRule, 0, len(h.HostRules)+1)
	for _, rule := range h.HostRules {
		if normalizeRequestHost(rule.Host) == newRule.Host && !updated {
			if targetPathModeMissing {
				newRule.TargetPathMode = models.NormalizeHostTargetPathMode(rule.TargetPathMode)
			}
			if protocolModeMissing {
				newRule.ProtocolMode = models.NormalizeHostProtocolMode(rule.ProtocolMode)
			}
			if visibilityMissing {
				newRule.Visibility = rule.Visibility
				newRule.Visibility.CIDRs = append([]string(nil), rule.Visibility.CIDRs...)
			}
			if groupMetadataMissing {
				newRule.GroupID = rule.GroupID
				newRule.GroupName = rule.GroupName
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
	candidatePolicies := copyVisibilityPolicies(h.VisibilityPolicies)
	candidateSets := make(map[string]*compiledipset.Set, len(h.compiledVisibilityPolicies)+1)
	for id, set := range h.compiledVisibilityPolicies {
		candidateSets[id] = set
	}
	for i := range nextRules {
		visibility, visibilityErr := prepareHostVisibilityPolicy(
			nextRules[i].Visibility,
			candidatePolicies,
			candidateSets,
		)
		if visibilityErr != nil {
			h.mu.Unlock()
			return fmt.Errorf("host %s visibility: %w", nextRules[i].Host, visibilityErr)
		}
		nextRules[i].Visibility = visibility
		if _, advancedErr := compileAdvancedAuthPolicyWithSets(
			nextRules[i].AdvancedAuth,
			candidateSets,
		); advancedErr != nil {
			h.mu.Unlock()
			return fmt.Errorf("host %s advanced auth: %w", nextRules[i].Host, advancedErr)
		}
	}
	pruneVisibilityPolicies(nextRules, h.GatewayVisibility, candidatePolicies, candidateSets)
	changedProtocolHosts := changedHostProtocolModes(h.HostRules, nextRules)
	if err := h.persistHostRulesAndPoliciesLocked(nextRules, candidatePolicies); err != nil {
		h.mu.Unlock()
		return err
	}
	h.HostRules = nextRules
	h.VisibilityPolicies = candidatePolicies
	h.compiledVisibilityPolicies = candidateSets
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
	h.clearAuthCache()
	return nil
}

func (h *Handler) SetHostRules(rules []models.HostRule) error {
	return h.SetHostRulesBundle(rules, nil)
}

func (h *Handler) SetHostRulesBundle(
	rules []models.HostRule,
	incomingPolicies map[string]models.CompiledIPSet,
) error {
	decodedPolicies, decodedSets, err := decodeVisibilityPolicies(incomingPolicies)
	if err != nil {
		return err
	}
	normalizedRules := make([]models.HostRule, 0, len(rules))
	targetPathModeMissing := make([]bool, 0, len(rules))
	protocolModeMissing := make([]bool, 0, len(rules))
	visibilityMissing := make([]bool, 0, len(rules))
	groupMetadataMissing := make([]bool, 0, len(rules))
	indexByHost := make(map[string]int, len(rules))

	for _, rule := range rules {
		pathModeMissing := strings.TrimSpace(rule.TargetPathMode) == ""
		modeMissing := strings.TrimSpace(rule.ProtocolMode) == ""
		ruleVisibilityMissing := strings.TrimSpace(rule.Visibility.Mode) == "" && len(rule.Visibility.CIDRs) == 0
		ruleGroupMetadataMissing := !rule.GroupMetadataSet &&
			strings.TrimSpace(rule.GroupID) == "" &&
			strings.TrimSpace(rule.GroupName) == ""
		normalizedRule, err := h.normalizeHostRule(rule)
		if err != nil {
			return err
		}

		if idx, exists := indexByHost[normalizedRule.Host]; exists {
			normalizedRules[idx] = normalizedRule
			targetPathModeMissing[idx] = pathModeMissing
			protocolModeMissing[idx] = modeMissing
			visibilityMissing[idx] = ruleVisibilityMissing
			groupMetadataMissing[idx] = ruleGroupMetadataMissing
			continue
		}

		indexByHost[normalizedRule.Host] = len(normalizedRules)
		normalizedRules = append(normalizedRules, normalizedRule)
		targetPathModeMissing = append(targetPathModeMissing, pathModeMissing)
		protocolModeMissing = append(protocolModeMissing, modeMissing)
		visibilityMissing = append(visibilityMissing, ruleVisibilityMissing)
		groupMetadataMissing = append(groupMetadataMissing, ruleGroupMetadataMissing)
	}
	keepFirstDefaultHostRule(normalizedRules)

	h.mu.Lock()
	candidatePolicies := copyVisibilityPolicies(h.VisibilityPolicies)
	candidateSets := make(map[string]*compiledipset.Set, len(h.compiledVisibilityPolicies)+len(decodedSets))
	for id, set := range h.compiledVisibilityPolicies {
		candidateSets[id] = set
	}
	for id, policy := range decodedPolicies {
		candidatePolicies[id] = policy
		candidateSets[id] = decodedSets[id]
	}
	existingTargetPathModes := make(map[string]string, len(h.HostRules))
	existingModes := make(map[string]string, len(h.HostRules))
	existingVisibilities := make(map[string]models.HostRuleVisibility, len(h.HostRules))
	existingAdvancedAuth := make(map[string]models.AdvancedAuthConfig, len(h.HostRules))
	existingGroups := make(map[string][2]string, len(h.HostRules))
	for _, existingRule := range h.HostRules {
		host := normalizeRequestHost(existingRule.Host)
		if host == "" {
			continue
		}
		if _, exists := existingModes[host]; exists {
			continue
		}
		existingTargetPathModes[host] = models.NormalizeHostTargetPathMode(existingRule.TargetPathMode)
		existingModes[host] = models.NormalizeHostProtocolMode(existingRule.ProtocolMode)
		visibility := existingRule.Visibility
		visibility.CIDRs = append([]string(nil), existingRule.Visibility.CIDRs...)
		existingVisibilities[host] = visibility
		existingAdvancedAuth[host] = copyAdvancedAuthConfig(existingRule.AdvancedAuth)
		existingGroups[host] = [2]string{existingRule.GroupID, existingRule.GroupName}
	}
	for i := range normalizedRules {
		if targetPathModeMissing[i] {
			if existingMode, exists := existingTargetPathModes[normalizedRules[i].Host]; exists {
				normalizedRules[i].TargetPathMode = existingMode
			}
		}
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
		if groupMetadataMissing[i] {
			if existingGroup, exists := existingGroups[normalizedRules[i].Host]; exists {
				normalizedRules[i].GroupID = existingGroup[0]
				normalizedRules[i].GroupName = existingGroup[1]
			}
		}
		// Host mapping editors predating advanced authentication omit this
		// field entirely. Preserve an existing policy in that case so an
		// unrelated host edit cannot silently disable a security boundary.
		if !normalizedRules[i].AdvancedAuthSet &&
			isEmptyAdvancedAuthConfig(normalizedRules[i].AdvancedAuth) {
			if existingPolicy, exists := existingAdvancedAuth[normalizedRules[i].Host]; exists && !isEmptyAdvancedAuthConfig(existingPolicy) {
				normalizedRules[i].AdvancedAuth = existingPolicy
			}
		}
		visibility, visibilityErr := prepareHostVisibilityPolicy(
			normalizedRules[i].Visibility,
			candidatePolicies,
			candidateSets,
		)
		if visibilityErr != nil {
			h.mu.Unlock()
			return fmt.Errorf("host %s visibility: %w", normalizedRules[i].Host, visibilityErr)
		}
		normalizedRules[i].Visibility = visibility
		if _, advancedErr := compileAdvancedAuthPolicyWithSets(
			normalizedRules[i].AdvancedAuth,
			candidateSets,
		); advancedErr != nil {
			h.mu.Unlock()
			return fmt.Errorf(
				"host %s advanced auth: %w",
				normalizedRules[i].Host,
				advancedErr,
			)
		}
	}
	pruneVisibilityPolicies(normalizedRules, h.GatewayVisibility, candidatePolicies, candidateSets)
	if hostRulesConfigurationEqual(h.HostRules, normalizedRules, h.VisibilityPolicies, candidatePolicies) {
		h.mu.Unlock()
		return nil
	}
	changedProtocolHosts := changedHostProtocolModes(h.HostRules, normalizedRules)
	if err := h.persistHostRulesAndPoliciesLocked(normalizedRules, candidatePolicies); err != nil {
		h.mu.Unlock()
		return err
	}
	h.HostRules = normalizedRules
	h.VisibilityPolicies = candidatePolicies
	h.compiledVisibilityPolicies = candidateSets
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
	h.clearAuthCache()
	return nil
}

func (h *Handler) FlushHostRules() error {
	h.mu.Lock()
	changedProtocolHosts := changedHostProtocolModes(h.HostRules, nil)
	nextRules := make([]models.HostRule, 0)
	nextPolicies := copyVisibilityPolicies(h.VisibilityPolicies)
	nextSets := make(map[string]*compiledipset.Set, len(h.compiledVisibilityPolicies))
	for id, set := range h.compiledVisibilityPolicies {
		nextSets[id] = set
	}
	pruneVisibilityPolicies(nextRules, h.GatewayVisibility, nextPolicies, nextSets)
	if hostRulesConfigurationEqual(h.HostRules, nextRules, h.VisibilityPolicies, nextPolicies) {
		h.mu.Unlock()
		return nil
	}
	if err := h.persistHostRulesAndPoliciesLocked(nextRules, nextPolicies); err != nil {
		h.mu.Unlock()
		return err
	}
	h.HostRules = nextRules
	h.VisibilityPolicies = nextPolicies
	h.compiledVisibilityPolicies = nextSets
	h.publishRequestSnapshotLocked()
	hook := h.getHostProtocolModeChangeHook()
	h.mu.Unlock()
	if hook != nil && len(changedProtocolHosts) > 0 {
		hook(changedProtocolHosts)
	}
	if event := debugProxyEvent("host_rules_flushed", ""); event != nil {
		event.Send()
	}
	h.clearAuthCache()
	return nil
}

func (h *Handler) GetHostRules() []models.HostRule {
	h.mu.RLock()
	defer h.mu.RUnlock()

	return copyHostRules(h.HostRules)
}

func (h *Handler) GetVisibilityPoliciesForHostRules() map[string]models.CompiledIPSet {
	h.mu.RLock()
	defer h.mu.RUnlock()

	referenced := make(map[string]models.CompiledIPSet)
	for _, rule := range h.HostRules {
		id := strings.TrimSpace(rule.Visibility.PolicyID)
		if rule.Visibility.Mode == models.HostVisibilityModeCustom && id != "" {
			if policy, ok := h.VisibilityPolicies[id]; ok {
				referenced[id] = copyVisibilityPolicy(policy)
			}
		}
		for _, group := range rule.AdvancedAuth.Groups {
			for _, condition := range group.Conditions {
				id := strings.TrimSpace(condition.PolicyID)
				if id == "" {
					continue
				}
				if policy, ok := h.VisibilityPolicies[id]; ok {
					referenced[id] = copyVisibilityPolicy(policy)
				}
			}
		}
	}
	return referenced
}

func (h *Handler) SetStreamRules(rules []models.StreamRule) error {
	return h.setStreamRulesConfig(rules, nil, nil, false, false)
}

func (h *Handler) SetStreamRulesConfig(
	rules []models.StreamRule,
	availability *models.StreamAvailability,
) error {
	return h.setStreamRulesConfig(rules, availability, nil, true, false)
}

func (h *Handler) SetStreamRulesBundle(
	rules []models.StreamRule,
	availability *models.StreamAvailability,
	policies map[string]models.CompiledIPSet,
) error {
	return h.setStreamRulesConfig(rules, availability, policies, true, true)
}

func (h *Handler) setStreamRulesConfig(
	rules []models.StreamRule,
	availability *models.StreamAvailability,
	policies map[string]models.CompiledIPSet,
	replaceAvailability bool,
	replacePolicies bool,
) error {
	if !replacePolicies {
		h.mu.RLock()
		policies = copyVisibilityPolicies(h.StreamAccessPolicies)
		h.mu.RUnlock()
	}
	normalized, normalizedPolicies, err := h.ValidateStreamRulesBundle(rules, policies)
	if err != nil {
		return err
	}
	var normalizedAvailability *models.StreamAvailability
	if replaceAvailability {
		normalizedAvailability, err = models.NormalizeDailyAvailability(availability)
		if err != nil {
			return err
		}
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	previousRules := h.StreamRules
	previousAvailability := h.StreamAvailability
	previousPolicies := h.StreamAccessPolicies
	effectiveAvailability := previousAvailability
	if replaceAvailability {
		effectiveAvailability = normalizedAvailability
	}
	if err := h.commitConfigMutationLocked(
		func() {
			h.StreamRules = normalized
			if replacePolicies {
				h.StreamAccessPolicies = normalizedPolicies
			}
			if replaceAvailability {
				h.StreamAvailability = models.CopyDailyAvailability(normalizedAvailability)
			}
		},
		func() {
			h.StreamRules = previousRules
			h.StreamAvailability = previousAvailability
			h.StreamAccessPolicies = previousPolicies
		},
		func(conf *config.AppConfig) {
			conf.StreamRules = copyStreamRules(h.StreamRules)
			conf.StreamAvailability = models.CopyDailyAvailability(h.StreamAvailability)
			conf.StreamAccessPolicies = copyVisibilityPolicies(h.StreamAccessPolicies)
		},
		nil,
	); err != nil {
		return err
	}
	if event := debugProxyEvent("stream_rules_set", ""); event != nil {
		event.Int("stream_rule_count", len(normalized)).
			Bool("schedule_enabled", effectiveAvailability != nil).
			Interface("stream_rules", debugStreamRuleSummaries(normalized)).
			Send()
	}
	return nil
}

func (h *Handler) FlushStreamRules() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	previousRules := h.StreamRules
	previousAvailability := h.StreamAvailability
	previousPolicies := h.StreamAccessPolicies
	next := make([]models.StreamRule, 0)
	if err := h.commitConfigMutationLocked(
		func() {
			h.StreamRules = next
			h.StreamAvailability = nil
			h.StreamAccessPolicies = map[string]models.CompiledIPSet{}
		},
		func() {
			h.StreamRules = previousRules
			h.StreamAvailability = previousAvailability
			h.StreamAccessPolicies = previousPolicies
		},
		func(conf *config.AppConfig) {
			conf.StreamRules = copyStreamRules(h.StreamRules)
			conf.StreamAvailability = models.CopyDailyAvailability(h.StreamAvailability)
			conf.StreamAccessPolicies = copyVisibilityPolicies(h.StreamAccessPolicies)
		},
		nil,
	); err != nil {
		return err
	}
	if event := debugProxyEvent("stream_rules_flushed", ""); event != nil {
		event.Send()
	}
	return nil
}

func (h *Handler) GetStreamRules() []models.StreamRule {
	rules, _ := h.GetStreamRulesConfig()
	return rules
}

func (h *Handler) GetStreamRulesConfig() ([]models.StreamRule, *models.StreamAvailability) {
	rules, availability, _ := h.GetStreamRulesBundle()
	return rules, availability
}

func (h *Handler) GetStreamRulesBundle() ([]models.StreamRule, *models.StreamAvailability, map[string]models.CompiledIPSet) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	rules := copyStreamRules(h.StreamRules)
	return rules, models.CopyDailyAvailability(h.StreamAvailability), copyVisibilityPolicies(h.StreamAccessPolicies)
}

func (h *Handler) GetStreamAvailability() *models.StreamAvailability {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return models.CopyDailyAvailability(h.StreamAvailability)
}

func (h *Handler) GetDefaultRoute() string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.DefaultRoute
}

func (h *Handler) SetDefaultRoute(route string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	normalized := route
	if normalized == "" {
		normalized = "/__select__"
	}
	previous := h.DefaultRoute
	if err := h.commitConfigMutationLocked(
		func() { h.DefaultRoute = normalized },
		func() { h.DefaultRoute = previous },
		func(conf *config.AppConfig) {
			conf.DefaultRoute = h.DefaultRoute
		},
		h.publishRequestSnapshotLocked,
	); err != nil {
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
		h.mu.RLock()
		config := gatewaylog.NormalizeConfig(h.LoggingConfig)
		h.mu.RUnlock()
		return gatewaylog.ConfigInfo{
			Enabled:         config.Enabled,
			RecordLocalhost: config.RecordLocalhost,
			MaxDays:         config.MaxDays,
		}
	}
	return h.gatewayLogManager.GetConfigInfo()
}

func (h *Handler) SetLoggingConfig(cfg models.LoggingConfig) (gatewaylog.ConfigInfo, error) {
	normalized := gatewaylog.NormalizeConfig(cfg)

	h.mu.Lock()
	previous := h.LoggingConfig
	saveErr := h.commitConfigMutationLocked(
		func() { h.LoggingConfig = normalized },
		func() { h.LoggingConfig = previous },
		func(conf *config.AppConfig) {
			conf.Logging = h.LoggingConfig
		},
		nil,
	)
	h.mu.Unlock()
	if saveErr != nil {
		return h.GetLoggingConfig(), saveErr
	}
	if event := debugProxyEvent("gateway_logging_config_set", ""); event != nil {
		event.Bool("enabled", normalized.Enabled).
			Bool("record_localhost", normalized.RecordLocalhost).
			Int("max_days", normalized.MaxDays).
			Send()
	}

	if h.gatewayLogManager == nil {
		return gatewaylog.ConfigInfo{
			Enabled:         normalized.Enabled,
			RecordLocalhost: normalized.RecordLocalhost,
			MaxDays:         normalized.MaxDays,
		}, nil
	}
	return h.gatewayLogManager.UpdateConfig(normalized), nil
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

func (h *Handler) AnalyzeLogEntries(fromDate string, toDate string) (gatewaylog.AnalyticsResult, error) {
	return h.AnalyzeLogEntriesContext(context.Background(), fromDate, toDate)
}

func (h *Handler) AnalyzeLogEntriesContext(ctx context.Context, fromDate string, toDate string) (gatewaylog.AnalyticsResult, error) {
	if h.gatewayLogManager == nil {
		return gatewaylog.AnalyticsResult{}, nil
	}
	return h.gatewayLogManager.AnalyzeContext(ctx, fromDate, toDate)
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
	return proxywaf.CopyConfig(h.WAFConfig)
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
	h.wafChangeMu.Lock()
	defer h.wafChangeMu.Unlock()

	prepared, err := h.wafRuntime.PrepareConfig(cfg)
	if err != nil {
		if event := debugProxyEvent("waf_config_set_failed", ""); event != nil {
			event.Bool("enabled", cfg.Enabled).
				Str("mode", logger.SanitizeLogString(cfg.Mode)).
				Str("error", logger.SanitizeLogString(err.Error())).
				Send()
		}
		return h.wafRuntime.Status(), err
	}
	normalized := prepared.Config()
	h.mu.Lock()
	if reflect.DeepEqual(h.WAFConfig, normalized) {
		status := h.wafRuntime.Status()
		h.mu.Unlock()
		return status, nil
	}
	previous := h.WAFConfig
	h.WAFConfig = normalized
	saveErr := h.saveConfigMutationLocked(func(conf *config.AppConfig) {
		conf.WAF = proxywaf.CopyConfig(h.WAFConfig)
	})
	if saveErr != nil {
		h.WAFConfig = previous
		h.mu.Unlock()
		return h.wafRuntime.Status(), saveErr
	}
	status := h.wafRuntime.CommitPrepared(prepared)
	h.mu.Unlock()
	if event := debugProxyEvent("waf_config_set", ""); event != nil {
		event.Bool("enabled", normalized.Enabled).
			Str("mode", logger.SanitizeLogString(normalized.Mode)).
			Str("rules_dir", logger.SanitizeLogString(normalized.RulesDir)).
			Int("disabled_host_count", len(normalized.DisabledHosts)).
			Int("disabled_path_prefix_count", len(normalized.DisabledPathPrefixes)).
			Send()
	}
	return status, nil
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
	h.wafChangeMu.Lock()
	defer h.wafChangeMu.Unlock()

	prepared, err := h.wafRuntime.PrepareReload(cfg, bundleID, bundlePath)
	if err != nil {
		if event := debugProxyEvent("waf_bundle_reload_failed", ""); event != nil {
			event.Str("bundle_id", logger.SanitizeLogString(bundleID)).
				Str("bundle_path", logger.SanitizeLogString(bundlePath)).
				Str("error", logger.SanitizeLogString(err.Error())).
				Send()
		}
		return h.wafRuntime.Status(), err
	}
	normalized := prepared.Config()
	h.mu.Lock()
	previous := h.WAFConfig
	h.WAFConfig = normalized
	saveErr := h.saveConfigMutationLocked(func(conf *config.AppConfig) {
		conf.WAF = proxywaf.CopyConfig(h.WAFConfig)
	})
	if saveErr != nil {
		h.WAFConfig = previous
		h.mu.Unlock()
		return h.wafRuntime.Status(), saveErr
	}
	status := h.wafRuntime.CommitPrepared(prepared)
	h.mu.Unlock()
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

func (h *Handler) SetAuthConfig(candidate models.AuthConfig) error {
	if candidate.AuthPort <= 0 {
		candidate.AuthPort = 7997
	}
	if candidate.AuthURL == "" {
		candidate.AuthURL = "/api/auth/verify"
	}
	if candidate.LoginURL == "" {
		candidate.LoginURL = "/login"
	}
	if candidate.LogoutURL == "" {
		candidate.LogoutURL = "/api/auth/logout"
	}
	if candidate.PreflightURL == "" {
		candidate.PreflightURL = "/api/auth/preflight"
	}
	if candidate.AuthCacheTTL < 0 {
		candidate.AuthCacheTTL = 0
	}
	if candidate.AuthCacheFailTTL < 0 {
		candidate.AuthCacheFailTTL = 0
	}
	if candidate.PublicHTTPPort < 0 {
		candidate.PublicHTTPPort = 0
	}
	if candidate.PublicHTTPSPort < 0 {
		candidate.PublicHTTPSPort = 0
	}
	candidate.PublicAuthBaseURL = strings.TrimSpace(strings.TrimRight(candidate.PublicAuthBaseURL, "/"))
	candidate.AuthHost = normalizeRequestHost(candidate.AuthHost)
	candidate.NormalizeEdgeClientIPSelection()

	h.mu.Lock()
	defer h.mu.Unlock()
	previous := h.AuthConfig
	if err := h.commitConfigMutationLocked(
		func() { h.AuthConfig = candidate },
		func() { h.AuthConfig = previous },
		func(conf *config.AppConfig) {
			conf.AuthConfig = h.AuthConfig
		},
		h.publishRequestSnapshotLocked,
	); err != nil {
		return err
	}
	h.clearAuthCache()
	if event := debugProxyEvent("auth_config_set", ""); event != nil {
		event.Interface("auth_config", debugAuthConfigSummary(candidate)).
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

	result := models.GatewayVisibilityConfig{
		Enabled:   h.GatewayVisibility.Enabled,
		CIDRs:     cidrs,
		UpdatedAt: h.GatewayVisibility.UpdatedAt,
		PolicyID:  h.GatewayVisibility.PolicyID,
	}
	if policy, ok := h.VisibilityPolicies[result.PolicyID]; ok {
		copied := copyVisibilityPolicy(policy)
		result.Policy = &copied
	}
	return result
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
	previousRuntime := runtime.getConfig()
	previousConfigured := h.GeneralBlacklist
	normalized, result, err := runtime.addMany(ips, source, comment, time.Now())
	if err != nil {
		h.mu.Unlock()
		return models.GeneralBlacklistMutationResult{}, err
	}

	h.GeneralBlacklist = normalized
	if err := h.saveConfigMutationLocked(func(conf *config.AppConfig) {
		conf.GeneralBlacklist = h.GeneralBlacklist
	}); err != nil {
		runtime.updateConfig(previousRuntime)
		h.GeneralBlacklist = previousConfigured
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
	previousRuntime := runtime.getConfig()
	previousConfigured := h.GeneralBlacklist
	normalized, result, err := runtime.removeMany(ips)
	if err != nil {
		h.mu.Unlock()
		return models.GeneralBlacklistMutationResult{}, err
	}

	h.GeneralBlacklist = normalized
	if err := h.saveConfigMutationLocked(func(conf *config.AppConfig) {
		conf.GeneralBlacklist = h.GeneralBlacklist
	}); err != nil {
		runtime.updateConfig(previousRuntime)
		h.GeneralBlacklist = previousConfigured
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

func (h *Handler) GetGatewayTrustedClientIPs() models.GatewayTrustedClientIPsRuntime {
	h.mu.RLock()
	runtime := h.trustedClientIPs
	h.mu.RUnlock()

	if runtime == nil {
		return models.GatewayTrustedClientIPsRuntime{
			IPs:       []string{},
			CIDRs:     []string{},
			UpdatedAt: "",
		}
	}
	return runtime.getConfig()
}

func (h *Handler) IsGatewayTrustedClientIP(clientIP string) bool {
	h.mu.RLock()
	runtime := h.trustedClientIPs
	h.mu.RUnlock()
	return runtime != nil && runtime.contains(clientIP)
}

func (h *Handler) IsClientIPVisible(clientIP string) bool {
	h.mu.RLock()
	visibility := h.gatewayVisibility
	h.mu.RUnlock()

	if visibility == nil {
		return true
	}
	if !visibility.enabled() {
		return true
	}
	return visibility.contains(clientIP)
}

func (h *Handler) IsClientIPVisibleForHost(clientIP string, rule *models.HostRule, snapshot requestSnapshot) bool {
	visibility := snapshot.gatewayVisibility

	if visibility == nil {
		return true
	}
	if !visibility.enabled() {
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
	policy, ok := snapshot.hostVisibility[host]
	if !ok || policy == nil {
		// A missing custom policy is a corrupt security boundary. Keep the
		// request fail-closed instead of widening it to inherited visibility.
		addr, valid := visibilityClientAddr(clientIP)
		return valid && isVisibilityExemptAddr(addr)
	}
	addr, valid := visibilityClientAddr(clientIP)
	if !valid {
		return false
	}
	if isVisibilityExemptAddr(addr) {
		return true
	}
	return policy.Contains(addr)
}

func gatewayVisibilityPolicyContext(rule *models.HostRule, snapshot requestSnapshot) (string, string) {
	if rule == nil || normalizeRequestHost(rule.Host) == normalizeRequestHost(snapshot.authConfig.AuthHost) {
		return "gateway", models.HostVisibilityModeInherit
	}
	if models.NormalizeHostVisibilityMode(rule.Visibility.Mode) == models.HostVisibilityModeCustom {
		return "host", models.HostVisibilityModeCustom
	}
	return "gateway", models.HostVisibilityModeInherit
}

func gatewayVisibilityRouteContext(r *http.Request, snapshot requestSnapshot, rule *models.HostRule, fnosConnect bool) (string, string) {
	if fnosConnect {
		return fnosConnectRouteKey, fnosConnectRouteKey
	}
	requestPath := ""
	if r != nil && r.URL != nil {
		requestPath = r.URL.Path
	}
	isAuthRoute := strings.HasPrefix(requestPath, "/__auth__/")
	if isAuthRoute {
		return "auth_proxy", requestPath
	}
	if requestPath == "/__select__" {
		return "select", requestPath
	}
	if requestPath == "/__wol__" {
		return "wol", requestPath
	}

	matchedHostLocation := matchHostLocation(r, rule)
	if rule != nil {
		matchedHostLocation, _, _ = enforceReservedFnosShareRoute(
			requestPath,
			snapshot,
			rule,
			matchedHostLocation,
			nil,
			"",
		)
		if matchedHostLocation != nil {
			return "host_location", hostLocationRouteKey(rule, matchedHostLocation)
		}
		return "host_rule", rule.Host
	}

	var matchedRule *models.Rule
	needsSlashRedirect := ""
	if r != nil && r.URL != nil {
		matchedRule, needsSlashRedirect = matchRule(r, snapshot)
		_, matchedRule, needsSlashRedirect = enforceReservedFnosShareRoute(
			requestPath,
			snapshot,
			nil,
			nil,
			matchedRule,
			needsSlashRedirect,
		)
	}
	if matchedRule != nil {
		return "path_rule", matchedRule.Path
	}
	if needsSlashRedirect != "" {
		return "slash_redirect", needsSlashRedirect
	}

	resetUnmatchedConnection := snapshot.unmatchedRoute.Behavior ==
		models.GatewayUnmatchedRouteBehaviorResetConnection
	if !resetUnmatchedConnection && r != nil {
		defaultHostRule := snapshot.defaultHostRule
		if defaultHostRule != nil && !hostRuleAvailableNow(defaultHostRule, time.Now()) {
			defaultHostRule = nil
		}
		if buildDefaultHostRuleRedirectURL(r, defaultHostRule) != "" {
			return "default_host_redirect", defaultHostRule.Host
		}
	}
	if snapshot.defaultRule != nil && !isReservedFnosSharePath(snapshot.defaultRule.Path) {
		return "path_rule", snapshot.defaultRule.Path
	}
	if resetUnmatchedConnection && r != nil {
		return "unmatched_route_blocked", requestHostForRouting(r)
	}
	if r != nil {
		return "not_found", requestHostForRouting(r)
	}
	return "not_found", ""
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

func (h *Handler) SetCrawlerBlockerConfig(cfg models.CrawlerBlockerConfig) (models.CrawlerBlockerConfig, error) {
	normalized := normalizeCrawlerBlockerConfig(cfg)

	h.mu.Lock()
	previous := h.CrawlerBlocker
	saveErr := h.commitConfigMutationLocked(
		func() { h.CrawlerBlocker = normalized },
		func() { h.CrawlerBlocker = previous },
		func(conf *config.AppConfig) {
			conf.CrawlerBlocker = h.CrawlerBlocker
		},
		h.publishRequestSnapshotLocked,
	)
	h.mu.Unlock()
	if saveErr != nil {
		return previous, saveErr
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
	previous := h.GatewayPortal
	saveErr := h.commitConfigMutationLocked(
		func() { h.GatewayPortal = normalized },
		func() { h.GatewayPortal = previous },
		func(conf *config.AppConfig) {
			conf.Portal = h.GatewayPortal
		},
		h.publishRequestSnapshotLocked,
	)
	h.mu.Unlock()
	if saveErr != nil {
		return previous, saveErr
	}
	if event := debugProxyEvent("gateway_portal_config_set", ""); event != nil {
		event.Bool("enabled", normalized.Enabled).
			Str("display_style", logger.SanitizeLogString(normalized.DisplayStyle)).
			Str("icon_drag_mode", logger.SanitizeLogString(normalized.IconDragMode)).
			Str("version", logger.SanitizeLogString(normalized.Version)).
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
	saveErr := h.commitConfigMutationLocked(
		func() { h.GatewayUnmatchedRoute = normalized },
		func() { h.GatewayUnmatchedRoute = previous },
		func(conf *config.AppConfig) {
			conf.UnmatchedRoute = h.GatewayUnmatchedRoute
		},
		h.publishRequestSnapshotLocked,
	)
	h.mu.Unlock()
	if saveErr != nil {
		return previous, saveErr
	}
	if event := debugProxyEvent("gateway_unmatched_route_config_set", ""); event != nil {
		event.Str("behavior", normalized.Behavior).
			Str("upstream_error_detail", normalized.UpstreamErrorDetail).
			Send()
	}

	return normalized, nil
}

func (h *Handler) SetFnosPortIconHijackConfig(cfg models.FnosPortIconHijackConfig) (models.FnosPortIconHijackConfig, error) {
	normalized := models.FnosPortIconHijackConfig{
		Enabled:   cfg.Enabled,
		UpdatedAt: strings.TrimSpace(cfg.UpdatedAt),
	}

	h.mu.Lock()
	previous := h.FnosPortIconHijack
	saveErr := h.commitConfigMutationLocked(
		func() { h.FnosPortIconHijack = normalized },
		func() { h.FnosPortIconHijack = previous },
		func(conf *config.AppConfig) {
			conf.FnosPortIconHijack = h.FnosPortIconHijack
		},
		nil,
	)
	h.mu.Unlock()
	if saveErr != nil {
		return previous, saveErr
	}
	if event := debugProxyEvent("fnos_port_icon_hijack_config_set", ""); event != nil {
		event.Bool("enabled", normalized.Enabled).
			Str("updated_at", logger.SanitizeLogString(normalized.UpdatedAt)).
			Send()
	}

	return normalized, nil
}

func (h *Handler) SetReverseProxyThrottleExemptIPs(cfg models.ReverseProxyThrottleExemptIPsRuntime) error {
	h.mu.Lock()
	runtime := h.reverseProxyThrottleExempt
	if runtime == nil {
		runtime = newReverseProxyThrottleExemptIPsRuntime(
			models.ReverseProxyThrottleExemptIPsRuntime{},
		)
		h.reverseProxyThrottleExempt = runtime
	}
	h.mu.Unlock()

	if _, err := runtime.updateConfig(cfg); err != nil {
		return err
	}
	normalized := runtime.getConfig()
	if event := debugProxyEvent("reverse_proxy_throttle_exempt_ips_set", ""); event != nil {
		event.Bool("enabled", normalized.Enabled).
			Int("ip_count", len(normalized.IPs)).
			Str("policy_id", logger.SanitizeLogString(normalized.PolicyID)).
			Str("updated_at", logger.SanitizeLogString(normalized.UpdatedAt)).
			Send()
	}
	return nil
}

func (h *Handler) SetGatewayTrustedClientIPs(cfg models.GatewayTrustedClientIPsRuntime) error {
	h.mu.Lock()
	runtime := h.trustedClientIPs
	if runtime == nil {
		runtime = newGatewayTrustedClientIPsRuntime(
			models.GatewayTrustedClientIPsRuntime{},
		)
		h.trustedClientIPs = runtime
	}
	h.mu.Unlock()

	updated, err := runtime.updateConfig(cfg)
	if err != nil {
		return err
	}
	if !updated {
		return nil
	}
	normalized := runtime.getConfig()
	if event := debugProxyEvent("gateway_trusted_client_ips_set", ""); event != nil {
		event.Int("ip_count", len(normalized.IPs)).
			Str("policy_id", logger.SanitizeLogString(normalized.PolicyID)).
			Str("updated_at", logger.SanitizeLogString(normalized.UpdatedAt)).
			Send()
	}
	return nil
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

func (h *Handler) SetCommonLocationExemptions(cfg models.CommonLocationExemptionsRuntime) error {
	h.mu.Lock()
	runtime := h.commonLocationExemptions
	if runtime == nil {
		runtime = newCommonLocationExemptionsRuntime(
			models.CommonLocationExemptionsRuntime{},
		)
		h.commonLocationExemptions = runtime
	}
	h.mu.Unlock()

	if _, err := runtime.updateConfig(cfg); err != nil {
		return err
	}
	normalized := runtime.getConfig()
	if event := debugProxyEvent("common_location_exemptions_set", ""); event != nil {
		event.Bool("enabled", normalized.Enabled).
			Bool("waf_enabled", normalized.WAFEnabled).
			Str("policy_id", logger.SanitizeLogString(normalized.PolicyID)).
			Str("updated_at", logger.SanitizeLogString(normalized.UpdatedAt)).
			Send()
	}
	return nil
}

func (h *Handler) LogGatewayEntry(entry gatewaylog.Entry) {
	if h.gatewayLogManager != nil {
		h.gatewayLogManager.Log(entry)
	}
}

const loggedInActiveWindow = 2 * time.Minute
const loggedInActiveCleanupInterval = 30 * time.Second
const loggedInActiveMaxEntries = 8192

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
	handler            *Handler
	metrics            requestTrafficMetrics
	deepMonitor        *deepMonitorRequest
	skipAccessLog      bool
	upstreamErrorClass string
}

func (tw *trafficResponseWriter) WriteHeader(statusCode int) {
	if !tw.metrics.wroteHeader {
		tw.metrics.wroteHeader = true
		tw.metrics.statusCode = statusCode
		if tw.deepMonitor != nil {
			tw.deepMonitor.captureClientHeader(tw.Header())
		}
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
		if tw.deepMonitor != nil {
			tw.deepMonitor.captureClientBody(p[:n])
		}
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
	if r == nil || r.Body == nil || r.Body == http.NoBody {
		return
	}
	if _, ok := r.Body.(*trafficReadCloser); ok {
		return
	}
	r.Body = &trafficReadCloser{ReadCloser: r.Body, handler: h, metrics: metrics}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	diagnostics.BeginProxyRequest()
	defer diagnostics.EndProxyRequest()
	start := time.Now()
	certificateDeploySensitivePath := r.URL != nil &&
		(isCertificateDeployReservedPath(r.URL.Path) ||
			isCertificateDeployReservedPath(path.Clean(r.URL.Path)))
	certificateDeployHadQuery := certificateDeploySensitivePath && r.URL.RawQuery != ""
	if certificateDeployHadQuery {
		// Deployment credentials belong in Authorization. Remove every query
		// value before even debug/access logging, while retaining the fact that
		// a query was supplied so the reserved route can reject it below.
		r.URL.RawQuery = ""
	}
	var deepMonitorTrace *deepMonitorRequest
	if !certificateDeploySensitivePath {
		deepMonitorTrace = h.beginDeepMonitor(r, start)
	}
	r = withDeepMonitor(r, deepMonitorTrace)
	requestID := ""
	if logger.DebugEnabled() {
		requestID = logger.NextDebugRequestID()
	}
	tw := &trafficResponseWriter{ResponseWriter: w, handler: h, deepMonitor: deepMonitorTrace}
	tw.metrics.statusCode = http.StatusOK
	metrics := &tw.metrics
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
		AliRealClientIP: strings.TrimSpace(r.Header.Get(headerAliRealClientIP)),
		EOConnectingIP:  strings.TrimSpace(r.Header.Get(headerEOConnectingIP)),
		XForwardedFor:   firstForwardedValue(r.Header.Get("X-Forwarded-For")),
		XRealIP:         strings.TrimSpace(r.Header.Get(headerXRealIP)),
	}
	if certificateDeploySensitivePath {
		redactCertificateDeployAccessEntry(&accessEntry)
	}
	var clientIP string
	loggedStatusCode := 0

	w = tw
	debugHeaderField, debugHeaderValue := requestDebugHeaders(certificateDeploySensitivePath, r.Header)
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
			Interface(debugHeaderField, debugHeaderValue).
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
		accessEntry.UpstreamErrorClass = tw.upstreamErrorClass
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
			accessEntry.ClientIP = clientIP
		}
		if deepMonitorTrace != nil {
			deepMonitorTrace.captureClientHeader(tw.Header())
			deepMonitorTrace.finish(r, accessEntry)
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
				Str("upstream_error_class", accessEntry.UpstreamErrorClass).
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
	fnosConnect := fnosConnectContext(r)
	certificateDeployRouteKind := certificateDeployRouteNone
	if fnosConnect == nil {
		certificateDeployRouteKind = certificateDeployRoute(r, snapshot.authConfig.AuthHost, h.getSSLBundle())
	}
	if certificateDeployRouteKind != certificateDeployRouteNone {
		// The reserved route is owned by the actual Host header. Do not let a
		// client-supplied forwarding host select another HostRule's visibility
		// or availability policy before the header is rebuilt for Rust.
		r.Header.Del("X-Forwarded-Host")
	}
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

	if fnosConnect != nil {
		clientIP = fnosConnectClientIP(r)
	} else {
		clientIP = resolveClientIP(r, snapshot.authConfig, snapshot.proxyProtocolForce)
	}
	trustedClientIP := snapshot.trustedClientIPs != nil && snapshot.trustedClientIPs.contains(clientIP)
	accessEntry.RemoteIP = clientIP
	accessEntry.ClientIP = clientIP
	if deepMonitorTrace != nil {
		deepMonitorTrace.setClientIP(clientIP)
	}
	debugXFF, debugRealIP, debugAliIP, debugEOIP := requestDebugClientHeaders(certificateDeploySensitivePath, r)
	if event := debugProxyEvent("client_ip_resolved", requestID); event != nil {
		event.Str("client_ip", logger.SanitizeLogString(clientIP)).
			Bool("trusted_client_ip", trustedClientIP).
			Bool("proxy_protocol_force", snapshot.proxyProtocolForce).
			Bool("edge_client_ip_active", snapshot.authConfig.EdgeClientIPActive()).
			Str("x_forwarded_for", logger.SanitizeLogString(debugXFF)).
			Str("x_real_ip", logger.SanitizeLogString(debugRealIP)).
			Str("ali_real_client_ip", logger.SanitizeLogString(debugAliIP)).
			Str("eo_connecting_ip", logger.SanitizeLogString(debugEOIP)).
			Send()
	}

	matchedHostRule := matchHostRule(r, snapshot)
	if fnosConnect != nil {
		matchedHostRule = &fnosConnect.hostRule
	}
	if fnosConnect == nil && serveWebsiteIconRequest(w, r, matchedHostRule, &accessEntry, requestID) {
		return
	}

	crawlerBlocker := snapshot.crawlerBlocker
	if !trustedClientIP && fnosConnect == nil && crawlerBlocker.Enabled {
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

	var blacklistRecord models.GeneralBlacklistRecord
	blacklistBlocked := false
	if snapshot.generalBlacklist != nil {
		blacklistRecord, blacklistBlocked = snapshot.generalBlacklist.contains(clientIP)
	}
	if !trustedClientIP && blacklistBlocked {
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

	routeTimingStarted := time.Now()
	if !trustedClientIP && !h.IsClientIPVisibleForHost(clientIP, matchedHostRule, snapshot) {
		accessEntry.RouteType = "visibility"
		accessEntry.RouteKey = "cidr"
		accessEntry.AuthDecision = "visibility_denied"
		loggedStatusCode = 499
		visibilityScope, visibilityMode := gatewayVisibilityPolicyContext(matchedHostRule, snapshot)
		routeType, routeKey := gatewayVisibilityRouteContext(r, snapshot, matchedHostRule, fnosConnect != nil)
		h.enqueueGatewayVisibilityBlockedEvent(gatewayVisibilityBlockedEvent{
			ClientIP:        clientIP,
			BlockedAt:       time.Now(),
			Method:          r.Method,
			Scheme:          requestScheme(r),
			Host:            r.Host,
			Path:            r.URL.Path,
			RouteType:       routeType,
			RouteKey:        routeKey,
			VisibilityScope: visibilityScope,
			VisibilityMode:  visibilityMode,
		})
		if event := debugProxyEvent("visibility_denied", requestID); event != nil {
			event.Str("client_ip", logger.SanitizeLogString(clientIP)).
				Str("visibility_scope", visibilityScope).
				Str("visibility_mode", visibilityMode).
				Send()
		}
		h.abortConnection(w)
		return
	}

	if certificateDeploySensitivePath && certificateDeployRouteKind == certificateDeployRouteNone {
		accessEntry.RouteType = "certificate_deploy"
		accessEntry.RouteKey = certificateDeployPathPrefix
		accessEntry.AuthDecision = "not_found"
		accessEntry.Matched = false
		loggedStatusCode = http.StatusNotFound
		rejectMalformedCertificateDeployRoute(w, r)
		return
	}

	http1Required := isHTTP1OnlyHostOverHTTP2(r, matchedHostRule)
	http2Required := isHTTP2OnlyHostOverHTTP1(r, matchedHostRule)
	if http1Required || http2Required {
		if !h.allowReverseProxyRequest(w, r, clientIP, false, matchedHostRule, nil, nil, trustedClientIP, requestID) {
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

	if fnosConnect == nil && response.IsFaviconPath(r.URL.Path) {
		accessEntry.RouteType = "favicon"
		accessEntry.RouteKey = r.URL.Path
		accessEntry.Matched = true
		if event := debugProxyEvent("favicon_served", requestID); event != nil {
			event.Str("path", logger.SanitizeLogString(r.URL.Path)).Send()
		}
		response.ServeFavicon(w, r)
		return
	}

	if fnosConnect == nil && response.IsToolbarAssetPath(r.URL.Path) {
		accessEntry.RouteType = "toolbar_asset"
		accessEntry.RouteKey = r.URL.Path
		accessEntry.Matched = true
		response.ServeToolbarAsset(w, r)
		return
	}
	if fnosConnect == nil && response.IsToolbarDataPath(r.URL.Path) {
		accessEntry.RouteType = "toolbar_data"
		accessEntry.RouteKey = r.URL.Path
		accessEntry.Matched = true
		accessEntry.AuthRequired = true
		authResult := h.handleToolbarDataRoute(w, r, snapshot, clientIP, requestID, matchedHostRule)
		applyAuthResultToLogEntry(&accessEntry, authResult)
		return
	}

	isSelectRoute := fnosConnect == nil && r.URL.Path == "/__select__"
	isWOLPath := fnosConnect == nil && r.URL.Path == "/__wol__"
	isWOLRoute := isWOLPath && snapshot.gatewayPortal.ShowWOL
	isCertificateDeployRoute := certificateDeployRouteKind != certificateDeployRouteNone
	isBuiltinAuthRoute := isSelectRoute || isWOLRoute || isCertificateDeployRoute
	isAuthRoute := fnosConnect == nil && strings.HasPrefix(r.URL.Path, "/__auth__/")
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
	matchedHostLocation, matchedRule, needsSlashRedirect = enforceReservedFnosShareRoute(
		r.URL.Path,
		snapshot,
		matchedHostRule,
		matchedHostLocation,
		matchedRule,
		needsSlashRedirect,
	)
	if matchedHostRule != nil {
		matchedRule = nil
		needsSlashRedirect = ""
	}

	resetUnmatchedConnection := snapshot.unmatchedRoute.Behavior ==
		models.GatewayUnmatchedRouteBehaviorResetConnection
	if !resetUnmatchedConnection && matchedRule == nil && needsSlashRedirect == "" && matchedHostRule == nil && !isBuiltinAuthRoute && !isAuthRoute {
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

	if matchedHostRule == nil && matchedRule == nil && snapshot.defaultRule != nil &&
		!isReservedFnosSharePath(snapshot.defaultRule.Path) {
		matchedRule = snapshot.defaultRule
	}
	if resetUnmatchedConnection && matchedRule == nil && needsSlashRedirect == "" &&
		matchedHostRule == nil && !isBuiltinAuthRoute && !isAuthRoute {
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
	var routedBackend routedBackend
	if strings.TrimSpace(snapshot.authConfig.AuthURL) != "" {
		routedBackend = h.routedBackendForRequest(
			r,
			snapshot,
			matchedHostRule,
			matchedHostLocation,
			matchedRule,
		)
	}
	if deepMonitorTrace != nil {
		deepMonitorTrace.addRouteDuration(time.Since(routeTimingStarted))
	}
	if !h.allowReverseProxyRequest(w, r, clientIP, isAuthRoute || isCertificateDeployRoute, matchedHostRule, matchedHostLocation, matchedRule, trustedClientIP, requestID) {
		return
	}
	if isCertificateDeployRoute {
		accessEntry.RouteType = "certificate_deploy"
		accessEntry.RouteKey = certificateDeployPathPrefix
		accessEntry.Matched = true
		accessEntry.AuthDecision = "binding_token"
		if snapshot.authConfig.AuthPort > 0 {
			accessEntry.Upstream = localServiceBaseURL(snapshot.authConfig.AuthPort)
		}
		if originalPath != r.URL.Path || certificateDeployHadQuery {
			loggedStatusCode = http.StatusNotFound
			rejectMalformedCertificateDeployRoute(w, r)
			return
		}
		if _, valid := certificateDeployBindingID(r.URL.Path); !valid {
			loggedStatusCode = http.StatusNotFound
			rejectMalformedCertificateDeployRoute(w, r)
			return
		}
		if r.Method != http.MethodPut {
			w.Header().Set("Allow", http.MethodPut)
			applyNoStoreCacheHeaders(w.Header())
			loggedStatusCode = http.StatusMethodNotAllowed
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		wrapRequestBodyForTraffic(r, h, metrics)
		forwardedClientIP := clientIP
		if certificateDeployRouteKind == certificateDeployRouteLAN {
			forwardedClientIP = certificateDeployTransportClientIP(r)
		}
		h.handleCertificateDeployRoute(w, r, snapshot, forwardedClientIP)
		return
	}
	wafRouteType, wafRouteKey, wafUpstream := wafRouteContextForRequest(
		r,
		snapshot,
		isAuthRoute,
		matchedHostRule,
		matchedHostLocation,
		matchedRule,
	)
	wafRuntime := h.wafRuntime
	if wafRuntime != nil && wafRuntime.Active() {
		commonLocationExemptions := snapshot.commonLocationExemptions
		wafBypassedByCommonLocation := commonLocationExemptions != nil && commonLocationExemptions.shouldBypassWAF(clientIP)
		if !trustedClientIP && !wafBypassedByCommonLocation {
			wafTimingStarted := time.Now()
			decision := wafRuntime.Evaluate(r, proxywaf.EvaluateContext{
				ClientIP:   clientIP,
				RouteType:  wafRouteType,
				RouteKey:   wafRouteKey,
				Upstream:   wafUpstream,
				Scheme:     requestScheme(r),
				RemoteAddr: r.RemoteAddr,
			})
			if deepMonitorTrace != nil {
				deepMonitorTrace.addWAFDuration(time.Since(wafTimingStarted))
			}
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
	if isWOLPath && !isWOLRoute {
		// Keep the built-in path reserved even while its shortcut is disabled.
		// Otherwise a broad user path/host rule could unexpectedly expose an
		// upstream at /__wol__, contradicting the feature's fail-closed boundary.
		accessEntry.Matched = false
		accessEntry.RouteType = "not_found"
		accessEntry.RouteKey = r.URL.Path
		accessEntry.Upstream = ""
		loggedStatusCode = http.StatusNotFound
		response.RouteNotFound(w, r, nil, false)
		return
	}
	if matchedHostRule != nil && matchedHostRule.UseAuth && !isAuthRoute && !isBuiltinAuthRoute &&
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
	isMatch := isBuiltinAuthRoute || isAuthRoute || matchedHostRule != nil || matchedRule != nil || r.URL.Path == "/"
	accessEntry.Matched = isMatch
	accessEntry.AccessMode = accessMode
	var authTimingStarted time.Time
	finishAuthTiming := func() {
		if authTimingStarted.IsZero() {
			return
		}
		if deepMonitorTrace != nil {
			deepMonitorTrace.addAuthDuration(time.Since(authTimingStarted))
		}
		authTimingStarted = time.Time{}
	}
	defer finishAuthTiming()
	var preparedAuth *authCheckExecution
	if shouldRunPreflightForRoute(isBuiltinAuthRoute, isAuthRoute, matchedHostRule, matchedRule) {
		authTimingStarted = time.Now()
		if strings.TrimSpace(snapshot.authConfig.AuthURL) != "" {
			requestAuth = newRequestAuthContext(r, clientIP, authContextAccessMode, routedBackend)
		}
		preflight := preflightDecision{}
		verifyRequired := strings.TrimSpace(snapshot.authConfig.AuthURL) != "" && !isAuthRoute &&
			(isBuiltinAuthRoute || (matchedHostRule != nil && matchedHostRule.UseAuth) || (matchedRule != nil && matchedRule.UseAuth))
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
		if preflight.serviceUnavailable {
			accessEntry.RouteType = "preflight"
			accessEntry.AuthDecision = "auth_unavailable"
			loggedStatusCode = http.StatusServiceUnavailable
			if event := debugProxyEvent("preflight_auth_unavailable", requestID); event != nil {
				event.Bool("matched", isMatch).
					Str("access_mode", accessMode).
					Send()
			}
			respondAuthServiceUnavailable(w, r, preflight.retryAfter)
			return
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
		finishAuthTiming()
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
		authTimingStarted = time.Now()
		authResult := h.handleSelectRoute(w, r, snapshot, clientIP, requestID, requestAuth, preparedAuth)
		finishAuthTiming()
		applyAuthResultToLogEntry(&accessEntry, authResult)
		if event := debugProxyEvent("select_route_served", requestID); event != nil {
			event.Bool("auth_required", accessEntry.AuthRequired).
				Bool("authenticated", authResult.authenticated).
				Str("auth_decision", authResult.decision).
				Send()
		}
		return
	}
	if isWOLRoute {
		accessEntry.RouteType = "wol"
		accessEntry.RouteKey = r.URL.Path
		accessEntry.AuthRequired = true
		authTimingStarted = time.Now()
		authResult := h.handleWOLRoute(w, r, snapshot, clientIP, requestID, requestAuth, preparedAuth)
		finishAuthTiming()
		applyAuthResultToLogEntry(&accessEntry, authResult)
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
		if fnosConnect != nil {
			accessEntry.RouteType = fnosConnectRouteKey
			accessEntry.RouteKey = fnosConnectRouteKey
		}
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
			authTimingStarted = time.Now()
			authResult = h.checkAuth(w, r, snapshot.authConfig, clientIP, matchedHostRule.AccessMode, authUpstreamTarget, requestID, requestAuth, preparedAuth)
			finishAuthTiming()
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
				requestAuth = newRequestAuthContext(r, clientIP, "", routedBackend)
			}
			authTimingStarted = time.Now()
			authResult = h.checkAuthForToolbar(w, r, snapshot.authConfig, clientIP, requestID, requestAuth)
			finishAuthTiming()
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
				requestAuth = newRequestAuthContext(r, clientIP, "", routedBackend)
			}
			authTimingStarted = time.Now()
			authResult = h.checkAuthForToolbar(w, r, snapshot.authConfig, clientIP, requestID, requestAuth)
			finishAuthTiming()
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
		authTimingStarted = time.Now()
		authResult = h.checkAuth(w, r, snapshot.authConfig, clientIP, "", matchedRule.Target, requestID, requestAuth, preparedAuth)
		finishAuthTiming()
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
			requestAuth = newRequestAuthContext(r, clientIP, "", routedBackend)
		}
		authTimingStarted = time.Now()
		authResult = h.checkAuthForToolbar(w, r, snapshot.authConfig, clientIP, requestID, requestAuth)
		finishAuthTiming()
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

func filterAvailableHostRulesByAuthScope(hostRules []models.HostRule, authResult authCheckResult, now time.Time) []models.HostRule {
	return filterSelectHostRulesByAuthScope(filterAvailableHostRules(hostRules, now), authResult)
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
	portal := snapshot.gatewayPortal
	portal.ShowWOL = portal.ShowWOL && authResultAllowsWOL(authResult)
	response.SelectPageWithPrefilteredRoutes(
		w,
		r,
		snapshot.toolbarRules,
		filterAvailableHostRulesByAuthScope(snapshot.toolbarHostRules, authResult, time.Now()),
		portal,
	)
	return authResult
}

func authResultAllowsWOL(authResult authCheckResult) bool {
	if !authResult.subdomainAccessCustom {
		return true
	}
	_, allowed := authResult.allowedSubdomainHosts["__builtin_wol__"]
	return allowed
}

func gatewayPortalForAuth(portal models.GatewayPortalConfig, authResult authCheckResult) models.GatewayPortalConfig {
	portal.ShowWOL = portal.ShowWOL && authResultAllowsWOL(authResult)
	return portal
}

func (h *Handler) handleWOLRoute(w http.ResponseWriter, r *http.Request, snapshot requestSnapshot, clientIP string, requestID string, requestAuth *requestAuthContext, prepared *authCheckExecution) authCheckResult {
	authResult := h.checkAuth(w, r, snapshot.authConfig, clientIP, "", "", requestID, requestAuth, prepared)
	if !authResult.allowed {
		return authResult
	}
	if !authResult.authenticated {
		applyNoStoreCacheHeaders(w.Header())
		http.Redirect(w, r, authLoginRedirectLocation(snapshot.authConfig, r), http.StatusFound)
		return authCheckResult{decision: "redirected"}
	}
	if !authResultAllowsWOL(authResult) {
		response.AccessDenied(w, r)
		return authCheckResult{decision: "scope_denied", statusCode: http.StatusForbidden}
	}
	applyNoStoreCacheHeaders(w.Header())
	response.WOLPage(w, r)
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
	if !authProxyOriginAllowed(r) {
		applyNoStoreCacheHeaders(w.Header())
		http.Error(w, "Cross-origin authentication request denied", http.StatusForbidden)
		return true
	}
	bodyDigest, err := authProxyRequestBodyDigest(r)
	if err != nil {
		applyNoStoreCacheHeaders(w.Header())
		status := http.StatusBadRequest
		if stderrors.Is(err, errAuthProxyRequestBodyTooLarge) {
			status = http.StatusRequestEntityTooLarge
		}
		http.Error(w, "Failed to read authentication request body", status)
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
	proxy.Transport = h.monitoredTransport(transport)

	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		applyInternalAuthProxyHeaders(req, r, targetURL, clientIP, snapshot.authConfig, h.authHMACSecret, bodyDigest)
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

func (h *Handler) routedBackendForRequest(
	r *http.Request,
	snapshot requestSnapshot,
	hostRule *models.HostRule,
	location *models.HostLocation,
	rule *models.Rule,
) routedBackend {
	target := ""
	preserveHost := false
	routeID := snapshot.routeGeneration
	if hostRule != nil {
		if location == nil {
			target = strings.TrimSpace(hostRule.Target)
			if selected := snapshot.routeIDs[hostRouteIncarnationKey(hostRule)]; selected != "" {
				routeID = selected
			}
		} else if location.Action == models.HostLocationActionProxy {
			target = strings.TrimSpace(location.Target)
			if selected := snapshot.routeIDs[hostLocationRouteIncarnationKey(hostRule, location)]; selected != "" {
				routeID = selected
			}
		} else {
			if selected := snapshot.routeIDs[hostLocationRouteIncarnationKey(hostRule, location)]; selected != "" {
				routeID = selected
			}
			return newRoutedBackendWithRouteID("", "", routeID)
		}
		preserveHost = hostRule.PreserveHost
	} else if rule != nil {
		target = strings.TrimSpace(rule.Target)
		preserveHost = true
		if selected := snapshot.routeIDs[pathRouteIncarnationKey(rule)]; selected != "" {
			routeID = selected
		}
	} else {
		return routedBackend{}
	}

	if target == "" {
		return newRoutedBackendWithRouteID("", "", routeID)
	}
	targetRuntime := reverseProxyTargetRuntimeFor(snapshot, target)
	if targetRuntime.err != nil || targetRuntime.transportURL == nil {
		return routedBackend{
			matched:    true,
			target:     target,
			routeID:    strings.TrimSpace(routeID),
			targetSet:  true,
			routeIDSet: true,
		}
	}
	transportTarget := targetRuntime.transportURL
	if h.shouldOmitPreserveHostKey(targetRuntime.policyKey) {
		preserveHost = false
	}
	if fnosConnectContext(r) != nil {
		preserveHost = true
	}

	upstreamHost := transportTarget.Host
	if preserveHost && r != nil && strings.TrimSpace(r.Host) != "" {
		upstreamHost = r.Host
	}
	return newRoutedBackendWithRouteID(
		targetRuntime.transportTarget,
		upstreamHost,
		routeID,
	)
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

func enforceReservedFnosShareRoute(
	requestPath string,
	snapshot requestSnapshot,
	hostRule *models.HostRule,
	location *models.HostLocation,
	rule *models.Rule,
	needsSlashRedirect string,
) (*models.HostLocation, *models.Rule, string) {
	if !isReservedFnosSharePath(requestPath) {
		return location, rule, needsSlashRedirect
	}
	if hostRule != nil {
		return nil, nil, ""
	}
	defaultRule := snapshot.defaultRule
	if defaultRule != nil && isReservedFnosSharePath(defaultRule.Path) {
		defaultRule = nil
	}
	return nil, defaultRule, ""
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
	if trace := deepMonitorFromRequest(r); trace != nil {
		trace.setConnectionIdentity(clientIP, authResult)
	}
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
	omitForwardedHeaders := h.shouldOmitForwardedHeadersKey(targetRuntime.policyKey)
	preserveHost := matchedRule.PreserveHost && !h.shouldOmitPreserveHostKey(targetRuntime.policyKey)
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
		Transport:  h.monitoredTransport(transport),
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

			if targetSupportsHTMLFeatures && location.RewriteHTML {
				pr.Out.Header.Del("Accept-Encoding")
			}
			if toolbarCandidate {
				prepareToolbarProxyRequest(pr.Out)
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
			h.handleUpstreamUnavailable(w, r, snapshot.unmatchedRoute, snapshot.rules, authResult.authenticated, err)
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
				return response.GenerateToolbarBootstrap()
			},
			requestID: requestID,
			routeType: "host_location",
			routeKey:  hostLocationRouteKey(&matchedRule, &location),
		})
	}

	if h.maybeProxyFnosPortIconHijackWebSocket(w, r, fnosPortIconHijackWebSocketOptions{
		targetURL:            transportTargetURL,
		hostRules:            snapshot.hostRules,
		unmatchedRoute:       snapshot.unmatchedRoute,
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
	if trace := deepMonitorFromRequest(r); trace != nil {
		trace.setConnectionIdentity(clientIP, authResult)
	}
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
	omitForwardedHeaders := h.shouldOmitForwardedHeadersKey(targetRuntime.policyKey)
	preserveHost := matchedRule.PreserveHost && !h.shouldOmitPreserveHostKey(targetRuntime.policyKey)
	if fnosConnectContext(r) != nil {
		// Relay-provided client identity and the original Host are part of the
		// FN Connect protocol boundary, not a user host-rule preference.
		omitForwardedHeaders = false
		preserveHost = true
	}
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
		Transport:  h.monitoredTransport(transport),
		BufferPool: sharedProxyBufferPool,
		Rewrite: func(pr *httputil.ProxyRequest) {
			applyForwardedHeaderPolicy(pr.Out, pr.In, clientIP, omitForwardedHeaders)
			if fnosConnectContext(pr.In) != nil {
				applyFnosConnectForwardedHeaders(pr.Out, pr.In, clientIP)
			}
			copyUserAgentHeader(pr.Out, pr.In)
			stripAdvancedAuthGrantCookie(pr.Out.Header)
			pr.SetURL(transportTargetURL)
			applyHostReverseProxyPath(pr.Out.URL, transportTargetURL, pr.In.URL, matchedRule.TargetPathMode)
			applyBasicAuthInjection(pr.Out, matchedRule.BasicAuth)
			applyUpstreamPrivateIPv4HintHeader(pr.Out, transportTargetURL)
			applyPreserveHostPolicy(pr.Out, pr.In, transportTargetURL, preserveHost)
			if fnosConnectContext(pr.In) == nil {
				h.maybePrepareFnosPortIconHijackHTTPProxyRequest(pr.Out)
			}

			if !preserveHost {
				if origin := pr.In.Header.Get("Origin"); origin != "" {
					pr.Out.Header.Set("Origin", transportTargetURL.Scheme+"://"+transportTargetURL.Host)
				}
				if referer := pr.In.Header.Get("Referer"); referer != "" {
					ref, err := url.Parse(referer)
					if err == nil {
						ref.Scheme = transportTargetURL.Scheme
						ref.Host = transportTargetURL.Host
						applyHostReverseProxyPath(ref, transportTargetURL, ref, matchedRule.TargetPathMode)
						pr.Out.Header.Set("Referer", ref.String())
					}
				}
			}

			if toolbarCandidate {
				prepareToolbarProxyRequest(pr.Out)
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
			h.handleUpstreamUnavailable(w, r, snapshot.unmatchedRoute, snapshot.rules, authResult.authenticated, err)
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
		if fnosConnectContext(r) == nil {
			if err := h.maybeRewriteFnosPortIconHijackHTTPResponse(resp, snapshot.hostRules); err != nil {
				return err
			}
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
				return response.GenerateToolbarBootstrap()
			},
			requestID: requestID,
			routeType: "host_rule",
			routeKey:  matchedRule.Host,
		})
	}

	if fnosConnectContext(r) == nil && h.maybeProxyFnosPortIconHijackWebSocket(w, r, fnosPortIconHijackWebSocketOptions{
		targetURL:            transportTargetURL,
		hostRules:            snapshot.hostRules,
		unmatchedRoute:       snapshot.unmatchedRoute,
		clientIP:             clientIP,
		omitForwardedHeaders: omitForwardedHeaders,
		preserveHost:         preserveHost,
		basicAuth:            matchedRule.BasicAuth,
		rewriteOriginReferer: !preserveHost,
		stripPath:            false,
		pathPrefix:           "",
		hostTargetPathMode:   matchedRule.TargetPathMode,
	}) {
		return
	}

	serveReverseProxyWithResponseCoalescing(proxy, w, r)
}

func (h *Handler) proxyToRuleTarget(w http.ResponseWriter, r *http.Request, snapshot requestSnapshot, matchedRule models.Rule, clientIP string, authResult authCheckResult, requestID string) {
	if trace := deepMonitorFromRequest(r); trace != nil {
		trace.setConnectionIdentity(clientIP, authResult)
	}
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
	preserveHost := !h.shouldOmitPreserveHostKey(targetRuntime.policyKey)
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
		Transport:  h.monitoredTransport(transport),
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

			if targetSupportsHTMLFeatures && matchedRule.RewriteHTML {
				pr.Out.Header.Del("Accept-Encoding")
			}
			if toolbarCandidate {
				prepareToolbarProxyRequest(pr.Out)
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
			h.handleUpstreamUnavailable(w, r, snapshot.unmatchedRoute, snapshot.rules, authResult.authenticated, err)
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
				return response.GenerateToolbarBootstrap()
			},
			requestID: requestID,
			routeType: "path_rule",
			routeKey:  matchedRule.Path,
		})
	}

	if h.maybeProxyFnosPortIconHijackWebSocket(w, r, fnosPortIconHijackWebSocketOptions{
		targetURL:            transportTargetURL,
		hostRules:            snapshot.hostRules,
		unmatchedRoute:       snapshot.unmatchedRoute,
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
