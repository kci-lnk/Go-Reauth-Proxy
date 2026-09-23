package proxy

import (
	"context"
	stderrors "errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"go-reauth-proxy/pkg/diagnostics"
	"go-reauth-proxy/pkg/errors"
	"go-reauth-proxy/pkg/grpc/pb"
	"go-reauth-proxy/pkg/logger"
	"go-reauth-proxy/pkg/models"
	"go-reauth-proxy/pkg/response"
	"go-reauth-proxy/pkg/rpcbridge"
)

type authCheckErrorPage struct {
	code       int
	title      string
	message    string
	retryAfter string
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
		failure := classifyAuthBridgeFailure(rpcbridge.ErrAuthBridgeUnavailable)
		log.Printf("Auth bridge request failed: cause=%s duration_ms=0", failure.cause)
		return authCheckPlan{
			result:    authCheckResult{decision: "error"},
			errorPage: failure.errorPage(),
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
		failure := classifyAuthBridgeFailure(err)
		if event := debugProxyEvent("auth_check_request_failed", requestID); event != nil {
			event.Str("transport", "auth_bridge").
				Str("cause", failure.cause).
				Int64("duration_ms", time.Since(start).Milliseconds()).
				Send()
		}
		log.Printf("Auth bridge request failed: cause=%s duration_ms=%d", failure.cause, time.Since(start).Milliseconds())
		return authCheckPlan{
			result:    authCheckResult{decision: "error"},
			errorPage: failure.errorPage(),
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
	bridgeDecision := strings.TrimSpace(resp.GetDecision())
	// A temporary-grant issuance limiter is deliberately fail-closed. Preserve
	// the bridge's 429 and Retry-After instead of converting it to a login
	// redirect or the generic access-denied page. Classify this before success
	// so an internally inconsistent bridge response can never grant access.
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
	if authResponseIsUnavailable(resp, responseHeaders, statusCode) {
		// A bridge/storage failure is not a policy denial. Keep the request
		// fail-closed, but return a well-formed response so HTTP/2 clients do not
		// see an application error disguised as a protocol-level stream reset.
		if event := debugProxyEvent("auth_check_end", requestID); event != nil {
			event.Int("status", http.StatusServiceUnavailable).
				Bool("success", false).
				Str("decision", "auth_unavailable").
				Str("bridge_decision", logger.SanitizeLogString(bridgeDecision)).
				Int("bridge_status", statusCode).
				Int64("duration_ms", time.Since(start).Milliseconds()).
				Send()
		}
		return authCheckPlan{
			result: authCheckResult{
				decision:   "auth_unavailable",
				statusCode: http.StatusServiceUnavailable,
			},
			errorPage: &authCheckErrorPage{
				code:       http.StatusServiceUnavailable,
				title:      authServiceUnavailableMessage,
				message:    authServiceUnavailableMessage,
				retryAfter: strings.TrimSpace(responseHeaders.Get("Retry-After")),
			},
		}
	}

	if resp.GetSuccess() && statusCode < http.StatusBadRequest {
		subdomainAccessCustom, allowedSubdomainHosts := parseAllowedSubdomainHosts(responseHeaders)
		credentialIdentity := parseAuthCredentialIdentity(responseHeaders)
		isSubdomainRuleGrant := resp.GetGrantKind() == pb.AuthGrantKind_AUTH_GRANT_KIND_SUBDOMAIN_RULE
		authenticated := verifyResponseHasSystemLogin(resp)
		decision := bridgeDecision
		if isSubdomainRuleGrant {
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
		if plan.errorPage.retryAfter != "" {
			w.Header().Set("Retry-After", plan.errorPage.retryAfter)
		}
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

func (h *Handler) cachedAuthEntry(lookup authCacheLookup, now time.Time) (*authCacheEntry, authCacheKey, bool) {
	if entry, ok := h.authCacheGet(lookup.cacheKey, now); ok {
		return entry, lookup.cacheKey, true
	}
	if lookup.hostCacheKey != (authCacheKey{}) {
		if entry, ok := h.authCacheGet(lookup.hostCacheKey, now); ok {
			return entry, lookup.hostCacheKey, true
		}
	}
	return nil, authCacheKey{}, false
}

type authBridgeFailure struct {
	cause      string
	status     int
	retryAfter string
}

func classifyAuthBridgeFailure(err error) authBridgeFailure {
	switch {
	case stderrors.Is(err, context.DeadlineExceeded):
		return authBridgeFailure{cause: "timeout", status: http.StatusGatewayTimeout}
	case stderrors.Is(err, rpcbridge.ErrAuthBridgeQueueFull):
		return authBridgeFailure{cause: "queue_full", status: http.StatusServiceUnavailable, retryAfter: "1"}
	case stderrors.Is(err, rpcbridge.ErrAuthBridgeDisconnected):
		return authBridgeFailure{cause: "disconnected", status: http.StatusServiceUnavailable, retryAfter: "1"}
	case stderrors.Is(err, rpcbridge.ErrAuthBridgeUnavailable):
		return authBridgeFailure{cause: "bridge_unavailable", status: http.StatusServiceUnavailable, retryAfter: "1"}
	case stderrors.Is(err, rpcbridge.ErrAuthBridgeInvalidResponse):
		return authBridgeFailure{cause: "invalid_response", status: http.StatusBadGateway}
	default:
		return authBridgeFailure{cause: "internal", status: http.StatusBadGateway}
	}
}

func (failure authBridgeFailure) errorPage() *authCheckErrorPage {
	return &authCheckErrorPage{
		code:       failure.status,
		title:      "Authentication Service Unavailable",
		message:    "Authentication Service Unavailable",
		retryAfter: failure.retryAfter,
	}
}

func canceledAuthCheckExecution(err error) authCheckExecution {
	failure := classifyAuthBridgeFailure(err)
	return authCheckExecution{plan: authCheckPlan{
		result:    authCheckResult{decision: "error"},
		errorPage: failure.errorPage(),
	}}
}

func (h *Handler) executeAuthCheck(r *http.Request, authConfig models.AuthConfig, clientIP string, accessMode string, requestID string, requestAuth *requestAuthContext) authCheckExecution {
	return h.executeAuthCheckAtGeneration(r, authConfig, clientIP, accessMode, requestID, requestAuth, h.authGenerationForContext(requestAuth))
}

func (h *Handler) executeAuthCheckAtGeneration(r *http.Request, authConfig models.AuthConfig, clientIP string, accessMode string, requestID string, requestAuth *requestAuthContext, generation uint64) authCheckExecution {
	now := time.Now()
	useCache := authCacheEnabled(authConfig)
	dimensions, canLookup := buildAuthCacheDimensionsWithRouteIdentity(r, clientIP, accessMode, authRouteIdentityForContext(r, requestAuth))
	var lookup authCacheLookup
	if canLookup {
		lookup = dimensions.authLookup()
	}
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
				return authCheckExecution{entry: entry}
			}
		}

		sharedRequest := r.WithContext(context.WithoutCancel(r.Context()))
		resultCh := h.authCache.group.DoChan(lookup.cacheKey.flightKey(generation), func() (any, error) {
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
					return authCheckExecution{entry: entry}, nil
				}
			}

			plan := h.performAuthCheck(sharedRequest, authConfig, clientIP, accessMode, requestID, requestAuth)
			if plan.errorPage == nil && len(plan.setCookies) == 0 {
				if ttl := authCacheTTL(authConfig, plan.result); ttl > 0 {
					var cacheKey authCacheKey
					switch plan.cacheScope {
					case pb.AuthCacheScope_AUTH_CACHE_SCOPE_EXACT_REQUEST:
						cacheKey = lookup.cacheKey
					case pb.AuthCacheScope_AUTH_CACHE_SCOPE_HOST:
						cacheKey = lookup.hostCacheKey
					}
					if cacheKey == (authCacheKey{}) {
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
						h.authCacheStore(cacheKey, entry, generation)
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
	if baseURL == nil || baseURL.Host == "" {
		return
	}
	if authConfig.EdgeClientIPActive() || isManagedCloudflareTunnelIngress(r) || isCloudflareEdgeRequest(r, baseURL.Scheme) {
		// The stored public auth URL may predate edge mode and still contain the
		// origin ingress port. Edge mode and trusted Cloudflare ingress are
		// authoritative, so normalize it back to the browser-facing standard port
		// instead of preserving :7999.
		baseURL.Host = formatURLHost(baseURL.Hostname(), "", baseURL.Scheme)
		return
	}
	if baseURL.Port() != "" {
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
