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
			failure := classifyAuthBridgeFailure(err)
			if event := debugProxyEvent("authorize_http_request_failed", requestID); event != nil {
				event.Str("cause", failure.cause).
					Int64("duration_ms", time.Since(start).Milliseconds()).
					Send()
			}
			log.Printf("Auth bridge request failed: cause=%s duration_ms=%d", failure.cause, time.Since(start).Milliseconds())
			return combinedHTTPAuthExecution{auth: canceledAuthCheckExecution(err), handled: true}
		}
		h.preflightSkipUntilUnixNano.Store(0)
		if response.GetPreflight() == nil {
			return combinedHTTPAuthExecution{auth: canceledAuthCheckExecution(rpcbridge.ErrAuthBridgeInvalidResponse), handled: true}
		}
		execution := combinedHTTPAuthExecution{
			preflight: h.preflightDecisionFromResponse(response.GetPreflight(), requestID, start),
			handled:   true,
		}
		if preflightStopsHTTPAuthorization(execution.preflight) {
			return h.storeCombinedHTTPAuth(callRequest, authConfig, response, execution, preflightLookup, canPreflightLookup, authLookup, canAuthLookup)
		}
		if response.GetVerify() == nil {
			execution.auth = canceledAuthCheckExecution(rpcbridge.ErrAuthBridgeInvalidResponse)
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
