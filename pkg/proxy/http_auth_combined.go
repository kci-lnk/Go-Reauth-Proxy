package proxy

import (
	"context"
	"log"
	"net/http"
	"strings"
	"time"

	"go-reauth-proxy/pkg/diagnostics"
	"go-reauth-proxy/pkg/grpc/pb"
	"go-reauth-proxy/pkg/models"
	"go-reauth-proxy/pkg/rpcbridge"
)

func preflightStopsHTTPAuthorization(decision preflightDecision) bool {
	return decision.deny || decision.accessDeniedReason != "" || decision.serviceUnavailable || decision.redirectLocation != ""
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
				authExecution.entry = entry
				authHit = true
			}
		}
	}
	return preflight, preflightHit, authExecution, authHit
}

func (h *Handler) storeCombinedHTTPAuth(r *http.Request, authConfig models.AuthConfig, response *pb.AuthorizeHttpResponse, execution combinedHTTPAuthExecution, preflightLookup preflightCacheLookup, canPreflightLookup bool, authLookup authCacheLookup, canAuthLookup bool, generation uint64) combinedHTTPAuthExecution {
	now := time.Now()
	if canPreflightLookup && response.GetPreflightCacheScope() == pb.AuthCacheScope_AUTH_CACHE_SCOPE_EXACT_REQUEST {
		if ttl := preflightCacheTTL(authConfig); ttl > 0 && !shouldBypassFNAppNegativePreflightCache(r, execution.preflight) {
			h.preflightCacheStore(preflightLookup.cacheKey, preflightCacheEntry{
				decision:    execution.preflight,
				expiresAt:   now.Add(ttl),
				identityKey: preflightLookup.identityKey,
			}, generation)
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
	var cacheKey authCacheKey
	switch response.GetVerifyCacheScope() {
	case pb.AuthCacheScope_AUTH_CACHE_SCOPE_EXACT_REQUEST:
		cacheKey = authLookup.cacheKey
	case pb.AuthCacheScope_AUTH_CACHE_SCOPE_HOST:
		cacheKey = authLookup.hostCacheKey
	}
	if cacheKey == (authCacheKey{}) {
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
	stored := h.authCacheStore(cacheKey, entry, generation)
	execution.auth = authCheckExecution{entry: stored}
	return execution
}

func (h *Handler) executeCombinedHTTPAuth(r *http.Request, authConfig models.AuthConfig, clientIP string, accessMode string, isMatch bool, requestID string, requestAuth *requestAuthContext) (combinedHTTPAuthExecution, bool) {
	generation := h.authGenerationForContext(requestAuth)
	bridge := h.authBridgeManager()
	if bridge == nil || !bridge.SupportsCapability(rpcbridge.CapabilityAuthorizeHTTPV1) {
		return combinedHTTPAuthExecution{}, false
	}

	dimensions, canLookup := buildAuthCacheDimensionsWithRouteIdentity(r, clientIP, accessMode, authRouteIdentityForContext(r, requestAuth))
	preflightLookup, canPreflightLookup := preflightCacheLookup{}, canLookup
	authLookup, canAuthLookup := authCacheLookup{}, canLookup
	if canLookup {
		preflightLookup = dimensions.preflightLookup(isMatch)
		authLookup = dimensions.authLookup()
	}
	preflight, preflightHit, authExecution, authHit := h.cachedCombinedHTTPAuth(r, authConfig, time.Now(), preflightLookup, canPreflightLookup, authLookup, canAuthLookup)
	if !preflightHit && h.preflightSkipUntilUnixNano.Load() > time.Now().UnixNano() && !requestAuth.preflightRequired() {
		if !authHit {
			authExecution = h.executeAuthCheckAtGeneration(r, authConfig, clientIP, accessMode, requestID, requestAuth, generation)
		}
		return combinedHTTPAuthExecution{auth: authExecution, handled: true}, true
	}
	if preflightHit {
		if !preflightStopsHTTPAuthorization(preflight) && !authHit {
			authExecution = h.executeAuthCheckAtGeneration(r, authConfig, clientIP, accessMode, requestID, requestAuth, generation)
		}
		return combinedHTTPAuthExecution{preflight: preflight, auth: authExecution, handled: true}, true
	}
	if authHit {
		preflight = h.runPreflightAtGeneration(r, authConfig, clientIP, isMatch, accessMode, requestID, requestAuth, generation)
		return combinedHTTPAuthExecution{preflight: preflight, auth: authExecution, handled: true}, true
	}
	return h.executeCombinedHTTPAuthMiss(r, authConfig, clientIP, accessMode, isMatch, requestID, requestAuth, bridge, preflightLookup, authLookup, canLookup, generation)
}

// Keep singleflight callbacks out of the hit path so their captured configuration
// and closures are allocated only when a request needs an authorization RPC.
func (h *Handler) executeCombinedHTTPAuthMiss(r *http.Request, authConfig models.AuthConfig, clientIP string, accessMode string, isMatch bool, requestID string, requestAuth *requestAuthContext, bridge authBridgeClient, preflightLookup preflightCacheLookup, authLookup authCacheLookup, canLookup bool, generation uint64) (combinedHTTPAuthExecution, bool) {
	canPreflightLookup, canAuthLookup := canLookup, canLookup
	resolveCached := func(callRequest *http.Request, preflight preflightDecision, preflightHit bool, authExecution authCheckExecution, authHit bool) (combinedHTTPAuthExecution, bool) {
		switch {
		case preflightHit && (preflightStopsHTTPAuthorization(preflight) || authHit):
			return combinedHTTPAuthExecution{preflight: preflight, auth: authExecution, handled: true}, true
		case preflightHit:
			authExecution = h.executeAuthCheckAtGeneration(callRequest, authConfig, clientIP, accessMode, requestID, requestAuth, generation)
			return combinedHTTPAuthExecution{preflight: preflight, auth: authExecution, handled: true}, true
		case authHit:
			preflight = h.runPreflightAtGeneration(callRequest, authConfig, clientIP, isMatch, accessMode, requestID, requestAuth, generation)
			return combinedHTTPAuthExecution{preflight: preflight, auth: authExecution, handled: true}, true
		default:
			return combinedHTTPAuthExecution{}, false
		}
	}
	run := func(callRequest *http.Request) combinedHTTPAuthExecution {
		if preflight, preflightHit, authExecution, authHit := h.cachedCombinedHTTPAuth(callRequest, authConfig, time.Now(), preflightLookup, canPreflightLookup, authLookup, canAuthLookup); preflightHit || authHit {
			if !preflightHit && h.preflightSkipUntilUnixNano.Load() > time.Now().UnixNano() && !requestAuth.preflightRequired() {
				if !authHit {
					authExecution = h.executeAuthCheckAtGeneration(callRequest, authConfig, clientIP, accessMode, requestID, requestAuth, generation)
				}
				return combinedHTTPAuthExecution{auth: authExecution, handled: true}
			}
			if execution, resolved := resolveCached(callRequest, preflight, preflightHit, authExecution, authHit); resolved {
				return execution
			}
		}
		if h.preflightSkipUntilUnixNano.Load() > time.Now().UnixNano() && !requestAuth.preflightRequired() {
			return combinedHTTPAuthExecution{
				auth:    h.executeAuthCheckAtGeneration(callRequest, authConfig, clientIP, accessMode, requestID, requestAuth, generation),
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
			return h.storeCombinedHTTPAuth(callRequest, authConfig, response, execution, preflightLookup, canPreflightLookup, authLookup, canAuthLookup, generation)
		}
		if response.GetVerify() == nil {
			execution.auth = canceledAuthCheckExecution(rpcbridge.ErrAuthBridgeInvalidResponse)
			return execution
		}
		execution.auth.plan = h.authCheckPlanFromResponse(callRequest, authConfig, accessMode, requestID, start, response.GetVerify())
		return h.storeCombinedHTTPAuth(callRequest, authConfig, response, execution, preflightLookup, canPreflightLookup, authLookup, canAuthLookup, generation)
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
	key := "authorize-http:" + preflightLookup.cacheKey.flightKey(generation) + ":" + authLookup.cacheKey.flightKey(generation)
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
