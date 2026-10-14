package proxy

import (
	"net/http"
	"time"

	"go-reauth-proxy/pkg/response"
)

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
	portal := gatewayPortalForNavigation(snapshot.gatewayPortal, clientIP)
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

func (h *Handler) handleNoMatchRoute(w http.ResponseWriter, r *http.Request, snapshot requestSnapshot, authenticated bool) {
	if r.URL.Path == "/" {
		if len(snapshot.rules) == 0 && len(snapshot.hostRules) == 0 {
			response.Welcome(w, r, nil)
			return
		}
		if len(snapshot.rules) > 0 && snapshot.gatewayPortal.IsSelectPageEnabled() {
			http.Redirect(w, r, "/__select__", http.StatusFound)
			return
		}
	}
	response.RouteNotFound(w, r, snapshot.rules, authenticated && snapshot.gatewayPortal.IsSelectPageEnabled())
}
