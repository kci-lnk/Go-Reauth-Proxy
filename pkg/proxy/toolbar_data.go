package proxy

import (
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"go-reauth-proxy/pkg/models"
	"go-reauth-proxy/pkg/response"
)

const (
	toolbarPagePathMaxBytes = 8 * 1024
	toolbarPageQueryHeader  = "X-Reauth-Toolbar-Page-Query"
)

func normalizeToolbarPagePath(raw string) (string, bool) {
	if raw == "" || len(raw) > toolbarPagePathMaxBytes || raw[0] != '/' || toolbarInputHasInvalidText(raw) {
		return "", false
	}
	cleaned := path.Clean(raw)
	if strings.HasSuffix(raw, "/") && cleaned != "/" {
		cleaned += "/"
	}
	return cleaned, true
}

func normalizeToolbarPageQuery(raw string) (string, bool) {
	if len(raw) > toolbarPagePathMaxBytes || strings.ContainsRune(raw, '#') || toolbarInputHasInvalidText(raw) {
		return "", false
	}
	decoded, err := url.QueryUnescape(raw)
	if err != nil || toolbarInputHasInvalidText(decoded) {
		return "", false
	}
	return raw, true
}

func toolbarInputHasInvalidText(raw string) bool {
	if !utf8.ValidString(raw) {
		return true
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] < 0x20 || raw[i] == 0x7f {
			return true
		}
	}
	return false
}

func toolbarPageRequest(r *http.Request, pagePath string, pageQuery string) *http.Request {
	pageRequest := r.Clone(r.Context())
	pageURL := &url.URL{Path: pagePath, RawQuery: pageQuery}
	pageRequest.URL = pageURL
	pageRequest.RequestURI = pageURL.RequestURI()
	pageRequest.Header.Del(toolbarPageQueryHeader)
	return pageRequest
}

func (h *Handler) handleToolbarDataRoute(w http.ResponseWriter, r *http.Request, snapshot requestSnapshot, clientIP string, requestID string, matchedHostRule *models.HostRule) authCheckResult {
	result := authCheckResult{allowed: true, decision: "not_required"}
	applyNoStoreCacheHeaders(w.Header())
	w.Header().Set("X-Content-Type-Options", "nosniff")

	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", http.MethodGet+", "+http.MethodHead)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return result
	}

	queryValues, err := url.ParseQuery(r.URL.RawQuery)
	pagePaths := queryValues["page_path"]
	if err != nil || len(queryValues) != 1 || len(pagePaths) != 1 {
		http.Error(w, "Invalid page_path", http.StatusBadRequest)
		return result
	}
	pagePath, ok := normalizeToolbarPagePath(pagePaths[0])
	if !ok {
		http.Error(w, "Invalid page_path", http.StatusBadRequest)
		return result
	}
	pageQuery, ok := normalizeToolbarPageQuery(r.Header.Get(toolbarPageQueryHeader))
	if !ok {
		http.Error(w, "Invalid page query", http.StatusBadRequest)
		return result
	}
	if !snapshot.gatewayPortal.Enabled || response.ShouldSuppressToolbarForUserAgent(r.UserAgent()) || !requestHasExplicitAuthIdentity(r) {
		w.WriteHeader(http.StatusNoContent)
		return result
	}

	pageRequest := toolbarPageRequest(r, pagePath, pageQuery)
	var matchedHostLocation *models.HostLocation
	var matchedRule *models.Rule
	currentPath := pagePath
	currentHost := ""
	excludedHost := ""
	filteredHostRules := []models.HostRule(nil)

	if matchedHostRule != nil {
		if !hostRuleAvailableNow(matchedHostRule, time.Now()) {
			w.WriteHeader(http.StatusNoContent)
			return result
		}
		matchedHostLocation = matchHostLocation(pageRequest, matchedHostRule)
		target := matchedHostRule.Target
		if matchedHostLocation != nil {
			if matchedHostLocation.Action != models.HostLocationActionProxy {
				w.WriteHeader(http.StatusNoContent)
				return result
			}
			target = matchedHostLocation.Target
		}
		if matchedHostRule.SuppressToolbar || !snapshotReverseProxyTargetSupportsHTMLFeatures(snapshot, target) {
			w.WriteHeader(http.StatusNoContent)
			return result
		}
		currentHost = matchedHostRule.Host
		excludedHost = snapshot.authConfig.AuthHost
	} else {
		matchedRule, _ = matchRule(pageRequest, snapshot)
		if matchedRule == nil && snapshot.defaultRule != nil && !isReservedFnosSharePath(snapshot.defaultRule.Path) {
			matchedRule = snapshot.defaultRule
		}
		if matchedRule == nil || !snapshotReverseProxyTargetSupportsHTMLFeatures(snapshot, matchedRule.Target) {
			w.WriteHeader(http.StatusNoContent)
			return result
		}
		currentPath = matchedRule.Path
	}

	accessMode := ""
	if matchedHostRule != nil && matchedHostRule.UseAuth {
		accessMode = matchedHostRule.AccessMode
		if normalizeRequestHost(matchedHostRule.Host) != normalizeRequestHost(snapshot.authConfig.AuthHost) {
			withAdvancedAuthPolicyVersion(pageRequest, matchedHostRule.AdvancedAuth.PolicyVersion)
		}
	}
	routedBackend := h.routedBackendForRequest(pageRequest, snapshot, matchedHostRule, matchedHostLocation, matchedRule)
	requestAuth := newRequestAuthContext(pageRequest, clientIP, accessMode, routedBackend)
	authResult := h.checkToolbarDataAuth(w, pageRequest, snapshot.authConfig, clientIP, accessMode, requestID, requestAuth)
	if !authResult.authenticated || authResult.suppressToolbar {
		w.WriteHeader(http.StatusNoContent)
		return authResult
	}

	portal := gatewayPortalForAuth(snapshot.gatewayPortal, authResult)
	if matchedHostRule != nil {
		filteredHostRules = filterAvailableHostRulesByAuthScope(snapshot.toolbarHostRules, authResult, time.Now())
	}
	body := response.GenerateToolbarDataWithPrefilteredHostsForRequest(
		pageRequest,
		snapshot.toolbarRules,
		filteredHostRules,
		currentPath,
		currentHost,
		excludedHost,
		portal,
	)
	if body == "" {
		w.WriteHeader(http.StatusNoContent)
		return authResult
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return authResult
	}
	_, _ = w.Write([]byte(body))
	return authResult
}

func (h *Handler) checkToolbarDataAuth(w http.ResponseWriter, r *http.Request, authConfig models.AuthConfig, clientIP string, accessMode string, requestID string, requestAuth *requestAuthContext) authCheckResult {
	// This endpoint exposes the current portal navigation and authorization
	// scope. A positive proxy-auth cache entry can outlive a logout/revocation,
	// so it must never be used here: every bootstrap request revalidates the
	// presented credential against the authentication service and fails closed.
	plan := h.performAuthCheck(r, authConfig, clientIP, accessMode, requestID, requestAuth)
	return h.applyToolbarAuthCheckPlan(w, r, plan, clientIP)
}

func prepareToolbarProxyRequest(r *http.Request) {
	if !toolbarRequestMayBeDocument(r) {
		return
	}
	r.Header.Del("Accept-Encoding")
	if r.Method == http.MethodGet {
		r.Header.Del("If-None-Match")
		r.Header.Del("If-Modified-Since")
	}
}

func toolbarRequestMayBeDocument(r *http.Request) bool {
	if r == nil || r.Method != http.MethodGet {
		return false
	}
	if destination := strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Dest"))); destination != "" {
		return destination == "document" || destination == "iframe" || destination == "frame"
	}

	accept := strings.ToLower(r.Header.Get("Accept"))
	if accept != "" &&
		!strings.Contains(accept, "text/html") &&
		!strings.Contains(accept, "application/xhtml+xml") &&
		!strings.Contains(accept, "*/*") {
		return false
	}

	switch strings.ToLower(path.Ext(r.URL.Path)) {
	case ".css", ".js", ".mjs", ".json", ".map", ".xml", ".txt",
		".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".svg", ".ico",
		".woff", ".woff2", ".ttf", ".otf", ".eot",
		".mp3", ".mp4", ".webm", ".wav", ".ogg":
		return false
	default:
		return true
	}
}
