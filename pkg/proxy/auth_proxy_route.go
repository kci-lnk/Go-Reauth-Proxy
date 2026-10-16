package proxy

import (
	stderrors "errors"
	"net/http"
	"net/http/httputil"
	"path"
	"strings"

	"go-reauth-proxy/pkg/errors"
	"go-reauth-proxy/pkg/logger"
	"go-reauth-proxy/pkg/response"
)

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
	transport := h.authTransport()
	proxy.Transport = h.monitoredTransport(transport)
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		if h.handleAuthUnmatchedError(w, r, err) {
			return
		}
		logger.UpstreamFailure(targetURL, requestTraceID(r), "auth_proxy", classifyUpstreamFailure(err).class, err)
		applyNoStoreCacheHeaders(w.Header())
		h.handleUpstreamUnavailable(w, r, snapshot.unmatchedRoute, snapshot.rules, false, err)
	}

	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		applyInternalAuthProxyHeaders(req, r, targetURL, clientIP, snapshot.authConfig, h.authHMACSecret, bodyDigest)
	}
	proxy.ModifyResponse = func(resp *http.Response) error {
		if err := checkAuthUnmatchedResponse(resp, true, snapshot.unmatchedRoute); err != nil {
			return err
		}
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
