package proxy

import (
	"bytes"
	stderrors "errors"
	"io"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"strconv"
	"strings"

	"go-reauth-proxy/pkg/gatewaylog"
	"go-reauth-proxy/pkg/logger"
)

type certificateDeployRouteKind uint8

const (
	certificateDeployRouteNone certificateDeployRouteKind = iota
	certificateDeployRoutePublic
	certificateDeployRouteLAN
)

const (
	certificateDeployPathPrefix = "/__certificates__"
	certificateDeployBodyLimit  = int64(1024 * 1024)
	maxCertificateBindingIDLen  = 128
)

func isCertificateDeployReservedPath(requestPath string) bool {
	return requestPath == certificateDeployPathPrefix ||
		strings.HasPrefix(requestPath, certificateDeployPathPrefix+"/")
}

func certificateDeployBindingID(requestPath string) (string, bool) {
	if !strings.HasPrefix(requestPath, certificateDeployPathPrefix+"/") {
		return "", false
	}
	bindingID := strings.TrimPrefix(requestPath, certificateDeployPathPrefix+"/")
	if bindingID == "" || len(bindingID) > maxCertificateBindingIDLen || strings.Contains(bindingID, "/") {
		return "", false
	}
	for _, char := range bindingID {
		if (char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || char == '-' || char == '_' {
			continue
		}
		return "", false
	}
	return bindingID, true
}

func certificateDeployRoute(r *http.Request, authHost string, bundle *sslRuntimeBundle) certificateDeployRouteKind {
	if r == nil || r.URL == nil || !isCertificateDeployReservedPath(r.URL.Path) {
		return certificateDeployRouteNone
	}
	requestHost := strings.TrimSuffix(normalizeRequestHost(r.Host), ".")
	configuredHost := strings.TrimSuffix(normalizeRequestHost(authHost), ".")
	// A configured LAN IP always keeps LAN semantics, even if an administrator
	// also entered that IP as AuthHost. Otherwise the public-host branch could
	// accidentally bypass the LAN TLS and transport-peer checks.
	if bundle.lanAddressAllowed(requestHost) {
		if r.TLS != nil && certificateDeployTransportClientAllowed(r) {
			return certificateDeployRouteLAN
		}
		return certificateDeployRouteNone
	}
	if configuredHost != "" && requestHost == configuredHost {
		return certificateDeployRoutePublic
	}
	return certificateDeployRouteNone
}

func certificateDeployRouteMatches(r *http.Request, authHost string, bundle *sslRuntimeBundle) bool {
	return certificateDeployRoute(r, authHost, bundle) != certificateDeployRouteNone
}

func certificateDeployTransportClientIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	// RemoteAddr is either the direct socket peer or the authenticated PROXY
	// protocol address. HTTP forwarding headers are deliberately ignored.
	return normalizeClientIP(r.RemoteAddr)
}

func certificateDeployTransportClientAllowed(r *http.Request) bool {
	address, err := netip.ParseAddr(certificateDeployTransportClientIP(r))
	if err != nil {
		return false
	}
	if address.IsLoopback() || address.IsPrivate() {
		return true
	}
	return netip.MustParsePrefix("100.64.0.0/10").Contains(address)
}

func stripCertificateDeployInternalHeaders(headers http.Header) {
	for _, name := range []string{
		"Forwarded",
		"X-Forwarded-For",
		"X-Forwarded-Host",
		"X-Forwarded-Proto",
		"X-Forwarded-Path",
		"X-Real-IP",
		"X-Match",
		"X-Timestamp",
		"X-Nonce",
		"X-Signature",
		headerAliRealClientIP,
		headerEOConnectingIP,
	} {
		headers.Del(name)
	}
}

func certificateDeployForwardedProto(r *http.Request) string {
	// A direct TLS connection is authoritative. In particular, do not let a
	// client-supplied X-Forwarded-Proto downgrade a valid LAN request before
	// Rust performs its second transport check. Non-TLS public ingress keeps
	// the existing trusted-edge scheme resolution behavior.
	if r != nil && r.TLS != nil {
		return "https"
	}
	return requestScheme(r)
}

func redactCertificateDeployAccessEntry(entry *gatewaylog.Entry) {
	if entry == nil {
		return
	}
	entry.UserAgent = ""
	entry.Referer = ""
	entry.AliRealClientIP = ""
	entry.EOConnectingIP = ""
	entry.XForwardedFor = ""
	entry.XRealIP = ""
}

func requestDebugHeaders(sensitive bool, headers http.Header) (string, any) {
	if sensitive {
		return "header_names", logger.SanitizedHeaderNames(headers)
	}
	return "headers", logger.SanitizeHeader(headers)
}

func requestDebugClientHeaders(sensitive bool, r *http.Request) (string, string, string, string) {
	if sensitive || r == nil {
		return "", "", "", ""
	}
	return firstForwardedValue(r.Header.Get("X-Forwarded-For")),
		r.Header.Get(headerXRealIP),
		r.Header.Get(headerAliRealClientIP),
		r.Header.Get(headerEOConnectingIP)
}

func (h *Handler) handleCertificateDeployRoute(
	w http.ResponseWriter,
	r *http.Request,
	snapshot requestSnapshot,
	clientIP string,
) {
	applyNoStoreCacheHeaders(w.Header())
	if snapshot.authConfig.AuthPort <= 0 {
		http.Error(w, "Certificate deployment service is unavailable", http.StatusNotFound)
		return
	}

	limitedBody := http.MaxBytesReader(w, r.Body, certificateDeployBodyLimit)
	body, err := io.ReadAll(limitedBody)
	if err != nil {
		var maxBytesError *http.MaxBytesError
		if stderrors.As(err, &maxBytesError) {
			http.Error(w, "Certificate deployment payload is too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "Failed to read certificate deployment payload", http.StatusBadRequest)
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	r.Header.Set("Content-Length", strconv.Itoa(len(body)))

	targetURL := localServiceTargetURL(snapshot.authConfig.AuthPort)
	proxy := &httputil.ReverseProxy{
		BufferPool: sharedProxyBufferPool,
		Rewrite: func(proxyRequest *httputil.ProxyRequest) {
			proxyRequest.SetURL(targetURL)
			stripCertificateDeployInternalHeaders(proxyRequest.Out.Header)
			proxyRequest.Out.Host = r.Host
			proxyRequest.Out.Header.Set(headerXRealIP, clientIP)
			proxyRequest.Out.Header.Set("X-Forwarded-For", clientIP)
			proxyRequest.Out.Header.Set("X-Forwarded-Host", r.Host)
			proxyRequest.Out.Header.Set("X-Forwarded-Proto", certificateDeployForwardedProto(r))
		},
		ModifyResponse: func(proxyResponse *http.Response) error {
			applyNoStoreCacheHeaders(proxyResponse.Header)
			return nil
		},
		ErrorHandler: func(responseWriter http.ResponseWriter, _ *http.Request, _ error) {
			applyNoStoreCacheHeaders(responseWriter.Header())
			http.Error(responseWriter, "Certificate deployment upstream is unavailable", http.StatusBadGateway)
		},
	}
	transport := h.proxyTransport
	if transport == nil {
		transport = newProxyTransport()
	}
	proxy.Transport = h.monitoredTransport(transport)
	proxy.ServeHTTP(w, r)
}

func rejectMalformedCertificateDeployRoute(w http.ResponseWriter, r *http.Request) {
	applyNoStoreCacheHeaders(w.Header())
	http.NotFound(w, r)
}
