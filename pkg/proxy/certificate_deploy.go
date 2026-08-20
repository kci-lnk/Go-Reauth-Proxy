package proxy

import (
	"bytes"
	stderrors "errors"
	"io"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
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

func certificateDeployRouteMatches(r *http.Request, authHost string) bool {
	if r == nil || r.URL == nil || !isCertificateDeployReservedPath(r.URL.Path) {
		return false
	}
	requestHost := strings.TrimSuffix(normalizeRequestHost(r.Host), ".")
	configuredHost := strings.TrimSuffix(normalizeRequestHost(authHost), ".")
	return configuredHost != "" && requestHost == configuredHost
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
			proxyRequest.Out.Header.Set("X-Forwarded-Proto", requestScheme(r))
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
