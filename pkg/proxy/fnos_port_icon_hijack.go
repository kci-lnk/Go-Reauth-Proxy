package proxy

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"go-reauth-proxy/pkg/models"
	"io"
	"log"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

const defaultFnosPortIconHijackGatewayPort = 7999
const defaultFnosPortIconHijackWebSocketMaxLifetime = 55 * time.Minute
const fnosPortIconHijackWebSocketCloseTimeout = 2 * time.Second
const fnosPortIconHijackWebSocketPath = "/websocket"
const fnosPortIconHijackServiceListPath = "/app-center/v1/service/list"
const fnosPortIconHijackHTTPBodyLimitBytes int64 = 2 * 1024 * 1024

type fnosPortIconHijackPublicEndpoint struct {
	protocol string
	port     int
}

type fnosPortIconHijackWebSocketOptions struct {
	targetURL             *url.URL
	hostRules             []models.HostRule
	unmatchedRoute        models.GatewayUnmatchedRouteConfig
	clientIP              string
	omitForwardedHeaders  bool
	preserveHost          bool
	basicAuth             models.BasicAuthConfig
	rewriteOriginReferer  bool
	stripPath             bool
	pathPrefix            string
	hostTargetPathIsEntry bool
	webSocketMaxLifetime  time.Duration
}

func (h *Handler) maybeProxyFnosPortIconHijackWebSocket(w http.ResponseWriter, r *http.Request, options fnosPortIconHijackWebSocketOptions) bool {
	if !h.shouldProxyFnosPortIconHijackWebSocket(r) {
		return false
	}

	targets := buildFnosPortIconHijackTargets(options.hostRules)
	if err := h.proxyFnosPortIconHijackWebSocket(w, r, options, targets); err != nil {
		if !isFNAppConnectionTermination(err) {
			log.Printf("FNOS port icon hijack websocket proxy failed: %v", err)
		}
	}
	return true
}

func (h *Handler) shouldProxyFnosPortIconHijackWebSocket(r *http.Request) bool {
	if r == nil || r.URL == nil || !isFNAppWebSocketRequest(r) {
		return false
	}
	if cleanFnosPortIconHijackPath(r.URL.Path) != fnosPortIconHijackWebSocketPath {
		return false
	}
	return h.GetFnosPortIconHijackConfig().Enabled
}

func (h *Handler) proxyFnosPortIconHijackWebSocket(w http.ResponseWriter, r *http.Request, options fnosPortIconHijackWebSocketOptions, targets map[int]string) error {
	if options.targetURL == nil {
		err := fmt.Errorf("missing websocket upstream target")
		if !h.abortUpstreamConnectionIfConfigured(w, options.unmatchedRoute) {
			http.Error(w, "missing upstream target", http.StatusBadGateway)
		}
		return err
	}

	upstreamURL := buildFnosPortIconHijackWebSocketURL(
		options.targetURL,
		r.URL,
		options.stripPath,
		options.pathPrefix,
		options.hostTargetPathIsEntry,
	)
	requestHeader := buildFnosPortIconHijackWebSocketHeader(r, options, upstreamURL)
	dialer := websocket.Dialer{
		Proxy:             http.ProxyFromEnvironment,
		HandshakeTimeout:  10 * time.Second,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		EnableCompression: false,
		Subprotocols:      websocket.Subprotocols(r),
	}

	upstreamConn, resp, err := dialer.DialContext(r.Context(), upstreamURL.String(), requestHeader)
	if resp != nil && resp.Body != nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	if err != nil {
		if !h.abortUpstreamConnectionIfConfigured(w, options.unmatchedRoute) {
			http.Error(w, "websocket upstream unavailable", http.StatusBadGateway)
		}
		return err
	}
	defer upstreamConn.Close()

	upgrader := websocket.Upgrader{
		CheckOrigin: func(_ *http.Request) bool {
			return true
		},
		EnableCompression: false,
	}
	if subprotocol := upstreamConn.Subprotocol(); subprotocol != "" {
		upgrader.Subprotocols = []string{subprotocol}
	}

	clientConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return err
	}
	defer clientConn.Close()

	maxLifetime := options.webSocketMaxLifetime
	if maxLifetime <= 0 {
		maxLifetime = defaultFnosPortIconHijackWebSocketMaxLifetime
	}

	var upstreamTransform func(int, []byte) (int, []byte, error)
	if shouldRewriteFnosPortIconHijackWebSocketPayload(r) {
		responseEndpoint := h.fnosPortIconHijackPublicEndpoint()
		upstreamTransform = func(messageType int, payload []byte) (int, []byte, error) {
			if messageType != websocket.TextMessage {
				return messageType, payload, nil
			}

			rewritten, changed, err := rewriteFnosPortIconHijackMessage(payload, targets, responseEndpoint)
			if err != nil {
				log.Printf("Failed to rewrite FNOS port icon payload: %v", err)
				return messageType, payload, nil
			}
			if !changed {
				return messageType, payload, nil
			}
			return messageType, rewritten, nil
		}
	}

	lifetimeTimer := time.NewTimer(maxLifetime)
	defer lifetimeTimer.Stop()
	errCh := make(chan error, 2)
	go func() {
		errCh <- relayWebSocketMessages(clientConn, upstreamConn, upstreamTransform)
	}()
	go func() {
		errCh <- relayWebSocketMessages(upstreamConn, clientConn, nil)
	}()

	select {
	case err = <-errCh:
	case <-lifetimeTimer.C:
		closeFnosPortIconHijackWebSocketPair(clientConn, upstreamConn)
		err = <-errCh
	}
	_ = clientConn.Close()
	_ = upstreamConn.Close()
	return err
}

func shouldRewriteFnosPortIconHijackWebSocketPayload(r *http.Request) bool {
	if r == nil || r.URL == nil {
		return false
	}
	requestType := strings.TrimSpace(r.URL.Query().Get("type"))
	return requestType == "" || strings.EqualFold(requestType, "main")
}

func closeFnosPortIconHijackWebSocketPair(clientConn *websocket.Conn, upstreamConn *websocket.Conn) {
	deadline := time.Now().Add(fnosPortIconHijackWebSocketCloseTimeout)
	closeMessage := websocket.FormatCloseMessage(websocket.CloseNormalClosure, "websocket lifetime exceeded")
	for _, conn := range []*websocket.Conn{clientConn, upstreamConn} {
		if conn == nil {
			continue
		}
		_ = conn.WriteControl(websocket.CloseMessage, closeMessage, deadline)
	}
	for _, conn := range []*websocket.Conn{clientConn, upstreamConn} {
		if conn == nil {
			continue
		}
		_ = conn.Close()
	}
}

func (h *Handler) fnosPortIconHijackResponsePort() int {
	return h.fnosPortIconHijackPublicEndpoint().port
}

func (h *Handler) fnosPortIconHijackPublicEndpoint() fnosPortIconHijackPublicEndpoint {
	sslEnabled := h.HasSSLCertificates()

	h.mu.RLock()
	edgeClientIPEnabled := h.AuthConfig.EdgeClientIPEnabled
	proxyPort := h.ProxyPort
	h.mu.RUnlock()

	protocol := "http"
	if sslEnabled {
		protocol = "https"
	}

	port := proxyPort
	if port <= 0 {
		port = defaultFnosPortIconHijackGatewayPort
	}
	if edgeClientIPEnabled {
		if sslEnabled {
			port = 443
		} else {
			port = 80
		}
	}

	return fnosPortIconHijackPublicEndpoint{
		protocol: protocol,
		port:     port,
	}
}

func buildFnosPortIconHijackWebSocketURL(
	targetURL *url.URL,
	incomingURL *url.URL,
	stripPath bool,
	pathPrefix string,
	hostTargetPathIsEntry bool,
) *url.URL {
	upstreamURL := *targetURL
	switch strings.ToLower(upstreamURL.Scheme) {
	case "https", "wss":
		upstreamURL.Scheme = "wss"
	default:
		upstreamURL.Scheme = "ws"
	}

	upstreamPath := "/"
	if incomingURL != nil {
		upstreamPath = incomingURL.Path
		upstreamURL.RawQuery = incomingURL.RawQuery
	} else {
		upstreamURL.RawQuery = ""
	}
	if hostTargetPathIsEntry {
		upstreamURL.Path = buildHostReverseProxyEntryPath(targetURL.Path, upstreamPath)
	} else {
		upstreamURL.Path = buildReverseProxyRoutePath(targetURL.Path, upstreamPath, stripPath, pathPrefix)
	}
	upstreamURL.RawPath = ""
	upstreamURL.Fragment = ""
	return &upstreamURL
}

func buildFnosPortIconHijackWebSocketHeader(r *http.Request, options fnosPortIconHijackWebSocketOptions, upstreamURL *url.URL) http.Header {
	headers := r.Header.Clone()
	for _, name := range []string{
		"Connection",
		"Upgrade",
		"Sec-WebSocket-Accept",
		"Sec-WebSocket-Extensions",
		"Sec-WebSocket-Key",
		"Sec-WebSocket-Protocol",
		"Sec-WebSocket-Version",
	} {
		headers.Del(name)
	}

	out := r.Clone(r.Context())
	out.Header = headers
	out.URL = upstreamURL
	out.Host = upstreamURL.Host
	applyForwardedHeaderPolicy(out, r, options.clientIP, options.omitForwardedHeaders)
	copyUserAgentHeader(out, r)
	stripAdvancedAuthGrantCookie(headers)
	applyUpstreamPrivateIPv4HintHeader(out, options.targetURL)
	applyPreserveHostPolicy(out, r, options.targetURL, options.preserveHost)
	applyBasicAuthInjection(out, options.basicAuth)

	if options.rewriteOriginReferer {
		if origin := r.Header.Get("Origin"); origin != "" {
			headers.Set("Origin", options.targetURL.Scheme+"://"+options.targetURL.Host)
		}
		if referer := r.Header.Get("Referer"); referer != "" {
			if ref, err := url.Parse(referer); err == nil {
				ref.Scheme = options.targetURL.Scheme
				ref.Host = options.targetURL.Host
				ref.Path = path.Clean(ref.Path)
				if options.hostTargetPathIsEntry {
					applyHostReverseProxyEntryPath(ref, options.targetURL, ref)
				} else {
					applyReverseProxyRoutePath(ref, reverseProxyRoutePathOptions{
						targetURL:  options.targetURL,
						incoming:   ref,
						stripPath:  options.stripPath,
						pathPrefix: options.pathPrefix,
					})
				}
				headers.Set("Referer", ref.String())
			}
		}
	}

	if out.Host != "" && out.Host != upstreamURL.Host {
		headers.Set("Host", out.Host)
	}
	return headers
}

func (h *Handler) maybePrepareFnosPortIconHijackHTTPProxyRequest(r *http.Request) {
	if h.shouldHijackFnosPortIconHijackServiceList(r) {
		r.Header.Del("Accept-Encoding")
	}
}

func (h *Handler) maybeRewriteFnosPortIconHijackHTTPResponse(resp *http.Response, hostRules []models.HostRule) error {
	if resp == nil || !h.shouldHijackFnosPortIconHijackServiceList(resp.Request) {
		return nil
	}
	if resp.Body == nil {
		return nil
	}

	targets := buildFnosPortIconHijackTargets(hostRules)
	if len(targets) == 0 {
		return nil
	}

	bodyBytes, ok, err := readFnosPortIconHijackHTTPBody(resp, fnosPortIconHijackHTTPBodyLimitBytes)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}

	rewritten, changed, err := rewriteFnosPortIconHijackMessage(bodyBytes, targets, h.fnosPortIconHijackPublicEndpoint())
	if err != nil {
		resetFnosPortIconHijackResponseBody(resp, bodyBytes)
		log.Printf("Failed to rewrite FNOS port icon HTTP response: %v", err)
		return nil
	}
	if !changed {
		resetFnosPortIconHijackResponseBody(resp, bodyBytes)
		return nil
	}

	resetFnosPortIconHijackResponseBody(resp, rewritten)
	resp.Header.Del("Content-Encoding")
	resp.Header.Del("Content-MD5")
	resp.Header.Del("ETag")
	return nil
}

func readFnosPortIconHijackHTTPBody(resp *http.Response, limit int64) ([]byte, bool, error) {
	if resp == nil || resp.Body == nil {
		return nil, false, nil
	}
	if limit <= 0 {
		return nil, false, nil
	}
	if resp.ContentLength > limit {
		return nil, false, nil
	}

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(bodyBytes)) > limit {
		resp.Body = &prependReadCloser{
			reader: io.MultiReader(bytes.NewReader(bodyBytes), resp.Body),
			closer: resp.Body,
		}
		return nil, false, nil
	}

	_ = resp.Body.Close()
	return bodyBytes, true, nil
}

func resetFnosPortIconHijackResponseBody(resp *http.Response, body []byte) {
	if resp.Header == nil {
		resp.Header = http.Header{}
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
}

func (h *Handler) shouldHijackFnosPortIconHijackServiceList(r *http.Request) bool {
	if r == nil || r.URL == nil {
		return false
	}
	if cleanFnosPortIconHijackPath(r.URL.Path) != fnosPortIconHijackServiceListPath {
		return false
	}
	return h.GetFnosPortIconHijackConfig().Enabled
}

func cleanFnosPortIconHijackPath(rawPath string) string {
	cleanPath := path.Clean(rawPath)
	if cleanPath == "." {
		return "/"
	}
	return cleanPath
}

func relayWebSocketMessages(dst *websocket.Conn, src *websocket.Conn, transform func(int, []byte) (int, []byte, error)) error {
	for {
		messageType, payload, err := src.ReadMessage()
		if err != nil {
			return err
		}
		if transform != nil {
			messageType, payload, err = transform(messageType, payload)
			if err != nil {
				return err
			}
		}
		if err := dst.WriteMessage(messageType, payload); err != nil {
			return err
		}
	}
}

func buildFnosPortIconHijackTargets(hostRules []models.HostRule) map[int]string {
	targets := make(map[int]string)
	for _, rule := range hostRules {
		host := normalizeRequestHost(rule.Host)
		if host == "" {
			continue
		}

		port, ok := hostRuleTargetPort(rule.Target)
		if !ok {
			continue
		}
		if _, exists := targets[port]; exists {
			continue
		}
		targets[port] = host
	}
	return targets
}

func hostRuleTargetPort(rawTarget string) (int, bool) {
	target := strings.TrimSpace(rawTarget)
	scheme, rest, ok := strings.Cut(target, "://")
	if !ok || scheme == "" {
		return 0, false
	}

	authority := rest
	if end := strings.IndexAny(authority, "/?#"); end >= 0 {
		authority = authority[:end]
	}
	if authority == "" {
		return 0, false
	}
	if userinfoEnd := strings.LastIndexByte(authority, '@'); userinfoEnd >= 0 {
		authority = authority[userinfoEnd+1:]
		if authority == "" {
			return 0, false
		}
	}

	if port, ok, invalid := hostRuleAuthorityPort(authority); ok {
		return port, true
	} else if invalid {
		return 0, false
	}

	if equalFoldASCIIString(scheme, "http") || equalFoldASCIIString(scheme, "ws") {
		return 80, true
	}
	if equalFoldASCIIString(scheme, "https") || equalFoldASCIIString(scheme, "wss") {
		return 443, true
	}
	return 0, false
}

func hostRuleAuthorityPort(authority string) (int, bool, bool) {
	if authority == "" {
		return 0, false, false
	}
	if authority[0] == '[' {
		closeBracket := strings.IndexByte(authority, ']')
		if closeBracket < 0 {
			return 0, false, true
		}
		if len(authority) == closeBracket+1 {
			return 0, false, false
		}
		if authority[closeBracket+1] != ':' {
			return 0, false, true
		}
		return parseHostRulePort(authority[closeBracket+2:])
	}

	colon := strings.LastIndexByte(authority, ':')
	if colon < 0 {
		return 0, false, false
	}
	return parseHostRulePort(authority[colon+1:])
}

func parseHostRulePort(port string) (int, bool, bool) {
	if port == "" {
		return 0, false, false
	}
	value := 0
	for i := 0; i < len(port); i++ {
		c := port[i]
		if c < '0' || c > '9' {
			return 0, false, true
		}
		value = value*10 + int(c-'0')
		if value > 65535 {
			return 0, false, true
		}
	}
	if value == 0 {
		return 0, false, true
	}
	return value, true, false
}

func rewriteFnosPortIconHijackMessage(payload []byte, hostByPort map[int]string, endpoint fnosPortIconHijackPublicEndpoint) ([]byte, bool, error) {
	endpoint = normalizeFnosPortIconHijackPublicEndpoint(endpoint)
	if len(hostByPort) == 0 || endpoint.port <= 0 {
		return payload, false, nil
	}

	var value any
	if err := json.Unmarshal(payload, &value); err != nil {
		return payload, false, nil
	}

	if !rewriteFnosPortIconHijackValue(value, hostByPort, endpoint) {
		return payload, false, nil
	}

	rewritten, err := json.Marshal(value)
	if err != nil {
		return payload, false, err
	}
	return rewritten, true, nil
}

func normalizeFnosPortIconHijackPublicEndpoint(endpoint fnosPortIconHijackPublicEndpoint) fnosPortIconHijackPublicEndpoint {
	switch strings.ToLower(strings.TrimSpace(endpoint.protocol)) {
	case "https":
		endpoint.protocol = "https"
	default:
		endpoint.protocol = "http"
	}
	return endpoint
}

func rewriteFnosPortIconHijackValue(value any, hostByPort map[int]string, endpoint fnosPortIconHijackPublicEndpoint) bool {
	switch typed := value.(type) {
	case map[string]any:
		changed := rewriteFnosPortIconHijackObject(typed, hostByPort, endpoint)
		for _, child := range typed {
			if rewriteFnosPortIconHijackValue(child, hostByPort, endpoint) {
				changed = true
			}
		}
		return changed
	case []any:
		changed := false
		for _, child := range typed {
			if rewriteFnosPortIconHijackValue(child, hostByPort, endpoint) {
				changed = true
			}
		}
		return changed
	default:
		return false
	}
}

func rewriteFnosPortIconHijackObject(object map[string]any, hostByPort map[int]string, endpoint fnosPortIconHijackPublicEndpoint) bool {
	rawHost, hasHost := object["host"]
	if !hasHost {
		return false
	}
	host, ok := rawHost.(string)
	if !ok || strings.TrimSpace(host) != "" {
		return false
	}

	port, ok := jsonPortNumber(object["port"])
	if !ok {
		return false
	}

	nextHost := hostByPort[port]
	if nextHost == "" {
		return false
	}

	object["host"] = nextHost
	object["port"] = strconv.Itoa(endpoint.port)
	object["protocol"] = endpoint.protocol
	object["path"] = ""
	return true
}

func jsonPortNumber(value any) (int, bool) {
	switch typed := value.(type) {
	case string:
		port, err := strconv.Atoi(strings.TrimSpace(typed))
		if err != nil || port <= 0 || port > 65535 {
			return 0, false
		}
		return port, true
	case float64:
		port := int(typed)
		if typed != float64(port) || port <= 0 || port > 65535 {
			return 0, false
		}
		return port, true
	case json.Number:
		port, err := strconv.Atoi(typed.String())
		if err != nil || port <= 0 || port > 65535 {
			return 0, false
		}
		return port, true
	default:
		return 0, false
	}
}
