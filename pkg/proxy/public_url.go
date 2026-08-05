package proxy

import (
	"encoding/json"
	"go-reauth-proxy/pkg/models"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// ManagedCloudflareIngressPort is a dedicated loopback listener used by
// fn-knock-managed Cloudflare Tunnels. Keeping it distinct from the normal
// ingress gives security-sensitive client IP resolution a transport-level
// trust boundary instead of trusting request headers alone.
const ManagedCloudflareIngressPort = 17999

func BuildHTTPSRedirectURL(r *http.Request, authConfig models.AuthConfig) string {
	target := buildPublicRequestURL(r, authConfig, "https")
	if target == nil {
		return ""
	}
	return target.String()
}

func IsPublicHTTPSRequest(r *http.Request) bool {
	return publicRequestScheme(r) == "https"
}

func ShouldRedirectHTTPToHTTPS(r *http.Request, authConfig models.AuthConfig) bool {
	return !authConfig.TrustForwardedProto || !IsPublicHTTPSRequest(r)
}

func buildPublicRequestURL(r *http.Request, authConfig models.AuthConfig, schemeOverride string) *url.URL {
	if r == nil {
		return nil
	}

	scheme := normalizedPublicScheme(r, schemeOverride)
	host := publicRequestHost(r, authConfig, scheme)
	if host == "" {
		host = strings.TrimSpace(r.Host)
	}

	return &url.URL{
		Scheme:   scheme,
		Host:     host,
		Path:     r.URL.Path,
		RawQuery: r.URL.RawQuery,
	}
}

func normalizedPublicScheme(r *http.Request, schemeOverride string) string {
	if scheme := normalizePublicSchemeValue(schemeOverride); scheme != "" {
		return scheme
	}

	if scheme := publicRequestScheme(r); scheme != "" {
		return scheme
	}

	return "http"
}

func publicRequestHost(r *http.Request, authConfig models.AuthConfig, scheme string) string {
	requestHost := publicRequestHostHeader(r)
	hostname, hostPort := splitRequestHostPort(requestHost)
	if hostname == "" {
		return strings.TrimSpace(requestHost)
	}

	port := resolvedPublicPort(r, authConfig, scheme, hostPort)
	return formatURLHost(hostname, port, scheme)
}

func publicRequestHostHeader(r *http.Request) string {
	if r == nil {
		return ""
	}

	if forwardedHost := firstForwardedValue(canonicalHeaderValue(r.Header, "X-Forwarded-Host")); forwardedHost != "" {
		return strings.TrimSpace(forwardedHost)
	}

	return strings.TrimSpace(r.Host)
}

func splitRequestHostPort(host string) (string, string) {
	host = strings.TrimSpace(host)
	if host == "" {
		return "", ""
	}

	if hostname, port, ok := splitRequestHostPortFast(host); ok {
		return hostname, port
	}

	parsed, err := url.Parse("//" + host)
	if err != nil {
		return host, ""
	}

	hostname := parsed.Hostname()
	if hostname == "" {
		return host, ""
	}

	return hostname, parsed.Port()
}

func splitRequestHostPortFast(host string) (string, string, bool) {
	if strings.ContainsAny(host, "/?#@") {
		return "", "", false
	}

	if strings.HasPrefix(host, "[") {
		idx := strings.LastIndexByte(host, ']')
		if idx <= 1 {
			return "", "", false
		}
		hostname := host[1:idx]
		if hostname == "" || strings.ContainsAny(hostname, "[]") {
			return "", "", false
		}
		rest := host[idx+1:]
		if rest == "" {
			return hostname, "", true
		}
		if len(rest) > 1 && rest[0] == ':' && rest[1:] == strings.TrimSpace(rest[1:]) && isValidPort(rest[1:]) {
			return hostname, rest[1:], true
		}
		return "", "", false
	}

	idx := strings.IndexByte(host, ':')
	if idx == -1 {
		return host, "", true
	}
	if idx == 0 || strings.IndexByte(host[idx+1:], ':') != -1 {
		return "", "", false
	}

	hostname := host[:idx]
	port := host[idx+1:]
	if hostname != strings.TrimSpace(hostname) || port == "" || port != strings.TrimSpace(port) || !isValidPort(port) {
		return "", "", false
	}
	return hostname, port, true
}

func resolvedPublicPort(r *http.Request, authConfig models.AuthConfig, scheme string, requestHostPort string) string {
	// Edge-backed ingress exposes the gateway through the scheme's standard
	// public port. It must take precedence over persisted ingress ports and
	// proxy/request headers, which can still describe the origin listener
	// (typically 7999) rather than the browser-facing endpoint.
	if authConfig.EdgeClientIPActive() || isManagedCloudflareTunnelIngress(r) || isCloudflareEdgeRequest(r, scheme) {
		return ""
	}

	if configuredPort := configuredPublicPort(authConfig, scheme); configuredPort != "" {
		return configuredPort
	}

	if forwardedPort := forwardedRequestPort(r); forwardedPort != "" {
		return forwardedPort
	}

	if isValidPort(requestHostPort) {
		return requestHostPort
	}

	return ""
}

func isCloudflareEdgeRequest(r *http.Request, scheme string) bool {
	if r == nil {
		return false
	}

	visitorScheme := cloudflareVisitorScheme(canonicalHeaderValue(r.Header, "Cf-Visitor"))
	if visitorScheme == "" || visitorScheme != normalizePublicSchemeValue(scheme) {
		return false
	}
	if !isValidCloudflareRay(canonicalHeaderValue(r.Header, "Cf-Ray")) {
		return false
	}

	connectingIP := firstForwardedValue(canonicalHeaderValue(r.Header, "Cf-Connecting-Ip"))
	return net.ParseIP(strings.TrimSpace(connectingIP)) != nil
}

func isManagedCloudflareTunnelIngress(r *http.Request) bool {
	if r == nil {
		return false
	}
	localAddr, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if !ok || localAddr == nil {
		return false
	}

	switch value := localAddr.(type) {
	case *net.TCPAddr:
		return value.IP.IsLoopback() && value.Port == ManagedCloudflareIngressPort
	case *net.UDPAddr:
		return value.IP.IsLoopback() && value.Port == ManagedCloudflareIngressPort
	default:
		host, port, err := net.SplitHostPort(localAddr.String())
		return err == nil && net.ParseIP(strings.Trim(host, "[]")).IsLoopback() &&
			port == strconv.Itoa(ManagedCloudflareIngressPort)
	}
}

func isValidCloudflareRay(value string) bool {
	rayID, colo, ok := strings.Cut(strings.TrimSpace(firstForwardedValue(value)), "-")
	if !ok || len(rayID) < 8 || len(colo) != 3 {
		return false
	}
	for i := 0; i < len(rayID); i++ {
		c := rayID[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	for i := 0; i < len(colo); i++ {
		c := colo[i]
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}

func publicRequestScheme(r *http.Request) string {
	if r == nil {
		return "http"
	}

	if proto := forwardedHeaderParam(canonicalHeaderValue(r.Header, "Forwarded"), "proto"); proto != "" {
		return proto
	}
	if proto := normalizePublicSchemeValue(firstForwardedValue(canonicalHeaderValue(r.Header, "X-Forwarded-Proto"))); proto != "" {
		return proto
	}
	if proto := normalizePublicSchemeValue(firstForwardedValue(canonicalHeaderValue(r.Header, "X-Forwarded-Scheme"))); proto != "" {
		return proto
	}
	if proto := normalizePublicSchemeValue(firstForwardedValue(canonicalHeaderValue(r.Header, "X-Original-Proto"))); proto != "" {
		return proto
	}
	if proto := normalizePublicSchemeValue(firstForwardedValue(canonicalHeaderValue(r.Header, "X-Original-Scheme"))); proto != "" {
		return proto
	}
	if proto := cloudflareVisitorScheme(canonicalHeaderValue(r.Header, "Cf-Visitor")); proto != "" {
		return proto
	}
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

func canonicalHeaderValue(header http.Header, key string) string {
	if len(header) == 0 {
		return ""
	}
	values := header[key]
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func forwardedHeaderParam(value string, key string) string {
	first := firstForwardedValue(value)
	if first == "" {
		return ""
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return ""
	}

	for first != "" {
		segment := first
		if before, after, ok := strings.Cut(first, ";"); ok {
			segment = before
			first = after
		} else {
			first = ""
		}

		name, rawValue, ok := strings.Cut(segment, "=")
		if !ok || !equalFoldASCIIString(strings.TrimSpace(name), key) {
			continue
		}
		normalized := normalizePublicSchemeValue(strings.Trim(strings.TrimSpace(rawValue), `"`))
		if normalized != "" {
			return normalized
		}
	}
	return ""
}

func cloudflareVisitorScheme(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if scheme, ok := cloudflareVisitorSchemeFast(value); ok {
		return scheme
	}

	var visitor struct {
		Scheme string `json:"scheme"`
	}
	if err := json.Unmarshal([]byte(value), &visitor); err != nil {
		return ""
	}
	return normalizePublicSchemeValue(visitor.Scheme)
}

func cloudflareVisitorSchemeFast(value string) (string, bool) {
	const key = `"scheme"`
	for offset := 0; offset < len(value); {
		idx := strings.Index(value[offset:], key)
		if idx == -1 {
			return "", false
		}

		i := offset + idx + len(key)
		for i < len(value) && isASCIISpace(value[i]) {
			i++
		}
		if i >= len(value) || value[i] != ':' {
			offset += idx + len(key)
			continue
		}

		i++
		for i < len(value) && isASCIISpace(value[i]) {
			i++
		}
		if i >= len(value) || value[i] != '"' {
			return "", false
		}

		start := i + 1
		for i = start; i < len(value); i++ {
			switch value[i] {
			case '\\':
				return "", false
			case '"':
				return normalizePublicSchemeValue(value[start:i]), true
			}
		}
		return "", false
	}
	return "", false
}

func normalizePublicSchemeValue(value string) string {
	scheme := strings.TrimSpace(value)
	if len(scheme) > 0 && scheme[len(scheme)-1] == ':' {
		scheme = strings.TrimSpace(scheme[:len(scheme)-1])
	}
	switch len(scheme) {
	case len("http"):
		if equalFoldASCIIString(scheme, "http") {
			return "http"
		}
	case len("https"):
		if equalFoldASCIIString(scheme, "https") {
			return "https"
		}
	}
	return ""
}

func configuredPublicPort(authConfig models.AuthConfig, scheme string) string {
	switch strings.ToLower(strings.TrimSpace(scheme)) {
	case "http":
		if authConfig.PublicHTTPPort > 0 {
			return strconv.Itoa(authConfig.PublicHTTPPort)
		}
	case "https":
		if authConfig.PublicHTTPSPort > 0 {
			return strconv.Itoa(authConfig.PublicHTTPSPort)
		}
	}

	if derivedPort := publicPortFromAuthBaseURL(authConfig.PublicAuthBaseURL, scheme); derivedPort != "" {
		return derivedPort
	}

	return ""
}

func publicPortFromAuthBaseURL(rawBaseURL string, scheme string) string {
	baseURL := strings.TrimSpace(rawBaseURL)
	rawScheme, rest, ok := strings.Cut(baseURL, "://")
	if !ok || rawScheme == "" || !equalFoldASCIIString(rawScheme, strings.TrimSpace(scheme)) {
		return ""
	}

	authority := rest
	if end := strings.IndexAny(authority, "/?#"); end >= 0 {
		authority = authority[:end]
	}
	if authority == "" {
		return ""
	}
	if userinfoEnd := strings.LastIndexByte(authority, '@'); userinfoEnd >= 0 {
		authority = authority[userinfoEnd+1:]
		if authority == "" {
			return ""
		}
	}

	port, ok, invalid := urlAuthorityPort(authority)
	if !ok || invalid {
		return ""
	}
	return port
}

func urlAuthorityPort(authority string) (string, bool, bool) {
	if authority == "" {
		return "", false, false
	}
	if authority[0] == '[' {
		closeBracket := strings.IndexByte(authority, ']')
		if closeBracket < 0 {
			return "", false, true
		}
		if len(authority) == closeBracket+1 {
			return "", false, false
		}
		if authority[closeBracket+1] != ':' {
			return "", false, true
		}
		return validateURLPort(authority[closeBracket+2:])
	}

	colon := strings.LastIndexByte(authority, ':')
	if colon < 0 {
		return "", false, false
	}
	return validateURLPort(authority[colon+1:])
}

func validateURLPort(port string) (string, bool, bool) {
	if port == "" {
		return "", false, false
	}
	value := 0
	for i := 0; i < len(port); i++ {
		c := port[i]
		if c < '0' || c > '9' {
			return "", false, true
		}
		value = value*10 + int(c-'0')
		if value > 65535 {
			return "", false, true
		}
	}
	if value == 0 {
		return "", false, true
	}
	return port, true, false
}

func forwardedRequestPort(r *http.Request) string {
	if r == nil {
		return ""
	}

	value := firstForwardedValue(canonicalHeaderValue(r.Header, "X-Forwarded-Port"))
	if !isValidPort(value) {
		return ""
	}

	return value
}

func localRequestPort(r *http.Request) string {
	if r == nil {
		return ""
	}

	localAddr := r.Context().Value(http.LocalAddrContextKey)
	addr, ok := localAddr.(net.Addr)
	if !ok || addr == nil {
		return ""
	}

	switch value := addr.(type) {
	case *net.TCPAddr:
		if value.Port <= 0 {
			return ""
		}
		return strconv.Itoa(value.Port)
	case *net.UDPAddr:
		if value.Port <= 0 {
			return ""
		}
		return strconv.Itoa(value.Port)
	default:
		_, port, err := net.SplitHostPort(addr.String())
		if err != nil || !isValidPort(port) {
			return ""
		}
		return port
	}
}

func formatURLHost(hostname string, port string, scheme string) string {
	if hostname == "" {
		return ""
	}

	if port == "" || port == defaultPortForScheme(scheme) {
		if strings.Contains(hostname, ":") {
			return "[" + hostname + "]"
		}
		return hostname
	}

	return net.JoinHostPort(hostname, port)
}

func defaultPortForScheme(scheme string) string {
	switch strings.ToLower(strings.TrimSpace(scheme)) {
	case "http":
		return "80"
	case "https":
		return "443"
	default:
		return ""
	}
}

func isValidPort(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	if value[0] == '+' {
		value = value[1:]
	}
	if value == "" || len(value) > 5 {
		return false
	}
	port := 0
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c < '0' || c > '9' {
			return false
		}
		port = port*10 + int(c-'0')
		if port > 65535 {
			return false
		}
	}
	return port > 0
}
