package proxy

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go-reauth-proxy/pkg/config"
	"go-reauth-proxy/pkg/errors"

	"go-reauth-proxy/pkg/models"
	"go-reauth-proxy/pkg/response"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Handler struct {
	mu                    sync.RWMutex
	Rules                 []models.Rule
	DefaultRoute          string
	AuthConfig            models.AuthConfig
	AdminPort             int
	ProxyProtocolForce    bool
	sslCert               atomic.Value
	sslOnChange           atomic.Value
	proxyProtocolOnChange atomic.Value

	configManager *config.Manager
	certPEM       string
	keyPEM        string

	trafficTotalIn  uint64
	trafficTotalOut uint64
	trafficActive   int64
	trafficError5xx uint64

	loggedInActive sync.Map
}

type requestSnapshot struct {
	rules              []models.Rule
	defaultRoute       string
	authConfig         models.AuthConfig
	proxyProtocolForce bool
}

func (h *Handler) snapshotForRequest() requestSnapshot {
	h.mu.RLock()
	rules := make([]models.Rule, len(h.Rules))
	copy(rules, h.Rules)
	s := requestSnapshot{
		rules:              rules,
		defaultRoute:       h.DefaultRoute,
		authConfig:         h.AuthConfig,
		proxyProtocolForce: h.ProxyProtocolForce,
	}
	h.mu.RUnlock()
	return s
}

func resolveClientIP(r *http.Request, proxyProtocolForce bool) string {
	if !proxyProtocolForce {
		remoteIP, _, _ := net.SplitHostPort(r.RemoteAddr)
		return remoteIP
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			ip := strings.TrimSpace(parts[0])
			if ip != "" {
				return ip
			}
		}
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	remoteIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	return remoteIP
}

func copyRule(rule models.Rule) *models.Rule {
	r := rule
	return &r
}

func newInternalTransport() *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConns = 100
	transport.MaxIdleConnsPerHost = 100
	transport.IdleConnTimeout = 90 * time.Second
	transport.ForceAttemptHTTP2 = true
	return transport
}

func newProxyTransport() *http.Transport {
	transport := newInternalTransport()
	transport.DialContext = (&net.Dialer{
		Timeout:   6 * time.Second,
		KeepAlive: 30 * time.Second,
	}).DialContext
	transport.TLSHandshakeTimeout = 10 * time.Second
	transport.ResponseHeaderTimeout = 10 * time.Second
	return transport
}

func ensureLeadingSlash(p string) string {
	if p == "" {
		return "/"
	}
	if strings.HasPrefix(p, "/") {
		return p
	}
	return "/" + p
}

func localServiceURL(port int, urlPath string) string {
	return fmt.Sprintf("http://127.0.0.1:%d%s", port, ensureLeadingSlash(urlPath))
}

func (h *Handler) shouldDenyByPreflight(r *http.Request, authConfig models.AuthConfig, clientIP string, isMatch bool) bool {
	if authConfig.AuthPort <= 0 {
		return false
	}

	preflightURLPath := authConfig.PreflightURL
	if preflightURLPath == "" {
		preflightURLPath = "/api/auth/preflight"
	}
	preflightURL := localServiceURL(authConfig.AuthPort, preflightURLPath)

	preflightReq, err := http.NewRequest(http.MethodHead, preflightURL, nil)
	if err != nil {
		log.Printf("Failed to create preflight request: %v", err)
		return false
	}

	preflightReq.Header.Set("X-Real-IP", clientIP)
	preflightReq.Header.Set("X-Forwarded-For", clientIP)
	preflightReq.Header.Set("X-Forwarded-Path", r.URL.RequestURI())
	preflightReq.Header.Set("X-Match", strconv.FormatBool(isMatch))

	if cookie := r.Header.Get("Cookie"); cookie != "" {
		preflightReq.Header.Set("Cookie", cookie)
	}
	if auth := r.Header.Get("Authorization"); auth != "" {
		preflightReq.Header.Set("Authorization", auth)
	}

	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: newInternalTransport(),
	}

	resp, err := client.Do(preflightReq)
	if err != nil {
		log.Printf("Preflight request failed: %v", err)
		return false
	}
	resp.Body.Close()

	return strings.EqualFold(resp.Header.Get("X-Option"), "deny")
}

func (h *Handler) abortConnection(w http.ResponseWriter) {
	rc := http.NewResponseController(w)
	conn, _, err := rc.Hijack()
	if err == nil && conn != nil {
		conn.Close()
		return
	}
	panic(http.ErrAbortHandler)
}

func NewHandler(adminPort int, cfgManager *config.Manager, initialCfg *config.AppConfig) *Handler {
	h := &Handler{
		Rules:              initialCfg.Rules,
		DefaultRoute:       initialCfg.DefaultRoute,
		AuthConfig:         initialCfg.AuthConfig,
		AdminPort:          adminPort,
		ProxyProtocolForce: initialCfg.ProxyProtocolForce,
		configManager:      cfgManager,
		certPEM:            initialCfg.SSLCert,
		keyPEM:             initialCfg.SSLKey,
	}

	var emptyHook func()
	h.sslOnChange.Store(emptyHook)
	h.proxyProtocolOnChange.Store(emptyHook)

	if h.certPEM != "" && h.keyPEM != "" {
		cert, err := tls.X509KeyPair([]byte(h.certPEM), []byte(h.keyPEM))
		if err == nil {
			h.sslCert.Store(&cert)
		} else {
			log.Printf("Failed to load initial SSL cert: %v", err)
			var empty *tls.Certificate
			h.sslCert.Store(empty)
		}
	} else {
		var empty *tls.Certificate
		h.sslCert.Store(empty)
	}
	return h
}

func (h *Handler) SetSSLChangeHook(hook func()) {
	h.sslOnChange.Store(hook)
}

func (h *Handler) getSSLChangeHook() func() {
	val := h.sslOnChange.Load()
	if val == nil {
		return nil
	}
	hook, _ := val.(func())
	return hook
}

func (h *Handler) SetProxyProtocolForceChangeHook(hook func()) {
	h.proxyProtocolOnChange.Store(hook)
}

func (h *Handler) getProxyProtocolForceChangeHook() func() {
	val := h.proxyProtocolOnChange.Load()
	if val == nil {
		return nil
	}
	hook, _ := val.(func())
	return hook
}

func (h *Handler) saveConfigLocked() {
	if h.configManager == nil {
		return
	}

	rulesCopy := make([]models.Rule, len(h.Rules))
	copy(rulesCopy, h.Rules)

	if err := h.configManager.Update(func(conf *config.AppConfig) error {
		conf.Rules = rulesCopy
		conf.DefaultRoute = h.DefaultRoute
		conf.AuthConfig = h.AuthConfig
		conf.ProxyProtocolForce = h.ProxyProtocolForce
		conf.SSLCert = h.certPEM
		conf.SSLKey = h.keyPEM
		return nil
	}); err != nil {
		log.Printf("Failed to save config: %v", err)
	}
}

func (h *Handler) GetProxyProtocolForce() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.ProxyProtocolForce
}

func (h *Handler) SetProxyProtocolForce(force bool) {
	h.mu.Lock()
	changed := h.ProxyProtocolForce != force
	h.ProxyProtocolForce = force
	h.saveConfigLocked()
	hook := h.getProxyProtocolForceChangeHook()
	h.mu.Unlock()
	if changed && hook != nil {
		hook()
	}
}

func (h *Handler) SetSSLCertificate(cert *tls.Certificate, certPEM, keyPEM string) {
	h.mu.Lock()
	if cert == nil {
		var empty *tls.Certificate
		h.sslCert.Store(empty)
		h.certPEM = ""
		h.keyPEM = ""
	} else {
		h.sslCert.Store(cert)
		h.certPEM = certPEM
		h.keyPEM = keyPEM
	}
	h.saveConfigLocked()
	hook := h.getSSLChangeHook()
	h.mu.Unlock()
	if hook != nil {
		hook()
	}
}

func (h *Handler) GetSSLCertificate() *tls.Certificate {
	val := h.sslCert.Load()
	if val == nil {
		return nil
	}
	cert, _ := val.(*tls.Certificate)
	return cert
}

func (h *Handler) ClearSSLCertificate() {
	h.mu.Lock()
	var empty *tls.Certificate
	h.sslCert.Store(empty)
	h.certPEM = ""
	h.keyPEM = ""
	h.saveConfigLocked()
	hook := h.getSSLChangeHook()
	h.mu.Unlock()
	if hook != nil {
		hook()
	}
}

func (h *Handler) AddRule(newRule models.Rule) error {
	if newRule.Path == "/" || newRule.Path == "" {
		return fmt.Errorf("cannot add rule for root path '/' or empty path")
	}
	if newRule.Target == "" {
		return fmt.Errorf("cannot add rule with empty target")
	}
	if strings.HasPrefix(newRule.Path, "/__") || strings.HasPrefix(newRule.Path, "__") {
		return fmt.Errorf("cannot add rule for reserved path starting with '__'")
	}
	if strings.HasSuffix(newRule.Path, "/") {
		return fmt.Errorf("path cannot end with a slash '/'")
	}
	if err := h.checkSafeTarget(newRule.Target); err != nil {
		return fmt.Errorf("invalid target: %v", err)
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	updated := false
	for i, rule := range h.Rules {
		if rule.Path == newRule.Path {
			h.Rules[i] = newRule
			updated = true
			break
		}
	}
	if !updated {
		h.Rules = append(h.Rules, newRule)
	}
	h.saveConfigLocked()
	return nil
}

func (h *Handler) checkSafeTarget(target string) error {
	u, err := url.Parse(target)
	if err != nil {
		return err
	}
	hostname := u.Hostname()
	port := u.Port()

	isInternal := false
	if hostname == "localhost" {
		isInternal = true
	} else if ip := net.ParseIP(hostname); ip != nil {
		if ip.IsPrivate() || ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() {
			isInternal = true
		}
	} else {
		ips, err := net.LookupIP(hostname)
		if err != nil {
			return fmt.Errorf("failed to resolve target hostname: %v", err)
		}

		if len(ips) > 0 {
			isInternal = true
			for _, ip := range ips {
				if !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsUnspecified() && !ip.IsLinkLocalUnicast() {
					isInternal = false
					break
				}
			}
		}
	}

	if !isInternal {
		return fmt.Errorf("target must be an internal network address, external address not allowed: %s", hostname)
	}

	if hostname == "localhost" || hostname == "127.0.0.1" || hostname == "::1" {
		if port == strconv.Itoa(h.AdminPort) {
			return fmt.Errorf("cannot target local admin port %d", h.AdminPort)
		}
	}
	return nil
}

func (h *Handler) RemoveRule(path string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	newRules := make([]models.Rule, 0, len(h.Rules))
	for _, rule := range h.Rules {
		if rule.Path != path {
			newRules = append(newRules, rule)
		}
	}
	h.Rules = newRules
	h.saveConfigLocked()
}

func (h *Handler) FlushRules() {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.Rules = make([]models.Rule, 0)
	h.saveConfigLocked()
}

func (h *Handler) GetRules() []models.Rule {
	h.mu.RLock()
	defer h.mu.RUnlock()

	rules := make([]models.Rule, len(h.Rules))
	copy(rules, h.Rules)
	return rules
}

func (h *Handler) GetDefaultRoute() string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.DefaultRoute
}

func (h *Handler) SetDefaultRoute(route string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if route == "" {
		h.DefaultRoute = "/__select__"
	} else {
		h.DefaultRoute = route
	}
	h.saveConfigLocked()
}

func (h *Handler) GetAuthConfig() models.AuthConfig {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.AuthConfig
}

func (h *Handler) SetAuthConfig(config models.AuthConfig) error {
	if config.AuthPort <= 0 {
		config.AuthPort = 7997
	}
	if config.AuthURL == "" {
		config.AuthURL = "/api/auth/verify"
	}
	if config.LoginURL == "" {
		config.LoginURL = "/login"
	}
	if config.LogoutURL == "" {
		config.LogoutURL = "/api/auth/logout"
	}
	if config.PreflightURL == "" {
		config.PreflightURL = "/api/auth/preflight"
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	h.AuthConfig = config
	h.saveConfigLocked()
	return nil
}

type TrafficStats struct {
	TotalIn     uint64 `json:"total_in"`
	TotalOut    uint64 `json:"total_out"`
	ActiveConns int64  `json:"active_conns"`
	Error5xx    uint64 `json:"error_5xx"`
}

func (h *Handler) GetTrafficStats(timestamp time.Time) TrafficStats {
	return TrafficStats{
		TotalIn:     atomic.LoadUint64(&h.trafficTotalIn),
		TotalOut:    atomic.LoadUint64(&h.trafficTotalOut),
		ActiveConns: h.activeLoggedInCount(timestamp),
		Error5xx:    atomic.LoadUint64(&h.trafficError5xx),
	}
}

const loggedInActiveWindow = 2 * time.Minute

func canonicalCookieIdentity(r *http.Request) string {
	cookies := r.Cookies()
	if len(cookies) == 0 {
		return ""
	}

	filtered := make([]*http.Cookie, 0, len(cookies))
	for _, c := range cookies {
		if c == nil {
			continue
		}
		if c.Name == "__proxy_path" {
			continue
		}
		if c.Name == "" || c.Value == "" {
			continue
		}
		filtered = append(filtered, c)
	}
	if len(filtered) == 0 {
		return ""
	}

	sort.Slice(filtered, func(i, j int) bool {
		if filtered[i].Name == filtered[j].Name {
			return filtered[i].Value < filtered[j].Value
		}
		return filtered[i].Name < filtered[j].Name
	})

	var b strings.Builder
	for i, c := range filtered {
		if i > 0 {
			b.WriteByte(';')
		}
		b.WriteString(c.Name)
		b.WriteByte('=')
		b.WriteString(c.Value)
	}
	return b.String()
}

func activeIdentityKey(r *http.Request, clientIP string) string {
	var src string
	if cookieID := canonicalCookieIdentity(r); cookieID != "" {
		src = "cookie:" + cookieID
	} else if auth := r.Header.Get("Authorization"); auth != "" {
		src = "auth:" + auth
	} else if clientIP != "" {
		src = "ip:" + clientIP
	} else {
		return ""
	}

	sum := sha256.Sum256([]byte(src))
	return hex.EncodeToString(sum[:])
}

func (h *Handler) markLoggedInActive(r *http.Request, clientIP string, now time.Time) {
	key := activeIdentityKey(r, clientIP)
	if key == "" {
		return
	}
	h.loggedInActive.Store(key, now.UnixNano())
}

func (h *Handler) activeLoggedInCount(now time.Time) int64 {
	cutoff := now.Add(-loggedInActiveWindow).UnixNano()
	var count int64

	h.loggedInActive.Range(func(key, value any) bool {
		ts, ok := value.(int64)
		if !ok || ts < cutoff {
			h.loggedInActive.Delete(key)
			return true
		}
		count++
		return true
	})

	return count
}

type requestTrafficMetrics struct {
	inBytes     uint64
	outBytes    uint64
	statusCode  int
	wroteHeader bool
}

type trafficReadCloser struct {
	io.ReadCloser
	metrics *requestTrafficMetrics
}

func (trc *trafficReadCloser) Read(p []byte) (int, error) {
	n, err := trc.ReadCloser.Read(p)
	if n > 0 {
		trc.metrics.inBytes += uint64(n)
	}
	return n, err
}

type trafficResponseWriter struct {
	http.ResponseWriter
	metrics *requestTrafficMetrics
}

func (tw *trafficResponseWriter) WriteHeader(statusCode int) {
	if !tw.metrics.wroteHeader {
		tw.metrics.wroteHeader = true
		tw.metrics.statusCode = statusCode
	}
	tw.ResponseWriter.WriteHeader(statusCode)
}

func (tw *trafficResponseWriter) Write(p []byte) (int, error) {
	if !tw.metrics.wroteHeader {
		tw.WriteHeader(http.StatusOK)
	}
	n, err := tw.ResponseWriter.Write(p)
	if n > 0 {
		tw.metrics.outBytes += uint64(n)
	}
	return n, err
}

func (tw *trafficResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := tw.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	return hj.Hijack()
}

func (tw *trafficResponseWriter) Flush() {
	if fl, ok := tw.ResponseWriter.(http.Flusher); ok {
		fl.Flush()
	}
}

func (tw *trafficResponseWriter) Push(target string, opts *http.PushOptions) error {
	ps, ok := tw.ResponseWriter.(http.Pusher)
	if !ok {
		return http.ErrNotSupported
	}
	return ps.Push(target, opts)
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	atomic.AddInt64(&h.trafficActive, 1)

	metrics := &requestTrafficMetrics{
		statusCode: http.StatusOK,
	}
	if r.Body != nil {
		r.Body = &trafficReadCloser{
			ReadCloser: r.Body,
			metrics:    metrics,
		}
	}
	w = &trafficResponseWriter{
		ResponseWriter: w,
		metrics:        metrics,
	}

	defer func() {
		atomic.AddInt64(&h.trafficActive, -1)

		if metrics.inBytes != 0 {
			atomic.AddUint64(&h.trafficTotalIn, metrics.inBytes)
		}
		if metrics.outBytes != 0 {
			atomic.AddUint64(&h.trafficTotalOut, metrics.outBytes)
		}
		if metrics.statusCode >= 500 {
			atomic.AddUint64(&h.trafficError5xx, 1)
		}

		if rec := recover(); rec != nil {
			panic(rec)
		}
	}()

	snapshot := h.snapshotForRequest()

	cleanedPath := path.Clean(r.URL.Path)
	if strings.HasSuffix(r.URL.Path, "/") && cleanedPath != "/" {
		cleanedPath += "/"
	}
	r.URL.Path = cleanedPath
	if response.IsFaviconPath(r.URL.Path) {
		response.ServeFavicon(w, r)
		return
	}

	clientIP := resolveClientIP(r, snapshot.proxyProtocolForce)

	if h.handleSelectRoute(w, r, snapshot, clientIP) {
		return
	}
	if h.handleAuthProxyRoute(w, r, snapshot, clientIP) {
		return
	}

	matchedRule, needsSlashRedirect := matchRule(r, snapshot.rules)
	if needsSlashRedirect != "" {
		newPath := needsSlashRedirect
		if r.URL.RawQuery != "" {
			newPath += "?" + r.URL.RawQuery
		}
		http.Redirect(w, r, newPath, http.StatusMovedPermanently)
		return
	}

	if matchedRule == nil {
		h.handleNoMatchRoute(w, r, snapshot, clientIP)
		return
	}

	if matchedRule.UseRootMode && matchedRule.Path != "/" && strings.HasPrefix(r.URL.Path, matchedRule.Path) {
		http.SetCookie(w, &http.Cookie{
			Name:  "__proxy_path",
			Value: matchedRule.Path,
			Path:  "/",
		})
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	if matchedRule.UseAuth && snapshot.authConfig.AuthURL != "" {
		if !h.checkAuth(w, r, snapshot.authConfig, clientIP) {
			return
		}
	}

	if h.shouldDenyByPreflight(r, snapshot.authConfig, clientIP, true) {
		h.abortConnection(w)
		return
	}

	h.proxyToRuleTarget(w, r, snapshot, *matchedRule, clientIP)
}

func (h *Handler) handleSelectRoute(w http.ResponseWriter, r *http.Request, snapshot requestSnapshot, clientIP string) bool {
	if r.URL.Path != "/__select__" {
		return false
	}

	if h.shouldDenyByPreflight(r, snapshot.authConfig, clientIP, true) {
		h.abortConnection(w)
		return true
	}
	if snapshot.authConfig.AuthURL != "" {
		if !h.checkAuth(w, r, snapshot.authConfig, clientIP) {
			return true
		}
	}
	response.SelectPage(w, snapshot.rules)
	return true
}

func (h *Handler) handleAuthProxyRoute(w http.ResponseWriter, r *http.Request, snapshot requestSnapshot, clientIP string) bool {
	if !strings.HasPrefix(r.URL.Path, "/__auth__/") {
		return false
	}

	if snapshot.authConfig.AuthPort <= 0 {
		response.HTML(w, errors.CodeInternal, "Authentication service is not configured", nil)
		return true
	}
	if h.shouldDenyByPreflight(r, snapshot.authConfig, clientIP, true) {
		h.abortConnection(w)
		return true
	}

	targetURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", snapshot.authConfig.AuthPort))

	proxyPath := r.URL.Path
	switch r.URL.Path {
	case "/__auth__/login":
		proxyPath = snapshot.authConfig.LoginURL
		if proxyPath == "" {
			proxyPath = "/login"
		}
	case "/__auth__/api/auth/logout":
		proxyPath = snapshot.authConfig.LogoutURL
		if proxyPath == "" {
			proxyPath = "/api/auth/logout"
		}
	default:
		rawProxyPath := strings.TrimPrefix(r.URL.Path, "/__auth__")
		proxyPath = path.Clean(ensureLeadingSlash(rawProxyPath))
	}

	targetURL.Path = singleJoiningSlash(targetURL.Path, proxyPath)

	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	proxy.Transport = newProxyTransport()

	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Host = targetURL.Host
		req.URL.Path = targetURL.Path

		req.Header.Set("X-Real-IP", clientIP)
		req.Header.Set("X-Forwarded-For", clientIP)
		// Prevent X-Forwarded-Path and X-Match from being passed to the backend
		req.Header.Del("X-Forwarded-Path")
		req.Header.Del("X-Match")
	}

	proxy.ServeHTTP(w, r)
	return true
}

func matchRule(r *http.Request, rules []models.Rule) (*models.Rule, string) {
	var matchedRule *models.Rule
	var longestMatch int
	var needsSlashRedirect string

	for _, rule := range rules {
		if strings.HasPrefix(r.URL.Path, rule.Path) && len(rule.Path) > longestMatch {
			matchedRule = copyRule(rule)
			longestMatch = len(rule.Path)
		}
		if r.URL.Path+"/" == rule.Path {
			needsSlashRedirect = rule.Path
		}
	}

	if matchedRule != nil && matchedRule.Path != "/" && r.URL.Path == matchedRule.Path && !strings.HasSuffix(matchedRule.Path, "/") {
		if r.Method == http.MethodGet {
			needsSlashRedirect = matchedRule.Path + "/"
			matchedRule = nil
		}
	} else if longestMatch == len(r.URL.Path) {
		needsSlashRedirect = ""
	} else if needsSlashRedirect != "" {
		matchedRule = nil
	}

	if matchedRule == nil && needsSlashRedirect == "" {
		isWebSocket := strings.ToLower(r.Header.Get("Upgrade")) == "websocket"
		canUseCookie := r.URL.Path == "/" || r.Header.Get("Referer") != "" || r.Header.Get("Origin") != "" || isWebSocket
		if canUseCookie {
			if cookie, err := r.Cookie("__proxy_path"); err == nil && cookie.Value != "" {
				for _, rule := range rules {
					if cookie.Value == rule.Path {
						matchedRule = copyRule(rule)
						break
					}
				}
			}
		}

		if matchedRule == nil {
			referer := r.Header.Get("Referer")
			if referer != "" {
				refURL, err := url.Parse(referer)
				if err == nil {
					var longestRefMatch int
					for _, rule := range rules {
						if strings.HasPrefix(refURL.Path, rule.Path) && len(rule.Path) > longestRefMatch {
							matchedRule = copyRule(rule)
							longestRefMatch = len(rule.Path)
						}
					}
				}
			}
		}
	}

	return matchedRule, needsSlashRedirect
}

func (h *Handler) handleNoMatchRoute(w http.ResponseWriter, r *http.Request, snapshot requestSnapshot, clientIP string) {
	if r.URL.Path == "/" {
		if h.shouldDenyByPreflight(r, snapshot.authConfig, clientIP, true) {
			h.abortConnection(w)
			return
		}
		if len(snapshot.rules) == 0 {
			response.Welcome(w, nil)
			return
		}
		http.Redirect(w, r, snapshot.defaultRoute, http.StatusFound)
		return
	}

	if h.shouldDenyByPreflight(r, snapshot.authConfig, clientIP, false) {
		h.abortConnection(w)
		return
	}
	response.HTML(w, errors.CodeNotFound, "Not Found", snapshot.rules)
}

func (h *Handler) proxyToRuleTarget(w http.ResponseWriter, r *http.Request, snapshot requestSnapshot, matchedRule models.Rule, clientIP string) {
	targetURL, err := url.Parse(matchedRule.Target)
	if err != nil {
		response.HTML(w, errors.CodeProxyTargetInvalid, "Invalid target URL configuration", snapshot.rules)
		return
	}

	switch targetURL.Scheme {
	case "ws":
		targetURL.Scheme = "http"
	case "wss":
		targetURL.Scheme = "https"
	}

	transport := newProxyTransport()
	proxy := &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetXForwarded()
			pr.Out.Header.Set("X-Forwarded-For", clientIP)
			pr.Out.Header.Set("X-Real-IP", clientIP)
			pr.SetURL(targetURL)
			pr.Out.Host = targetURL.Host

			if matchedRule.StripPath {
				pr.Out.URL.Path = strings.TrimPrefix(pr.Out.URL.Path, matchedRule.Path)
				if !strings.HasPrefix(pr.Out.URL.Path, "/") {
					pr.Out.URL.Path = "/" + pr.Out.URL.Path
				}
				pr.Out.URL.RawPath = ""
			}

			if origin := pr.In.Header.Get("Origin"); origin != "" {
				pr.Out.Header.Set("Origin", targetURL.Scheme+"://"+targetURL.Host)
			}
			if referer := pr.In.Header.Get("Referer"); referer != "" {
				ref, err := url.Parse(referer)
				if err == nil {
					ref.Scheme = targetURL.Scheme
					ref.Host = targetURL.Host
					ref.Path = path.Clean(ref.Path)

					if matchedRule.StripPath {
						ref.Path = strings.TrimPrefix(ref.Path, matchedRule.Path)
						if !strings.HasPrefix(ref.Path, "/") {
							ref.Path = "/" + ref.Path
						}
					}
					ref.RawPath = ""

					pr.Out.Header.Set("Referer", ref.String())
				}
			}

			if matchedRule.RewriteHTML || matchedRule.UseAuth {
				pr.Out.Header.Del("Accept-Encoding")
			}
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("Proxy error: %v", err)
			response.HTML(w, errors.CodeProxyTimeout, "Upstream unavailable: "+err.Error(), h.GetRules())
		},
	}

	proxy.ModifyResponse = func(resp *http.Response) error {
		cookie := &http.Cookie{
			Name:  "__proxy_path",
			Value: matchedRule.Path,
			Path:  "/",
		}
		resp.Header.Add("Set-Cookie", cookie.String())

		needsRewrite := matchedRule.RewriteHTML && !matchedRule.UseRootMode
		needsToolbar := matchedRule.UseAuth
		if !needsRewrite && !needsToolbar {
			return nil
		}

		if needsRewrite {
			if location := resp.Header.Get("Location"); location != "" {
				if strings.HasPrefix(location, "/") {
					resp.Header.Set("Location", matchedRule.Path+location)
				}
			}
		}

		contentType := resp.Header.Get("Content-Type")
		if !strings.Contains(strings.ToLower(contentType), "text/html") {
			return nil
		}

		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		resp.Body.Close()

		bodyStr := string(bodyBytes)

		if needsRewrite {
			prefix := strings.TrimSuffix(matchedRule.Path, "/")
			replacements := []struct {
				old string
				new string
			}{
				{`href="/`, `href="` + prefix + `/`},
				{`src="/`, `src="` + prefix + `/`},
				{`action="/`, `action="` + prefix + `/`},
				{`<base href="/">`, `<base href="` + prefix + `/">`},
			}

			for _, rep := range replacements {
				bodyStr = strings.ReplaceAll(bodyStr, rep.old, rep.new)
			}
		}

		if needsToolbar {
			toolbarHTML := response.GenerateToolbar(snapshot.rules, matchedRule.Path)
			lowerBody := strings.ToLower(bodyStr)
			if idx := strings.LastIndex(lowerBody, "</body>"); idx != -1 {
				bodyStr = bodyStr[:idx] + toolbarHTML + bodyStr[idx:]
			} else if strings.Contains(lowerBody, "<html") || strings.Contains(lowerBody, "<head") || strings.Contains(lowerBody, "<body") || strings.Contains(lowerBody, "<!doctype") {
				bodyStr += toolbarHTML
			}
		}

		newBody := []byte(bodyStr)
		resp.Body = io.NopCloser(bytes.NewReader(newBody))
		resp.ContentLength = int64(len(newBody))
		resp.Header.Set("Content-Length", strconv.Itoa(len(newBody)))
		return nil
	}

	proxy.ServeHTTP(w, r)
}

func (h *Handler) checkAuth(w http.ResponseWriter, r *http.Request, authConfig models.AuthConfig, clientIP string) bool {
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: newInternalTransport(),
	}

	if authConfig.AuthPort <= 0 {
		log.Printf("Auth check requested but AuthPort is not configured")
		response.HTML(w, errors.CodeInternal, "Authentication Service Not Configured", nil)
		return false
	}

	authURLPath := authConfig.AuthURL
	if authURLPath == "" {
		authURLPath = "/api/auth/verify"
	}
	authURL := localServiceURL(authConfig.AuthPort, authURLPath)

	authReq, err := http.NewRequest("GET", authURL, nil)
	if err != nil {
		log.Printf("Failed to create auth request: %v", err)
		response.HTML(w, errors.CodeInternal, "Internal Server Error during Auth", nil)
		return false
	}

	authReq.Header.Set("X-Real-IP", clientIP)
	authReq.Header.Set("X-Forwarded-For", clientIP)

	if cookie := r.Header.Get("Cookie"); cookie != "" {
		authReq.Header.Set("Cookie", cookie)
	}
	if auth := r.Header.Get("Authorization"); auth != "" {
		authReq.Header.Set("Authorization", auth)
	}

	authReq.Header.Set("X-Forwarded-Path", r.URL.RequestURI())

	resp, err := client.Do(authReq)
	if err != nil {
		log.Printf("Auth request failed: %v", err)
		response.HTML(w, errors.CodeProxyAuthFailed, "Authentication Service Unavailable", nil)
		return false
	}
	defer resp.Body.Close()

	var authResponse struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&authResponse); err != nil {
		log.Printf("Failed to decode auth response: %v", err)
		response.HTML(w, errors.CodeInternal, "Invalid Auth Response Format", nil)
		return false
	}
	if authResponse.Success {
		h.markLoggedInActive(r, clientIP, time.Now())
		return true
	}
	log.Printf("Auth failed: %s", authResponse.Message)

	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	host := r.Host
	if forwardedHost := r.Header.Get("X-Forwarded-Host"); forwardedHost != "" {
		host = forwardedHost
	}

	originalURL := url.URL{
		Scheme:   scheme,
		Host:     host,
		Path:     r.URL.Path,
		RawQuery: r.URL.RawQuery,
	}

	loginURL, _ := url.Parse("/__auth__/login")
	q := loginURL.Query()
	q.Set("redirect_uri", originalURL.String())
	loginURL.RawQuery = q.Encode()

	http.Redirect(w, r, loginURL.String(), http.StatusFound)
	return false
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
