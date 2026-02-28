package proxy

import (
	"bytes"
	"crypto/tls"
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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Handler struct {
	mu           sync.RWMutex
	Rules        []models.Rule
	DefaultRoute string
	AuthConfig   models.AuthConfig
	AdminPort    int
	sslCert      atomic.Value

	configManager *config.Manager
	certPEM       string
	keyPEM        string
}

func NewHandler(adminPort int, cfgManager *config.Manager, initialCfg *config.AppConfig) *Handler {
	h := &Handler{
		Rules:         initialCfg.Rules,
		DefaultRoute:  initialCfg.DefaultRoute,
		AuthConfig:    initialCfg.AuthConfig,
		AdminPort:     adminPort,
		configManager: cfgManager,
		certPEM:       initialCfg.SSLCert,
		keyPEM:        initialCfg.SSLKey,
	}

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
		conf.SSLCert = h.certPEM
		conf.SSLKey = h.keyPEM
		return nil
	}); err != nil {
		log.Printf("Failed to save config: %v", err)
	}
}

func (h *Handler) SetSSLCertificate(cert *tls.Certificate, certPEM, keyPEM string) {
	h.mu.Lock()
	defer h.mu.Unlock()
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
	defer h.mu.Unlock()
	var empty *tls.Certificate
	h.sslCert.Store(empty)
	h.certPEM = ""
	h.keyPEM = ""
	h.saveConfigLocked()
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

	h.mu.Lock()
	defer h.mu.Unlock()
	h.AuthConfig = config
	h.saveConfigLocked()
	return nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Serve embedded favicon/static files
	if response.IsFaviconPath(r.URL.Path) {
		response.ServeFavicon(w, r)
		return
	}

	if r.URL.Path == "/__select__" {
		h.mu.RLock()
		authConfig := h.AuthConfig
		rules := h.GetRules()
		h.mu.RUnlock()

		if authConfig.AuthURL != "" {
			if !h.checkAuth(w, r, authConfig) {
				return
			}
		}

		response.SelectPage(w, rules)
		return
	}

	if strings.HasPrefix(r.URL.Path, "/__auth__/") {
		h.mu.RLock()
		authConfig := h.AuthConfig
		h.mu.RUnlock()

		if authConfig.AuthPort <= 0 {
			response.HTML(w, errors.CodeInternal, "Authentication service is not configured", nil)
			return
		}

		targetURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", authConfig.AuthPort))

		proxyPath := r.URL.Path
		switch r.URL.Path {
		case "/__auth__/login":
			proxyPath = authConfig.LoginURL
			if proxyPath == "" {
				proxyPath = "/login"
			}
		case "/__auth__/api/auth/logout":
			proxyPath = authConfig.LogoutURL
			if proxyPath == "" {
				proxyPath = "/api/auth/logout"
			}
		default:
			proxyPath = strings.TrimPrefix(r.URL.Path, "/__auth__")
		}

		if !strings.HasPrefix(proxyPath, "/") {
			proxyPath = "/" + proxyPath
		}

		targetURL.Path = singleJoiningSlash(targetURL.Path, proxyPath)

		proxy := httputil.NewSingleHostReverseProxy(targetURL)

		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.DialContext = (&net.Dialer{
			Timeout:   6 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext
		transport.TLSHandshakeTimeout = 10 * time.Second
		transport.ResponseHeaderTimeout = 10 * time.Second
		transport.MaxIdleConns = 100
		transport.MaxIdleConnsPerHost = 100
		transport.IdleConnTimeout = 90 * time.Second
		transport.ForceAttemptHTTP2 = true
		proxy.Transport = transport

		originalDirector := proxy.Director
		proxy.Director = func(req *http.Request) {
			originalDirector(req)
			req.Host = targetURL.Host
			req.URL.Path = targetURL.Path

			remoteIP, _, _ := net.SplitHostPort(r.RemoteAddr)
			req.Header.Set("X-Real-IP", remoteIP)
			req.Header.Set("X-Forwarded-For", remoteIP)
		}

		proxy.ServeHTTP(w, r)
		return
	}

	h.mu.RLock()
	var matchedRule *models.Rule
	var longestMatch int
	var needsSlashRedirect string

	for _, rule := range h.Rules {
		if strings.HasPrefix(r.URL.Path, rule.Path) && len(rule.Path) > longestMatch {
			rCopy := rule
			matchedRule = &rCopy
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
				for _, rule := range h.Rules {
					if cookie.Value == rule.Path {
						rCopy := rule
						matchedRule = &rCopy
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
					for _, rule := range h.Rules {
						if strings.HasPrefix(refURL.Path, rule.Path) && len(rule.Path) > longestRefMatch {
							rCopy := rule
							matchedRule = &rCopy
							longestRefMatch = len(rule.Path)
						}
					}
				}
			}
		}
	}
	h.mu.RUnlock()

	if needsSlashRedirect != "" {
		newPath := needsSlashRedirect
		if r.URL.RawQuery != "" {
			newPath += "?" + r.URL.RawQuery
		}
		http.Redirect(w, r, newPath, http.StatusMovedPermanently)
		return
	}

	if matchedRule == nil {
		if r.URL.Path == "/" {
			h.mu.RLock()
			count := len(h.Rules)
			h.mu.RUnlock()

			if count == 0 {
				response.Welcome(w, nil)
				return
			}

			http.Redirect(w, r, h.GetDefaultRoute(), http.StatusFound)
			return
		}

		response.HTML(w, errors.CodeNotFound, "Not Found", h.GetRules())
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
	if matchedRule.UseAuth {
		h.mu.RLock()
		authConfig := h.AuthConfig
		h.mu.RUnlock()
		if authConfig.AuthURL != "" {
			if !h.checkAuth(w, r, authConfig) {
				return
			}
		}
	}

	targetURL, err := url.Parse(matchedRule.Target)
	if err != nil {
		response.HTML(w, errors.CodeProxyTargetInvalid, "Invalid target URL configuration", h.GetRules())
		return
	}

	switch targetURL.Scheme {
	case "ws":
		targetURL.Scheme = "http"
	case "wss":
		targetURL.Scheme = "https"
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = (&net.Dialer{
		Timeout:   6 * time.Second,
		KeepAlive: 30 * time.Second,
	}).DialContext
	transport.TLSHandshakeTimeout = 10 * time.Second
	transport.ResponseHeaderTimeout = 10 * time.Second
	transport.MaxIdleConns = 100
	transport.MaxIdleConnsPerHost = 100
	transport.IdleConnTimeout = 90 * time.Second
	transport.ForceAttemptHTTP2 = true

	proxy := &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(pr *httputil.ProxyRequest) {
			remoteIP, _, _ := net.SplitHostPort(pr.In.RemoteAddr)
			pr.SetXForwarded()
			pr.Out.Header.Set("X-Forwarded-For", remoteIP)
			pr.Out.Header.Set("X-Real-IP", remoteIP)
			pr.SetURL(targetURL)
			pr.Out.Host = targetURL.Host

			if matchedRule.StripPath {
				pr.Out.URL.Path = strings.TrimPrefix(pr.Out.URL.Path, matchedRule.Path)
				if pr.Out.URL.RawPath != "" {
					pr.Out.URL.RawPath = strings.TrimPrefix(pr.Out.URL.RawPath, matchedRule.Path)
				}
				if pr.Out.URL.Path == "" {
					pr.Out.URL.Path = "/"
				}
			}

			if origin := pr.In.Header.Get("Origin"); origin != "" {
				pr.Out.Header.Set("Origin", targetURL.Scheme+"://"+targetURL.Host)
			}
			if referer := pr.In.Header.Get("Referer"); referer != "" {
				ref, err := url.Parse(referer)
				if err == nil {
					ref.Scheme = targetURL.Scheme
					ref.Host = targetURL.Host
					if matchedRule.StripPath {
						ref.Path = strings.TrimPrefix(ref.Path, matchedRule.Path)
						if ref.Path == "" {
							ref.Path = "/"
						}
					}
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
			h.mu.RLock()
			rules := h.GetRules()
			h.mu.RUnlock()
			toolbarHTML := response.GenerateToolbar(rules, matchedRule.Path)

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

func (h *Handler) checkAuth(w http.ResponseWriter, r *http.Request, authConfig models.AuthConfig) bool {
	authTransport := http.DefaultTransport.(*http.Transport).Clone()
	authTransport.MaxIdleConns = 100
	authTransport.MaxIdleConnsPerHost = 100
	authTransport.IdleConnTimeout = 90 * time.Second
	authTransport.ForceAttemptHTTP2 = true

	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: authTransport,
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
	if !strings.HasPrefix(authURLPath, "/") {
		authURLPath = "/" + authURLPath
	}

	authURL := fmt.Sprintf("http://127.0.0.1:%d%s", authConfig.AuthPort, authURLPath)

	authReq, err := http.NewRequest("GET", authURL, nil)
	if err != nil {
		log.Printf("Failed to create auth request: %v", err)
		response.HTML(w, errors.CodeInternal, "Internal Server Error during Auth", nil)
		return false
	}

	remoteIP, _, _ := net.SplitHostPort(r.RemoteAddr)

	authReq.Header.Set("X-Real-IP", remoteIP)
	authReq.Header.Set("X-Forwarded-For", remoteIP)

	if cookie := r.Header.Get("Cookie"); cookie != "" {
		authReq.Header.Set("Cookie", cookie)
	}
	if auth := r.Header.Get("Authorization"); auth != "" {
		authReq.Header.Set("Authorization", auth)
	}

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
