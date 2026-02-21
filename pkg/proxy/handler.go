package proxy

import (
	"bytes"
	"fmt"
	"go-reauth-proxy/pkg/auth"
	"go-reauth-proxy/pkg/errors"
	"go-reauth-proxy/pkg/models"
	"go-reauth-proxy/pkg/response"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Handler struct {
	mu           sync.RWMutex
	Rules        []models.Rule
	DefaultRoute string
	AuthConfig   models.AuthConfig
	AuthCache    *auth.Cache
	AdminPort    int
}

func NewHandler(cache *auth.Cache, adminPort int) *Handler {
	return &Handler{
		Rules:        make([]models.Rule, 0),
		DefaultRoute: "/__select__",
		AuthConfig: models.AuthConfig{
			AuthPort:        7997,
			AuthURL:         "/auth",
			LoginURL:        "/login",
			AuthCacheExpire: 60,
		},
		AuthCache: cache,
		AdminPort: adminPort,
	}
}

func (h *Handler) AddRule(newRule models.Rule) error {
	if newRule.Path == "/" || newRule.Path == "" {
		return fmt.Errorf("cannot add rule for root path '/'")
	}
	if strings.HasPrefix(newRule.Path, "/__") || strings.HasPrefix(newRule.Path, "__") {
		return fmt.Errorf("cannot add rule for reserved path starting with '__'")
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
	return nil
}

func (h *Handler) checkSafeTarget(target string) error {
	u, err := url.Parse(target)
	if err != nil {
		return err
	}
	hostname := u.Hostname()
	port := u.Port()

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
}

func (h *Handler) FlushRules() {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.Rules = make([]models.Rule, 0)
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
		config.AuthURL = "/auth"
	}
	if config.LoginURL == "" {
		config.LoginURL = "/login"
	}
	if config.AuthCacheExpire <= 0 {
		config.AuthCacheExpire = 60
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	h.AuthConfig = config
	if h.AuthCache != nil {
		h.AuthCache.SetTTL(time.Duration(config.AuthCacheExpire) * time.Second)
	}
	return nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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
			response.HTML(w, errors.CodeInternal, "Authentication service is not configured")
			return
		}

		targetURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", authConfig.AuthPort))

		proxyPath := r.URL.Path
		if r.URL.Path == "/__auth__/login" {
			proxyPath = authConfig.LoginURL
			if proxyPath == "" {
				proxyPath = "/login"
			}
		} else {
			proxyPath = strings.TrimPrefix(r.URL.Path, "/__auth__")
		}

		if !strings.HasPrefix(proxyPath, "/") {
			proxyPath = "/" + proxyPath
		}

		targetURL.Path = singleJoiningSlash(targetURL.Path, proxyPath)

		proxy := httputil.NewSingleHostReverseProxy(targetURL)

		originalDirector := proxy.Director
		proxy.Director = func(req *http.Request) {
			originalDirector(req)
			req.Host = targetURL.Host
			req.URL.Path = targetURL.Path
		}

		proxy.ServeHTTP(w, r)
		return
	}

	h.mu.RLock()
	var matchedRule *models.Rule
	var longestMatch int
	for _, rule := range h.Rules {
		if strings.HasPrefix(r.URL.Path, rule.Path) && len(rule.Path) > longestMatch {
			rCopy := rule
			matchedRule = &rCopy
			longestMatch = len(rule.Path)
		}
	}

	if matchedRule == nil {
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

	if matchedRule == nil {
		if r.URL.Path == "/" {
			h.mu.RLock()
			count := len(h.Rules)
			h.mu.RUnlock()

			if count == 0 {
				response.Welcome(w)
				return
			}

			http.Redirect(w, r, h.GetDefaultRoute(), http.StatusFound)
			return
		}

		response.HTML(w, errors.CodeNotFound, "Not Found")
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
		response.HTML(w, errors.CodeProxyTargetInvalid, "Invalid target URL configuration")
		return
	}

	switch targetURL.Scheme {
	case "ws":
		targetURL.Scheme = "http"
	case "wss":
		targetURL.Scheme = "https"
	}

	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetXForwarded()
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

			if matchedRule.RewriteHTML {
				pr.Out.Header.Del("Accept-Encoding")
			}
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("Proxy error: %v", err)
			response.HTML(w, errors.CodeProxyTimeout, "Upstream unavailable: "+err.Error())
		},
	}

	proxy.ModifyResponse = func(resp *http.Response) error {
		cookie := &http.Cookie{
			Name:  "__proxy_path",
			Value: matchedRule.Path,
			Path:  "/",
		}
		resp.Header.Add("Set-Cookie", cookie.String())

		if !matchedRule.RewriteHTML || matchedRule.UseRootMode {
			return nil
		}

		if location := resp.Header.Get("Location"); location != "" {
			if strings.HasPrefix(location, "/") {
				resp.Header.Set("Location", matchedRule.Path+location)
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
		prefix := matchedRule.Path
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

		newBody := []byte(bodyStr)
		resp.Body = io.NopCloser(bytes.NewReader(newBody))
		resp.ContentLength = int64(len(newBody))
		resp.Header.Set("Content-Length", strconv.Itoa(len(newBody)))

		return nil
	}

	proxy.ServeHTTP(w, r)
}

func (h *Handler) checkAuth(w http.ResponseWriter, r *http.Request, authConfig models.AuthConfig) bool {
	cookieHeader := r.Header.Get("Cookie")
	authHeader := r.Header.Get("Authorization")

	cacheKey := auth.GenerateKey(cookieHeader, authHeader)

	if valid, found := h.AuthCache.Get(cacheKey); found && valid {
		return true
	}
	client := &http.Client{Timeout: 5 * time.Second}

	if authConfig.AuthPort <= 0 {
		log.Printf("Auth check requested but AuthPort is not configured")
		response.HTML(w, errors.CodeInternal, "Authentication Service Not Configured")
		return false
	}

	authURLPath := authConfig.AuthURL
	if authURLPath == "" {
		authURLPath = "/auth"
	}
	if !strings.HasPrefix(authURLPath, "/") {
		authURLPath = "/" + authURLPath
	}

	authURL := fmt.Sprintf("http://127.0.0.1:%d%s", authConfig.AuthPort, authURLPath)

	authReq, err := http.NewRequest("GET", authURL, nil)
	if err != nil {
		log.Printf("Failed to create auth request: %v", err)
		response.HTML(w, errors.CodeInternal, "Internal Server Error during Auth")
		return false
	}

	authReq.Header = r.Header.Clone()

	resp, err := client.Do(authReq)
	if err != nil {
		log.Printf("Auth request failed: %v", err)
		response.HTML(w, errors.CodeProxyAuthFailed, "Authentication Service Unavailable")
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		h.AuthCache.Set(cacheKey, true)
		return true
	}

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
