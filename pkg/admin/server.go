package admin

import (
	"encoding/json"
	"fmt"
	"go-reauth-proxy/pkg/config"
	"go-reauth-proxy/pkg/errors"
	"go-reauth-proxy/pkg/i18n"
	"go-reauth-proxy/pkg/iptables"
	"go-reauth-proxy/pkg/models"
	"go-reauth-proxy/pkg/proxy"
	"go-reauth-proxy/pkg/response"
	"go-reauth-proxy/pkg/stream"
	"go-reauth-proxy/pkg/version"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

type Server struct {
	ProxyHandler    *proxy.Handler
	IptablesHandler *iptables.Handler
	StreamManager   *stream.Manager
	ConfigManager   *config.Manager
	Port            int
}

type ServerInfo struct {
	Version string `json:"version" example:"0.0.1"`
}

type authConfigPatch struct {
	AuthPort              *int    `json:"auth_port"`
	AuthURL               *string `json:"auth_url"`
	LoginURL              *string `json:"login_url"`
	LogoutURL             *string `json:"logout_url"`
	PreflightURL          *string `json:"preflight_url"`
	AuthCacheTTL          *int    `json:"auth_cache_ttl_seconds"`
	AuthCacheFailTTL      *int    `json:"auth_cache_unauthorized_ttl_seconds"`
	EdgeClientIPEnabled   *bool   `json:"edge_client_ip_enabled"`
	AliyunESAEnabled      *bool   `json:"aliyun_esa_enabled"`
	TencentEdgeOneEnabled *bool   `json:"tencent_edgeone_enabled"`
	PublicAuthBaseURL     *string `json:"public_auth_base_url"`
	PublicHTTPPort        *int    `json:"public_http_port"`
	PublicHTTPSPort       *int    `json:"public_https_port"`
	AuthHost              *string `json:"auth_host"`
	TrustForwardedProto   *bool   `json:"trust_forwarded_proto"`
}

type reverseProxyThrottleExemptIPsRuntimeResponse = models.ReverseProxyThrottleExemptIPsRuntime
type commonLocationExemptionsRuntimeResponse = models.CommonLocationExemptionsRuntime

func NewServer(handler *proxy.Handler, port int, cfgManager *config.Manager, initialCfg *config.AppConfig, streamManager *stream.Manager) *Server {
	iptablesChainName := "REAUTH_FW"
	if initialCfg != nil && initialCfg.IptablesChainName != "" {
		iptablesChainName = initialCfg.IptablesChainName
	}

	iptablesManager := iptables.NewManager(iptables.Options{
		ChainName:   iptablesChainName,
		ParentChain: []string{"INPUT", "DOCKER-USER"},
	})
	iptablesHandler := iptables.NewHandler(iptablesManager, cfgManager)

	return &Server{
		ProxyHandler:    handler,
		IptablesHandler: iptablesHandler,
		StreamManager:   streamManager,
		ConfigManager:   cfgManager,
		Port:            port,
	}
}

// handleGetRules returns all proxy rules
// @Summary Get all rules
// @Description Get all configured proxy rules
// @Tags rules
// @Produce  json
// @Success 200 {object} response.Response{data=[]models.Rule}
// @Router /api/rules [get]
func (s *Server) handleGetRules(w http.ResponseWriter, r *http.Request) {
	rules := s.ProxyHandler.GetRules()
	response.Success(w, rules)
}

// handleAddRule sets proxy rules (overrides existing)
// @Summary Set rules
// @Description Set proxy rules (overrides existing rules)
// @Tags rules
// @Accept  json
// @Produce  json
// @Param rules body []models.Rule true "List of rules to set"
// @Success 200 {object} response.Response{data=[]models.Rule}
// @Failure 400 {object} response.Response
// @Router /api/rules [post]
func (s *Server) handleAddRule(w http.ResponseWriter, r *http.Request) {
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		response.Error(w, errors.CodeReadBodyFailed, "Failed to read request body")
		return
	}
	r.Body.Close()

	type ruleRequest struct {
		Path        string `json:"path"`
		Target      string `json:"target"`
		UseAuth     *bool  `json:"use_auth"`
		StripPath   *bool  `json:"strip_path"`
		RewriteHTML *bool  `json:"rewrite_html"`
		UseRootMode *bool  `json:"use_root_mode"`
	}

	var reqs []ruleRequest
	if err := json.Unmarshal(bodyBytes, &reqs); err != nil {
		response.Error(w, errors.CodeInvalidJSON, "Invalid JSON array: "+err.Error())
		return
	}

	nextRules := make([]models.Rule, 0, len(reqs))
	for _, req := range reqs {
		stripPath := true
		if req.StripPath != nil {
			stripPath = *req.StripPath
		}

		rewriteHTML := true
		if req.RewriteHTML != nil {
			rewriteHTML = *req.RewriteHTML
		}

		nextRules = append(nextRules, models.Rule{
			Path:        req.Path,
			Target:      req.Target,
			UseAuth:     req.UseAuth != nil && *req.UseAuth,
			StripPath:   stripPath,
			RewriteHTML: rewriteHTML,
			UseRootMode: req.UseRootMode != nil && *req.UseRootMode,
		})
	}
	if err := s.ProxyHandler.SetRules(nextRules); err != nil {
		response.Error(w, errors.CodeInvalidRule, fmt.Sprintf("Failed to set rules: %v", err))
		return
	}

	response.Success(w, s.ProxyHandler.GetRules())
}

// handleFlushRules clears all proxy rules
// @Summary Flush all rules
// @Description Remove all proxy rules
// @Tags rules
// @Produce  json
// @Success 200 {object} response.Response
// @Router /api/rules [delete]
func (s *Server) handleFlushRules(w http.ResponseWriter, r *http.Request) {
	if err := s.ProxyHandler.FlushRules(); err != nil {
		response.Error(w, errors.CodeInternal, "Failed to flush rules: "+err.Error())
		return
	}
	response.Success(w, nil)
}

// handleGetHostRules returns all exact-host proxy rules
// @Summary Get host rules
// @Description Get all exact-host reverse proxy rules
// @Tags host-rules
// @Produce  json
// @Success 200 {object} response.Response{data=[]models.HostRule}
// @Router /api/host-rules [get]
func (s *Server) handleGetHostRules(w http.ResponseWriter, r *http.Request) {
	rules := s.ProxyHandler.GetHostRules()
	response.Success(w, rules)
}

// handleAddHostRule replaces all exact-host proxy rules
// @Summary Set host rules
// @Description Replace all exact-host reverse proxy rules
// @Tags host-rules
// @Accept  json
// @Produce  json
// @Param rules body []models.HostRule true "List of host rules to set"
// @Success 200 {object} response.Response{data=[]models.HostRule}
// @Failure 400 {object} response.Response
// @Router /api/host-rules [post]
func (s *Server) handleAddHostRule(w http.ResponseWriter, r *http.Request) {
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		response.Error(w, errors.CodeReadBodyFailed, "Failed to read request body")
		return
	}
	r.Body.Close()

	type hostLocationRequest struct {
		Path        string                      `json:"path"`
		Match       string                      `json:"match"`
		Action      string                      `json:"action"`
		Target      string                      `json:"target"`
		StripPath   *bool                       `json:"strip_path"`
		RewriteHTML *bool                       `json:"rewrite_html"`
		Response    models.HostLocationResponse `json:"response"`
	}
	type hostRuleRequest struct {
		Host            string                 `json:"host"`
		Target          string                 `json:"target"`
		UseAuth         *bool                  `json:"use_auth"`
		AccessMode      string                 `json:"access_mode"`
		SuppressToolbar *bool                  `json:"suppress_toolbar"`
		PreserveHost    *bool                  `json:"preserve_host"`
		IsDefault       bool                   `json:"is_default"`
		Title           string                 `json:"title"`
		Favicon         *string                `json:"favicon"`
		BasicAuth       models.BasicAuthConfig `json:"basic_auth"`
		Locations       []hostLocationRequest  `json:"locations"`
	}

	var reqs []hostRuleRequest
	if err := json.Unmarshal(bodyBytes, &reqs); err != nil {
		response.Error(w, errors.CodeInvalidJSON, "Invalid JSON array: "+err.Error())
		return
	}

	rules := make([]models.HostRule, 0, len(reqs))
	for _, req := range reqs {
		locations := make([]models.HostLocation, 0, len(req.Locations))
		for _, locationReq := range req.Locations {
			stripPath := true
			if locationReq.StripPath != nil {
				stripPath = *locationReq.StripPath
			}
			rewriteHTML := true
			if locationReq.RewriteHTML != nil {
				rewriteHTML = *locationReq.RewriteHTML
			}
			locations = append(locations, models.HostLocation{
				Path:        locationReq.Path,
				Match:       locationReq.Match,
				Action:      locationReq.Action,
				Target:      locationReq.Target,
				StripPath:   stripPath,
				RewriteHTML: rewriteHTML,
				Response:    locationReq.Response,
			})
		}

		rules = append(rules, models.HostRule{
			Host:            req.Host,
			Target:          req.Target,
			UseAuth:         req.UseAuth == nil || *req.UseAuth,
			AccessMode:      req.AccessMode,
			SuppressToolbar: req.SuppressToolbar != nil && *req.SuppressToolbar,
			PreserveHost:    req.PreserveHost == nil || *req.PreserveHost,
			IsDefault:       req.IsDefault,
			Title:           req.Title,
			Favicon: func() string {
				if req.Favicon == nil {
					return ""
				}
				return *req.Favicon
			}(),
			BasicAuth: req.BasicAuth,
			Locations: locations,
		})
	}

	if err := s.ProxyHandler.SetHostRules(rules); err != nil {
		response.Error(w, errors.CodeInvalidRule, fmt.Sprintf("Failed to set host rules: %v", err))
		return
	}

	response.Success(w, s.ProxyHandler.GetHostRules())
}

// handleFlushHostRules clears all exact-host proxy rules
// @Summary Flush host rules
// @Description Remove all exact-host reverse proxy rules
// @Tags host-rules
// @Produce  json
// @Success 200 {object} response.Response
// @Router /api/host-rules [delete]
func (s *Server) handleFlushHostRules(w http.ResponseWriter, r *http.Request) {
	if err := s.ProxyHandler.FlushHostRules(); err != nil {
		response.Error(w, errors.CodeInternal, "Failed to flush host rules: "+err.Error())
		return
	}
	response.Success(w, nil)
}

func (s *Server) handleGetStreamRules(w http.ResponseWriter, r *http.Request) {
	rules := s.ProxyHandler.GetStreamRules()
	response.Success(w, rules)
}

func (s *Server) handleSetStreamRules(w http.ResponseWriter, r *http.Request) {
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		response.Error(w, errors.CodeReadBodyFailed, "Failed to read request body")
		return
	}
	r.Body.Close()

	type streamRuleRequest struct {
		Protocol   string `json:"protocol"`
		ListenPort int    `json:"listen_port"`
		Target     string `json:"target"`
		UseAuth    *bool  `json:"use_auth"`
	}

	var reqs []streamRuleRequest
	if err := json.Unmarshal(bodyBytes, &reqs); err != nil {
		response.Error(w, errors.CodeInvalidJSON, "Invalid JSON array: "+err.Error())
		return
	}

	nextRules := make([]models.StreamRule, 0, len(reqs))
	for _, req := range reqs {
		nextRules = append(nextRules, models.StreamRule{
			Protocol:   req.Protocol,
			ListenPort: req.ListenPort,
			Target:     req.Target,
			UseAuth:    req.UseAuth == nil || *req.UseAuth,
		})
	}

	normalizedRules, err := s.ProxyHandler.ValidateStreamRules(nextRules)
	if err != nil {
		response.Error(w, errors.CodeInvalidRule, fmt.Sprintf("Failed to set stream rules: %v", err))
		return
	}

	if s.StreamManager != nil {
		if err := s.StreamManager.Reconcile(normalizedRules); err != nil {
			response.Error(w, errors.CodeInvalidRule, fmt.Sprintf("Failed to reconcile stream listeners: %v", err))
			return
		}
	}

	if err := s.ProxyHandler.SetStreamRules(normalizedRules); err != nil {
		response.Error(w, errors.CodeInvalidRule, fmt.Sprintf("Failed to persist stream rules: %v", err))
		return
	}

	response.Success(w, s.ProxyHandler.GetStreamRules())
}

func (s *Server) handleFlushStreamRules(w http.ResponseWriter, r *http.Request) {
	if err := s.ProxyHandler.FlushStreamRules(); err != nil {
		response.Error(w, errors.CodeInternal, "Failed to flush stream rules: "+err.Error())
		return
	}
	if s.StreamManager != nil {
		if err := s.StreamManager.Reconcile(nil); err != nil {
			response.Error(w, errors.CodeInvalidRule, fmt.Sprintf("Failed to flush stream listeners: %v", err))
			return
		}
	}
	response.Success(w, nil)
}

// handleInfo returns server information
// @Summary Get server info
// @Description Get version and other server info
// @Tags info
// @Produce  json
// @Success 200 {object} response.Response{data=ServerInfo}
// @Router /api/info [get]
func (s *Server) handleInfo(w http.ResponseWriter, r *http.Request) {
	response.Success(w, ServerInfo{
		Version: version.Version,
	})
}

// handleTraffic returns proxy traffic stats
// @Summary Get traffic stats
// @Description Get proxy traffic stats (bytes in/out, active logged-in users in last 2 minutes, and 5xx count)
// @Tags traffic
// @Produce  json
// @Success 200 {object} response.Response{data=proxy.TrafficStats}
// @Router /api/traffic [get]
func (s *Server) handleTraffic(w http.ResponseWriter, r *http.Request) {
	response.Success(w, s.ProxyHandler.GetTrafficStats(time.Now()))
}

// handleTrafficActiveIPs returns recently active client IPs for one host mapping
// @Summary Get active IPs for host traffic
// @Description Get recently active client IPs for one proxy host mapping
// @Tags traffic
// @Produce  json
// @Param host query string true "Host mapping"
// @Success 200 {object} response.Response{data=proxy.HostActiveIPsStats}
// @Failure 400 {object} response.Response
// @Router /api/traffic/active-ips [get]
func (s *Server) handleTrafficActiveIPs(w http.ResponseWriter, r *http.Request) {
	host := strings.TrimSpace(r.URL.Query().Get("host"))
	if host == "" {
		response.Error(w, errors.CodeBadRequest, "host is required")
		return
	}
	response.Success(w, s.ProxyHandler.GetHostActiveIPs(host, time.Now()))
}

type generalBlacklistRequest struct {
	IPs     []string `json:"ips"`
	Source  string   `json:"source,omitempty"`
	Comment string   `json:"comment,omitempty"`
}

func (s *Server) handleListGeneralBlacklist(w http.ResponseWriter, r *http.Request) {
	page := 1
	if raw := strings.TrimSpace(r.URL.Query().Get("page")); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value <= 0 {
			response.Error(w, errors.CodeBadRequest, "page must be a positive integer")
			return
		}
		page = value
	}

	limit := 20
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value <= 0 {
			response.Error(w, errors.CodeBadRequest, "limit must be a positive integer")
			return
		}
		limit = value
	}

	response.Success(w, s.ProxyHandler.ListGeneralBlacklist(page, limit, r.URL.Query().Get("search")))
}

func (s *Server) handleGeneralBlacklistStatus(w http.ResponseWriter, r *http.Request) {
	var req generalBlacklistRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, errors.CodeInvalidJSON, "Invalid JSON object")
		return
	}

	result, err := s.ProxyHandler.CheckGeneralBlacklist(req.IPs)
	if err != nil {
		response.Error(w, errors.CodeBadRequest, err.Error())
		return
	}
	response.Success(w, result)
}

func (s *Server) handleAddGeneralBlacklist(w http.ResponseWriter, r *http.Request) {
	var req generalBlacklistRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, errors.CodeInvalidJSON, "Invalid JSON object")
		return
	}

	result, err := s.ProxyHandler.AddGeneralBlacklist(req.IPs, req.Source, req.Comment)
	if err != nil {
		response.Error(w, errors.CodeBadRequest, err.Error())
		return
	}
	response.Success(w, result)
}

func (s *Server) handleDeleteGeneralBlacklist(w http.ResponseWriter, r *http.Request) {
	var req generalBlacklistRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, errors.CodeInvalidJSON, "Invalid JSON object")
		return
	}

	result, err := s.ProxyHandler.RemoveGeneralBlacklist(req.IPs)
	if err != nil {
		response.Error(w, errors.CodeBadRequest, err.Error())
		return
	}
	response.Success(w, result)
}

func (s *Server) handleDeleteGeneralBlacklistIP(w http.ResponseWriter, r *http.Request) {
	ip := mux.Vars(r)["ip"]
	result, err := s.ProxyHandler.RemoveGeneralBlacklist([]string{ip})
	if err != nil {
		response.Error(w, errors.CodeBadRequest, err.Error())
		return
	}
	response.Success(w, result)
}

// handleGetDefaultRoute gets the default route
// @Summary Get default route
// @Description Get the configured default route when root route is requested
// @Tags config
// @Produce  json
// @Success 200 {object} response.Response{data=string}
// @Router /api/config/default-route [get]
func (s *Server) handleGetDefaultRoute(w http.ResponseWriter, r *http.Request) {
	route := s.ProxyHandler.GetDefaultRoute()
	response.Success(w, route)
}

// handleSetDefaultRoute sets the default route
// @Summary Set default route
// @Description Set the configured default route when root route is requested
// @Tags config
// @Accept  json
// @Produce  json
// @Param rule body string true "Route configuration, example: {\"default_route\": \"/test\"}"
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Router /api/config/default-route [post]
func (s *Server) handleSetDefaultRoute(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DefaultRoute string `json:"default_route"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, errors.CodeInvalidJSON, "Invalid JSON object")
		return
	}

	if req.DefaultRoute == "" {
		response.Error(w, errors.CodeBadRequest, "default_route is required")
		return
	}

	if err := s.ProxyHandler.SetDefaultRoute(req.DefaultRoute); err != nil {
		response.Error(w, errors.CodeInternal, "Failed to set default route: "+err.Error())
		return
	}
	response.Success(w, nil)
}

type proxyProtocolForceResponse struct {
	ProxyProtocolForce bool `json:"proxy_protocol_force" example:"false"`
}

type proxyProtocolForceRequest struct {
	ProxyProtocolForce bool `json:"proxy_protocol_force" example:"true"`
}

type reverseProxyThrottleResponse = models.ReverseProxyThrottleConfig

// handleGetProxyProtocolForce gets the current proxy protocol policy
// @Summary Get proxy protocol force
// @Description Get whether the proxy port requires Proxy Protocol header
// @Tags config
// @Produce  json
// @Success 200 {object} response.Response{data=proxyProtocolForceResponse}
// @Router /api/config/proxy-protocol [get]
func (s *Server) handleGetProxyProtocolForce(w http.ResponseWriter, r *http.Request) {
	if s.ConfigManager == nil {
		response.Error(w, errors.CodeInternal, "Config manager not initialized")
		return
	}
	cfg, err := s.ConfigManager.Load()
	if err != nil {
		response.Error(w, errors.CodeInternal, "Failed to load config: "+err.Error())
		return
	}
	response.Success(w, proxyProtocolForceResponse{ProxyProtocolForce: cfg.ProxyProtocolForce})
}

// handleSetProxyProtocolForce sets whether the proxy port requires Proxy Protocol header
// @Summary Set proxy protocol force
// @Description Enable or disable requiring Proxy Protocol header on proxy port
// @Tags config
// @Accept  json
// @Produce  json
// @Param request body proxyProtocolForceRequest true "Proxy protocol options"
// @Success 200 {object} response.Response{data=proxyProtocolForceResponse}
// @Failure 400 {object} response.Response
// @Router /api/config/proxy-protocol [post]
func (s *Server) handleSetProxyProtocolForce(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProxyProtocolForce *bool `json:"proxy_protocol_force"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, errors.CodeInvalidJSON, "Invalid JSON object")
		return
	}
	if req.ProxyProtocolForce == nil {
		response.Error(w, errors.CodeBadRequest, "proxy_protocol_force is required")
		return
	}

	if err := s.ProxyHandler.SetProxyProtocolForce(*req.ProxyProtocolForce); err != nil {
		response.Error(w, errors.CodeInternal, "Failed to set proxy protocol force: "+err.Error())
		return
	}
	response.Success(w, proxyProtocolForceResponse{ProxyProtocolForce: *req.ProxyProtocolForce})
}

func (s *Server) handleGetLocaleConfig(w http.ResponseWriter, r *http.Request) {
	if s.ConfigManager == nil {
		response.Error(w, errors.CodeInternal, "Config manager not initialized")
		return
	}

	cfg, err := s.ConfigManager.Load()
	if err != nil {
		response.Error(w, errors.CodeInternal, "Failed to load config: "+err.Error())
		return
	}

	normalized := i18n.NormalizeConfig(i18n.LocaleConfig{DefaultLocale: cfg.Locale.DefaultLocale})
	response.Success(w, models.LocaleConfig{DefaultLocale: normalized.DefaultLocale})
}

func (s *Server) handleSetLocaleConfig(w http.ResponseWriter, r *http.Request) {
	if s.ConfigManager == nil {
		response.Error(w, errors.CodeInternal, "Config manager not initialized")
		return
	}

	var req models.LocaleConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, errors.CodeInvalidJSON, "Invalid JSON object")
		return
	}

	normalized := i18n.NormalizeConfig(i18n.LocaleConfig{DefaultLocale: req.DefaultLocale})
	if err := s.ConfigManager.Update(func(cfg *config.AppConfig) error {
		cfg.Locale.DefaultLocale = normalized.DefaultLocale
		return nil
	}); err != nil {
		response.Error(w, errors.CodeInternal, "Failed to save config: "+err.Error())
		return
	}

	i18n.SetDefaultLocale(normalized.DefaultLocale)
	response.Success(w, models.LocaleConfig{DefaultLocale: normalized.DefaultLocale})
}

func (s *Server) handleGetReverseProxyThrottle(w http.ResponseWriter, r *http.Request) {
	response.Success(w, s.ProxyHandler.GetReverseProxyThrottle())
}

func (s *Server) handleSetReverseProxyThrottle(w http.ResponseWriter, r *http.Request) {
	var req reverseProxyThrottleResponse
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, errors.CodeInvalidJSON, "Invalid JSON object")
		return
	}
	if err := s.ProxyHandler.SetReverseProxyThrottle(req); err != nil {
		response.Error(w, errors.CodeInternal, "Failed to set reverse proxy throttle: "+err.Error())
		return
	}
	response.Success(w, s.ProxyHandler.GetReverseProxyThrottle())
}

func (s *Server) handleGetGatewayVisibility(w http.ResponseWriter, r *http.Request) {
	response.Success(w, s.ProxyHandler.GetGatewayVisibility())
}

func (s *Server) handleSetGatewayVisibility(w http.ResponseWriter, r *http.Request) {
	var req models.GatewayVisibilityConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, errors.CodeInvalidJSON, "Invalid JSON object")
		return
	}

	if err := s.ProxyHandler.SetGatewayVisibility(req); err != nil {
		response.Error(w, errors.CodeBadRequest, err.Error())
		return
	}

	response.Success(w, s.ProxyHandler.GetGatewayVisibility())
}

// handleGetForwardedHeadersConfig gets the current forwarded-headers runtime config
// @Summary Get forwarded headers config
// @Description Get the current explicit forwarded-headers runtime configuration
// @Tags config
// @Produce  json
// @Success 200 {object} response.Response{data=models.ForwardedHeadersConfig}
// @Router /api/config/forwarded-headers [get]
func (s *Server) handleGetForwardedHeadersConfig(w http.ResponseWriter, r *http.Request) {
	response.Success(w, s.ProxyHandler.GetForwardedHeadersConfig())
}

// handleSetForwardedHeadersConfig sets the forwarded-headers runtime config
// @Summary Set forwarded headers config
// @Description Replace the explicit forwarded-headers runtime configuration
// @Tags config
// @Accept  json
// @Produce  json
// @Param request body models.ForwardedHeadersConfig true "Forwarded headers config"
// @Success 200 {object} response.Response{data=models.ForwardedHeadersConfig}
// @Failure 400 {object} response.Response
// @Router /api/config/forwarded-headers [post]
func (s *Server) handleSetForwardedHeadersConfig(w http.ResponseWriter, r *http.Request) {
	var req models.ForwardedHeadersConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, errors.CodeInvalidJSON, "Invalid JSON object")
		return
	}

	if err := s.ProxyHandler.SetForwardedHeadersConfig(req); err != nil {
		response.Error(w, errors.CodeInternal, "Failed to set forwarded headers config: "+err.Error())
		return
	}
	response.Success(w, s.ProxyHandler.GetForwardedHeadersConfig())
}

// handleGetPreserveHostConfig gets the current preserve-host runtime config
// @Summary Get preserve host config
// @Description Get the current explicit preserve-host runtime configuration
// @Tags config
// @Produce  json
// @Success 200 {object} response.Response{data=models.PreserveHostConfig}
// @Router /api/config/preserve-host [get]
func (s *Server) handleGetPreserveHostConfig(w http.ResponseWriter, r *http.Request) {
	response.Success(w, s.ProxyHandler.GetPreserveHostConfig())
}

// handleSetPreserveHostConfig sets the preserve-host runtime config
// @Summary Set preserve host config
// @Description Replace the explicit preserve-host runtime configuration
// @Tags config
// @Accept  json
// @Produce  json
// @Param request body models.PreserveHostConfig true "Preserve host config"
// @Success 200 {object} response.Response{data=models.PreserveHostConfig}
// @Failure 400 {object} response.Response
// @Router /api/config/preserve-host [post]
func (s *Server) handleSetPreserveHostConfig(w http.ResponseWriter, r *http.Request) {
	var req models.PreserveHostConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, errors.CodeInvalidJSON, "Invalid JSON object")
		return
	}

	if err := s.ProxyHandler.SetPreserveHostConfig(req); err != nil {
		response.Error(w, errors.CodeInternal, "Failed to set preserve host config: "+err.Error())
		return
	}
	response.Success(w, s.ProxyHandler.GetPreserveHostConfig())
}

// handleGetCrawlerBlockerConfig gets the current crawler-blocker runtime config
// @Summary Get crawler blocker config
// @Description Get the current crawler-blocker runtime configuration
// @Tags config
// @Produce  json
// @Success 200 {object} response.Response{data=models.CrawlerBlockerConfig}
// @Router /api/config/crawler-blocker [get]
func (s *Server) handleGetCrawlerBlockerConfig(w http.ResponseWriter, r *http.Request) {
	response.Success(w, s.ProxyHandler.GetCrawlerBlockerConfig())
}

// handleSetCrawlerBlockerConfig sets the crawler-blocker runtime config
// @Summary Set crawler blocker config
// @Description Replace the crawler-blocker runtime configuration
// @Tags config
// @Accept  json
// @Produce  json
// @Param request body models.CrawlerBlockerConfig true "Crawler blocker config"
// @Success 200 {object} response.Response{data=models.CrawlerBlockerConfig}
// @Failure 400 {object} response.Response
// @Router /api/config/crawler-blocker [post]
func (s *Server) handleSetCrawlerBlockerConfig(w http.ResponseWriter, r *http.Request) {
	var req models.CrawlerBlockerConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, errors.CodeInvalidJSON, "Invalid JSON object")
		return
	}

	cfg, err := s.ProxyHandler.SetCrawlerBlockerConfig(req)
	if err != nil {
		response.Error(w, errors.CodeInternal, "Failed to set crawler blocker config: "+err.Error())
		return
	}
	response.Success(w, cfg)
}

func (s *Server) handleGetGatewayPortalConfig(w http.ResponseWriter, r *http.Request) {
	response.Success(w, s.ProxyHandler.GetGatewayPortalConfig())
}

func (s *Server) handleSetGatewayPortalConfig(w http.ResponseWriter, r *http.Request) {
	var req models.GatewayPortalConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, errors.CodeInvalidJSON, "Invalid JSON object")
		return
	}

	cfg, err := s.ProxyHandler.SetGatewayPortalConfig(req)
	if err != nil {
		response.Error(w, errors.CodeInternal, "Failed to set gateway portal config: "+err.Error())
		return
	}
	response.Success(w, cfg)
}

func (s *Server) handleGetFnosPortIconHijackConfig(w http.ResponseWriter, r *http.Request) {
	response.Success(w, s.ProxyHandler.GetFnosPortIconHijackConfig())
}

func (s *Server) handleSetFnosPortIconHijackConfig(w http.ResponseWriter, r *http.Request) {
	var req models.FnosPortIconHijackConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, errors.CodeInvalidJSON, "Invalid JSON object")
		return
	}

	cfg, err := s.ProxyHandler.SetFnosPortIconHijackConfig(req)
	if err != nil {
		response.Error(w, errors.CodeInternal, "Failed to set FNOS port icon hijack config: "+err.Error())
		return
	}
	response.Success(w, cfg)
}

func (s *Server) handleGetReverseProxyThrottleExemptIPs(w http.ResponseWriter, r *http.Request) {
	response.Success(w, s.ProxyHandler.GetReverseProxyThrottleExemptIPs())
}

func (s *Server) handleSetReverseProxyThrottleExemptIPs(w http.ResponseWriter, r *http.Request) {
	var req reverseProxyThrottleExemptIPsRuntimeResponse
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, errors.CodeInvalidJSON, "Invalid JSON object")
		return
	}

	s.ProxyHandler.SetReverseProxyThrottleExemptIPs(req)
	response.Success(w, s.ProxyHandler.GetReverseProxyThrottleExemptIPs())
}

func (s *Server) handleGetCommonLocationExemptions(w http.ResponseWriter, r *http.Request) {
	response.Success(w, s.ProxyHandler.GetCommonLocationExemptions())
}

func (s *Server) handleSetCommonLocationExemptions(w http.ResponseWriter, r *http.Request) {
	var req commonLocationExemptionsRuntimeResponse
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, errors.CodeInvalidJSON, "Invalid JSON object")
		return
	}

	s.ProxyHandler.SetCommonLocationExemptions(req)
	response.Success(w, s.ProxyHandler.GetCommonLocationExemptions())
}

// handleGetAuth gets the global auth configuration (port and relative urls)
// @Summary Get global auth config
// @Description Get the configured global authentication URLs and port
// @Tags config
// @Produce  json
// @Success 200 {object} response.Response{data=models.AuthConfig}
// @Router /api/auth [get]
func (s *Server) handleGetAuth(w http.ResponseWriter, r *http.Request) {
	config := s.ProxyHandler.GetAuthConfig()
	response.Success(w, config)
}

func mergeAuthConfig(current models.AuthConfig, patch authConfigPatch) (models.AuthConfig, error) {
	merged := current

	if patch.EdgeClientIPEnabled != nil && !*patch.EdgeClientIPEnabled {
		if patch.AliyunESAEnabled != nil && *patch.AliyunESAEnabled {
			return models.AuthConfig{}, fmt.Errorf("edge_client_ip_enabled=false conflicts with aliyun_esa_enabled=true")
		}
		if patch.TencentEdgeOneEnabled != nil && *patch.TencentEdgeOneEnabled {
			return models.AuthConfig{}, fmt.Errorf("edge_client_ip_enabled=false conflicts with tencent_edgeone_enabled=true")
		}
	}
	if patch.AliyunESAEnabled != nil && *patch.AliyunESAEnabled && patch.TencentEdgeOneEnabled != nil && *patch.TencentEdgeOneEnabled {
		return models.AuthConfig{}, fmt.Errorf("aliyun_esa_enabled and tencent_edgeone_enabled cannot both be true")
	}

	if patch.AuthPort != nil {
		merged.AuthPort = *patch.AuthPort
	}
	if patch.AuthURL != nil {
		merged.AuthURL = *patch.AuthURL
	}
	if patch.LoginURL != nil {
		merged.LoginURL = *patch.LoginURL
	}
	if patch.LogoutURL != nil {
		merged.LogoutURL = *patch.LogoutURL
	}
	if patch.PreflightURL != nil {
		merged.PreflightURL = *patch.PreflightURL
	}
	if patch.AuthCacheTTL != nil {
		merged.AuthCacheTTL = *patch.AuthCacheTTL
	}
	if patch.AuthCacheFailTTL != nil {
		merged.AuthCacheFailTTL = *patch.AuthCacheFailTTL
	}
	if patch.EdgeClientIPEnabled != nil {
		merged.EdgeClientIPEnabled = *patch.EdgeClientIPEnabled
		if !*patch.EdgeClientIPEnabled {
			merged.AliyunESAEnabled = false
			merged.TencentEdgeOneEnabled = false
		}
	}
	if patch.AliyunESAEnabled != nil {
		merged.AliyunESAEnabled = *patch.AliyunESAEnabled
		if *patch.AliyunESAEnabled {
			merged.EdgeClientIPEnabled = true
			merged.TencentEdgeOneEnabled = false
		}
	}
	if patch.TencentEdgeOneEnabled != nil {
		merged.TencentEdgeOneEnabled = *patch.TencentEdgeOneEnabled
		if *patch.TencentEdgeOneEnabled {
			merged.EdgeClientIPEnabled = true
			merged.AliyunESAEnabled = false
		}
	}
	if patch.PublicAuthBaseURL != nil {
		merged.PublicAuthBaseURL = *patch.PublicAuthBaseURL
	}
	if patch.PublicHTTPPort != nil {
		merged.PublicHTTPPort = *patch.PublicHTTPPort
	}
	if patch.PublicHTTPSPort != nil {
		merged.PublicHTTPSPort = *patch.PublicHTTPSPort
	}
	if patch.AuthHost != nil {
		merged.AuthHost = *patch.AuthHost
	}
	if patch.TrustForwardedProto != nil {
		merged.TrustForwardedProto = *patch.TrustForwardedProto
	}

	merged.NormalizeEdgeClientIPSelection()
	return merged, nil
}

// handleSetAuth sets the global auth configuration
// @Summary Set global auth config
// @Description Set the global authentication configurations (port, auth_url, login_url)
// @Tags config
// @Accept  json
// @Produce  json
// @Param config body models.AuthConfig true "Auth configuration"
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Router /api/auth [post]
func (s *Server) handleSetAuth(w http.ResponseWriter, r *http.Request) {
	var req authConfigPatch
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, errors.CodeInvalidJSON, "Invalid JSON object")
		return
	}

	nextConfig, err := mergeAuthConfig(s.ProxyHandler.GetAuthConfig(), req)
	if err != nil {
		response.Error(w, errors.CodeBadRequest, err.Error())
		return
	}
	if err := s.ProxyHandler.SetAuthConfig(nextConfig); err != nil {
		response.Error(w, errors.CodeBadRequest, err.Error())
		return
	}
	response.Success(w, nil)
}

func (s *Server) handleGetLoggingConfig(w http.ResponseWriter, r *http.Request) {
	response.Success(w, s.ProxyHandler.GetLoggingConfig())
}

func (s *Server) handleSetLoggingConfig(w http.ResponseWriter, r *http.Request) {
	var req models.LoggingConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, errors.CodeInvalidJSON, "Invalid JSON object")
		return
	}
	if req.MaxDays < 0 {
		response.Error(w, errors.CodeBadRequest, "max_days must be greater than 0")
		return
	}

	cfg, err := s.ProxyHandler.SetLoggingConfig(req)
	if err != nil {
		response.Error(w, errors.CodeInternal, "Failed to set logging config: "+err.Error())
		return
	}
	response.Success(w, cfg)
}

func (s *Server) handleGetLoggingDirectory(w http.ResponseWriter, r *http.Request) {
	response.Success(w, s.ProxyHandler.GetLoggingDirectory())
}

func (s *Server) handleGetWAFStatus(w http.ResponseWriter, r *http.Request) {
	response.Success(w, s.ProxyHandler.GetWAFStatus())
}

func (s *Server) handleSetWAFConfig(w http.ResponseWriter, r *http.Request) {
	var req models.WAFConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, errors.CodeInvalidJSON, "Invalid JSON object")
		return
	}
	status, err := s.ProxyHandler.SetWAFConfig(req)
	if err != nil {
		response.Error(w, errors.CodeBadRequest, err.Error())
		return
	}
	response.Success(w, status)
}

type wafBundleRequest struct {
	BundleID   string            `json:"bundle_id"`
	BundlePath string            `json:"bundle_path"`
	Config     *models.WAFConfig `json:"config,omitempty"`
}

func (s *Server) handleValidateWAFBundle(w http.ResponseWriter, r *http.Request) {
	var req wafBundleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, errors.CodeInvalidJSON, "Invalid JSON object")
		return
	}
	cfg := s.ProxyHandler.GetWAFConfig()
	if req.Config != nil {
		cfg = *req.Config
	}
	result, err := s.ProxyHandler.ValidateWAFBundle(cfg, req.BundleID, req.BundlePath)
	if err != nil {
		response.JSON(w, false, errors.CodeBadRequest, result.Error, result)
		return
	}
	response.Success(w, result)
}

func (s *Server) handleReloadWAFBundle(w http.ResponseWriter, r *http.Request) {
	var req wafBundleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, errors.CodeInvalidJSON, "Invalid JSON object")
		return
	}
	cfg := s.ProxyHandler.GetWAFConfig()
	if req.Config != nil {
		cfg = *req.Config
	}
	if strings.TrimSpace(req.BundleID) == "" {
		req.BundleID = cfg.ActiveBundleID
	}
	status, err := s.ProxyHandler.ReloadWAFBundle(cfg, req.BundleID, req.BundlePath)
	if err != nil {
		response.Error(w, errors.CodeBadRequest, err.Error())
		return
	}
	response.Success(w, status)
}

func (s *Server) handleDrainWAFEvents(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Limit int `json:"limit"`
	}
	if r.Body != nil {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err != io.EOF {
			response.Error(w, errors.CodeInvalidJSON, "Invalid JSON object")
			return
		}
	}
	if req.Limit <= 0 {
		req.Limit = 500
	}
	if req.Limit > 5000 {
		req.Limit = 5000
	}
	response.Success(w, s.ProxyHandler.DrainWAFEvents(req.Limit))
}

func (s *Server) handleGetLoggingDates(w http.ResponseWriter, r *http.Request) {
	result, err := s.ProxyHandler.GetLogDates()
	if err != nil {
		response.Error(w, errors.CodeInternal, "Failed to list log dates: "+err.Error())
		return
	}
	response.Success(w, result)
}

func (s *Server) handleGetLoggingEntries(w http.ResponseWriter, r *http.Request) {
	pagination := strings.TrimSpace(r.URL.Query().Get("pagination"))
	paginationMode := "page"
	if strings.EqualFold(pagination, "cursor") {
		paginationMode = "cursor"
	}
	page := 1
	if paginationMode == "page" {
		if raw := strings.TrimSpace(r.URL.Query().Get("page")); raw != "" {
			value, err := strconv.Atoi(raw)
			if err != nil || value <= 0 {
				response.Error(w, errors.CodeBadRequest, "page must be a positive integer")
				return
			}
			page = value
		}
	} else if pagination != "" && !strings.EqualFold(pagination, "cursor") {
		response.Error(w, errors.CodeBadRequest, "pagination must be 'page' or 'cursor'")
		return
	}

	limit := 20
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value <= 0 {
			response.Error(w, errors.CodeBadRequest, "limit must be a positive integer")
			return
		}
		limit = value
	}

	result, err := s.ProxyHandler.QueryLogEntries(
		r.URL.Query().Get("date"),
		page,
		limit,
		r.URL.Query().Get("search"),
		r.URL.Query().Get("status"),
		r.URL.Query().Get("logged_in"),
		r.URL.Query().Get("credential"),
		r.URL.Query().Get("cursor"),
		paginationMode,
	)
	if err != nil {
		response.Error(w, errors.CodeBadRequest, err.Error())
		return
	}
	response.Success(w, result)
}

func (s *Server) handleDeleteLoggingEntries(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Date string `json:"date"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, errors.CodeInvalidJSON, "Invalid JSON object")
		return
	}

	result, err := s.ProxyHandler.DeleteLogDate(req.Date)
	if err != nil {
		response.Error(w, errors.CodeBadRequest, err.Error())
		return
	}
	response.Success(w, result)
}

// handleGetSSL gets the current SSL status
// @Summary Get SSL status
// @Description Check if dynamic SSL is currently enabled and configured on the proxy port
// @Tags ssl
// @Produce  json
// @Success 200 {object} response.Response{data=models.SSLInfo}
// @Router /api/ssl [get]
func (s *Server) handleGetSSL(w http.ResponseWriter, r *http.Request) {
	response.Success(w, s.ProxyHandler.GetSSLInfo())
}

// handleSetSSL sets the dynamic SSL certificate
// @Summary Set SSL certificate
// @Description Upload a legacy PEM certificate/key pair or a deployed SSL bundle to enable HTTPS on the proxy port
// @Tags ssl
// @Accept  json
// @Produce  json
// @Param ssl body models.SSLDeploymentRequest true "SSL deployment payload"
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Router /api/ssl [post]
func (s *Server) handleSetSSL(w http.ResponseWriter, r *http.Request) {
	var req models.SSLDeploymentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, errors.CodeInvalidJSON, "Invalid JSON object")
		return
	}

	if strings.TrimSpace(req.Cert) != "" || strings.TrimSpace(req.Key) != "" {
		if len(req.Certificates) > 0 || req.DeploymentMode != "" {
			response.Error(w, errors.CodeBadRequest, "cert/key mode cannot be mixed with deployment_mode/certificates")
			return
		}
		if err := s.ProxyHandler.SetSSLCertificatePEM(req.Cert, req.Key); err != nil {
			response.Error(w, errors.CodeBadRequest, fmt.Sprintf("Invalid certificate or key: %v", err))
			return
		}
		response.Success(w, nil)
		return
	}

	if err := s.ProxyHandler.SetSSLDeployment(models.SSLConfig{
		DeploymentMode: req.DeploymentMode,
		Certificates:   req.Certificates,
	}); err != nil {
		response.Error(w, errors.CodeBadRequest, err.Error())
		return
	}
	response.Success(w, nil)
}

// handleClearSSL clears the dynamic SSL certificate
// @Summary Clear SSL certificate
// @Description Clear the configured SSL certificate and disable HTTPS on the proxy port
// @Tags ssl
// @Produce  json
// @Success 200 {object} response.Response
// @Router /api/ssl [delete]
func (s *Server) handleClearSSL(w http.ResponseWriter, r *http.Request) {
	if err := s.ProxyHandler.ClearSSLCertificate(); err != nil {
		response.Error(w, errors.CodeInternal, "Failed to clear SSL certificate: "+err.Error())
		return
	}
	response.Success(w, nil)
}
