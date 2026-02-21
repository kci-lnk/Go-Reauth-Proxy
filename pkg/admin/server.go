package admin

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"go-reauth-proxy/pkg/errors"
	"go-reauth-proxy/pkg/iptables"
	"go-reauth-proxy/pkg/middleware"
	"go-reauth-proxy/pkg/models"
	"go-reauth-proxy/pkg/proxy"
	"go-reauth-proxy/pkg/response"
	"go-reauth-proxy/pkg/version"
	"io"
	"net/http"

	"github.com/gorilla/mux"
	httpSwagger "github.com/swaggo/http-swagger"
)

type Server struct {
	ProxyHandler    *proxy.Handler
	IptablesHandler *iptables.Handler
	Port            int
}

type ServerInfo struct {
	Version string `json:"version" example:"0.0.1"`
}

func NewServer(handler *proxy.Handler, port int) *Server {
	iptablesManager := iptables.NewManager(iptables.Options{
		ChainName:   "REAUTH_FW",
		ParentChain: []string{"INPUT", "DOCKER-USER"},
	})
	iptablesHandler := iptables.NewHandler(iptablesManager)

	return &Server{
		ProxyHandler:    handler,
		IptablesHandler: iptablesHandler,
		Port:            port,
	}
}

func (s *Server) Start() error {
	r := mux.NewRouter()

	r.HandleFunc("/api/rules", s.handleGetRules).Methods("GET")
	r.HandleFunc("/api/rules", s.handleAddRule).Methods("POST")
	r.HandleFunc("/api/rules", s.handleFlushRules).Methods("DELETE")
	r.HandleFunc("/api/info", s.handleInfo).Methods("GET")
	r.HandleFunc("/api/config/default-route", s.handleGetDefaultRoute).Methods("GET")
	r.HandleFunc("/api/config/default-route", s.handleSetDefaultRoute).Methods("POST")
	r.HandleFunc("/api/auth", s.handleGetAuth).Methods("GET")
	r.HandleFunc("/api/auth", s.handleSetAuth).Methods("POST")
	r.HandleFunc("/api/ssl", s.handleGetSSL).Methods("GET")
	r.HandleFunc("/api/ssl", s.handleSetSSL).Methods("POST")
	r.HandleFunc("/api/ssl", s.handleClearSSL).Methods("DELETE")

	r.HandleFunc("/docs", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/docs/index.html", http.StatusMovedPermanently)
	})
	r.PathPrefix("/docs/").Handler(httpSwagger.Handler(
		httpSwagger.URL("/docs/doc.json"), // The url pointing to API definition
		httpSwagger.DeepLinking(true),
		httpSwagger.DocExpansion("none"),
		httpSwagger.DomID("swagger-ui"),
	)).Methods("GET")

	r.HandleFunc("/api/iptables/init", s.IptablesHandler.HandleInit).Methods("POST")
	r.HandleFunc("/api/iptables/clean", s.IptablesHandler.HandleClean).Methods("POST")
	r.HandleFunc("/api/iptables/flush", s.IptablesHandler.HandleFlush).Methods("POST")
	r.HandleFunc("/api/iptables/allow", s.IptablesHandler.HandleAllowIP).Methods("POST")
	r.HandleFunc("/api/iptables/block", s.IptablesHandler.HandleBlockIP).Methods("POST")
	r.HandleFunc("/api/iptables/block-all", s.IptablesHandler.HandleBlockAll).Methods("POST")
	r.HandleFunc("/api/iptables/allow-all", s.IptablesHandler.HandleAllowAll).Methods("POST")
	r.HandleFunc("/api/iptables/list", s.IptablesHandler.HandleList).Methods("GET")

	addr := fmt.Sprintf("127.0.0.1:%d", s.Port)
	fmt.Printf("Admin Server listening on %s\n", addr)

	loggedRouter := middleware.Logger(middleware.CORS(r))

	r.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response.Error(w, errors.CodeNotFound, "Resource Not Found")
	})
	r.MethodNotAllowedHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response.Error(w, errors.CodeBadRequest, "Method Not Allowed")
	})

	return http.ListenAndServe(addr, loggedRouter)
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

	s.ProxyHandler.FlushRules()

	var addedRules []models.Rule
	for _, req := range reqs {
		stripPath := true
		if req.StripPath != nil {
			stripPath = *req.StripPath
		}

		rewriteHTML := true
		if req.RewriteHTML != nil {
			rewriteHTML = *req.RewriteHTML
		}

		rule := models.Rule{
			Path:        req.Path,
			Target:      req.Target,
			UseAuth:     req.UseAuth != nil && *req.UseAuth,
			StripPath:   stripPath,
			RewriteHTML: rewriteHTML,
			UseRootMode: req.UseRootMode != nil && *req.UseRootMode,
		}

		if err := s.ProxyHandler.AddRule(rule); err != nil {
			response.Error(w, errors.CodeInvalidRule, fmt.Sprintf("Failed to add rule: %v", err))
			return
		}
		addedRules = append(addedRules, rule)
	}

	response.Success(w, addedRules)
}

// handleFlushRules clears all proxy rules
// @Summary Flush all rules
// @Description Remove all proxy rules
// @Tags rules
// @Produce  json
// @Success 200 {object} response.Response
// @Router /api/rules [delete]
func (s *Server) handleFlushRules(w http.ResponseWriter, r *http.Request) {
	s.ProxyHandler.FlushRules()
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

	s.ProxyHandler.SetDefaultRoute(req.DefaultRoute)
	response.Success(w, nil)
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
	var req models.AuthConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, errors.CodeInvalidJSON, "Invalid JSON object")
		return
	}

	if err := s.ProxyHandler.SetAuthConfig(req); err != nil {
		response.Error(w, errors.CodeBadRequest, err.Error())
		return
	}
	response.Success(w, nil)
}

// handleGetSSL gets the current SSL status
// @Summary Get SSL status
// @Description Check if dynamic SSL is currently enabled and configured on the proxy port
// @Tags ssl
// @Produce  json
// @Success 200 {object} response.Response{data=models.SSLInfo}
// @Router /api/ssl [get]
func (s *Server) handleGetSSL(w http.ResponseWriter, r *http.Request) {
	cert := s.ProxyHandler.GetSSLCertificate()
	response.Success(w, models.SSLInfo{Enabled: cert != nil})
}

// handleSetSSL sets the dynamic SSL certificate
// @Summary Set SSL certificate
// @Description Upload a PEM encoded certificate and private key to enable HTTPS on the proxy port
// @Tags ssl
// @Accept  json
// @Produce  json
// @Param ssl body models.SSLRequest true "SSL Certificate and Key"
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Router /api/ssl [post]
func (s *Server) handleSetSSL(w http.ResponseWriter, r *http.Request) {
	var req models.SSLRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, errors.CodeInvalidJSON, "Invalid JSON object")
		return
	}

	cert, err := tls.X509KeyPair([]byte(req.Cert), []byte(req.Key))
	if err != nil {
		response.Error(w, errors.CodeBadRequest, fmt.Sprintf("Invalid certificate or key: %v", err))
		return
	}

	s.ProxyHandler.SetSSLCertificate(&cert)
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
	s.ProxyHandler.ClearSSLCertificate()
	response.Success(w, nil)
}
