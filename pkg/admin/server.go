package admin

import (
	"bytes"
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
	r.HandleFunc("/api/rules/delete", s.handleRemoveRule).Methods("POST")
	r.HandleFunc("/api/flush", s.handleFlushRules).Methods("POST")
	r.HandleFunc("/api/info", s.handleInfo).Methods("GET")
	r.HandleFunc("/api/config/default-route", s.handleGetDefaultRoute).Methods("GET")
	r.HandleFunc("/api/config/default-route", s.handleSetDefaultRoute).Methods("POST")

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

// handleAddRule adds one or more proxy rules
// @Summary Add rules
// @Description Add one or more proxy rules
// @Tags rules
// @Accept  json
// @Produce  json
// @Param rules body []models.Rule true "List of rules to add"
// @Success 200 {object} response.Response{data=[]models.Rule}
// @Failure 400 {object} response.ErrorResponse
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
		AuthURL     string `json:"auth_url"`
		LoginURL    string `json:"login_url"`
		StripPath   *bool  `json:"strip_path"`
		RewriteHTML *bool  `json:"rewrite_html"`
		UseRootMode *bool  `json:"use_root_mode"`
	}

	var reqs []ruleRequest

	trimmedBody := bytes.TrimSpace(bodyBytes)
	if len(trimmedBody) > 0 && trimmedBody[0] == '[' {
		// Array
		if err := json.Unmarshal(bodyBytes, &reqs); err != nil {
			response.Error(w, errors.CodeInvalidJSON, "Invalid JSON array: "+err.Error())
			return
		}
	} else {
		// Single Object
		var singleReq ruleRequest
		if err := json.Unmarshal(bodyBytes, &singleReq); err != nil {
			response.Error(w, errors.CodeInvalidJSON, "Invalid JSON object: "+err.Error())
			return
		}
		reqs = append(reqs, singleReq)
	}

	var addedRules []models.Rule
	for _, req := range reqs {
		if req.Path == "" || req.Target == "" {
			response.Error(w, errors.CodeInvalidRule, fmt.Sprintf("Path and Target are required for rule: %+v", req))
			return
		}
		if req.Path == "/" {
			response.Error(w, errors.CodeInvalidRule, "Cannot add rule for root path '/'")
			return
		}

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
			AuthURL:     req.AuthURL,
			LoginURL:    req.LoginURL,
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

	if len(addedRules) == 1 {
		if len(trimmedBody) > 0 && trimmedBody[0] == '{' {
			response.Success(w, addedRules[0])
		} else {
			response.Success(w, addedRules)
		}
	} else {
		response.Success(w, addedRules)
	}
}

// handleRemoveRule removes a proxy rule
// @Summary Remove a rule
// @Description Remove a proxy rule by path
// @Tags rules
// @Produce  json
// @Param path query string true "Path of the rule to remove"
// @Success 200 {object} response.Response
// @Failure 400 {object} response.ErrorResponse
// @Router /api/rules/delete [post]
func (s *Server) handleRemoveRule(w http.ResponseWriter, r *http.Request) {
	// For POST /api/rules/delete, we expect JSON body or query param?
	// User didn't specify, but query param is easier for migration.
	// But standard POST usually has body. Let's support both or just body.
	// Previous implementation used query param. Let's stick to query param for simplicity or check body.
	// Let's check body first for "path" field, then query param.

	path := r.URL.Query().Get("path")
	if path == "" {
		var body struct {
			Path string `json:"path"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err == nil {
			path = body.Path
		}
	}

	if path == "" {
		response.Error(w, errors.CodeBadRequest, "Path is required")
		return
	}

	s.ProxyHandler.RemoveRule(path)
	response.Success(w, nil)
}

// handleFlushRules clears all proxy rules
// @Summary Flush all rules
// @Description Remove all proxy rules
// @Tags rules
// @Produce  json
// @Success 200 {object} response.Response
// @Router /api/flush [post]
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
// @Failure 400 {object} response.ErrorResponse
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
