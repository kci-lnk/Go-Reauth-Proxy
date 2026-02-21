package iptables

import (
	"encoding/json"
	"go-reauth-proxy/pkg/errors"
	"go-reauth-proxy/pkg/response"
	"io"
	"net/http"
)

type Handler struct {
	Manager *Manager
}

func NewHandler(manager *Manager) *Handler {
	return &Handler{
		Manager: manager,
	}
}

type initRequest struct {
	ChainName   string      `json:"chain_name"`
	ParentChain interface{} `json:"parent_chain"` // string or []string
	ExemptPorts []string    `json:"exempt_ports"`
}

// HandleInit initializes the iptables chain
// @Summary Initialize iptables
// @Description Initialize the custom iptables chain
// @Tags iptables
// @Accept  json
// @Produce  json
// @Param request body initRequest false "Initialization options"
// @Success 200 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/iptables/init [post]
func (h *Handler) HandleInit(w http.ResponseWriter, r *http.Request) {
	bodyBytes, err := io.ReadAll(r.Body)
	if err == nil && len(bodyBytes) > 0 {
		var req initRequest
		if err := json.Unmarshal(bodyBytes, &req); err == nil {
			if req.ChainName != "" {
				h.Manager.Chain = req.ChainName
			}
			if req.ParentChain != nil {
				switch v := req.ParentChain.(type) {
				case string:
					h.Manager.ParentChains = []string{v}
				case []interface{}: // JSON arrays come as []interface{}
					var parents []string
					for _, item := range v {
						if s, ok := item.(string); ok {
							parents = append(parents, s)
						}
					}
					h.Manager.ParentChains = parents
				}
			}
			if len(req.ExemptPorts) > 0 {
				h.Manager.ExemptPorts = req.ExemptPorts
			}
		}
	}
	r.Body.Close()

	if err := h.Manager.Init(); err != nil {
		handleError(w, err)
		return
	}
	response.Success(w, nil)
}

// HandleClean cleans and destroys the chain
// @Summary Clean iptables
// @Description Remove the custom iptables chain
// @Tags iptables
// @Produce  json
// @Success 200 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/iptables/clean [post]
func (h *Handler) HandleClean(w http.ResponseWriter, r *http.Request) {
	if err := h.Manager.Destroy(); err != nil {
		handleError(w, err)
		return
	}
	response.Success(w, nil)
}

// HandleFlush flushes the chain rules
// @Summary Flush iptables rules
// @Description Flush all rules in the custom chain
// @Tags iptables
// @Produce  json
// @Success 200 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/iptables/flush [post]
func (h *Handler) HandleFlush(w http.ResponseWriter, r *http.Request) {
	if err := h.Manager.Flush(); err != nil {
		handleError(w, err)
		return
	}
	response.Success(w, nil)
}

// ipRequest structure for IP operations
type ipRequest struct {
	IP string `json:"ip" example:"192.168.1.100"`
}

// HandleAllowIP adds an ALLOW rule for an IP
// @Summary Allow IP
// @Description Add an ALLOW rule for a specific IP
// @Tags iptables
// @Accept  json
// @Produce  json
// @Param request body ipRequest true "IP to allow"
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/iptables/allow [post]
func (h *Handler) HandleAllowIP(w http.ResponseWriter, r *http.Request) {
	var req ipRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, errors.CodeInvalidJSON, "Invalid JSON body")
		return
	}
	if req.IP == "" {
		response.Error(w, errors.CodeBadRequest, "IP is required")
		return
	}

	if err := h.Manager.AllowIP(req.IP); err != nil {
		handleError(w, err)
		return
	}
	response.Success(w, nil)
}

// HandleBlockIP adds a DROP rule for an IP
// @Summary Block IP
// @Description Add a DROP rule for a specific IP
// @Tags iptables
// @Accept  json
// @Produce  json
// @Param request body ipRequest true "IP to block"
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/iptables/block [post]
func (h *Handler) HandleBlockIP(w http.ResponseWriter, r *http.Request) {
	var req ipRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, errors.CodeInvalidJSON, "Invalid JSON body")
		return
	}
	if req.IP == "" {
		response.Error(w, errors.CodeBadRequest, "IP is required")
		return
	}

	if err := h.Manager.BlockIP(req.IP); err != nil {
		handleError(w, err)
		return
	}
	response.Success(w, nil)
}

// HandleBlockAll blocks all traffic (adds DROP at end)
// @Summary Block all traffic
// @Description Add a catch-all DROP rule at the end of the chain
// @Tags iptables
// @Produce  json
// @Success 200 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/iptables/block-all [post]
func (h *Handler) HandleBlockAll(w http.ResponseWriter, r *http.Request) {
	if err := h.Manager.BlockAll(); err != nil {
		handleError(w, err)
		return
	}
	response.Success(w, nil)
}

// HandleAllowAll allows all traffic (removes DROP at end)
// @Summary Allow all traffic
// @Description Remove the catch-all DROP rule
// @Tags iptables
// @Produce  json
// @Success 200 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/iptables/allow-all [post]
func (h *Handler) HandleAllowAll(w http.ResponseWriter, r *http.Request) {
	if err := h.Manager.AllowAll(); err != nil {
		handleError(w, err)
		return
	}
	response.Success(w, nil)
}

// HandleList lists all rules
// @Summary List iptables rules
// @Description List all rules in the custom chain
// @Tags iptables
// @Produce  json
// @Success 200 {object} response.Response{data=[]string}
// @Failure 500 {object} response.Response
// @Router /api/iptables/list [get]
func (h *Handler) HandleList(w http.ResponseWriter, r *http.Request) {
	rules, err := h.Manager.ParseRules()
	if err != nil {
		handleError(w, err)
		return
	}
	response.Success(w, rules)
}

func handleError(w http.ResponseWriter, err error) {
	if customErr, ok := err.(*errors.CustomError); ok {
		response.Error(w, customErr.Code, customErr.Message)
	} else {
		response.Error(w, errors.CodeInternal, err.Error())
	}
}
