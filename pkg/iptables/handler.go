package iptables

import (
	"encoding/json"
	"go-reauth-proxy/pkg/config"
	"go-reauth-proxy/pkg/errors"
	"go-reauth-proxy/pkg/response"
	"io"
	"net/http"
	"strconv"
	"strings"
)

type Handler struct {
	Manager       *Manager
	configManager *config.Manager
}

func NewHandler(manager *Manager, cfgManager *config.Manager) *Handler {
	return &Handler{
		Manager:       manager,
		configManager: cfgManager,
	}
}

type initRequest struct {
	ChainName   string      `json:"chain_name" example:"KNOCK_FW"`
	ParentChain interface{} `json:"parent_chain" swaggertype:"array,string" example:"INPUT,DOCKER-USER"` // string or []string
	ExemptPorts *PortList   `json:"exempt_ports" example:"7999,7999"`
}

type PortList []string

func (p *PortList) UnmarshalJSON(data []byte) error {
	var stringsValue []string
	if err := json.Unmarshal(data, &stringsValue); err == nil {
		ports := make([]string, 0, len(stringsValue))
		for _, s := range stringsValue {
			s = strings.TrimSpace(s)
			if s != "" {
				ports = append(ports, s)
			}
		}
		*p = ports
		return nil
	}

	var numbersValue []int
	if err := json.Unmarshal(data, &numbersValue); err == nil {
		ports := make([]string, 0, len(numbersValue))
		for _, n := range numbersValue {
			if n > 0 {
				ports = append(ports, strconv.Itoa(n))
			}
		}
		*p = ports
		return nil
	}

	var singleString string
	if err := json.Unmarshal(data, &singleString); err == nil {
		*p = splitCommaSeparated(singleString)
		return nil
	}

	return errors.New(errors.CodeInvalidJSON, "Invalid exempt_ports")
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
	var chainName string
	bodyBytes, err := io.ReadAll(r.Body)
	if err == nil && len(bodyBytes) > 0 {
		var req initRequest
		if err := json.Unmarshal(bodyBytes, &req); err == nil {
			if req.ChainName != "" {
				h.Manager.Chain = req.ChainName
				chainName = req.ChainName
			}
			if req.ParentChain != nil {
				if parents := parseParentChains(req.ParentChain); len(parents) > 0 {
					h.Manager.ParentChains = parents
				}
			}
			if req.ExemptPorts != nil {
				h.Manager.ExemptPorts = []string(*req.ExemptPorts)
			}
		}
	}
	r.Body.Close()

	if err := h.Manager.Init(); err != nil {
		handleError(w, err)
		return
	}

	if chainName != "" && h.configManager != nil {
		if err := h.configManager.Update(func(cfg *config.AppConfig) error {
			cfg.IptablesChainName = chainName
			return nil
		}); err != nil {
			handleError(w, errors.New(errors.CodeInternal, "Failed to save config: "+err.Error()))
			return
		}
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

// HandleRemoveIP removes an IP rule (ACCEPT/DROP) if exists
// @Summary Remove IP rule
// @Description Remove an ALLOW/BLOCK rule for a specific IP
// @Tags iptables
// @Accept  json
// @Produce  json
// @Param request body ipRequest true "IP to remove"
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/iptables/remove [post]
func (h *Handler) HandleRemoveIP(w http.ResponseWriter, r *http.Request) {
	var req ipRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, errors.CodeInvalidJSON, "Invalid JSON body")
		return
	}
	if req.IP == "" {
		response.Error(w, errors.CodeBadRequest, "IP is required")
		return
	}

	if err := h.Manager.RemoveIPRule(req.IP); err != nil {
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
