package iptables

import (
	"encoding/json"
	stderrors "errors"
	"go-reauth-proxy/pkg/config"
	"go-reauth-proxy/pkg/errors"
	"go-reauth-proxy/pkg/response"
	"io"
	"net/http"
	"strconv"
	"strings"
)

const iptablesJSONBodyLimitBytes int64 = 1 << 20

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

func readIptablesJSONBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	if r == nil || r.Body == nil {
		return nil, true
	}
	if r.ContentLength > iptablesJSONBodyLimitBytes {
		response.JSONStatus(w, http.StatusRequestEntityTooLarge, false, errors.CodeReadBodyFailed, "Request body too large", nil)
		return nil, false
	}
	body := http.MaxBytesReader(w, r.Body, iptablesJSONBodyLimitBytes)
	defer body.Close()
	bodyBytes, err := io.ReadAll(body)
	if err == nil {
		return bodyBytes, true
	}
	var maxBytesErr *http.MaxBytesError
	if stderrors.As(err, &maxBytesErr) {
		response.JSONStatus(w, http.StatusRequestEntityTooLarge, false, errors.CodeReadBodyFailed, "Request body too large", nil)
		return nil, false
	}
	response.Error(w, errors.CodeReadBodyFailed, "Failed to read request body")
	return nil, false
}

func decodeIptablesJSONBody(w http.ResponseWriter, r *http.Request, dst interface{}) bool {
	if r == nil || r.Body == nil {
		response.Error(w, errors.CodeInvalidJSON, "Invalid JSON body")
		return false
	}
	if r.ContentLength > iptablesJSONBodyLimitBytes {
		response.JSONStatus(w, http.StatusRequestEntityTooLarge, false, errors.CodeReadBodyFailed, "Request body too large", nil)
		return false
	}
	body := http.MaxBytesReader(w, r.Body, iptablesJSONBodyLimitBytes)
	defer body.Close()
	decoder := json.NewDecoder(body)
	if err := decoder.Decode(dst); err != nil {
		var maxBytesErr *http.MaxBytesError
		if stderrors.As(err, &maxBytesErr) {
			response.JSONStatus(w, http.StatusRequestEntityTooLarge, false, errors.CodeReadBodyFailed, "Request body too large", nil)
			return false
		}
		response.Error(w, errors.CodeInvalidJSON, "Invalid JSON body")
		return false
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		var maxBytesErr *http.MaxBytesError
		if stderrors.As(err, &maxBytesErr) {
			response.JSONStatus(w, http.StatusRequestEntityTooLarge, false, errors.CodeReadBodyFailed, "Request body too large", nil)
			return false
		}
		response.Error(w, errors.CodeInvalidJSON, "Invalid JSON body")
		return false
	}
	return true
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

type IntPortList []int

func (p *IntPortList) UnmarshalJSON(data []byte) error {
	var numbersValue []int
	if err := json.Unmarshal(data, &numbersValue); err == nil {
		ports := make([]int, 0, len(numbersValue))
		for _, n := range numbersValue {
			if n > 0 {
				ports = append(ports, n)
			}
		}
		*p = ports
		return nil
	}

	var stringsValue []string
	if err := json.Unmarshal(data, &stringsValue); err == nil {
		ports := make([]int, 0, len(stringsValue))
		for _, s := range stringsValue {
			for _, part := range splitCommaSeparated(s) {
				if n, err := strconv.Atoi(part); err == nil && n > 0 {
					ports = append(ports, n)
				}
			}
		}
		*p = ports
		return nil
	}

	var singleString string
	if err := json.Unmarshal(data, &singleString); err == nil {
		ports := make([]int, 0)
		for _, part := range splitCommaSeparated(singleString) {
			if n, err := strconv.Atoi(part); err == nil && n > 0 {
				ports = append(ports, n)
			}
		}
		*p = ports
		return nil
	}

	return errors.New(errors.CodeInvalidJSON, "Invalid ports")
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
	bodyBytes, ok := readIptablesJSONBody(w, r)
	if !ok {
		return
	}
	if len(bodyBytes) > 0 {
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

type tcpRedirectRequest struct {
	ListenPort int `json:"listen_port" example:"80"`
	TargetPort int `json:"target_port" example:"7999"`
}

type tcpPortRuleRequest struct {
	IP   string `json:"ip" example:"192.168.1.100"`
	Port int    `json:"port" example:"22"`
}

type sshFirewallSyncRequest struct {
	ChainName         string      `json:"chain_name" example:"FN-KNOCK-SSH"`
	ParentChain       interface{} `json:"parent_chain" swaggertype:"array,string" example:"INPUT,DOCKER-USER"`
	Ports             IntPortList `json:"ports" example:"22"`
	AllowedCIDRs      []string    `json:"allowed_cidrs" example:"203.0.113.0/24"`
	BlockedIPs        []string    `json:"blocked_ips" example:"198.51.100.8"`
	IncludeLocalCIDRs *bool       `json:"include_local_cidrs" example:"true"`
}

type sshFirewallClearRequest struct {
	ChainName   string      `json:"chain_name" example:"FN-KNOCK-SSH"`
	ParentChain interface{} `json:"parent_chain" swaggertype:"array,string" example:"INPUT,DOCKER-USER"`
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
	if !decodeIptablesJSONBody(w, r, &req) {
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
	if !decodeIptablesJSONBody(w, r, &req) {
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
	if !decodeIptablesJSONBody(w, r, &req) {
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

// HandleBlockTCPPortForIP adds a TCP port DROP rule for a source IP
// @Summary Block TCP port for IP
// @Description Add a DROP rule for a specific source IP and TCP destination port
// @Tags iptables
// @Accept  json
// @Produce  json
// @Param request body tcpPortRuleRequest true "IP and TCP destination port to block"
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/iptables/tcp-port/block [post]
func (h *Handler) HandleBlockTCPPortForIP(w http.ResponseWriter, r *http.Request) {
	var req tcpPortRuleRequest
	if !decodeIptablesJSONBody(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.IP) == "" {
		response.Error(w, errors.CodeBadRequest, "IP is required")
		return
	}

	if err := h.Manager.BlockTCPPortForIP(req.IP, req.Port); err != nil {
		handleError(w, err)
		return
	}
	response.Success(w, nil)
}

// HandleRemoveTCPPortRule removes a TCP port ACCEPT/DROP rule for a source IP
// @Summary Remove TCP port rule for IP
// @Description Remove an ACCEPT/DROP rule for a specific source IP and TCP destination port
// @Tags iptables
// @Accept  json
// @Produce  json
// @Param request body tcpPortRuleRequest true "IP and TCP destination port rule to remove"
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/iptables/tcp-port/remove [post]
func (h *Handler) HandleRemoveTCPPortRule(w http.ResponseWriter, r *http.Request) {
	var req tcpPortRuleRequest
	if !decodeIptablesJSONBody(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.IP) == "" {
		response.Error(w, errors.CodeBadRequest, "IP is required")
		return
	}

	if err := h.Manager.RemoveTCPPortRule(req.IP, req.Port); err != nil {
		handleError(w, err)
		return
	}
	response.Success(w, nil)
}

func (h *Handler) HandleSyncSSHFirewall(w http.ResponseWriter, r *http.Request) {
	var req sshFirewallSyncRequest
	if !decodeIptablesJSONBody(w, r, &req) {
		return
	}

	chainName := req.ChainName
	if strings.TrimSpace(chainName) == "" {
		chainName = DefaultSSHFirewallChain
	}
	parents := parseParentChains(req.ParentChain)
	if len(parents) == 0 {
		parents = []string{"INPUT", "DOCKER-USER"}
	}
	includeLocalCIDRs := true
	if req.IncludeLocalCIDRs != nil {
		includeLocalCIDRs = *req.IncludeLocalCIDRs
	}
	defaultAction := "RETURN"
	if len(req.AllowedCIDRs) > 0 {
		defaultAction = "DROP"
	}

	if err := h.Manager.SyncTCPPortAccessPolicy(TCPPortAccessPolicy{
		Chain:             chainName,
		ParentChains:      parents,
		Ports:             []int(req.Ports),
		AllowSources:      req.AllowedCIDRs,
		BlockSources:      req.BlockedIPs,
		IncludeLocalCIDRs: includeLocalCIDRs,
		DefaultAction:     defaultAction,
	}); err != nil {
		handleError(w, err)
		return
	}

	response.Success(w, nil)
}

func (h *Handler) HandleClearSSHFirewall(w http.ResponseWriter, r *http.Request) {
	var req sshFirewallClearRequest
	bodyBytes, ok := readIptablesJSONBody(w, r)
	if !ok {
		return
	}
	if len(bodyBytes) > 0 {
		_ = json.Unmarshal(bodyBytes, &req)
	}

	chainName := req.ChainName
	if strings.TrimSpace(chainName) == "" {
		chainName = DefaultSSHFirewallChain
	}
	parents := parseParentChains(req.ParentChain)
	if len(parents) == 0 {
		parents = []string{"INPUT", "DOCKER-USER"}
	}

	if err := h.Manager.ClearTCPPortAccessPolicy(chainName, parents); err != nil {
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

// HandleEnsureTCPRedirect ensures a TCP REDIRECT rule exists in nat/PREROUTING
// @Summary Ensure TCP redirect
// @Description Ensure a tcp REDIRECT rule exists in nat PREROUTING for both iptables and ip6tables
// @Tags iptables
// @Accept  json
// @Produce  json
// @Param request body tcpRedirectRequest true "TCP redirect configuration"
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/iptables/tcp-redirect [post]
func (h *Handler) HandleEnsureTCPRedirect(w http.ResponseWriter, r *http.Request) {
	var req tcpRedirectRequest
	if !decodeIptablesJSONBody(w, r, &req) {
		return
	}

	if err := h.Manager.EnsureTCPRedirect(req.ListenPort, req.TargetPort); err != nil {
		handleError(w, err)
		return
	}
	response.Success(w, nil)
}

// HandleClearTCPRedirect removes a TCP REDIRECT rule from nat/PREROUTING
// @Summary Clear TCP redirect
// @Description Remove a tcp REDIRECT rule from nat PREROUTING for both iptables and ip6tables
// @Tags iptables
// @Accept  json
// @Produce  json
// @Param request body tcpRedirectRequest true "TCP redirect configuration"
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/iptables/tcp-redirect [delete]
func (h *Handler) HandleClearTCPRedirect(w http.ResponseWriter, r *http.Request) {
	var req tcpRedirectRequest
	if !decodeIptablesJSONBody(w, r, &req) {
		return
	}

	if err := h.Manager.ClearTCPRedirect(req.ListenPort, req.TargetPort); err != nil {
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
