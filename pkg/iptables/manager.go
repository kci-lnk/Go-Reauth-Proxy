package iptables

import (
	"fmt"
	"go-reauth-proxy/pkg/errors"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

type Options struct {
	ChainName   string
	ParentChain interface{} // string or []string
	ExemptPorts []string
}

type Manager struct {
	Chain         string
	ParentChains  []string
	ExemptPorts   []string
	BaseRuleCount int
}

func NewManager(opts Options) *Manager {
	chain := opts.ChainName
	if chain == "" {
		chain = "REAUTH_FW"
	}

	var parents []string
	switch v := opts.ParentChain.(type) {
	case string:
		if v != "" {
			parents = []string{v}
		} else {
			parents = []string{"INPUT"}
		}
	case []string:
		parents = v
	case []interface{}:
		for _, item := range v {
			if s, ok := item.(string); ok {
				parents = append(parents, s)
			}
		}
	default:
		parents = []string{"INPUT"}
	}
	if len(parents) == 0 {
		parents = []string{"INPUT"}
	}

	return &Manager{
		Chain:        chain,
		ParentChains: parents,
		ExemptPorts:  opts.ExemptPorts,
	}
}

func (m *Manager) runIptables(args ...string) error {
	cmd := exec.Command("sudo", append([]string{"iptables"}, args...)...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("iptables command failed: %s, output: %s", strings.Join(args, " "), string(output))
	}
	return nil
}

func (m *Manager) runIptablesOutput(args ...string) (string, error) {
	cmd := exec.Command("sudo", append([]string{"iptables"}, args...)...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("iptables command failed: %s, output: %s", strings.Join(args, " "), string(output))
	}
	return string(output), nil
}

func (m *Manager) Init() error {
	isNewChain := false

	if err := m.runIptables("-L", m.Chain, "-n"); err != nil {
		if err := m.runIptables("-N", m.Chain); err != nil {
			return errors.New(errors.CodeIptablesInitError, fmt.Sprintf("Failed to create chain: %v", err))
		}
		isNewChain = true
	}

	for _, parent := range m.ParentChains {
		if err := m.runIptables("-C", parent, "-j", m.Chain); err != nil {
			if err := m.runIptables("-I", parent, "1", "-j", m.Chain); err != nil {
				return errors.New(errors.CodeIptablesInitError, fmt.Sprintf("Failed to link chain to %s: %v", parent, err))
			}
		}
	}

	m.calculateBaseRuleCount()

	if isNewChain {
		if err := m.applyBaseRules(); err != nil {
			return errors.New(errors.CodeIptablesInitError, fmt.Sprintf("Failed to apply base rules: %v", err))
		}
	}

	return nil
}

func (m *Manager) Flush() error {
	if err := m.runIptables("-F", m.Chain); err != nil {
		return errors.New(errors.CodeIptablesCommandError, fmt.Sprintf("Failed to flush chain: %v", err))
	}
	if err := m.applyBaseRules(); err != nil {
		return errors.New(errors.CodeIptablesCommandError, fmt.Sprintf("Failed to reapply base rules: %v", err))
	}
	return nil
}

func (m *Manager) calculateBaseRuleCount() {
	count := 2
	if len(m.ExemptPorts) > 0 {
		chunks := (len(m.ExemptPorts) + 14) / 15
		count += chunks * 2
	}
	m.BaseRuleCount = count
}

func (m *Manager) applyBaseRules() error {
	if err := m.runIptables("-A", m.Chain, "-i", "lo", "-j", "ACCEPT"); err != nil {
		return err
	}
	if err := m.runIptables("-A", m.Chain, "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"); err != nil {
		return err
	}

	if len(m.ExemptPorts) > 0 {
		chunkSize := 15
		for i := 0; i < len(m.ExemptPorts); i += chunkSize {
			end := i + chunkSize
			if end > len(m.ExemptPorts) {
				end = len(m.ExemptPorts)
			}
			chunk := m.ExemptPorts[i:end]
			portsStr := strings.Join(chunk, ",")

			if err := m.runIptables("-A", m.Chain, "-p", "tcp", "-m", "multiport", "--dports", portsStr, "-j", "ACCEPT"); err != nil {
				return err
			}
			if err := m.runIptables("-A", m.Chain, "-p", "udp", "-m", "multiport", "--dports", portsStr, "-j", "ACCEPT"); err != nil {
				return err
			}
		}
	}

	m.calculateBaseRuleCount()
	return nil
}

func (m *Manager) Destroy() error {
	for _, parent := range m.ParentChains {
		for {
			if err := m.runIptables("-D", parent, "-j", m.Chain); err != nil {
				break
			}
		}
	}

	_ = m.runIptables("-F", m.Chain)
	_ = m.runIptables("-X", m.Chain)
	return nil
}

func (m *Manager) BlockAll() error {
	_ = m.RemoveBlockAll()
	if err := m.runIptables("-A", m.Chain, "-j", "DROP"); err != nil {
		return errors.New(errors.CodeIptablesCommandError, fmt.Sprintf("Failed to block all: %v", err))
	}
	return nil
}

func (m *Manager) AllowAll() error {
	return m.RemoveBlockAll()
}

func (m *Manager) RemoveBlockAll() error {
	for {
		if err := m.runIptables("-D", m.Chain, "-j", "DROP"); err != nil {
			break
		}
	}
	return nil
}

func (m *Manager) AllowIP(ip string) error {
	m.RemoveIPRule(ip)
	insertPos := strconv.Itoa(m.BaseRuleCount + 1)
	if err := m.runIptables("-I", m.Chain, insertPos, "-s", ip, "-j", "ACCEPT"); err != nil {
		return errors.New(errors.CodeIptablesCommandError, fmt.Sprintf("Failed to allow IP %s: %v", ip, err))
	}
	return nil
}

func (m *Manager) BlockIP(ip string) error {
	m.RemoveIPRule(ip)
	insertPos := strconv.Itoa(m.BaseRuleCount + 1)
	if err := m.runIptables("-I", m.Chain, insertPos, "-s", ip, "-j", "DROP"); err != nil {
		return errors.New(errors.CodeIptablesCommandError, fmt.Sprintf("Failed to block IP %s: %v", ip, err))
	}
	return nil
}

func (m *Manager) RemoveIPRule(ip string) {
	_ = m.runIptables("-D", m.Chain, "-s", ip, "-j", "ACCEPT")
	_ = m.runIptables("-D", m.Chain, "-s", ip, "-j", "DROP")
}

type Rule struct {
	IP     string `json:"ip"`
	Action string `json:"action"` // ACCEPT or DROP
}

func (m *Manager) ParseRules() ([]Rule, error) {
	output, err := m.runIptablesOutput("-S", m.Chain)
	if err != nil {
		return nil, errors.New(errors.CodeIptablesParseError, fmt.Sprintf("Failed to list rules: %v", err))
	}

	var rules []Rule
	lines := strings.Split(output, "\n")
	re := regexp.MustCompile(`-[AI]\s+\S+\s+-s\s+([0-9\.\/]+)\s+-j\s+(ACCEPT|DROP)`)

	for _, line := range lines {
		matches := re.FindStringSubmatch(line)
		if len(matches) == 3 {
			ip := matches[1]
			ip = strings.TrimSuffix(ip, "/32")
			action := matches[2]
			if ip != "0.0.0.0/0" {
				rules = append(rules, Rule{IP: ip, Action: action})
			}
		}
	}
	return rules, nil
}
