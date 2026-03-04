package iptables

import (
	"fmt"
	"go-reauth-proxy/pkg/errors"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

type Options struct {
	ChainName   string
	ParentChain interface{} // string or []string
	ExemptPorts []string
	Tables      []string
}

type commandRunner interface {
	CombinedOutput(command string, args ...string) ([]byte, error)
}

type sudoExecRunner struct{}

func (sudoExecRunner) CombinedOutput(command string, args ...string) ([]byte, error) {
	cmd := exec.Command("sudo", append([]string{command}, args...)...)
	return cmd.CombinedOutput()
}

type Manager struct {
	Chain         string
	ParentChains  []string
	ExemptPorts   []string
	BaseRuleCount int
	tables        []string
	runner        commandRunner
}

func parseParentChains(value interface{}) []string {
	switch v := value.(type) {
	case string:
		return splitCommaSeparated(v)
	case []string:
		var out []string
		for _, item := range v {
			out = append(out, splitCommaSeparated(item)...)
		}
		return out
	case []interface{}:
		var out []string
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, splitCommaSeparated(s)...)
			}
		}
		return out
	default:
		return nil
	}
}

func splitCommaSeparated(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func NewManager(opts Options) *Manager {
	chain := opts.ChainName
	if chain == "" {
		chain = "REAUTH_FW"
	}

	parents := parseParentChains(opts.ParentChain)
	if len(parents) == 0 {
		parents = []string{"INPUT"}
	}

	tables := normalizeTables(opts.Tables)
	if len(tables) == 0 {
		tables = []string{"iptables", "ip6tables"}
	}

	return &Manager{
		Chain:        chain,
		ParentChains: parents,
		ExemptPorts:  opts.ExemptPorts,
		tables:       tables,
		runner:       sudoExecRunner{},
	}
}

func normalizeTables(tables []string) []string {
	out := make([]string, 0, len(tables))
	seen := map[string]struct{}{}
	for _, t := range tables {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	return out
}

func (m *Manager) hasTable(table string) bool {
	for _, t := range m.tables {
		if t == table {
			return true
		}
	}
	return false
}

func (m *Manager) runTable(table string, args ...string) error {
	output, err := m.runner.CombinedOutput(table, args...)
	if err != nil {
		return fmt.Errorf("%s command failed: %s, output: %s", table, strings.Join(args, " "), string(output))
	}
	return nil
}

func (m *Manager) runTableOutput(table string, args ...string) (string, error) {
	output, err := m.runner.CombinedOutput(table, args...)
	if err != nil {
		return "", fmt.Errorf("%s command failed: %s, output: %s", table, strings.Join(args, " "), string(output))
	}
	return string(output), nil
}

func (m *Manager) tableForAddress(address string) (string, error) {
	address = strings.TrimSpace(address)
	if address == "" {
		return "", errors.New(errors.CodeBadRequest, "IP is required")
	}

	ip := net.ParseIP(address)
	if ip == nil {
		if cidrIP, _, err := net.ParseCIDR(address); err == nil {
			ip = cidrIP
		}
	}
	if ip == nil {
		return "", errors.New(errors.CodeBadRequest, "Invalid IP")
	}
	if ip.To4() != nil {
		if !m.hasTable("iptables") {
			return "", errors.New(errors.CodeIptablesCommandError, "iptables is not enabled")
		}
		return "iptables", nil
	}
	if !m.hasTable("ip6tables") {
		return "", errors.New(errors.CodeIptablesCommandError, "ip6tables is not enabled")
	}
	return "ip6tables", nil
}

func (m *Manager) Init() error {
	m.calculateBaseRuleCount()

	for _, table := range m.tables {
		isNewChain := false

		if err := m.runTable(table, "-L", m.Chain, "-n"); err != nil {
			if err := m.runTable(table, "-N", m.Chain); err != nil {
				return errors.New(errors.CodeIptablesInitError, fmt.Sprintf("Failed to create chain (%s): %v", table, err))
			}
			isNewChain = true
		}

		for _, parent := range m.ParentChains {
			if err := m.runTable(table, "-C", parent, "-j", m.Chain); err != nil {
				if err := m.runTable(table, "-I", parent, "1", "-j", m.Chain); err != nil {
					return errors.New(errors.CodeIptablesInitError, fmt.Sprintf("Failed to link chain to %s (%s): %v", parent, table, err))
				}
			}
		}

		if isNewChain {
			if err := m.applyBaseRules(table); err != nil {
				return errors.New(errors.CodeIptablesInitError, fmt.Sprintf("Failed to apply base rules (%s): %v", table, err))
			}
		}
	}

	return nil
}

func (m *Manager) Flush() error {
	for _, table := range m.tables {
		if err := m.runTable(table, "-F", m.Chain); err != nil {
			return errors.New(errors.CodeIptablesCommandError, fmt.Sprintf("Failed to flush chain (%s): %v", table, err))
		}
		if err := m.applyBaseRules(table); err != nil {
			return errors.New(errors.CodeIptablesCommandError, fmt.Sprintf("Failed to reapply base rules (%s): %v", table, err))
		}
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

func (m *Manager) applyBaseRules(table string) error {
	if err := m.runTable(table, "-A", m.Chain, "-i", "lo", "-j", "ACCEPT"); err != nil {
		return err
	}
	if err := m.runTable(table, "-A", m.Chain, "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"); err != nil {
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

			if err := m.runTable(table, "-A", m.Chain, "-p", "tcp", "-m", "multiport", "--dports", portsStr, "-j", "ACCEPT"); err != nil {
				return err
			}
			if err := m.runTable(table, "-A", m.Chain, "-p", "udp", "-m", "multiport", "--dports", portsStr, "-j", "ACCEPT"); err != nil {
				return err
			}
		}
	}

	m.calculateBaseRuleCount()
	return nil
}

func (m *Manager) Destroy() error {
	for _, table := range m.tables {
		for _, parent := range m.ParentChains {
			for {
				if err := m.runTable(table, "-D", parent, "-j", m.Chain); err != nil {
					break
				}
			}
		}

		_ = m.runTable(table, "-F", m.Chain)
		_ = m.runTable(table, "-X", m.Chain)
	}
	return nil
}

func (m *Manager) BlockAll() error {
	_ = m.RemoveBlockAll()
	for _, table := range m.tables {
		if err := m.runTable(table, "-A", m.Chain, "-j", "DROP"); err != nil {
			return errors.New(errors.CodeIptablesCommandError, fmt.Sprintf("Failed to block all (%s): %v", table, err))
		}
	}
	return nil
}

func (m *Manager) AllowAll() error {
	return m.RemoveBlockAll()
}

func (m *Manager) RemoveBlockAll() error {
	for _, table := range m.tables {
		for {
			if err := m.runTable(table, "-D", m.Chain, "-j", "DROP"); err != nil {
				break
			}
		}
	}
	return nil
}

func (m *Manager) AllowIP(ip string) error {
	_ = m.RemoveIPRule(ip)
	insertPos := strconv.Itoa(m.BaseRuleCount + 1)
	table, err := m.tableForAddress(ip)
	if err != nil {
		return err
	}
	if err := m.runTable(table, "-I", m.Chain, insertPos, "-s", ip, "-j", "ACCEPT"); err != nil {
		return errors.New(errors.CodeIptablesCommandError, fmt.Sprintf("Failed to allow IP %s (%s): %v", ip, table, err))
	}
	return nil
}

func (m *Manager) BlockIP(ip string) error {
	_ = m.RemoveIPRule(ip)
	insertPos := strconv.Itoa(m.BaseRuleCount + 1)
	table, err := m.tableForAddress(ip)
	if err != nil {
		return err
	}
	if err := m.runTable(table, "-I", m.Chain, insertPos, "-s", ip, "-j", "DROP"); err != nil {
		return errors.New(errors.CodeIptablesCommandError, fmt.Sprintf("Failed to block IP %s (%s): %v", ip, table, err))
	}
	return nil
}

func (m *Manager) RemoveIPRule(ip string) error {
	table, err := m.tableForAddress(ip)
	if err != nil {
		return err
	}
	_ = m.runTable(table, "-D", m.Chain, "-s", ip, "-j", "ACCEPT")
	_ = m.runTable(table, "-D", m.Chain, "-s", ip, "-j", "DROP")
	return nil
}

type Rule struct {
	IP     string `json:"ip"`
	Action string `json:"action"` // ACCEPT or DROP
}

func (m *Manager) ParseRules() ([]Rule, error) {
	var rules []Rule
	re := regexp.MustCompile(`-[AI]\s+\S+\s+-s\s+(\S+)\s+-j\s+(ACCEPT|DROP)`)

	for _, table := range m.tables {
		output, err := m.runTableOutput(table, "-S", m.Chain)
		if err != nil {
			return nil, errors.New(errors.CodeIptablesParseError, fmt.Sprintf("Failed to list rules (%s): %v", table, err))
		}

		lines := strings.Split(output, "\n")
		for _, line := range lines {
			matches := re.FindStringSubmatch(line)
			if len(matches) != 3 {
				continue
			}

			ip := matches[1]
			ip = strings.TrimSuffix(ip, "/32")
			ip = strings.TrimSuffix(ip, "/128")
			action := matches[2]

			if ip == "0.0.0.0/0" || ip == "::/0" {
				continue
			}
			rules = append(rules, Rule{IP: ip, Action: action})
		}
	}
	return rules, nil
}
