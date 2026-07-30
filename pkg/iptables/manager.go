package iptables

import (
	"fmt"
	"go-reauth-proxy/pkg/errors"
	"go-reauth-proxy/pkg/logger"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
)

const DefaultSSHFirewallChain = "FN-KNOCK-SSH"
const (
	sshNftTableName              = "fnknock_ssh"
	whitelistNftTableName        = "fnknock_whitelist"
	whitelistChainName           = "FNK-WHITELIST"
	whitelistMarkChainName       = "FNK-WL-MARK"
	whitelistPacketMark          = "0x40000000"
	whitelistPacketMarkWithMask  = "0x40000000/0x40000000"
	whitelistPacketMarkClearMask = "0xbfffffff"
	sshAllowMark                 = "0x10000000"
	sshAllowMarkWithMask         = "0x10000000/0x10000000"
	sshBlockMark                 = "0x20000000"
	sshBlockMarkWithMask         = "0x20000000/0x20000000"
	sshClassificationClearMask   = "0xcfffffff"
	sshClassificationMask        = "0x30000000"
	sshAllowActionChain          = "FNK-SSH-ALLOW"
	sshBlockActionChain          = "FNK-SSH-BLOCK"
	sshDefaultActionChain        = "FNK-SSH-DEFAULT"
	nftIntervalSetMinSourceSize  = 256
	nftClassifierPriority        = "-1"
)

type Options struct {
	ChainName   string
	ParentChain interface{} // string or []string
	ExemptPorts []string
	Tables      []string
	Disabled    bool
}

type commandRunner interface {
	CombinedOutput(command string, args ...string) ([]byte, error)
	CombinedOutputWithInput(input string, command string, args ...string) ([]byte, error)
}

type execRunner struct {
	useSudo bool
}

func shouldUseSudo() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("FN_KNOCK_IPTABLES_USE_SUDO"))) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	}

	if os.Geteuid() == 0 {
		return false
	}

	_, err := exec.LookPath("sudo")
	return err == nil
}

func (r execRunner) buildCommand(command string, args ...string) *exec.Cmd {
	if r.useSudo {
		return exec.Command("sudo", append([]string{command}, args...)...)
	}
	return exec.Command(command, args...)
}

func (r execRunner) CombinedOutput(command string, args ...string) ([]byte, error) {
	cmd := r.buildCommand(command, args...)
	return cmd.CombinedOutput()
}

func (r execRunner) CombinedOutputWithInput(input string, command string, args ...string) ([]byte, error) {
	cmd := r.buildCommand(command, args...)
	cmd.Stdin = strings.NewReader(input)
	return cmd.CombinedOutput()
}

type Manager struct {
	Chain                      string
	ParentChains               []string
	ExemptPorts                []string
	tables                     []string
	runner                     commandRunner
	baseRulesMu                sync.RWMutex
	baseFirewallEnabledByTable map[string]bool
	nftCommand                 string
	disabled                   bool
	whitelistPolicyMu          sync.Mutex
	whitelistNftReady          bool
}

type TCPPortAccessPolicy struct {
	Chain             string
	ParentChains      []string
	Ports             []int
	AllowSources      []string
	BlockSources      []string
	IncludeLocalCIDRs bool
	DefaultAction     string // DROP or RETURN
}

var localCIDRv4 = []string{
	"10.0.0.0/8",
	"100.64.0.0/10",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"169.254.0.0/16",
	"172.17.0.0/16",
}

var localCIDRv6 = []string{
	"fc00::/7",
	"fe80::/10",
}

func debugArgs(args []string) []string {
	out := make([]string, 0, len(args))
	for _, arg := range args {
		out = append(out, logger.SanitizeLogString(arg))
	}
	return out
}

func debugPorts(ports []int) []any {
	out := make([]any, 0, len(ports))
	for _, port := range ports {
		out = append(out, logger.SanitizePort(port))
	}
	return out
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
		runner:       execRunner{useSudo: shouldUseSudo()},
		nftCommand:   findNftCommand(),
		disabled:     opts.Disabled || iptablesDisabledByEnvironment(),
	}
}

func findNftCommand() string {
	if runtime.GOOS != "linux" {
		return ""
	}
	if command, err := exec.LookPath("nft"); err == nil {
		return command
	}
	for _, command := range []string{"/usr/sbin/nft", "/sbin/nft"} {
		if info, err := os.Stat(command); err == nil && !info.IsDir() {
			return command
		}
	}
	return ""
}

func iptablesDisabledByEnvironment() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("FN_KNOCK_DISABLE_IPTABLES"))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func (m *Manager) isDisabled() bool {
	if m.disabled {
		return true
	}
	if platformIptablesSupported() {
		return false
	}
	// A substituted runner is a unit-test seam and never executes the host's
	// firewall tools. Production managers always use execRunner and are
	// automatically disabled outside Linux.
	_, executesHostCommands := m.runner.(execRunner)
	return executesHostCommands
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
	if m.isDisabled() {
		return errors.New(errors.CodeIptablesCommandError, "iptables is disabled for this runtime")
	}
	output, err := m.runner.CombinedOutput(table, args...)
	if err != nil {
		if event := logger.DebugEvent("iptables", "command_failed"); event != nil {
			event.Str("table", logger.SanitizeLogString(table)).
				Interface("args", debugArgs(args)).
				Str("output", logger.SanitizeLogString(string(output))).
				Str("error", logger.SanitizeLogString(err.Error())).
				Send()
		}
		return fmt.Errorf("%s command failed: %s, output: %s", table, strings.Join(args, " "), string(output))
	}
	return nil
}

func (m *Manager) runTableOutput(table string, args ...string) (string, error) {
	if m.isDisabled() {
		return "", errors.New(errors.CodeIptablesCommandError, "iptables is disabled for this runtime")
	}
	output, err := m.runner.CombinedOutput(table, args...)
	if err != nil {
		if event := logger.DebugEvent("iptables", "command_failed"); event != nil {
			event.Str("table", logger.SanitizeLogString(table)).
				Interface("args", debugArgs(args)).
				Str("output", logger.SanitizeLogString(string(output))).
				Str("error", logger.SanitizeLogString(err.Error())).
				Send()
		}
		return "", fmt.Errorf("%s command failed: %s, output: %s", table, strings.Join(args, " "), string(output))
	}
	return string(output), nil
}

func restoreCommandForTable(table string) string {
	switch table {
	case "iptables":
		return "iptables-restore"
	case "ip6tables":
		return "ip6tables-restore"
	default:
		return ""
	}
}

func (m *Manager) runTableRestore(table string, input string) error {
	if m.isDisabled() {
		return errors.New(errors.CodeIptablesCommandError, "iptables is disabled for this runtime")
	}
	restoreCommand := restoreCommandForTable(table)
	if restoreCommand == "" {
		return fmt.Errorf("unsupported restore table: %s", table)
	}

	output, err := m.runner.CombinedOutputWithInput(
		input,
		restoreCommand,
		"--noflush",
	)
	if err != nil {
		if event := logger.DebugEvent("iptables", "restore_command_failed"); event != nil {
			event.Str("table", logger.SanitizeLogString(table)).
				Str("command", logger.SanitizeLogString(restoreCommand)).
				Str("output", logger.SanitizeLogString(string(output))).
				Str("error", logger.SanitizeLogString(err.Error())).
				Send()
		}
		return fmt.Errorf(
			"%s command failed: %s, output: %s",
			restoreCommand,
			"--noflush",
			string(output),
		)
	}
	return nil
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
	if event := logger.DebugEvent("iptables", "init_start"); event != nil {
		event.Str("chain", logger.SanitizeLogString(m.Chain)).
			Interface("parent_chains", debugArgs(m.ParentChains)).
			Interface("exempt_ports", debugArgs(m.ExemptPorts)).
			Interface("tables", debugArgs(m.tables)).
			Send()
	}
	if err := m.ensureNftWhitelistClassifier(); err != nil {
		return errors.New(
			errors.CodeIptablesInitError,
			fmt.Sprintf("Failed to initialize whitelist nft classifier: %v", err),
		)
	}
	for _, table := range m.tables {
		if err := m.runTable(table, "-L", m.Chain, "-n"); err != nil {
			if err := m.runTable(table, "-N", m.Chain); err != nil {
				if event := logger.DebugEvent("iptables", "init_failed"); event != nil {
					event.Str("table", logger.SanitizeLogString(table)).
						Str("chain", logger.SanitizeLogString(m.Chain)).
						Str("error", logger.SanitizeLogString(err.Error())).
						Send()
				}
				return errors.New(errors.CodeIptablesInitError, fmt.Sprintf("Failed to create chain (%s): %v", table, err))
			}
		}
		if err := m.prepareWhitelistSupportChains(table); err != nil {
			return errors.New(
				errors.CodeIptablesInitError,
				fmt.Sprintf("Failed to initialize whitelist support chains (%s): %v", table, err),
			)
		}

		for _, parent := range m.ParentChains {
			if !m.parentChainExists(table, parent) {
				if event := logger.DebugEvent("iptables", "parent_chain_missing"); event != nil {
					event.Str("table", logger.SanitizeLogString(table)).
						Str("chain", logger.SanitizeLogString(m.Chain)).
						Str("parent_chain", logger.SanitizeLogString(parent)).
						Send()
				}
				continue
			}
			if err := m.runTable(table, "-C", parent, "-j", m.Chain); err != nil {
				if err := m.runTable(table, "-I", parent, "1", "-j", m.Chain); err != nil {
					if event := logger.DebugEvent("iptables", "init_failed"); event != nil {
						event.Str("table", logger.SanitizeLogString(table)).
							Str("chain", logger.SanitizeLogString(m.Chain)).
							Str("parent_chain", logger.SanitizeLogString(parent)).
							Str("error", logger.SanitizeLogString(err.Error())).
							Send()
					}
					return errors.New(errors.CodeIptablesInitError, fmt.Sprintf("Failed to link chain to %s (%s): %v", parent, table, err))
				}
			}
		}

		// Re-initialize chain rules to keep a deterministic default-deny policy.
		if err := m.runTable(table, "-F", m.Chain); err != nil {
			if event := logger.DebugEvent("iptables", "init_failed"); event != nil {
				event.Str("table", logger.SanitizeLogString(table)).
					Str("chain", logger.SanitizeLogString(m.Chain)).
					Str("error", logger.SanitizeLogString(err.Error())).
					Send()
			}
			return errors.New(errors.CodeIptablesInitError, fmt.Sprintf("Failed to flush chain (%s): %v", table, err))
		}
		if err := m.applyBaseRules(table); err != nil {
			if event := logger.DebugEvent("iptables", "init_failed"); event != nil {
				event.Str("table", logger.SanitizeLogString(table)).
					Str("chain", logger.SanitizeLogString(m.Chain)).
					Str("error", logger.SanitizeLogString(err.Error())).
					Send()
			}
			return errors.New(errors.CodeIptablesInitError, fmt.Sprintf("Failed to apply base rules (%s): %v", table, err))
		}
	}

	if event := logger.DebugEvent("iptables", "init_end"); event != nil {
		event.Str("chain", logger.SanitizeLogString(m.Chain)).
			Interface("tables", debugArgs(m.tables)).
			Send()
	}
	return nil
}

func (m *Manager) Flush() error {
	if event := logger.DebugEvent("iptables", "flush_start"); event != nil {
		event.Str("chain", logger.SanitizeLogString(m.Chain)).
			Interface("tables", debugArgs(m.tables)).
			Send()
	}
	if err := m.ensureNftWhitelistClassifier(); err != nil {
		return errors.New(
			errors.CodeIptablesCommandError,
			fmt.Sprintf("Failed to initialize whitelist nft classifier: %v", err),
		)
	}
	for _, table := range m.tables {
		if err := m.prepareWhitelistSupportChains(table); err != nil {
			return errors.New(
				errors.CodeIptablesCommandError,
				fmt.Sprintf("Failed to reset whitelist support chains (%s): %v", table, err),
			)
		}
		if err := m.runTable(table, "-F", m.Chain); err != nil {
			if event := logger.DebugEvent("iptables", "flush_failed"); event != nil {
				event.Str("table", logger.SanitizeLogString(table)).
					Str("chain", logger.SanitizeLogString(m.Chain)).
					Str("error", logger.SanitizeLogString(err.Error())).
					Send()
			}
			return errors.New(errors.CodeIptablesCommandError, fmt.Sprintf("Failed to flush chain (%s): %v", table, err))
		}
		if err := m.applyBaseRules(table); err != nil {
			if event := logger.DebugEvent("iptables", "flush_failed"); event != nil {
				event.Str("table", logger.SanitizeLogString(table)).
					Str("chain", logger.SanitizeLogString(m.Chain)).
					Str("error", logger.SanitizeLogString(err.Error())).
					Send()
			}
			return errors.New(errors.CodeIptablesCommandError, fmt.Sprintf("Failed to reapply base rules (%s): %v", table, err))
		}
	}
	if event := logger.DebugEvent("iptables", "flush_end"); event != nil {
		event.Str("chain", logger.SanitizeLogString(m.Chain)).Send()
	}
	return nil
}

func (m *Manager) localCIDRsForTable(table string) []string {
	if table == "ip6tables" {
		return localCIDRv6
	}
	return localCIDRv4
}

func normalizeChainName(chain string, fallback string) string {
	chain = strings.TrimSpace(chain)
	if chain == "" {
		return fallback
	}
	return chain
}

func normalizePorts(ports []int) ([]int, error) {
	out := make([]int, 0, len(ports))
	seen := map[int]struct{}{}
	for _, port := range ports {
		if err := validatePort(port); err != nil {
			return nil, err
		}
		if _, ok := seen[port]; ok {
			continue
		}
		seen[port] = struct{}{}
		out = append(out, port)
	}
	return out, nil
}

func normalizeSources(sources []string) []string {
	out := make([]string, 0, len(sources))
	seen := map[string]struct{}{}
	for _, source := range sources {
		source = strings.TrimSpace(source)
		if source == "" {
			continue
		}
		key := strings.ToLower(source)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, source)
	}
	return out
}

func normalizeDefaultAction(action string) (string, error) {
	action = strings.ToUpper(strings.TrimSpace(action))
	if action == "" {
		return "RETURN", nil
	}
	if action != "DROP" && action != "RETURN" {
		return "", errors.New(errors.CodeBadRequest, "default action must be DROP or RETURN")
	}
	return action, nil
}

func (m *Manager) ensureChain(table string, chain string) error {
	if err := m.runTable(table, "-L", chain, "-n"); err != nil {
		if err := m.runTable(table, "-N", chain); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) prepareWhitelistSupportChains(table string) error {
	for _, chain := range []string{whitelistChainName, whitelistMarkChainName} {
		if err := m.ensureChain(table, chain); err != nil {
			return err
		}
		if err := m.runTable(table, "-F", chain); err != nil {
			return err
		}
	}
	if err := m.runTable(
		table,
		"-A", whitelistMarkChainName,
		"-j", "MARK",
		"--set-xmark", "0x0/0x40000000",
	); err != nil {
		return err
	}
	return m.runTable(table, "-A", whitelistMarkChainName, "-j", "ACCEPT")
}

func (m *Manager) parentChainExists(table string, parent string) bool {
	return m.runTable(table, "-L", parent, "-n") == nil
}

func (m *Manager) deleteParentJumpsToChain(table string, parent string, chain string) {
	if !m.parentChainExists(table, parent) {
		return
	}

	output, err := m.runTableOutput(table, "-S", parent)
	if err == nil {
		for start := 0; start < len(output); {
			end := strings.IndexByte(output[start:], '\n')
			lineEnd := len(output)
			if end >= 0 {
				lineEnd = start + end
			}
			if args, ok := parentJumpDeleteArgs(output[start:lineEnd], parent, chain); ok {
				_ = m.runTable(table, args...)
			}
			if end < 0 {
				break
			}
			start = lineEnd + 1
		}
	}

	for {
		if err := m.runTable(table, "-D", parent, "-j", chain); err != nil {
			break
		}
	}
}

func (m *Manager) clearTCPPortAccessPolicyForTable(table string, chain string, parents []string) {
	for _, parent := range parents {
		m.deleteParentJumpsToChain(table, parent, chain)
	}
	_ = m.runTable(table, "-F", chain)
	_ = m.runTable(table, "-X", chain)
	for _, actionChain := range sshActionChains() {
		_ = m.runTable(table, "-F", actionChain)
		_ = m.runTable(table, "-X", actionChain)
	}
}

func (m *Manager) tablesForAccessPolicy(policy TCPPortAccessPolicy) ([]string, error) {
	active := map[string]struct{}{}
	for _, source := range append(policy.AllowSources, policy.BlockSources...) {
		table, err := m.tableForAddress(source)
		if err != nil {
			return nil, err
		}
		active[table] = struct{}{}
	}

	if policy.IncludeLocalCIDRs {
		for _, table := range m.tables {
			active[table] = struct{}{}
		}
	}

	if strings.ToUpper(strings.TrimSpace(policy.DefaultAction)) == "DROP" {
		for _, table := range m.tables {
			active[table] = struct{}{}
		}
	}

	out := make([]string, 0, len(m.tables))
	for _, table := range m.tables {
		if _, ok := active[table]; ok {
			out = append(out, table)
		}
	}
	return out, nil
}

func (m *Manager) addSourceRule(table string, chain string, source string, action string) error {
	return m.runTable(table, "-A", chain, "-s", source, "-j", action)
}

func (m *Manager) addTCPPortJump(table string, parent string, chain string, port int) error {
	portText := strconv.Itoa(port)
	args := []string{"-p", "tcp", "--dport", portText, "-j", chain}
	if err := m.runTable(table, append([]string{"-C", parent}, args...)...); err == nil {
		return nil
	}
	return m.runTable(table, append([]string{"-I", parent, "1"}, args...)...)
}

func (m *Manager) SyncTCPPortAccessPolicy(policy TCPPortAccessPolicy) error {
	chain := normalizeChainName(policy.Chain, DefaultSSHFirewallChain)
	parents := policy.ParentChains
	if len(parents) == 0 {
		parents = m.ParentChains
	}
	if len(parents) == 0 {
		parents = []string{"INPUT"}
	}

	ports, err := normalizePorts(policy.Ports)
	if err != nil {
		return err
	}

	allowSources := normalizeSources(policy.AllowSources)
	blockSources := normalizeSources(policy.BlockSources)
	defaultAction, err := normalizeDefaultAction(policy.DefaultAction)
	if err != nil {
		return err
	}
	normalizedPolicy := TCPPortAccessPolicy{
		Chain:             chain,
		ParentChains:      parents,
		Ports:             ports,
		AllowSources:      allowSources,
		BlockSources:      blockSources,
		IncludeLocalCIDRs: policy.IncludeLocalCIDRs,
		DefaultAction:     defaultAction,
	}
	if event := logger.DebugEvent("iptables", "tcp_port_access_policy_sync_start"); event != nil {
		event.Str("chain", logger.SanitizeLogString(chain)).
			Interface("parent_chains", debugArgs(parents)).
			Interface("ports", debugPorts(ports)).
			Int("allow_source_count", len(allowSources)).
			Int("block_source_count", len(blockSources)).
			Bool("include_local_cidrs", policy.IncludeLocalCIDRs).
			Str("default_action", logger.SanitizeLogString(defaultAction)).
			Send()
	}

	tables, err := m.tablesForAccessPolicy(normalizedPolicy)
	if err != nil {
		if event := logger.DebugEvent("iptables", "tcp_port_access_policy_sync_failed"); event != nil {
			event.Str("chain", logger.SanitizeLogString(chain)).
				Str("error", logger.SanitizeLogString(err.Error())).
				Send()
		}
		return err
	}
	if len(ports) == 0 || len(tables) == 0 {
		return m.ClearTCPPortAccessPolicy(chain, parents)
	}

	if m.nftCommand != "" &&
		len(allowSources)+len(blockSources) >= nftIntervalSetMinSourceSize {
		if err := m.syncNftTCPPortAccessPolicy(normalizedPolicy); err != nil {
			return err
		}
		activeTables := make(map[string]struct{}, len(tables))
		for _, table := range tables {
			activeTables[table] = struct{}{}
		}
		for _, table := range m.tables {
			if _, ok := activeTables[table]; !ok {
				m.clearTCPPortAccessPolicyForTable(table, chain, parents)
				continue
			}
			if err := m.ensureChain(table, chain); err != nil {
				return errors.New(
					errors.CodeIptablesInitError,
					fmt.Sprintf("Failed to create SSH chain (%s): %v", table, err),
				)
			}
			for _, actionChain := range sshActionChains() {
				if err := m.ensureChain(table, actionChain); err != nil {
					return errors.New(
						errors.CodeIptablesInitError,
						fmt.Sprintf("Failed to create SSH action chain (%s): %v", table, err),
					)
				}
			}
			for _, parent := range parents {
				if !m.parentChainExists(table, parent) {
					continue
				}
				m.deleteParentJumpsToChain(table, parent, chain)
				for _, port := range ports {
					if err := m.addTCPPortJump(table, parent, chain, port); err != nil {
						return errors.New(
							errors.CodeIptablesInitError,
							fmt.Sprintf(
								"Failed to link SSH chain to %s:%d (%s): %v",
								parent,
								port,
								table,
								err,
							),
						)
					}
				}
			}
			if err := m.applyNftClassifiedTCPPortAccessPolicy(table, normalizedPolicy); err != nil {
				return err
			}
		}
		return nil
	}

	activeTables := map[string]struct{}{}
	for _, table := range tables {
		activeTables[table] = struct{}{}
	}
	for _, table := range m.tables {
		if _, ok := activeTables[table]; !ok {
			m.clearTCPPortAccessPolicyForTable(table, chain, parents)
			continue
		}

		if err := m.ensureChain(table, chain); err != nil {
			if event := logger.DebugEvent("iptables", "tcp_port_access_policy_sync_failed"); event != nil {
				event.Str("table", logger.SanitizeLogString(table)).
					Str("chain", logger.SanitizeLogString(chain)).
					Str("error", logger.SanitizeLogString(err.Error())).
					Send()
			}
			return errors.New(errors.CodeIptablesInitError, fmt.Sprintf("Failed to create SSH chain (%s): %v", table, err))
		}
		for _, parent := range parents {
			if !m.parentChainExists(table, parent) {
				continue
			}
			m.deleteParentJumpsToChain(table, parent, chain)
			for _, port := range ports {
				if err := m.addTCPPortJump(table, parent, chain, port); err != nil {
					if event := logger.DebugEvent("iptables", "tcp_port_access_policy_sync_failed"); event != nil {
						event.Str("table", logger.SanitizeLogString(table)).
							Str("parent_chain", logger.SanitizeLogString(parent)).
							Str("chain", logger.SanitizeLogString(chain)).
							Interface("port", logger.SanitizePort(port)).
							Str("error", logger.SanitizeLogString(err.Error())).
							Send()
					}
					return errors.New(errors.CodeIptablesInitError, fmt.Sprintf("Failed to link SSH chain to %s:%d (%s): %v", parent, port, table, err))
				}
			}
		}

		if err := m.applyTCPPortAccessPolicy(table, normalizedPolicy); err != nil {
			if event := logger.DebugEvent("iptables", "tcp_port_access_policy_sync_failed"); event != nil {
				event.Str("table", logger.SanitizeLogString(table)).
					Str("chain", logger.SanitizeLogString(chain)).
					Str("error", logger.SanitizeLogString(err.Error())).
					Send()
			}
			return err
		}
	}
	if err := m.clearNftTCPPortAccessPolicy(); err != nil {
		return err
	}

	if event := logger.DebugEvent("iptables", "tcp_port_access_policy_sync_end"); event != nil {
		event.Str("chain", logger.SanitizeLogString(chain)).
			Interface("tables", debugArgs(tables)).
			Send()
	}
	return nil
}

func (m *Manager) applyTCPPortAccessPolicy(table string, policy TCPPortAccessPolicy) error {
	chain := normalizeChainName(policy.Chain, DefaultSSHFirewallChain)
	localCIDRs := []string{}
	if policy.IncludeLocalCIDRs {
		localCIDRs = m.localCIDRsForTable(table)
	}

	blockRules := make([]string, 0, len(policy.BlockSources))
	for _, source := range policy.BlockSources {
		sourceTable, _ := m.tableForAddress(source)
		if sourceTable == table {
			blockRules = append(blockRules, source)
		}
	}

	allowRules := make([]string, 0, len(policy.AllowSources))
	for _, source := range policy.AllowSources {
		sourceTable, _ := m.tableForAddress(source)
		if sourceTable == table {
			allowRules = append(allowRules, source)
		}
	}

	var builder strings.Builder
	builder.WriteString("*filter\n")
	builder.WriteString("-F ")
	builder.WriteString(chain)
	builder.WriteString("\n")
	if policy.IncludeLocalCIDRs {
		// Match the loopback interface instead of trusting 127.0.0.0/8 or
		// ::1/128 by source alone. This keeps local TCP relays working without
		// allowing a spoofed loopback source arriving on another interface.
		builder.WriteString("-A ")
		builder.WriteString(chain)
		builder.WriteString(" -i lo -j ACCEPT\n")
	}
	for _, cidr := range localCIDRs {
		builder.WriteString("-A ")
		builder.WriteString(chain)
		builder.WriteString(" -s ")
		builder.WriteString(cidr)
		builder.WriteString(" -j ACCEPT\n")
	}
	for _, source := range blockRules {
		builder.WriteString("-A ")
		builder.WriteString(chain)
		builder.WriteString(" -s ")
		builder.WriteString(source)
		builder.WriteString(" -j DROP\n")
	}
	for _, source := range allowRules {
		builder.WriteString("-A ")
		builder.WriteString(chain)
		builder.WriteString(" -s ")
		builder.WriteString(source)
		builder.WriteString(" -j ACCEPT\n")
	}
	builder.WriteString("-A ")
	builder.WriteString(chain)
	builder.WriteString(" -j ")
	builder.WriteString(policy.DefaultAction)
	builder.WriteString("\nCOMMIT\n")

	if err := m.runTableRestore(table, builder.String()); err != nil {
		return errors.New(
			errors.CodeIptablesCommandError,
			fmt.Sprintf("Failed to batch apply SSH policy (%s): %v", table, err),
		)
	}
	return nil
}

func sshActionChains() []string {
	return []string{sshAllowActionChain, sshBlockActionChain, sshDefaultActionChain}
}

func (m *Manager) applyNftClassifiedTCPPortAccessPolicy(
	table string,
	policy TCPPortAccessPolicy,
) error {
	chain := normalizeChainName(policy.Chain, DefaultSSHFirewallChain)
	var builder strings.Builder
	builder.WriteString("*filter\n-F ")
	builder.WriteString(chain)
	builder.WriteByte('\n')
	for _, actionChain := range sshActionChains() {
		builder.WriteString("-F ")
		builder.WriteString(actionChain)
		builder.WriteByte('\n')
		builder.WriteString("-A ")
		builder.WriteString(actionChain)
		builder.WriteString(" -j MARK --set-xmark 0x0/")
		builder.WriteString(sshClassificationMask)
		builder.WriteByte('\n')
	}
	builder.WriteString("-A ")
	builder.WriteString(sshAllowActionChain)
	builder.WriteString(" -j ACCEPT\n-A ")
	builder.WriteString(sshBlockActionChain)
	builder.WriteString(" -j DROP\n-A ")
	builder.WriteString(sshDefaultActionChain)
	builder.WriteString(" -j ")
	builder.WriteString(policy.DefaultAction)
	builder.WriteByte('\n')

	if policy.IncludeLocalCIDRs {
		builder.WriteString("-A ")
		builder.WriteString(chain)
		builder.WriteString(" -i lo -j ACCEPT\n")
		for _, cidr := range m.localCIDRsForTable(table) {
			builder.WriteString("-A ")
			builder.WriteString(chain)
			builder.WriteString(" -s ")
			builder.WriteString(cidr)
			builder.WriteString(" -j ACCEPT\n")
		}
	}
	builder.WriteString("-A ")
	builder.WriteString(chain)
	builder.WriteString(" -m mark --mark ")
	builder.WriteString(sshBlockMarkWithMask)
	builder.WriteString(" -j ")
	builder.WriteString(sshBlockActionChain)
	builder.WriteByte('\n')
	builder.WriteString("-A ")
	builder.WriteString(chain)
	builder.WriteString(" -m mark --mark ")
	builder.WriteString(sshAllowMarkWithMask)
	builder.WriteString(" -j ")
	builder.WriteString(sshAllowActionChain)
	builder.WriteByte('\n')
	builder.WriteString("-A ")
	builder.WriteString(chain)
	builder.WriteString(" -j ")
	builder.WriteString(sshDefaultActionChain)
	builder.WriteString("\nCOMMIT\n")

	if err := m.runTableRestore(table, builder.String()); err != nil {
		return errors.New(
			errors.CodeIptablesCommandError,
			fmt.Sprintf("Failed to apply compact SSH classifier policy (%s): %v", table, err),
		)
	}
	return nil
}

func (m *Manager) ClearTCPPortAccessPolicy(chain string, parents []string) error {
	chain = normalizeChainName(chain, DefaultSSHFirewallChain)
	if len(parents) == 0 {
		parents = m.ParentChains
	}
	if len(parents) == 0 {
		parents = []string{"INPUT"}
	}
	for _, table := range m.tables {
		m.clearTCPPortAccessPolicyForTable(table, chain, parents)
	}
	if err := m.clearNftTCPPortAccessPolicy(); err != nil {
		return err
	}
	if event := logger.DebugEvent("iptables", "tcp_port_access_policy_cleared"); event != nil {
		event.Str("chain", logger.SanitizeLogString(chain)).
			Interface("parent_chains", debugArgs(parents)).
			Interface("tables", debugArgs(m.tables)).
			Send()
	}
	return nil
}

func (m *Manager) syncNftTCPPortAccessPolicy(policy TCPPortAccessPolicy) error {
	if m.isDisabled() {
		return errors.New(errors.CodeIptablesCommandError, "iptables is disabled for this runtime")
	}
	allow4, allow6, err := splitNftSources(policy.AllowSources)
	if err != nil {
		return err
	}
	block4, block6, err := splitNftSources(policy.BlockSources)
	if err != nil {
		return err
	}

	// Ensure the table exists so the following delete+recreate batch is atomic
	// even on the first successful synchronization.
	_, _ = m.runner.CombinedOutput(m.nftCommand, "add", "table", "inet", sshNftTableName)
	script := buildNftTCPPortAccessPolicy(policy, allow4, allow6, block4, block6)
	output, runErr := m.runner.CombinedOutputWithInput(script, m.nftCommand, "-f", "-")
	if runErr != nil {
		return errors.New(
			errors.CodeIptablesCommandError,
			fmt.Sprintf(
				"Failed to atomically apply SSH nft interval policy: %v, output: %s",
				runErr,
				logger.SanitizeLogString(string(output)),
			),
		)
	}
	return nil
}

func (m *Manager) ensureNftWhitelistClassifier() error {
	if m.nftCommand == "" || m.isDisabled() {
		return nil
	}
	m.whitelistPolicyMu.Lock()
	defer m.whitelistPolicyMu.Unlock()
	if m.whitelistNftReady {
		return nil
	}
	return m.replaceNftWhitelistIPSetLocked(nil, nil)
}

func (m *Manager) clearNftTCPPortAccessPolicy() error {
	return m.clearNftTable(sshNftTableName)
}

func (m *Manager) clearNftTable(table string) error {
	if m.nftCommand == "" || m.isDisabled() {
		return nil
	}
	output, err := m.runner.CombinedOutput(
		m.nftCommand,
		"delete",
		"table",
		"inet",
		table,
	)
	if err == nil || nftObjectMissing(output) {
		return nil
	}
	return errors.New(
		errors.CodeIptablesCommandError,
		fmt.Sprintf(
			"Failed to delete nft table %s: %v, output: %s",
			table,
			err,
			logger.SanitizeLogString(string(output)),
		),
	)
}

func nftObjectMissing(output []byte) bool {
	message := strings.ToLower(string(output))
	return strings.Contains(message, "no such file or directory") ||
		strings.Contains(message, "does not exist") ||
		strings.Contains(message, "not found")
}

// SyncWhitelistIPSet atomically replaces the complete direct-mode whitelist.
// Native nft interval sets keep large regional policies compact. On older
// systems without nft, one iptables-restore transaction per address family
// provides a compatible, bounded-RPC fallback.
func (m *Manager) SyncWhitelistIPSet(sources []string) error {
	m.whitelistPolicyMu.Lock()
	defer m.whitelistPolicyMu.Unlock()

	if m.isDisabled() {
		return errors.New(errors.CodeIptablesCommandError, "iptables is disabled for this runtime")
	}
	ipv4, ipv6, err := splitNftSources(normalizeSources(sources))
	if err != nil {
		return err
	}
	for _, table := range m.tables {
		if err := m.prepareWhitelistSupportChains(table); err != nil {
			return errors.New(
				errors.CodeIptablesCommandError,
				fmt.Sprintf("Failed to prepare whitelist chains (%s): %v", table, err),
			)
		}
	}
	if m.nftCommand == "" {
		return m.syncLegacyWhitelistIPSet(ipv4, ipv6)
	}
	return m.replaceNftWhitelistIPSetLocked(ipv4, ipv6)
}

func (m *Manager) replaceNftWhitelistIPSetLocked(ipv4 []string, ipv6 []string) error {
	// Ensure the table exists so delete+recreate below is one valid atomic
	// transaction both on first installation and subsequent replacements.
	_, _ = m.runner.CombinedOutput(
		m.nftCommand,
		"add",
		"table",
		"inet",
		whitelistNftTableName,
	)
	script := buildNftWhitelistIPSet(m.ParentChains, ipv4, ipv6)
	output, runErr := m.runner.CombinedOutputWithInput(script, m.nftCommand, "-f", "-")
	if runErr != nil {
		return errors.New(
			errors.CodeIptablesCommandError,
			fmt.Sprintf(
				"Failed to atomically apply whitelist nft interval policy: %v, output: %s",
				runErr,
				logger.SanitizeLogString(string(output)),
			),
		)
	}
	m.whitelistNftReady = true
	return nil
}

func (m *Manager) ClearWhitelistIPSet() error {
	m.whitelistPolicyMu.Lock()
	defer m.whitelistPolicyMu.Unlock()
	return m.clearWhitelistIPSetLocked()
}

func (m *Manager) clearWhitelistIPSetLocked() error {
	if m.nftCommand != "" {
		if err := m.replaceNftWhitelistIPSetLocked(nil, nil); err != nil {
			return err
		}
	}
	for _, table := range m.tables {
		if err := m.ensureChain(table, whitelistChainName); err != nil {
			return err
		}
		if err := m.runTable(table, "-F", whitelistChainName); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) syncLegacyWhitelistIPSet(ipv4 []string, ipv6 []string) error {
	if err := m.clearNftTable(whitelistNftTableName); err != nil {
		return err
	}
	for _, table := range m.tables {
		values := ipv4
		if table == "ip6tables" {
			values = ipv6
		}
		var builder strings.Builder
		builder.WriteString("*filter\n-F ")
		builder.WriteString(whitelistChainName)
		builder.WriteByte('\n')
		for _, source := range values {
			builder.WriteString("-A ")
			builder.WriteString(whitelistChainName)
			builder.WriteString(" -s ")
			builder.WriteString(source)
			builder.WriteString(" -j ACCEPT\n")
		}
		builder.WriteString("COMMIT\n")
		if err := m.runTableRestore(table, builder.String()); err != nil {
			return errors.New(
				errors.CodeIptablesCommandError,
				fmt.Sprintf("Failed to batch apply whitelist policy (%s): %v", table, err),
			)
		}
	}
	return nil
}

func buildNftWhitelistIPSet(parents []string, ipv4 []string, ipv6 []string) string {
	var builder strings.Builder
	builder.WriteString("delete table inet ")
	builder.WriteString(whitelistNftTableName)
	builder.WriteString("\nadd table inet ")
	builder.WriteString(whitelistNftTableName)
	builder.WriteByte('\n')
	writeNftSetForTable(&builder, whitelistNftTableName, "allow4", "ipv4_addr", ipv4)
	writeNftSetForTable(&builder, whitelistNftTableName, "allow6", "ipv6_addr", ipv6)
	for _, hook := range nftHooksForParents(parents) {
		builder.WriteString("add chain inet ")
		builder.WriteString(whitelistNftTableName)
		builder.WriteByte(' ')
		builder.WriteString(hook)
		builder.WriteString("_mark { type filter hook ")
		builder.WriteString(hook)
		builder.WriteString(" priority ")
		builder.WriteString(nftClassifierPriority)
		builder.WriteString("; policy accept; }\nadd rule inet ")
		builder.WriteString(whitelistNftTableName)
		builder.WriteByte(' ')
		builder.WriteString(hook)
		builder.WriteString("_mark meta mark set meta mark & ")
		builder.WriteString(whitelistPacketMarkClearMask)
		builder.WriteByte('\n')
		if len(ipv4) > 0 {
			builder.WriteString("add rule inet ")
			builder.WriteString(whitelistNftTableName)
			builder.WriteByte(' ')
			builder.WriteString(hook)
			builder.WriteString("_mark ip saddr @allow4 meta mark set meta mark | ")
			builder.WriteString(whitelistPacketMark)
			builder.WriteByte('\n')
		}
		if len(ipv6) > 0 {
			builder.WriteString("add rule inet ")
			builder.WriteString(whitelistNftTableName)
			builder.WriteByte(' ')
			builder.WriteString(hook)
			builder.WriteString("_mark ip6 saddr @allow6 meta mark set meta mark | ")
			builder.WriteString(whitelistPacketMark)
			builder.WriteByte('\n')
		}
	}
	return builder.String()
}

func splitNftSources(sources []string) ([]string, []string, error) {
	ipv4 := make([]string, 0, len(sources))
	ipv6 := make([]string, 0, len(sources))
	for _, source := range sources {
		source = strings.TrimSpace(source)
		if source == "" {
			continue
		}
		if address := net.ParseIP(source); address != nil {
			if address.To4() != nil {
				ipv4 = append(ipv4, address.String())
			} else {
				ipv6 = append(ipv6, address.String())
			}
			continue
		}
		address, network, parseErr := net.ParseCIDR(source)
		if parseErr != nil {
			return nil, nil, errors.New(errors.CodeBadRequest, "Invalid IP or CIDR")
		}
		if address.To4() != nil {
			ipv4 = append(ipv4, network.String())
		} else {
			ipv6 = append(ipv6, network.String())
		}
	}
	return ipv4, ipv6, nil
}

func buildNftTCPPortAccessPolicy(
	policy TCPPortAccessPolicy,
	allow4 []string,
	allow6 []string,
	block4 []string,
	block6 []string,
) string {
	var builder strings.Builder
	builder.WriteString("delete table inet ")
	builder.WriteString(sshNftTableName)
	builder.WriteString("\nadd table inet ")
	builder.WriteString(sshNftTableName)
	builder.WriteByte('\n')
	writeNftSet(&builder, "allow4", "ipv4_addr", allow4)
	writeNftSet(&builder, "allow6", "ipv6_addr", allow6)
	writeNftSet(&builder, "block4", "ipv4_addr", block4)
	writeNftSet(&builder, "block6", "ipv6_addr", block6)
	for _, hook := range nftHooksForParents(policy.ParentChains) {
		builder.WriteString("add chain inet ")
		builder.WriteString(sshNftTableName)
		builder.WriteByte(' ')
		builder.WriteString(hook)
		builder.WriteString("_classify { type filter hook ")
		builder.WriteString(hook)
		builder.WriteString(" priority ")
		builder.WriteString(nftClassifierPriority)
		builder.WriteString("; policy accept; }\nadd rule inet ")
		builder.WriteString(sshNftTableName)
		builder.WriteByte(' ')
		builder.WriteString(hook)
		builder.WriteString("_classify meta mark set meta mark & ")
		builder.WriteString(sshClassificationClearMask)
		builder.WriteByte('\n')
		writeNftSetMarkRule(&builder, hook, "allow4", "ip", allow4, sshAllowMark)
		writeNftSetMarkRule(&builder, hook, "allow6", "ip6", allow6, sshAllowMark)
		writeNftSetMarkRule(&builder, hook, "block4", "ip", block4, sshBlockMark)
		writeNftSetMarkRule(&builder, hook, "block6", "ip6", block6, sshBlockMark)
		builder.WriteString("add chain inet ")
		builder.WriteString(sshNftTableName)
		builder.WriteByte(' ')
		builder.WriteString(hook)
		builder.WriteString("_clear { type filter hook ")
		builder.WriteString(hook)
		builder.WriteString(" priority 10; policy accept; }\nadd rule inet ")
		builder.WriteString(sshNftTableName)
		builder.WriteByte(' ')
		builder.WriteString(hook)
		builder.WriteString("_clear meta mark & ")
		builder.WriteString(sshClassificationMask)
		builder.WriteString(" != 0 meta mark set meta mark & ")
		builder.WriteString(sshClassificationClearMask)
		builder.WriteByte('\n')
	}
	return builder.String()
}

func writeNftSet(builder *strings.Builder, name string, setType string, values []string) {
	writeNftSetForTable(builder, sshNftTableName, name, setType, values)
}

func writeNftSetForTable(
	builder *strings.Builder,
	table string,
	name string,
	setType string,
	values []string,
) {
	if len(values) == 0 {
		return
	}
	builder.WriteString("add set inet ")
	builder.WriteString(table)
	builder.WriteByte(' ')
	builder.WriteString(name)
	builder.WriteString(" { type ")
	builder.WriteString(setType)
	builder.WriteString("; flags interval; }\nadd element inet ")
	builder.WriteString(table)
	builder.WriteByte(' ')
	builder.WriteString(name)
	builder.WriteString(" { ")
	builder.WriteString(strings.Join(values, ", "))
	builder.WriteString(" }\n")
}

func writeNftSetMarkRule(
	builder *strings.Builder,
	hook string,
	name string,
	family string,
	values []string,
	mark string,
) {
	if len(values) == 0 {
		return
	}
	builder.WriteString("add rule inet ")
	builder.WriteString(sshNftTableName)
	builder.WriteByte(' ')
	builder.WriteString(hook)
	builder.WriteString("_classify ")
	builder.WriteString(family)
	builder.WriteString(" saddr @")
	builder.WriteString(name)
	builder.WriteString(" meta mark set meta mark | ")
	builder.WriteString(mark)
	builder.WriteByte('\n')
}

func nftHooksForParents(parents []string) []string {
	input := false
	forward := false
	for _, parent := range parents {
		switch strings.ToUpper(strings.TrimSpace(parent)) {
		case "INPUT":
			input = true
		case "FORWARD", "DOCKER-USER":
			forward = true
		}
	}
	hooks := make([]string, 0, 2)
	if input || (!input && !forward) {
		hooks = append(hooks, "input")
	}
	if forward {
		hooks = append(hooks, "forward")
	}
	return hooks
}

func (m *Manager) baseRuleCountForTable(table string) int {
	if !m.baseFirewallEnabledForTable(table) {
		return 3
	}
	count := 3
	if m.whitelistNftClassifierReady() {
		count++
	}
	count += len(m.localCIDRsForTable(table))
	count++
	if len(m.ExemptPorts) > 0 {
		chunks := (len(m.ExemptPorts) + 14) / 15
		count += chunks * 2
	}
	return count
}

func (m *Manager) whitelistNftClassifierReady() bool {
	m.whitelistPolicyMu.Lock()
	defer m.whitelistPolicyMu.Unlock()
	return m.whitelistNftReady
}

func (m *Manager) baseFirewallEnabledForTable(table string) bool {
	m.baseRulesMu.RLock()
	enabled, ok := m.baseFirewallEnabledByTable[table]
	m.baseRulesMu.RUnlock()
	if !ok {
		return true
	}
	return enabled
}

func (m *Manager) setBaseFirewallEnabledForTable(table string, enabled bool) {
	m.baseRulesMu.Lock()
	if m.baseFirewallEnabledByTable == nil {
		m.baseFirewallEnabledByTable = make(map[string]bool)
	}
	m.baseFirewallEnabledByTable[table] = enabled
	m.baseRulesMu.Unlock()
}

func (m *Manager) applyBaseRules(table string) error {
	m.setBaseFirewallEnabledForTable(table, false)

	if err := m.runTable(table, "-A", m.Chain, "-i", "lo", "-j", "ACCEPT"); err != nil {
		return err
	}
	if m.whitelistNftClassifierReady() {
		if err := m.runTable(
			table,
			"-A", m.Chain,
			"-m", "mark",
			"--mark", whitelistPacketMarkWithMask,
			"-j", whitelistMarkChainName,
		); err != nil {
			return err
		}
	}
	if err := m.runTable(table, "-A", m.Chain, "-j", whitelistChainName); err != nil {
		return err
	}
	establishedRuleAdded, err := m.appendEstablishedRelatedRule(table)
	if err != nil {
		return err
	}
	if !establishedRuleAdded {
		return nil
	}

	for _, cidr := range m.localCIDRsForTable(table) {
		if err := m.runTable(table, "-A", m.Chain, "-s", cidr, "-j", "ACCEPT"); err != nil {
			return err
		}
	}

	protocol := "icmp"
	if table == "ip6tables" {
		protocol = "ipv6-icmp"
	}
	if err := m.runTable(table, "-A", m.Chain, "-p", protocol, "-j", "ACCEPT"); err != nil {
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

	if err := m.runTable(table, "-A", m.Chain, "-j", "DROP"); err != nil {
		return err
	}
	m.setBaseFirewallEnabledForTable(table, true)
	return nil
}

func (m *Manager) appendEstablishedRelatedRule(table string) (bool, error) {
	err := m.runTable(table, "-A", m.Chain, "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT")
	if err == nil {
		return true, nil
	}
	if !isMatchUnavailableError(err, "state") {
		return false, err
	}

	conntrackErr := m.runTable(table, "-A", m.Chain, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT")
	if conntrackErr == nil {
		return true, nil
	}
	if !isMatchUnavailableError(conntrackErr, "conntrack") {
		return false, conntrackErr
	}

	if event := logger.DebugEvent("iptables", "established_related_rule_skipped"); event != nil {
		event.Str("table", logger.SanitizeLogString(table)).
			Str("chain", logger.SanitizeLogString(m.Chain)).
			Str("state_error", logger.SanitizeLogString(err.Error())).
			Str("conntrack_error", logger.SanitizeLogString(conntrackErr.Error())).
			Send()
	}
	return false, nil
}

func isMatchUnavailableError(err error, matchName string) bool {
	if err == nil {
		return false
	}
	matchName = strings.ToLower(strings.TrimSpace(matchName))
	if matchName == "" {
		return false
	}
	message := strings.ToLower(err.Error())
	if !strings.Contains(message, matchName) {
		return false
	}
	if strings.Contains(message, "couldn't load match") ||
		strings.Contains(message, "could not load match") ||
		strings.Contains(message, "can't load match") ||
		strings.Contains(message, "cannot load match") {
		return strings.Contains(message, "no such file or directory")
	}
	return strings.Contains(message, "extension "+matchName+" is not supported") ||
		strings.Contains(message, "missing kernel module")
}

func (m *Manager) Destroy() error {
	if event := logger.DebugEvent("iptables", "destroy_start"); event != nil {
		event.Str("chain", logger.SanitizeLogString(m.Chain)).
			Interface("parent_chains", debugArgs(m.ParentChains)).
			Interface("tables", debugArgs(m.tables)).
			Send()
	}
	for _, table := range m.tables {
		m.clearTCPPortAccessPolicyForTable(
			table,
			DefaultSSHFirewallChain,
			m.ParentChains,
		)
		for _, parent := range m.ParentChains {
			for {
				if err := m.runTable(table, "-D", parent, "-j", m.Chain); err != nil {
					break
				}
			}
		}

		_ = m.runTable(table, "-F", m.Chain)
		_ = m.runTable(table, "-X", m.Chain)
		for _, chain := range []string{whitelistChainName, whitelistMarkChainName} {
			_ = m.runTable(table, "-F", chain)
			_ = m.runTable(table, "-X", chain)
		}
	}
	if err := m.clearNftTCPPortAccessPolicy(); err != nil {
		return err
	}
	m.whitelistPolicyMu.Lock()
	if err := m.clearNftTable(whitelistNftTableName); err != nil {
		m.whitelistPolicyMu.Unlock()
		return err
	}
	m.whitelistNftReady = false
	m.whitelistPolicyMu.Unlock()
	if event := logger.DebugEvent("iptables", "destroy_end"); event != nil {
		event.Str("chain", logger.SanitizeLogString(m.Chain)).Send()
	}
	return nil
}

func (m *Manager) BlockAll() error {
	if event := logger.DebugEvent("iptables", "block_all_start"); event != nil {
		event.Str("chain", logger.SanitizeLogString(m.Chain)).Send()
	}
	_ = m.RemoveBlockAll()
	for _, table := range m.tables {
		if err := m.runTable(table, "-A", m.Chain, "-j", "DROP"); err != nil {
			if event := logger.DebugEvent("iptables", "block_all_failed"); event != nil {
				event.Str("table", logger.SanitizeLogString(table)).
					Str("chain", logger.SanitizeLogString(m.Chain)).
					Str("error", logger.SanitizeLogString(err.Error())).
					Send()
			}
			return errors.New(errors.CodeIptablesCommandError, fmt.Sprintf("Failed to block all (%s): %v", table, err))
		}
	}
	if event := logger.DebugEvent("iptables", "block_all_end"); event != nil {
		event.Str("chain", logger.SanitizeLogString(m.Chain)).Send()
	}
	return nil
}

func (m *Manager) AllowAll() error {
	err := m.RemoveBlockAll()
	if event := logger.DebugEvent("iptables", "allow_all"); event != nil {
		event.Str("chain", logger.SanitizeLogString(m.Chain)).
			Bool("ok", err == nil).
			Str("error", func() string {
				if err == nil {
					return ""
				}
				return logger.SanitizeLogString(err.Error())
			}()).
			Send()
	}
	return err
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
	if event := logger.DebugEvent("iptables", "allow_ip_start"); event != nil {
		event.Str("ip", logger.SanitizeLogString(ip)).
			Str("chain", logger.SanitizeLogString(m.Chain)).
			Send()
	}
	_ = m.RemoveIPRule(ip)
	table, err := m.tableForAddress(ip)
	if err != nil {
		if event := logger.DebugEvent("iptables", "allow_ip_failed"); event != nil {
			event.Str("ip", logger.SanitizeLogString(ip)).
				Str("error", logger.SanitizeLogString(err.Error())).
				Send()
		}
		return err
	}
	insertPos := strconv.Itoa(m.baseRuleCountForTable(table) + 1)
	if err := m.runTable(table, "-I", m.Chain, insertPos, "-s", ip, "-j", "ACCEPT"); err != nil {
		if event := logger.DebugEvent("iptables", "allow_ip_failed"); event != nil {
			event.Str("ip", logger.SanitizeLogString(ip)).
				Str("table", logger.SanitizeLogString(table)).
				Str("error", logger.SanitizeLogString(err.Error())).
				Send()
		}
		return errors.New(errors.CodeIptablesCommandError, fmt.Sprintf("Failed to allow IP %s (%s): %v", ip, table, err))
	}
	if event := logger.DebugEvent("iptables", "allow_ip_end"); event != nil {
		event.Str("ip", logger.SanitizeLogString(ip)).
			Str("table", logger.SanitizeLogString(table)).
			Send()
	}
	return nil
}

func (m *Manager) BlockIP(ip string) error {
	if event := logger.DebugEvent("iptables", "block_ip_start"); event != nil {
		event.Str("ip", logger.SanitizeLogString(ip)).
			Str("chain", logger.SanitizeLogString(m.Chain)).
			Send()
	}
	_ = m.RemoveIPRule(ip)
	table, err := m.tableForAddress(ip)
	if err != nil {
		if event := logger.DebugEvent("iptables", "block_ip_failed"); event != nil {
			event.Str("ip", logger.SanitizeLogString(ip)).
				Str("error", logger.SanitizeLogString(err.Error())).
				Send()
		}
		return err
	}
	insertPos := strconv.Itoa(m.baseRuleCountForTable(table) + 1)
	if err := m.runTable(table, "-I", m.Chain, insertPos, "-s", ip, "-j", "DROP"); err != nil {
		if event := logger.DebugEvent("iptables", "block_ip_failed"); event != nil {
			event.Str("ip", logger.SanitizeLogString(ip)).
				Str("table", logger.SanitizeLogString(table)).
				Str("error", logger.SanitizeLogString(err.Error())).
				Send()
		}
		return errors.New(errors.CodeIptablesCommandError, fmt.Sprintf("Failed to block IP %s (%s): %v", ip, table, err))
	}
	if event := logger.DebugEvent("iptables", "block_ip_end"); event != nil {
		event.Str("ip", logger.SanitizeLogString(ip)).
			Str("table", logger.SanitizeLogString(table)).
			Send()
	}
	return nil
}

func (m *Manager) BlockTCPPortForIP(ip string, port int) error {
	return m.ensureTCPPortRule(ip, port, "DROP")
}

func (m *Manager) ensureTCPPortRule(ip string, port int, action string) error {
	if event := logger.DebugEvent("iptables", "tcp_port_rule_start"); event != nil {
		event.Str("ip", logger.SanitizeLogString(ip)).
			Interface("port", logger.SanitizePort(port)).
			Str("action", logger.SanitizeLogString(action)).
			Str("chain", logger.SanitizeLogString(m.Chain)).
			Send()
	}
	if action != "ACCEPT" && action != "DROP" {
		if event := logger.DebugEvent("iptables", "tcp_port_rule_failed"); event != nil {
			event.Str("ip", logger.SanitizeLogString(ip)).
				Interface("port", logger.SanitizePort(port)).
				Str("action", logger.SanitizeLogString(action)).
				Str("error", "action must be ACCEPT or DROP").
				Send()
		}
		return errors.New(errors.CodeBadRequest, "action must be ACCEPT or DROP")
	}
	if err := validatePort(port); err != nil {
		if event := logger.DebugEvent("iptables", "tcp_port_rule_failed"); event != nil {
			event.Str("ip", logger.SanitizeLogString(ip)).
				Interface("port", logger.SanitizePort(port)).
				Str("action", logger.SanitizeLogString(action)).
				Str("error", logger.SanitizeLogString(err.Error())).
				Send()
		}
		return err
	}

	_ = m.RemoveTCPPortRule(ip, port)

	table, err := m.tableForAddress(ip)
	if err != nil {
		if event := logger.DebugEvent("iptables", "tcp_port_rule_failed"); event != nil {
			event.Str("ip", logger.SanitizeLogString(ip)).
				Interface("port", logger.SanitizePort(port)).
				Str("action", logger.SanitizeLogString(action)).
				Str("error", logger.SanitizeLogString(err.Error())).
				Send()
		}
		return err
	}

	insertPos := strconv.Itoa(m.baseRuleCountForTable(table) + 1)
	if err := m.runTable(
		table,
		"-I", m.Chain, insertPos,
		"-s", ip,
		"-p", "tcp",
		"--dport", strconv.Itoa(port),
		"-j", action,
	); err != nil {
		if event := logger.DebugEvent("iptables", "tcp_port_rule_failed"); event != nil {
			event.Str("ip", logger.SanitizeLogString(ip)).
				Interface("port", logger.SanitizePort(port)).
				Str("action", logger.SanitizeLogString(action)).
				Str("table", logger.SanitizeLogString(table)).
				Str("error", logger.SanitizeLogString(err.Error())).
				Send()
		}
		return errors.New(
			errors.CodeIptablesCommandError,
			fmt.Sprintf("Failed to add TCP port rule for IP %s port %d (%s): %v", ip, port, table, err),
		)
	}

	if event := logger.DebugEvent("iptables", "tcp_port_rule_end"); event != nil {
		event.Str("ip", logger.SanitizeLogString(ip)).
			Interface("port", logger.SanitizePort(port)).
			Str("action", logger.SanitizeLogString(action)).
			Str("table", logger.SanitizeLogString(table)).
			Send()
	}
	return nil
}

func (m *Manager) RemoveIPRule(ip string) error {
	table, err := m.tableForAddress(ip)
	if err != nil {
		if event := logger.DebugEvent("iptables", "remove_ip_rule_failed"); event != nil {
			event.Str("ip", logger.SanitizeLogString(ip)).
				Str("error", logger.SanitizeLogString(err.Error())).
				Send()
		}
		return err
	}
	_ = m.runTable(table, "-D", m.Chain, "-s", ip, "-j", "ACCEPT")
	_ = m.runTable(table, "-D", m.Chain, "-s", ip, "-j", "DROP")
	if event := logger.DebugEvent("iptables", "remove_ip_rule"); event != nil {
		event.Str("ip", logger.SanitizeLogString(ip)).
			Str("table", logger.SanitizeLogString(table)).
			Str("chain", logger.SanitizeLogString(m.Chain)).
			Send()
	}
	return nil
}

func (m *Manager) RemoveTCPPortRule(ip string, port int) error {
	if err := validatePort(port); err != nil {
		if event := logger.DebugEvent("iptables", "remove_tcp_port_rule_failed"); event != nil {
			event.Str("ip", logger.SanitizeLogString(ip)).
				Interface("port", logger.SanitizePort(port)).
				Str("error", logger.SanitizeLogString(err.Error())).
				Send()
		}
		return err
	}

	table, err := m.tableForAddress(ip)
	if err != nil {
		if event := logger.DebugEvent("iptables", "remove_tcp_port_rule_failed"); event != nil {
			event.Str("ip", logger.SanitizeLogString(ip)).
				Interface("port", logger.SanitizePort(port)).
				Str("error", logger.SanitizeLogString(err.Error())).
				Send()
		}
		return err
	}

	portText := strconv.Itoa(port)
	for {
		if err := m.runTable(
			table,
			"-D", m.Chain,
			"-s", ip,
			"-p", "tcp",
			"--dport", portText,
			"-j", "ACCEPT",
		); err != nil {
			break
		}
	}
	for {
		if err := m.runTable(
			table,
			"-D", m.Chain,
			"-s", ip,
			"-p", "tcp",
			"--dport", portText,
			"-j", "DROP",
		); err != nil {
			break
		}
	}

	if event := logger.DebugEvent("iptables", "remove_tcp_port_rule"); event != nil {
		event.Str("ip", logger.SanitizeLogString(ip)).
			Interface("port", logger.SanitizePort(port)).
			Str("table", logger.SanitizeLogString(table)).
			Str("chain", logger.SanitizeLogString(m.Chain)).
			Send()
	}
	return nil
}

func (m *Manager) EnsureTCPRedirect(listenPort int, targetPort int) error {
	if event := logger.DebugEvent("iptables", "tcp_redirect_ensure_start"); event != nil {
		event.Interface("listen_port", logger.SanitizePort(listenPort)).
			Interface("target_port", logger.SanitizePort(targetPort)).
			Interface("tables", debugArgs(m.tables)).
			Send()
	}
	if err := validatePort(listenPort); err != nil {
		if event := logger.DebugEvent("iptables", "tcp_redirect_ensure_failed"); event != nil {
			event.Interface("listen_port", logger.SanitizePort(listenPort)).
				Interface("target_port", logger.SanitizePort(targetPort)).
				Str("error", logger.SanitizeLogString(err.Error())).
				Send()
		}
		return err
	}
	if err := validatePort(targetPort); err != nil {
		if event := logger.DebugEvent("iptables", "tcp_redirect_ensure_failed"); event != nil {
			event.Interface("listen_port", logger.SanitizePort(listenPort)).
				Interface("target_port", logger.SanitizePort(targetPort)).
				Str("error", logger.SanitizeLogString(err.Error())).
				Send()
		}
		return err
	}

	for _, table := range m.tables {
		if err := m.clearTCPRedirectForTable(table, listenPort, targetPort); err != nil {
			return err
		}
		if err := m.runTable(table, redirectInsertArgs(listenPort, targetPort)...); err != nil {
			if event := logger.DebugEvent("iptables", "tcp_redirect_ensure_failed"); event != nil {
				event.Str("table", logger.SanitizeLogString(table)).
					Interface("listen_port", logger.SanitizePort(listenPort)).
					Interface("target_port", logger.SanitizePort(targetPort)).
					Str("error", logger.SanitizeLogString(err.Error())).
					Send()
			}
			return errors.New(
				errors.CodeIptablesCommandError,
				fmt.Sprintf("Failed to add TCP redirect %d->%d (%s): %v", listenPort, targetPort, table, err),
			)
		}
	}
	if event := logger.DebugEvent("iptables", "tcp_redirect_ensure_end"); event != nil {
		event.Interface("listen_port", logger.SanitizePort(listenPort)).
			Interface("target_port", logger.SanitizePort(targetPort)).
			Send()
	}
	return nil
}

func (m *Manager) ClearTCPRedirect(listenPort int, targetPort int) error {
	if event := logger.DebugEvent("iptables", "tcp_redirect_clear_start"); event != nil {
		event.Interface("listen_port", logger.SanitizePort(listenPort)).
			Interface("target_port", logger.SanitizePort(targetPort)).
			Interface("tables", debugArgs(m.tables)).
			Send()
	}
	if err := validatePort(listenPort); err != nil {
		if event := logger.DebugEvent("iptables", "tcp_redirect_clear_failed"); event != nil {
			event.Interface("listen_port", logger.SanitizePort(listenPort)).
				Interface("target_port", logger.SanitizePort(targetPort)).
				Str("error", logger.SanitizeLogString(err.Error())).
				Send()
		}
		return err
	}
	if err := validatePort(targetPort); err != nil {
		if event := logger.DebugEvent("iptables", "tcp_redirect_clear_failed"); event != nil {
			event.Interface("listen_port", logger.SanitizePort(listenPort)).
				Interface("target_port", logger.SanitizePort(targetPort)).
				Str("error", logger.SanitizeLogString(err.Error())).
				Send()
		}
		return err
	}

	for _, table := range m.tables {
		if err := m.clearTCPRedirectForTable(table, listenPort, targetPort); err != nil {
			if event := logger.DebugEvent("iptables", "tcp_redirect_clear_failed"); event != nil {
				event.Str("table", logger.SanitizeLogString(table)).
					Interface("listen_port", logger.SanitizePort(listenPort)).
					Interface("target_port", logger.SanitizePort(targetPort)).
					Str("error", logger.SanitizeLogString(err.Error())).
					Send()
			}
			return err
		}
	}
	if event := logger.DebugEvent("iptables", "tcp_redirect_clear_end"); event != nil {
		event.Interface("listen_port", logger.SanitizePort(listenPort)).
			Interface("target_port", logger.SanitizePort(targetPort)).
			Send()
	}
	return nil
}

func (m *Manager) clearTCPRedirectForTable(table string, listenPort int, targetPort int) error {
	for {
		if err := m.runTable(table, redirectDeleteArgs(listenPort, targetPort)...); err != nil {
			break
		}
	}
	return nil
}

func redirectInsertArgs(listenPort int, targetPort int) []string {
	return []string{
		"-t", "nat",
		"-I", "PREROUTING", "1",
		"-p", "tcp",
		"--dport", strconv.Itoa(listenPort),
		"-j", "REDIRECT",
		"--to-ports", strconv.Itoa(targetPort),
	}
}

func redirectDeleteArgs(listenPort int, targetPort int) []string {
	return []string{
		"-t", "nat",
		"-D", "PREROUTING",
		"-p", "tcp",
		"--dport", strconv.Itoa(listenPort),
		"-j", "REDIRECT",
		"--to-ports", strconv.Itoa(targetPort),
	}
}

func validatePort(port int) error {
	if port <= 0 || port > 65535 {
		return errors.New(errors.CodeBadRequest, "port must be between 1 and 65535")
	}
	return nil
}

type Rule struct {
	IP       string `json:"ip"`
	Action   string `json:"action"`             // ACCEPT or DROP
	Protocol string `json:"protocol,omitempty"` // tcp when the rule is port-scoped
	Port     int    `json:"port,omitempty"`
}

func (m *Manager) ParseRules() ([]Rule, error) {
	var rules []Rule

	for _, table := range m.tables {
		output, err := m.runTableOutput(table, "-S", m.Chain)
		if err != nil {
			return nil, errors.New(errors.CodeIptablesParseError, fmt.Sprintf("Failed to list rules (%s): %v", table, err))
		}

		for start := 0; start < len(output); {
			end := strings.IndexByte(output[start:], '\n')
			lineEnd := len(output)
			if end >= 0 {
				lineEnd = start + end
			}
			line := output[start:lineEnd]
			rule, ok := parseRuleLine(line)
			if ok && rule.IP != "0.0.0.0/0" && rule.IP != "::/0" {
				rules = append(rules, rule)
			}
			if end < 0 {
				break
			}
			start = lineEnd + 1
		}
	}
	return rules, nil
}

func parseRuleLine(line string) (Rule, bool) {
	var ip string
	var action string
	var protocol string
	var port int

	pendingField := ""
	for rest := line; ; {
		field, nextRest, ok := nextRuleField(rest)
		if !ok {
			break
		}
		if pendingField != "" {
			switch pendingField {
			case "-s":
				ip = field
				ip = strings.TrimSuffix(ip, "/32")
				ip = strings.TrimSuffix(ip, "/128")
			case "-p":
				protocol = lowerASCIIString(field)
			case "--dport":
				if parsed, ok := parsePortDigits(field); ok {
					port = parsed
				}
			case "-j":
				action = field
			}
			pendingField = ""
		}
		switch field {
		case "-s":
			pendingField = "-s"
		case "-p":
			pendingField = "-p"
		case "--dport":
			pendingField = "--dport"
		case "-j":
			pendingField = "-j"
		}
		rest = nextRest
	}

	if ip == "" || (action != "ACCEPT" && action != "DROP") {
		return Rule{}, false
	}

	return Rule{
		IP:       ip,
		Action:   action,
		Protocol: protocol,
		Port:     port,
	}, true
}

func parentJumpDeleteArgs(line string, parent string, chain string) ([]string, bool) {
	first, rest, ok := nextRuleField(line)
	if !ok || first != "-A" {
		return nil, false
	}
	second, rest, ok := nextRuleField(rest)
	if !ok || second != parent {
		return nil, false
	}
	var stackFields [16]string
	var extraFields []string
	fieldCount := 0
	previous := ""
	hasJump := false
	for {
		field, nextRest, ok := nextRuleField(rest)
		if !ok {
			break
		}
		if previous == "-j" && field == chain {
			hasJump = true
		}
		if fieldCount < len(stackFields) {
			stackFields[fieldCount] = field
		} else {
			extraFields = append(extraFields, field)
		}
		fieldCount++
		previous = field
		rest = nextRest
	}
	if !hasJump {
		return nil, false
	}
	args := make([]string, 0, 2+fieldCount)
	args = append(args, "-D", parent)
	if fieldCount <= len(stackFields) {
		args = append(args, stackFields[:fieldCount]...)
	} else {
		args = append(args, stackFields[:]...)
		args = append(args, extraFields...)
	}
	return args, true
}

func nextRuleField(line string) (field string, rest string, ok bool) {
	i := 0
	for i < len(line) && isASCIISpace(line[i]) {
		i++
	}
	if i >= len(line) {
		return "", "", false
	}
	start := i
	for i < len(line) && !isASCIISpace(line[i]) {
		i++
	}
	return line[start:i], line[i:], true
}

func lowerASCIIString(value string) string {
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c >= 0x80 || (c >= 'A' && c <= 'Z') {
			return strings.ToLower(value)
		}
	}
	return value
}

func parsePortDigits(value string) (int, bool) {
	if value == "" {
		return 0, false
	}
	maxInt := int(^uint(0) >> 1)
	port := 0
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		digit := int(c - '0')
		if port > (maxInt-digit)/10 {
			return 0, false
		}
		port = port*10 + digit
	}
	return port, true
}

func isASCIISpace(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', '\f', '\v':
		return true
	default:
		return false
	}
}
