package iptables

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"go-reauth-proxy/pkg/config"
)

type recordingIptablesRunner struct {
	calls    [][]string
	restores []recordedRestore
	outputs  map[string]string
}

type recordedRestore struct {
	Input   string
	Command string
	Args    []string
}

type failingNftDeleteRunner struct {
	recordingIptablesRunner
}

func (r *failingNftDeleteRunner) CombinedOutput(command string, args ...string) ([]byte, error) {
	if command == "nft" && len(args) >= 4 && args[0] == "delete" && args[1] == "table" {
		return []byte("Operation not permitted"), errors.New("exit status 1")
	}
	return r.recordingIptablesRunner.CombinedOutput(command, args...)
}

func (r *recordingIptablesRunner) CombinedOutput(command string, args ...string) ([]byte, error) {
	call := append([]string{command}, args...)
	r.calls = append(r.calls, call)
	for _, arg := range args {
		if arg == "-D" {
			return []byte("missing"), errors.New("missing rule")
		}
	}
	if len(args) >= 1 && args[0] == "-S" {
		if r.outputs != nil {
			return []byte(r.outputs[strings.Join(call, "\x00")]), nil
		}
		return []byte("-A INPUT -p tcp --dport 22 -j TEST_CHAIN\n"), nil
	}
	return []byte("ok"), nil
}

func (r *recordingIptablesRunner) CombinedOutputWithInput(input string, command string, args ...string) ([]byte, error) {
	r.restores = append(r.restores, recordedRestore{Input: input, Command: command, Args: append([]string(nil), args...)})
	return []byte("ok"), nil
}

func TestParseParentChainsStringSplitsCommaSeparatedValues(t *testing.T) {
	got := parseParentChains(" INPUT, DOCKER-USER ,, FORWARD ")
	want := []string{"INPUT", "DOCKER-USER", "FORWARD"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseParentChains() = %#v, want %#v", got, want)
	}
}

func TestParseParentChainsInterfaceSliceFlattensStrings(t *testing.T) {
	got := parseParentChains([]interface{}{"INPUT,FORWARD", 7, " DOCKER-USER "})
	want := []string{"INPUT", "FORWARD", "DOCKER-USER"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseParentChains() = %#v, want %#v", got, want)
	}
}

func TestSplitCommaSeparatedDropsEmptyParts(t *testing.T) {
	got := splitCommaSeparated(" a,, b , ")
	want := []string{"a", "b"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("splitCommaSeparated() = %#v, want %#v", got, want)
	}
}

func TestNewManagerAppliesDefaultChainParentsAndTables(t *testing.T) {
	manager := NewManager(Options{})
	if manager.Chain != "REAUTH_FW" {
		t.Fatalf("Chain = %q", manager.Chain)
	}
	if !reflect.DeepEqual(manager.ParentChains, []string{"INPUT"}) {
		t.Fatalf("ParentChains = %#v", manager.ParentChains)
	}
	if !reflect.DeepEqual(manager.tables, []string{"iptables", "ip6tables"}) {
		t.Fatalf("tables = %#v", manager.tables)
	}
}

func TestDisabledManagerNeverInvokesCommandRunner(t *testing.T) {
	runner := &recordingIptablesRunner{}
	manager := NewManager(Options{Disabled: true})
	manager.runner = runner

	if err := manager.Init(); err == nil {
		t.Fatal("Init() error = nil, want disabled error")
	}
	if _, err := manager.ParseRules(); err == nil {
		t.Fatal("ParseRules() error = nil, want disabled error")
	}
	if len(runner.calls) != 0 || len(runner.restores) != 0 {
		t.Fatalf("disabled manager invoked command runner: calls=%v restores=%v", runner.calls, runner.restores)
	}
}

func TestNormalizeTablesTrimsAndDeduplicates(t *testing.T) {
	got := normalizeTables([]string{" iptables ", "", "iptables", "ip6tables"})
	want := []string{"iptables", "ip6tables"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalizeTables() = %#v, want %#v", got, want)
	}
}

func TestTableForAddressUsesIPv4Table(t *testing.T) {
	manager := NewManager(Options{Tables: []string{"iptables"}})
	got, err := manager.tableForAddress("198.51.100.7")
	if err != nil || got != "iptables" {
		t.Fatalf("tableForAddress() = %q, %v; want iptables", got, err)
	}
}

func TestTableForAddressRejectsIPv6WhenTableDisabled(t *testing.T) {
	manager := NewManager(Options{Tables: []string{"iptables"}})
	if _, err := manager.tableForAddress("2001:db8::1"); err == nil {
		t.Fatal("tableForAddress() returned nil error for disabled ip6tables")
	}
}

func TestTableForAddressAcceptsCIDR(t *testing.T) {
	manager := NewManager(Options{Tables: []string{"iptables", "ip6tables"}})
	got, err := manager.tableForAddress("203.0.113.0/24")
	if err != nil || got != "iptables" {
		t.Fatalf("tableForAddress(CIDR) = %q, %v; want iptables", got, err)
	}
}

func TestValidatePortRejectsZero(t *testing.T) {
	if err := validatePort(0); err == nil {
		t.Fatal("validatePort(0) returned nil error")
	}
}

func TestValidatePortRejectsTooLarge(t *testing.T) {
	if err := validatePort(65536); err == nil {
		t.Fatal("validatePort(65536) returned nil error")
	}
}

func TestNormalizePortsDeduplicates(t *testing.T) {
	got, err := normalizePorts([]int{22, 22, 443})
	if err != nil {
		t.Fatalf("normalizePorts() returned error: %v", err)
	}
	want := []int{22, 443}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalizePorts() = %#v, want %#v", got, want)
	}
}

func TestNormalizeSourcesTrimsAndDeduplicatesCaseInsensitively(t *testing.T) {
	got := normalizeSources([]string{" 2001:DB8::1 ", "2001:db8::1", "", "198.51.100.7"})
	want := []string{"2001:DB8::1", "198.51.100.7"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalizeSources() = %#v, want %#v", got, want)
	}
}

func TestNormalizeDefaultActionDefaultsToReturn(t *testing.T) {
	got, err := normalizeDefaultAction(" ")
	if err != nil || got != "RETURN" {
		t.Fatalf("normalizeDefaultAction() = %q, %v; want RETURN", got, err)
	}
}

func TestNormalizeDefaultActionRejectsUnknownAction(t *testing.T) {
	if _, err := normalizeDefaultAction("ACCEPT"); err == nil {
		t.Fatal("normalizeDefaultAction() accepted unsupported action")
	}
}

func TestRestoreCommandForTableRejectsUnknownTable(t *testing.T) {
	if got := restoreCommandForTable("nft"); got != "" {
		t.Fatalf("restoreCommandForTable() = %q, want empty", got)
	}
}

func TestRunTableRestoreRejectsUnsupportedTable(t *testing.T) {
	manager := NewManager(Options{Tables: []string{"iptables"}})
	manager.runner = &recordingIptablesRunner{}
	if err := manager.runTableRestore("nft", "*filter\nCOMMIT\n"); err == nil {
		t.Fatal("runTableRestore() returned nil error for unsupported table")
	}
}

func TestRedirectInsertArgsContainsPorts(t *testing.T) {
	got := redirectInsertArgs(80, 7999)
	want := []string{"-t", "nat", "-I", "PREROUTING", "1", "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-ports", "7999"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("redirectInsertArgs() = %#v, want %#v", got, want)
	}
}

func TestRedirectDeleteArgsContainsPorts(t *testing.T) {
	got := redirectDeleteArgs(443, 7999)
	want := []string{"-t", "nat", "-D", "PREROUTING", "-p", "tcp", "--dport", "443", "-j", "REDIRECT", "--to-ports", "7999"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("redirectDeleteArgs() = %#v, want %#v", got, want)
	}
}

func TestAllowIPInsertsAcceptRuleAfterBaseRules(t *testing.T) {
	runner := &recordingIptablesRunner{}
	manager := NewManager(Options{ChainName: "REAUTH_FW", Tables: []string{"iptables"}})
	manager.runner = runner
	manager.setBaseFirewallEnabledForTable("iptables", false)

	if err := manager.AllowIP("198.51.100.7"); err != nil {
		t.Fatalf("AllowIP() returned error: %v", err)
	}
	if !callContains(runner.calls, "-I", "REAUTH_FW", "4", "-s", "198.51.100.7", "-j", "ACCEPT") {
		t.Fatalf("ACCEPT insert not recorded: %#v", runner.calls)
	}
}

func TestBlockIPInsertsDropRuleAfterBaseRules(t *testing.T) {
	runner := &recordingIptablesRunner{}
	manager := NewManager(Options{ChainName: "REAUTH_FW", Tables: []string{"iptables"}})
	manager.runner = runner
	manager.setBaseFirewallEnabledForTable("iptables", false)

	if err := manager.BlockIP("198.51.100.8"); err != nil {
		t.Fatalf("BlockIP() returned error: %v", err)
	}
	if !callContains(runner.calls, "-I", "REAUTH_FW", "4", "-s", "198.51.100.8", "-j", "DROP") {
		t.Fatalf("DROP insert not recorded: %#v", runner.calls)
	}
}

func TestBlockTCPPortForIPRejectsInvalidPort(t *testing.T) {
	manager := NewManager(Options{Tables: []string{"iptables"}})
	manager.runner = &recordingIptablesRunner{}
	if err := manager.BlockTCPPortForIP("198.51.100.7", 0); err == nil {
		t.Fatal("BlockTCPPortForIP() returned nil error for invalid port")
	}
}

func TestBlockTCPPortForIPInsertsPortScopedDrop(t *testing.T) {
	runner := &recordingIptablesRunner{}
	manager := NewManager(Options{ChainName: "REAUTH_FW", Tables: []string{"iptables"}})
	manager.runner = runner
	manager.setBaseFirewallEnabledForTable("iptables", false)

	if err := manager.BlockTCPPortForIP("198.51.100.7", 22); err != nil {
		t.Fatalf("BlockTCPPortForIP() returned error: %v", err)
	}
	if !callContains(runner.calls, "-I", "REAUTH_FW", "4", "-s", "198.51.100.7", "-p", "tcp", "--dport", "22", "-j", "DROP") {
		t.Fatalf("port DROP insert not recorded: %#v", runner.calls)
	}
}

func TestEnsureTCPRedirectDeletesThenInserts(t *testing.T) {
	runner := &recordingIptablesRunner{}
	manager := NewManager(Options{Tables: []string{"iptables"}})
	manager.runner = runner

	if err := manager.EnsureTCPRedirect(80, 7999); err != nil {
		t.Fatalf("EnsureTCPRedirect() returned error: %v", err)
	}
	if !callContains(runner.calls, redirectDeleteArgs(80, 7999)...) ||
		!callContains(runner.calls, redirectInsertArgs(80, 7999)...) {
		t.Fatalf("redirect delete/insert not recorded: %#v", runner.calls)
	}
}

func TestClearTCPRedirectDeletesOnly(t *testing.T) {
	runner := &recordingIptablesRunner{}
	manager := NewManager(Options{Tables: []string{"iptables"}})
	manager.runner = runner

	if err := manager.ClearTCPRedirect(443, 7999); err != nil {
		t.Fatalf("ClearTCPRedirect() returned error: %v", err)
	}
	if !callContains(runner.calls, redirectDeleteArgs(443, 7999)...) {
		t.Fatalf("redirect delete not recorded: %#v", runner.calls)
	}
	if callContains(runner.calls, redirectInsertArgs(443, 7999)...) {
		t.Fatalf("redirect insert should not be recorded: %#v", runner.calls)
	}
}

func TestSyncTCPPortAccessPolicyWritesRestoreInput(t *testing.T) {
	runner := &recordingIptablesRunner{}
	manager := NewManager(Options{Tables: []string{"iptables"}, ParentChain: []string{"INPUT"}})
	manager.runner = runner

	err := manager.SyncTCPPortAccessPolicy(TCPPortAccessPolicy{
		Chain:             "SSH_TEST",
		Ports:             []int{22},
		AllowSources:      []string{"203.0.113.0/24"},
		BlockSources:      []string{"198.51.100.9"},
		IncludeLocalCIDRs: true,
		DefaultAction:     "DROP",
	})
	if err != nil {
		t.Fatalf("SyncTCPPortAccessPolicy() returned error: %v", err)
	}
	if len(runner.restores) != 1 {
		t.Fatalf("restore count = %d, want 1; calls=%#v", len(runner.restores), runner.calls)
	}
	input := runner.restores[0].Input
	rulesInOrder := []string{
		"-A SSH_TEST -i lo -j ACCEPT",
		"-A SSH_TEST -s 10.0.0.0/8 -j ACCEPT",
		"-A SSH_TEST -s 100.64.0.0/10 -j ACCEPT",
		"-A SSH_TEST -s 198.51.100.9 -j DROP",
		"-A SSH_TEST -s 203.0.113.0/24 -j ACCEPT",
		"-A SSH_TEST -j DROP",
	}
	previousIndex := -1
	for _, want := range rulesInOrder {
		if !strings.Contains(input, want) {
			t.Fatalf("restore input missing %q:\n%s", want, input)
		}
		index := strings.Index(input, want)
		if index <= previousIndex {
			t.Fatalf("restore rule %q is out of order:\n%s", want, input)
		}
		previousIndex = index
	}
}

func TestSyncTCPPortAccessPolicyAllowsLoopbackAndPrivateIPv6(t *testing.T) {
	runner := &recordingIptablesRunner{}
	manager := NewManager(Options{Tables: []string{"ip6tables"}, ParentChain: []string{"INPUT"}})
	manager.runner = runner

	err := manager.SyncTCPPortAccessPolicy(TCPPortAccessPolicy{
		Chain:             "SSH_TEST",
		Ports:             []int{22},
		AllowSources:      []string{"2001:db8::/32"},
		IncludeLocalCIDRs: true,
		DefaultAction:     "DROP",
	})
	if err != nil {
		t.Fatalf("SyncTCPPortAccessPolicy() returned error: %v", err)
	}
	if len(runner.restores) != 1 {
		t.Fatalf("restore count = %d, want 1; calls=%#v", len(runner.restores), runner.calls)
	}
	input := runner.restores[0].Input
	for _, want := range []string{
		"-A SSH_TEST -i lo -j ACCEPT",
		"-A SSH_TEST -s fc00::/7 -j ACCEPT",
		"-A SSH_TEST -s fe80::/10 -j ACCEPT",
		"-A SSH_TEST -s 2001:db8::/32 -j ACCEPT",
		"-A SSH_TEST -j DROP",
	} {
		if !strings.Contains(input, want) {
			t.Fatalf("restore input missing %q:\n%s", want, input)
		}
	}
}

func TestSyncTCPPortAccessPolicyDoesNotTrustLocalSourcesWhenDisabled(t *testing.T) {
	runner := &recordingIptablesRunner{}
	manager := NewManager(Options{Tables: []string{"iptables"}, ParentChain: []string{"INPUT"}})
	manager.runner = runner

	err := manager.SyncTCPPortAccessPolicy(TCPPortAccessPolicy{
		Chain:         "SSH_TEST",
		Ports:         []int{22},
		AllowSources:  []string{"203.0.113.0/24"},
		DefaultAction: "DROP",
	})
	if err != nil {
		t.Fatalf("SyncTCPPortAccessPolicy() returned error: %v", err)
	}
	if len(runner.restores) != 1 {
		t.Fatalf("restore count = %d, want 1; calls=%#v", len(runner.restores), runner.calls)
	}
	input := runner.restores[0].Input
	for _, unwanted := range []string{" -i lo -j ACCEPT", " -s 10.0.0.0/8 -j ACCEPT", " -s 100.64.0.0/10 -j ACCEPT"} {
		if strings.Contains(input, unwanted) {
			t.Fatalf("restore input unexpectedly trusts %q:\n%s", unwanted, input)
		}
	}
}

func TestSyncTCPPortAccessPolicyUsesNftIntervalSetsForLargePolicies(t *testing.T) {
	runner := &recordingIptablesRunner{}
	manager := NewManager(Options{
		Tables:      []string{"iptables", "ip6tables"},
		ParentChain: []string{"INPUT", "DOCKER-USER"},
	})
	manager.runner = runner
	manager.nftCommand = "nft"
	allowSources := make([]string, 0, nftIntervalSetMinSourceSize)
	for index := range nftIntervalSetMinSourceSize {
		allowSources = append(allowSources, fmt.Sprintf("198.18.%d.%d/32", index/256, index%256))
	}

	err := manager.SyncTCPPortAccessPolicy(TCPPortAccessPolicy{
		Chain:             "SSH_TEST",
		ParentChains:      []string{"INPUT", "DOCKER-USER"},
		Ports:             []int{22, 2222},
		AllowSources:      allowSources,
		BlockSources:      []string{"2001:db8::7"},
		IncludeLocalCIDRs: true,
		DefaultAction:     "DROP",
	})
	if err != nil {
		t.Fatalf("SyncTCPPortAccessPolicy() returned error: %v", err)
	}
	if len(runner.restores) != 3 {
		t.Fatalf("restore count = %d, want one nft and two compact iptables restores", len(runner.restores))
	}
	restore := runner.restores[0]
	if restore.Command != "nft" || !reflect.DeepEqual(restore.Args, []string{"-f", "-"}) {
		t.Fatalf("nft command = %q %#v", restore.Command, restore.Args)
	}
	for _, want := range []string{
		"add set inet fnknock_ssh allow4 { type ipv4_addr; flags interval; }",
		"add set inet fnknock_ssh block6 { type ipv6_addr; flags interval; }",
		"add rule inet fnknock_ssh input_classify meta mark set meta mark & 0xcfffffff",
		"add rule inet fnknock_ssh input_classify ip saddr @allow4 meta mark set meta mark | 0x10000000",
		"add rule inet fnknock_ssh forward_classify ip6 saddr @block6 meta mark set meta mark | 0x20000000",
		"add chain inet fnknock_ssh input_classify { type filter hook input priority -1; policy accept; }",
		"add chain inet fnknock_ssh forward_clear { type filter hook forward priority 10; policy accept; }",
	} {
		if !strings.Contains(restore.Input, want) {
			t.Fatalf("nft input missing %q:\n%s", want, restore.Input)
		}
	}
	if strings.Count(restore.Input, "ip saddr @allow4 meta mark set meta mark | 0x10000000") != 2 {
		t.Fatalf("large allow set should use one membership rule:\n%s", restore.Input)
	}
	if strings.Contains(restore.Input, " drop\n") || strings.Contains(restore.Input, " jump enforce") {
		t.Fatalf("native classifier must not enforce outside configured parent chains:\n%s", restore.Input)
	}
	for _, restore := range runner.restores[1:] {
		if strings.Contains(restore.Input, "198.18.") {
			t.Fatalf("compact iptables classifier unexpectedly expanded CIDRs:\n%s", restore.Input)
		}
		for _, want := range []string{
			"-m mark --mark 0x20000000/0x20000000 -j FNK-SSH-BLOCK",
			"-m mark --mark 0x10000000/0x10000000 -j FNK-SSH-ALLOW",
			"-j MARK --set-xmark 0x0/0x30000000",
		} {
			if !strings.Contains(restore.Input, want) {
				t.Fatalf("compact SSH restore missing %q:\n%s", want, restore.Input)
			}
		}
	}
	if !callContains(runner.calls, "-C", "DOCKER-USER", "-p", "tcp", "--dport", "22", "-j", "SSH_TEST") {
		t.Fatalf("DOCKER-USER scoped jump was not reconciled: %#v", runner.calls)
	}
}

func TestSyncWhitelistIPSetUsesOneNativeIntervalPolicy(t *testing.T) {
	runner := &recordingIptablesRunner{}
	manager := NewManager(Options{
		Tables:      []string{"iptables", "ip6tables"},
		ParentChain: []string{"INPUT", "DOCKER-USER"},
	})
	manager.runner = runner
	manager.nftCommand = "nft"

	if err := manager.SyncWhitelistIPSet([]string{"192.0.2.0/24", "2001:db8::/48"}); err != nil {
		t.Fatalf("SyncWhitelistIPSet() returned error: %v", err)
	}
	if len(runner.restores) != 1 {
		t.Fatalf("nft restore count = %d, want 1", len(runner.restores))
	}
	input := runner.restores[0].Input
	for _, want := range []string{
		"add set inet fnknock_whitelist allow4 { type ipv4_addr; flags interval; }",
		"add set inet fnknock_whitelist allow6 { type ipv6_addr; flags interval; }",
		"add chain inet fnknock_whitelist input_mark { type filter hook input priority -1; policy accept; }",
		"add chain inet fnknock_whitelist forward_mark { type filter hook forward priority -1; policy accept; }",
		"input_mark meta mark set meta mark & 0xbfffffff",
		"forward_mark meta mark set meta mark & 0xbfffffff",
		"ip saddr @allow4 meta mark set meta mark | 0x40000000",
		"ip6 saddr @allow6 meta mark set meta mark | 0x40000000",
	} {
		if !strings.Contains(input, want) {
			t.Fatalf("nft input missing %q:\n%s", want, input)
		}
	}
	clearIndex := strings.Index(input, "input_mark meta mark set meta mark & 0xbfffffff")
	setIndex := strings.Index(input, "input_mark ip saddr @allow4 meta mark set meta mark | 0x40000000")
	if clearIndex < 0 || setIndex < 0 || clearIndex >= setIndex {
		t.Fatalf("whitelist classifier must clear an untrusted mark before setting it:\n%s", input)
	}
}

func TestSyncEmptyWhitelistKeepsMarkSanitizerActive(t *testing.T) {
	runner := &recordingIptablesRunner{}
	manager := NewManager(Options{
		Tables:      []string{"iptables", "ip6tables"},
		ParentChain: []string{"INPUT", "DOCKER-USER"},
	})
	manager.runner = runner
	manager.nftCommand = "nft"

	if err := manager.SyncWhitelistIPSet(nil); err != nil {
		t.Fatalf("SyncWhitelistIPSet(nil) returned error: %v", err)
	}
	if len(runner.restores) != 1 {
		t.Fatalf("nft restore count = %d, want 1", len(runner.restores))
	}
	input := runner.restores[0].Input
	if !strings.Contains(input, "input_mark meta mark set meta mark & 0xbfffffff") {
		t.Fatalf("empty whitelist must retain the mark sanitizer:\n%s", input)
	}
	if strings.Contains(input, "meta mark set meta mark | 0x40000000") {
		t.Fatalf("empty whitelist unexpectedly marks a source as trusted:\n%s", input)
	}
}

func TestClearTCPPortAccessPolicyPropagatesNftDeleteFailure(t *testing.T) {
	runner := &failingNftDeleteRunner{}
	manager := NewManager(Options{Tables: []string{"iptables"}})
	manager.runner = runner
	manager.nftCommand = "nft"

	err := manager.ClearTCPPortAccessPolicy("SSH_TEST", []string{"INPUT"})
	if err == nil || !strings.Contains(err.Error(), "Operation not permitted") {
		t.Fatalf("ClearTCPPortAccessPolicy() error = %v, want nft delete failure", err)
	}
}

func TestDestroyRemovesClassifierSupportChainsAndTables(t *testing.T) {
	runner := &recordingIptablesRunner{}
	manager := NewManager(Options{
		ChainName:   "REAUTH_FW",
		Tables:      []string{"iptables"},
		ParentChain: []string{"INPUT"},
	})
	manager.runner = runner
	manager.nftCommand = "nft"
	manager.whitelistNftReady = true

	if err := manager.Destroy(); err != nil {
		t.Fatalf("Destroy() returned error: %v", err)
	}
	for _, chain := range []string{
		DefaultSSHFirewallChain,
		sshAllowActionChain,
		sshBlockActionChain,
		sshDefaultActionChain,
		whitelistChainName,
		whitelistMarkChainName,
	} {
		if !callContains(runner.calls, "-F", chain) || !callContains(runner.calls, "-X", chain) {
			t.Fatalf("Destroy() did not remove %s: %#v", chain, runner.calls)
		}
	}
	if !callContains(runner.calls, "delete", "table", "inet", sshNftTableName) ||
		!callContains(runner.calls, "delete", "table", "inet", whitelistNftTableName) {
		t.Fatalf("Destroy() did not remove nft classifier tables: %#v", runner.calls)
	}
}

func TestSyncTCPPortAccessPolicyClearsWhenPortsEmpty(t *testing.T) {
	runner := &recordingIptablesRunner{}
	manager := NewManager(Options{Tables: []string{"iptables"}, ParentChain: []string{"INPUT"}})
	manager.runner = runner

	if err := manager.SyncTCPPortAccessPolicy(TCPPortAccessPolicy{Chain: "SSH_TEST"}); err != nil {
		t.Fatalf("SyncTCPPortAccessPolicy() returned error: %v", err)
	}
	if !callContains(runner.calls, "-F", "SSH_TEST") || !callContains(runner.calls, "-X", "SSH_TEST") {
		t.Fatalf("clear calls not recorded: %#v", runner.calls)
	}
}

func TestPortListUnmarshalAcceptsCommaSeparatedString(t *testing.T) {
	var ports PortList
	if err := json.Unmarshal([]byte(`"22, 443,, 8080"`), &ports); err != nil {
		t.Fatalf("UnmarshalJSON() returned error: %v", err)
	}
	if !reflect.DeepEqual([]string(ports), []string{"22", "443", "8080"}) {
		t.Fatalf("ports = %#v", ports)
	}
}

func TestPortListUnmarshalAcceptsNumberArray(t *testing.T) {
	var ports PortList
	if err := json.Unmarshal([]byte(`[22,0,443]`), &ports); err != nil {
		t.Fatalf("UnmarshalJSON() returned error: %v", err)
	}
	if !reflect.DeepEqual([]string(ports), []string{"22", "443"}) {
		t.Fatalf("ports = %#v", ports)
	}
}

func TestIntPortListUnmarshalAcceptsStringArray(t *testing.T) {
	var ports IntPortList
	if err := json.Unmarshal([]byte(`["22, 443","bad","8080"]`), &ports); err != nil {
		t.Fatalf("UnmarshalJSON() returned error: %v", err)
	}
	if !reflect.DeepEqual([]int(ports), []int{22, 443, 8080}) {
		t.Fatalf("ports = %#v", ports)
	}
}

func TestHandleAllowIPRejectsMissingIP(t *testing.T) {
	rec := httptest.NewRecorder()
	handler := NewHandler(newRecordingManager(), nil)
	handler.HandleAllowIP(rec, httptest.NewRequest(http.MethodPost, "/allow", strings.NewReader(`{}`)))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"success":false`) {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandleAllowIPRecordsManagerCommand(t *testing.T) {
	manager := newRecordingManager()
	handler := NewHandler(manager, nil)
	rec := httptest.NewRecorder()
	handler.HandleAllowIP(rec, httptest.NewRequest(http.MethodPost, "/allow", strings.NewReader(`{"ip":"198.51.100.7"}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	runner := manager.runner.(*recordingIptablesRunner)
	if !callContains(runner.calls, "-I", "REAUTH_FW", "4", "-s", "198.51.100.7", "-j", "ACCEPT") {
		t.Fatalf("allow command not recorded: %#v", runner.calls)
	}
}

func TestHandleInitPersistsRequestedChainName(t *testing.T) {
	tempDir := t.TempDir()
	cfgManager := config.NewManager(tempDir + "/config.json")
	manager := newRecordingManager()
	handler := NewHandler(manager, cfgManager)

	rec := httptest.NewRecorder()
	handler.HandleInit(rec, httptest.NewRequest(http.MethodPost, "/init", bytes.NewReader([]byte(`{"chain_name":"TEST_FW","parent_chain":["INPUT"],"exempt_ports":[7999]}`))))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	cfg, err := cfgManager.Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if cfg.IptablesChainName != "TEST_FW" {
		t.Fatalf("IptablesChainName = %q", cfg.IptablesChainName)
	}
}

func TestHandleInitRejectsOversizedBody(t *testing.T) {
	handler := NewHandler(newRecordingManager(), nil)
	rec := httptest.NewRecorder()
	body := bytes.Repeat([]byte("x"), int(iptablesJSONBodyLimitBytes)+1)
	handler.HandleInit(rec, httptest.NewRequest(http.MethodPost, "/init", bytes.NewReader(body)))
	if rec.Code != http.StatusRequestEntityTooLarge || !strings.Contains(rec.Body.String(), `"success":false`) {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandleAllowIPRejectsOversizedBody(t *testing.T) {
	handler := NewHandler(newRecordingManager(), nil)
	rec := httptest.NewRecorder()
	body := bytes.Repeat([]byte("x"), int(iptablesJSONBodyLimitBytes)+1)
	handler.HandleAllowIP(rec, httptest.NewRequest(http.MethodPost, "/allow", bytes.NewReader(body)))
	if rec.Code != http.StatusRequestEntityTooLarge || !strings.Contains(rec.Body.String(), `"success":false`) {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandleAllowIPRejectsUnknownLengthOversizedTrailingWhitespace(t *testing.T) {
	handler := NewHandler(newRecordingManager(), nil)
	rec := httptest.NewRecorder()
	body := append([]byte(`{"ip":"198.51.100.7"}`), bytes.Repeat([]byte(" "), int(iptablesJSONBodyLimitBytes)+1)...)
	req := httptest.NewRequest(http.MethodPost, "/allow", bytes.NewReader(body))
	req.ContentLength = -1
	handler.HandleAllowIP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge || !strings.Contains(rec.Body.String(), `"success":false`) {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandleEnsureTCPRedirectRejectsInvalidJSON(t *testing.T) {
	rec := httptest.NewRecorder()
	handler := NewHandler(newRecordingManager(), nil)
	handler.HandleEnsureTCPRedirect(rec, httptest.NewRequest(http.MethodPost, "/redirect", strings.NewReader(`{`)))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"success":false`) {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
}

func newRecordingManager() *Manager {
	manager := NewManager(Options{ChainName: "REAUTH_FW", Tables: []string{"iptables"}, ParentChain: []string{"INPUT"}})
	manager.runner = &recordingIptablesRunner{}
	manager.setBaseFirewallEnabledForTable("iptables", false)
	return manager
}
