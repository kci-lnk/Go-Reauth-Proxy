package iptables

import (
	"bytes"
	"encoding/json"
	"errors"
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
	if !callContains(runner.calls, "-I", "REAUTH_FW", "2", "-s", "198.51.100.7", "-j", "ACCEPT") {
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
	if !callContains(runner.calls, "-I", "REAUTH_FW", "2", "-s", "198.51.100.8", "-j", "DROP") {
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
	if !callContains(runner.calls, "-I", "REAUTH_FW", "2", "-s", "198.51.100.7", "-p", "tcp", "--dport", "22", "-j", "DROP") {
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
	for _, want := range []string{"-A SSH_TEST -s 10.0.0.0/8 -j ACCEPT", "-A SSH_TEST -s 198.51.100.9 -j DROP", "-A SSH_TEST -s 203.0.113.0/24 -j ACCEPT", "-A SSH_TEST -j DROP"} {
		if !strings.Contains(input, want) {
			t.Fatalf("restore input missing %q:\n%s", want, input)
		}
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
	if !callContains(runner.calls, "-I", "REAUTH_FW", "2", "-s", "198.51.100.7", "-j", "ACCEPT") {
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
