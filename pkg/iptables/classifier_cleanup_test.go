package iptables

import (
	"errors"
	"strings"
	"testing"
)

type inspectionErrorRunner struct {
	recordingIptablesRunner
	output string
}

func (r *inspectionErrorRunner) CombinedOutput(command string, args ...string) ([]byte, error) {
	return []byte(r.output), errors.New("inspection failed")
}

func TestChainInspectionDistinguishesMissingChainFromMissingExtension(t *testing.T) {
	for _, tc := range []struct {
		output  string
		missing bool
	}{
		{"No chain/target/match by that name", true},
		{"chain FNK-WL-MARK does not exist", true},
		{"Couldn't load match `mark':No such file or directory", false},
		{"Permission denied", false},
		{"No chain/target/match by that name\nOperation not permitted", false},
	} {
		m := newClassifierTestManager(&inspectionErrorRunner{output: tc.output})
		_, exists, err := m.chainRulesIfExists("iptables", whitelistMarkChainName)
		if exists || (err == nil) != tc.missing {
			t.Errorf("inspection %q: exists=%v, err=%v", tc.output, exists, err)
		}
	}
}

func TestClassifierCleanupIgnoresQuotedJumps(t *testing.T) {
	for _, rule := range []string{
		`-A INPUT -m comment --comment "text -j FNK-WL-MARK text" -j ACCEPT`,
		`-A INPUT -m comment --comment "escaped \"quote\" -j FNK-WL-MARK text" -j ACCEPT`,
		`-A INPUT -m comment --comment "-j" -j ACCEPT`,
		`-A INPUT -m comment --comment -j -j ACCEPT`,
	} {
		if firewallRuleJumpsTo(rule, "INPUT", whitelistMarkChainName) {
			t.Errorf("comment mistaken for jump: %s", rule)
		}
	}
	rule := `-A INPUT -m comment --comment "keep  spacing and \"quotes\"" -j FNK-WL-MARK`
	r := &classifierTestRunner{recordingIptablesRunner: recordingIptablesRunner{outputs: map[string]string{
		"iptables\x00-S\x00INPUT": rule + "\n",
	}}}
	m := newClassifierTestManager(r)
	if err := m.deleteParentJumpsToChain("iptables", "INPUT", whitelistMarkChainName); err != nil {
		t.Fatal(err)
	}
	if len(r.restores) != 1 || r.restores[0].Input != "*filter\n-D"+rule[2:]+"\nCOMMIT\n" {
		t.Fatalf("comment was changed during deletion: %#v", r.restores)
	}
}

func TestUnusedChainRemovalIsAtomic(t *testing.T) {
	r := &classifierTestRunner{restoreFail: true}
	m := newClassifierTestManager(r)
	if err := m.removeUnusedChain("iptables", sshBlockActionChain); err == nil {
		t.Fatal("failed removal reported success")
	}
	if callContains(r.calls, "-F", sshBlockActionChain) {
		t.Fatal("live chain flushed outside deletion transaction")
	}
	if len(r.restores) != 1 || r.restores[0].Input != "*filter\n-F FNK-SSH-BLOCK\n-X FNK-SSH-BLOCK\nCOMMIT\n" {
		t.Fatalf("non-atomic chain removal: %#v", r.restores)
	}
}

func TestFallbackRemovesStaleConsumersInReplacementTransaction(t *testing.T) {
	r := &classifierTestRunner{failTable: "iptables", markError: issue63MarkError}
	m := newClassifierTestManager(r)
	r.outputs = map[string]string{}
	for _, table := range m.tables {
		r.outputs[strings.Join([]string{table, "-S", m.Chain}, "\x00")] = "-N REAUTH_FW\n" +
			"-A REAUTH_FW -i lo -j ACCEPT\n" +
			"-A REAUTH_FW -m mark --mark 0x40000000/0x40000000 -j FNK-WL-MARK\n" +
			"-A REAUTH_FW -j FNK-WHITELIST\n" +
			"-A REAUTH_FW -m mark --mark 0x40000000/0x40000000 -j FNK-WL-MARK\n" +
			"-A REAUTH_FW -j DROP\n"
	}
	if err := m.SyncWhitelistIPSet([]string{"192.0.2.1", "2001:db8::1"}); err != nil {
		t.Fatal(err)
	}
	for _, restore := range r.restores {
		for _, want := range []string{"-D REAUTH_FW 4\n-D REAUTH_FW 2\n", "-F FNK-WL-MARK\n-X FNK-WL-MARK\n", "-F FNK-WHITELIST\n"} {
			if !strings.Contains(restore.Input, want) {
				t.Fatalf("missing %q in migration: %s", want, restore.Input)
			}
		}
		if strings.Contains(restore.Input, "-F REAUTH_FW") || strings.Contains(restore.Input, "-m mark") || strings.Contains(restore.Input, "-D REAUTH_FW 3") {
			t.Fatalf("migration changes unrelated rules or needs mark support: %s", restore.Input)
		}
	}
	last := r.events[len(r.events)-1]
	if last != "nft delete table inet fnknock_whitelist" {
		t.Fatalf("classifier removed before both consumers: %#v", r.events)
	}
}

func TestFallbackRestoreFailureKeepsOldClassifier(t *testing.T) {
	r := &classifierTestRunner{failTable: "iptables", markError: issue63MarkError, restoreFail: true}
	m := newClassifierTestManager(r)
	if err := m.SyncWhitelistIPSet([]string{"192.0.2.1"}); err == nil || !strings.Contains(err.Error(), "restore rejected") {
		t.Fatalf("restore failure lost: %v", err)
	}
	for _, event := range r.events {
		if strings.Contains(event, "nft delete") {
			t.Fatalf("classifier deleted after failed replacement: %s", event)
		}
	}
	if callContains(r.calls, "-F", whitelistChainName) {
		t.Fatal("failed replacement flushed the live whitelist")
	}
}

func TestClassifierCleanupFailuresPropagate(t *testing.T) {
	for _, operation := range []string{"sync", "clear-whitelist", "init", "flush", "clear-ssh", "destroy"} {
		for _, failure := range []string{"inspect", "delete"} {
			t.Run(operation+"/"+failure, func(t *testing.T) {
				r := &classifierTestRunner{failTable: "iptables", markError: issue63MarkError}
				r.inspectFail = failure == "inspect"
				r.deleteFail = failure == "delete"
				m := newClassifierTestManager(r)
				var err error
				switch operation {
				case "sync":
					err = m.SyncWhitelistIPSet(nil)
				case "clear-whitelist":
					err = m.ClearWhitelistIPSet()
				case "init":
					err = m.Init()
				case "flush":
					err = m.Flush()
				case "clear-ssh":
					err = m.ClearTCPPortAccessPolicy("", nil)
				case "destroy":
					err = m.Destroy()
				}
				if err == nil {
					t.Fatal("cleanup failure was swallowed")
				}
			})
		}
	}
}

func TestSmallSSHPolicyRemovesOldActionsBeforeClassifier(t *testing.T) {
	r := &classifierTestRunner{}
	m := newClassifierTestManager(r)
	if err := m.SyncTCPPortAccessPolicy(TCPPortAccessPolicy{Ports: []int{22}, DefaultAction: "DROP"}); err != nil {
		t.Fatal(err)
	}
	for _, table := range m.tables {
		replaced, removed := -1, -1
		for i, event := range r.events {
			if strings.HasPrefix(event, restoreCommandForTable(table)+"\n*filter\n-F "+DefaultSSHFirewallChain) {
				replaced = i
			}
			if strings.HasPrefix(event, restoreCommandForTable(table)+"\n") && strings.Contains(event, "\n-X "+sshDefaultActionChain+"\n") {
				removed = i
			}
		}
		if replaced < 0 || removed <= replaced {
			t.Fatalf("old actions removed before policy replacement: %#v", r.events)
		}
	}
	if r.events[len(r.events)-1] != "nft delete table inet fnknock_ssh" {
		t.Fatalf("classifier removed before all consumers: %#v", r.events)
	}
}
