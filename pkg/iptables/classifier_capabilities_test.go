package iptables

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"go-reauth-proxy/pkg/logger"
)

const issue63MarkError = "Warning: Extension MARK revision 0 not supported, missing kernel module?\niptables v1.8.9 (nf_tables): unknown option \"--set-xmark\""

type classifierTestRunner struct {
	recordingIptablesRunner
	failTable   string
	failMatch   bool
	markError   string
	cleanupFail string
	restoreFail bool
	deleteFail  bool
	inspectFail bool
	events      []string
}

func (r *classifierTestRunner) CombinedOutput(command string, args ...string) ([]byte, error) {
	r.events = append(r.events, command+" "+strings.Join(args, " "))
	output, err := r.recordingIptablesRunner.CombinedOutput(command, args...)
	if len(args) >= 2 && strings.HasPrefix(args[1], "FNK-PROBE-") {
		if args[0] == r.cleanupFail {
			return []byte("Operation not permitted"), errors.New("cleanup failed")
		}
		if command == r.failTable && args[0] == "-A" && (r.failMatch == (args[2] == "-m")) && r.markError != "" {
			return []byte(r.markError), errors.New("exit status 2")
		}
	}
	if r.inspectFail && len(args) > 1 && args[0] == "-S" {
		return []byte("Permission denied"), errors.New("inspection failed")
	}
	if r.deleteFail && command == "nft" && args[0] == "delete" {
		return []byte("Operation not permitted"), errors.New("delete failed")
	}
	return output, err
}

func (r *classifierTestRunner) CombinedOutputWithInput(input, command string, args ...string) ([]byte, error) {
	r.events = append(r.events, command+"\n"+input)
	output, err := r.recordingIptablesRunner.CombinedOutputWithInput(input, command, args...)
	if r.restoreFail {
		return []byte("restore rejected"), errors.New("exit status 1")
	}
	return output, err
}

func newClassifierTestManager(runner commandRunner) *Manager {
	m := NewManager(Options{Tables: []string{"iptables", "ip6tables"}, ParentChain: []string{"INPUT", "DOCKER-USER"}})
	m.runner = runner
	m.nftCommand = "nft"
	return m
}

func assertNoClassifierRules(t *testing.T, r *classifierTestRunner) {
	t.Helper()
	for _, call := range r.calls {
		if len(call) >= 3 && strings.HasPrefix(call[2], "FNK-PROBE-") {
			continue
		}
		text := strings.Join(call, " ")
		if strings.Contains(text, "-j MARK") || strings.Contains(text, "-m mark") || strings.Contains(text, "nft add") {
			t.Fatalf("fallback installed classifier: %s", text)
		}
	}
	for _, restore := range r.restores {
		if restore.Command == "nft" || strings.Contains(restore.Input, "-j MARK") || strings.Contains(restore.Input, "-m mark") {
			t.Fatalf("fallback installed classifier: %#v", restore)
		}
	}
}

func TestClassifierFallbackWhitelistLifecycle(t *testing.T) {
	for _, tc := range []struct {
		name, table, output string
		match, noNft        bool
	}{
		{"issue63", "iptables", issue63MarkError, false, false},
		{"ipv6-only", "ip6tables", issue63MarkError, false, false},
		{"match-missing", "iptables", "Couldn't load match `mark':No such file or directory", true, false},
		{"no-nft", "", "", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &classifierTestRunner{failTable: tc.table, failMatch: tc.match, markError: tc.output}
			m := newClassifierTestManager(r)
			if tc.noNft {
				m.nftCommand = ""
			}
			// Startup may synchronize an empty whitelist before Init.
			if err := m.SyncWhitelistIPSet(nil); err != nil {
				t.Fatal(err)
			}
			if err := m.Init(); err != nil {
				t.Fatal(err)
			}
			for _, sources := range [][]string{
				{"192.0.2.0/24", "2001:db8::/48"},
				{"198.51.100.1", "2001:db8:1::1"},
				{"198.51.100.1", "2001:db8:1::1"},
				nil,
			} {
				before := len(r.restores)
				if err := m.SyncWhitelistIPSet(sources); err != nil {
					t.Fatal(err)
				}
				if len(r.restores)-before != 2 {
					t.Fatalf("expected exactly one transaction per family, got %#v", r.restores[before:])
				}
				for i, restore := range r.restores[before:] {
					if !reflect.DeepEqual(restore.Args, []string{"--noflush"}) || !strings.HasPrefix(restore.Input, "*filter\n-F FNK-WHITELIST\n") {
						t.Fatalf("non-atomic replacement: %#v", restore)
					}
					if len(sources) != 0 && !strings.Contains(restore.Input, "-s "+sources[i]+" -j ACCEPT") {
						t.Fatalf("missing requested family policy: %s", restore.Input)
					}
					if len(sources) == 0 && strings.Contains(restore.Input, "-j ACCEPT") {
						t.Fatalf("empty policy still allows traffic: %s", restore.Input)
					}
				}
			}
			if err := m.ClearWhitelistIPSet(); err != nil {
				t.Fatal(err)
			}
			if err := m.Flush(); err != nil {
				t.Fatal(err)
			}
			if m.whitelistNftClassifierReady() {
				t.Fatal("fallback still trusts packet marks")
			}
			assertNoClassifierRules(t, r)
			if callContains(r.calls, "-F", whitelistChainName) {
				t.Fatal("live whitelist was flushed outside its replacement transaction")
			}
			probes := 0
			for _, call := range r.calls {
				if len(call) > 2 && call[1] == "-N" && strings.HasPrefix(call[2], "FNK-PROBE-") {
					probes++
				}
			}
			wantProbes := 2
			if tc.noNft {
				wantProbes = 0
			}
			if probes != wantProbes {
				t.Fatalf("probe count %d, want %d", probes, wantProbes)
			}
			if err := m.Destroy(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestClassifierFallbackLargeSSHPolicy(t *testing.T) {
	for _, defaultAction := range []string{"DROP", "RETURN"} {
		t.Run(defaultAction, func(t *testing.T) {
			r := &classifierTestRunner{failTable: "ip6tables", markError: issue63MarkError}
			m := newClassifierTestManager(r)
			allow := []string{"2001:db8::/48"}
			for i := 0; i < 300; i++ {
				allow = append(allow, fmt.Sprintf("198.18.%d.%d", i/256, i%256))
			}
			policy := TCPPortAccessPolicy{Ports: []int{22, 2222}, AllowSources: allow,
				BlockSources: []string{"198.18.0.1", "2001:db8::1"}, IncludeLocalCIDRs: true, DefaultAction: defaultAction}
			if err := m.SyncTCPPortAccessPolicy(policy); err != nil {
				t.Fatal(err)
			}
			assertNoClassifierRules(t, r)
			policies := policyRestoresForChain(r.restores, DefaultSSHFirewallChain)
			if len(policies) != 2 {
				t.Fatalf("expected two direct policies, got %d", len(policies))
			}
			for i, restore := range policies {
				local := strings.Index(restore.Input, "-i lo -j ACCEPT")
				block := strings.Index(restore.Input, "-s "+policy.BlockSources[i]+" -j DROP")
				allowSource := "198.18.0.1"
				if i == 1 {
					allowSource = "2001:db8::/48"
				}
				allowed := strings.Index(restore.Input, "-s "+allowSource+" -j ACCEPT")
				if local < 0 || block < local || allowed < block || !strings.HasSuffix(restore.Input, "-j "+defaultAction+"\nCOMMIT\n") {
					t.Fatalf("changed policy precedence: %s", restore.Input)
				}
			}
			if err := m.ClearTCPPortAccessPolicy("", nil); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestClassifierProbeOperationalFailuresAreRetried(t *testing.T) {
	for _, output := range []string{"Permission denied", "Operation not permitted", "Another app is currently holding the xtables lock", "unexpected failure", issue63MarkError + "\nPermission denied"} {
		t.Run(output, func(t *testing.T) {
			r := &classifierTestRunner{failTable: "iptables", markError: output}
			m := newClassifierTestManager(r)
			if err := m.SyncWhitelistIPSet(nil); err == nil || !strings.Contains(err.Error(), output) {
				t.Fatalf("operational error lost: %v", err)
			}
			if m.classificationChecked || len(r.restores) != 0 {
				t.Fatal("operational failure was cached or changed live policies")
			}
			r.markError = ""
			if enabled, err := m.nftClassificationEnabled(); err != nil || !enabled {
				t.Fatalf("retry failed: %v, %v", enabled, err)
			}
		})
	}
}

func TestClassifierProbeCleanupFailuresPreventFallback(t *testing.T) {
	for _, stage := range []string{"-F", "-X"} {
		t.Run(stage, func(t *testing.T) {
			r := &classifierTestRunner{failTable: "iptables", markError: issue63MarkError, cleanupFail: stage}
			m := newClassifierTestManager(r)
			if _, err := m.nftClassificationEnabled(); err == nil || !strings.Contains(err.Error(), "clean up MARK probe") {
				t.Fatalf("cleanup failure swallowed: %v", err)
			}
			if m.classificationChecked {
				t.Fatal("failed cleanup was cached as unsupported")
			}
			if r.calls[len(r.calls)-1][1] != "-X" {
				t.Fatal("probe deletion not attempted")
			}
		})
	}
}

func TestClassifierProbeConcurrentSelection(t *testing.T) {
	for _, missing := range []bool{false, true} {
		t.Run(fmt.Sprint(missing), func(t *testing.T) {
			r := &classifierTestRunner{}
			if missing {
				r.failTable, r.markError = "ip6tables", issue63MarkError
			}
			m := newClassifierTestManager(r)
			var group sync.WaitGroup
			for range 32 {
				group.Go(func() {
					enabled, err := m.nftClassificationEnabled()
					if err != nil || enabled == missing {
						t.Errorf("selection = %v, %v", enabled, err)
					}
				})
			}
			group.Wait()
			created, removed := map[string]bool{}, map[string]bool{}
			for _, call := range r.calls {
				if len(call) > 2 && strings.HasPrefix(call[2], "FNK-PROBE-") {
					key := call[0] + " " + call[2]
					if call[1] == "-N" {
						created[key] = true
					}
					if call[1] == "-X" {
						removed[key] = true
					}
				}
			}
			if len(created) != 2 || !reflect.DeepEqual(created, removed) {
				t.Fatalf("probe leak or repeated probe: created %v, removed %v", created, removed)
			}
		})
	}
}

func TestMarkExtensionUnavailableIsNarrow(t *testing.T) {
	for _, output := range []string{issue63MarkError, "Extension mark is not supported", "unknown option \"--mark\"", "Couldn't load target `MARK':No such file or directory"} {
		if !markExtensionUnavailable(output) {
			t.Errorf("unsupported extension not recognized: %s", output)
		}
	}
	for _, output := range []string{"unknown option --other", "No chain/target/match by that name", "Extension conntrack revision 0 not supported, missing kernel module?", "Couldn't load target `ACCEPT':No such file or directory"} {
		if markExtensionUnavailable(output) {
			t.Errorf("unrelated error downgraded: %s", output)
		}
	}
}

func TestClassifierFallbackDiagnosticContainsReason(t *testing.T) {
	dir := t.TempDir()
	t.Cleanup(logger.Setup)
	t.Setenv(logger.DiagnosticLogDirEnv, dir)
	logger.Setup()
	r := &classifierTestRunner{failTable: "ip6tables", markError: issue63MarkError}
	m := newClassifierTestManager(r)
	for range 3 {
		if enabled, err := m.nftClassificationEnabled(); err != nil || enabled {
			t.Fatalf("selection = %v, %v", enabled, err)
		}
	}
	logger.FlushDiagnosticLogger()
	data, err := os.ReadFile(filepath.Join(dir, "gateway.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	log := string(data)
	if strings.Count(log, `"event":"classifier_fallback"`) != 1 {
		t.Fatalf("expected one operational fallback event: %s", log)
	}
	for _, want := range []string{"mark_unavailable", "legacy_per_source", "ip6tables", "--set-xmark", "large policies may be slower"} {
		if !strings.Contains(log, want) {
			t.Errorf("diagnostic missing %q: %s", want, log)
		}
	}
}

func TestNativeSubmissionFailureDoesNotDowngrade(t *testing.T) {
	r := &classifierTestRunner{restoreFail: true}
	m := newClassifierTestManager(r)
	if err := m.SyncWhitelistIPSet(nil); err == nil || !strings.Contains(err.Error(), "restore rejected") {
		t.Fatalf("submission failure lost: %v", err)
	}
	if !m.classificationEnabled {
		t.Fatal("a submission error downgraded a supported classifier")
	}
}
