package iptables

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestExemptPortChunks(t *testing.T) {
	singles := make([]string, 15)
	for i := range singles {
		singles[i] = strconv.Itoa(i + 1)
	}
	for _, tc := range []struct {
		name  string
		ports []string
		sizes []int
	}{
		{"empty", nil, nil},
		{"15 singles", singles, []int{15}},
		{"16 singles", append(append([]string{}, singles...), "16"), []int{15, 1}},
		{"13 singles and range", append(append([]string{}, singles[:13]...), "50000:51000"), []int{14}},
		{"14 singles and range", append(append([]string{}, singles[:14]...), "50000:51000"), []int{14, 1}},
		{"8 ranges", []string{"1:2", "3:4", "5:6", "7:8", "9:10", "11:12", "13:14", "15:16"}, []int{7, 1}},
		{"wide range", []string{"1:65535"}, []int{1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var sizes []int
			var flattened []string
			for _, chunk := range exemptPortChunks(tc.ports) {
				sizes = append(sizes, len(chunk))
				flattened = append(flattened, chunk...)
				slots := 0
				for _, port := range chunk {
					slots++
					if strings.Contains(port, ":") {
						slots++
					}
				}
				if slots > 15 {
					t.Fatalf("chunk exceeds slot limit: %v", chunk)
				}
			}
			if !reflect.DeepEqual(sizes, tc.sizes) || !reflect.DeepEqual(flattened, tc.ports) {
				t.Fatalf("sizes=%v, flattened=%v", sizes, flattened)
			}
		})
	}
}

func TestExemptRangesApplyBothFamiliesAndKeepDynamicRulesBeforeDrop(t *testing.T) {
	for _, table := range []string{"iptables", "ip6tables"} {
		t.Run(table, func(t *testing.T) {
			m := newRecordingManager()
			m.tables = []string{table}
			runner := m.runner.(*recordingIptablesRunner)
			// Eight ranges require two multiport rules per protocol.
			for i := 0; i < 8; i++ {
				m.ExemptPorts = append(m.ExemptPorts, fmt.Sprintf("%d:%d", 50000+i*100, 50099+i*100))
			}
			if err := m.applyBaseRules(table); err != nil {
				t.Fatal(err)
			}
			appended, allows := 0, 0
			for _, call := range runner.calls {
				if len(call) < 3 || call[0] != table || call[1] != "-A" || call[2] != m.Chain {
					continue
				}
				appended++
				if strings.Contains(strings.Join(call, " "), "--dports") {
					allows++
				}
			}
			if allows != 4 {
				t.Fatalf("range rules=%d, calls=%v", allows, runner.calls)
			}
			for _, chunk := range exemptPortChunks(m.ExemptPorts) {
				for _, protocol := range []string{"tcp", "udp"} {
					if !callContains(runner.calls, "-A", m.Chain, "-p", protocol, "-m", "multiport", "--dports", strings.Join(chunk, ","), "-j", "ACCEPT") {
						t.Fatalf("missing %s range rule", protocol)
					}
				}
			}
			if got := m.baseRuleCountForTable(table); got != appended-1 {
				t.Fatalf("base count %d, appended %d", got, appended)
			}
			ip := "198.51.100.10"
			if table == "ip6tables" {
				ip = "2001:db8::10"
			}
			if err := m.AllowIP(ip); err != nil {
				t.Fatal(err)
			}
			if !callContains(runner.calls, "-I", m.Chain, strconv.Itoa(appended), "-s", ip, "-j", "ACCEPT") {
				t.Fatalf("incorrect insertion position: %v", runner.calls)
			}

		})
	}
}

// Exercise the public reset path: rebuilding rules without flushing first would
// leave an old passive FTP range open even after it was removed from config.
func TestInitClearsRemovedExemptRanges(t *testing.T) {
	m := newRecordingManager()
	m.tables = []string{"iptables", "ip6tables"}
	runner := m.runner.(*recordingIptablesRunner)
	m.ExemptPorts = []string{"21", "50000:51000"}
	if err := m.Init(); err != nil {
		t.Fatal(err)
	}
	m.ExemptPorts = []string{"21"}
	if err := m.Init(); err != nil {
		t.Fatal(err)
	}
	for _, table := range m.tables {
		var rules [][]string
		flushes := 0
		for _, call := range runner.calls {
			if len(call) < 3 || call[0] != table || call[2] != m.Chain {
				continue
			}
			switch call[1] {
			case "-F":
				rules = nil
				flushes++
			case "-A":
				rules = append(rules, call[1:])
			}
		}
		if flushes != 2 {
			t.Fatalf("%s: expected both initializations to flush, got %d", table, flushes)
		}
		for _, rule := range rules {
			if strings.Contains(strings.Join(rule, " "), "50000:51000") {
				t.Fatalf("%s: stale range: %v", table, rule)
			}
		}
		for _, protocol := range []string{"tcp", "udp"} {
			found := false
			for _, rule := range rules {
				if reflect.DeepEqual(rule, []string{"-A", m.Chain, "-p", protocol, "-m", "multiport", "--dports", "21", "-j", "ACCEPT"}) {
					found = true
				}
			}
			if !found {
				t.Fatalf("%s: missing retained %s control port rule: %v", table, protocol, rules)
			}
		}
	}
}
