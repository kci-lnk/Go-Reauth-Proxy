package iptables

import (
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

var (
	iptablesRuleSink  Rule
	iptablesRulesSink []Rule
	iptablesArgsSink  []string
	iptablesBoolSink  bool
)

type parseRulesRunner struct {
	output string
}

func (r parseRulesRunner) CombinedOutput(command string, args ...string) ([]byte, error) {
	return []byte(r.output), nil
}

func (r parseRulesRunner) CombinedOutputWithInput(input string, command string, args ...string) ([]byte, error) {
	return []byte("ok"), nil
}

type baseRuleRunner struct {
	stateOutput     string
	stateErr        error
	conntrackOutput string
	conntrackErr    error
	calls           [][]string
}

func (r *baseRuleRunner) CombinedOutput(command string, args ...string) ([]byte, error) {
	call := append([]string{command}, args...)
	r.calls = append(r.calls, call)
	if isStateEstablishedRelatedCall(args) && r.stateErr != nil {
		return []byte(r.stateOutput), r.stateErr
	}
	if isConntrackEstablishedRelatedCall(args) && r.conntrackErr != nil {
		return []byte(r.conntrackOutput), r.conntrackErr
	}
	return []byte("ok"), nil
}

func (r *baseRuleRunner) CombinedOutputWithInput(input string, command string, args ...string) ([]byte, error) {
	return []byte("ok"), nil
}

func isStateEstablishedRelatedCall(args []string) bool {
	want := []string{"-A", "REAUTH_FW", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"}
	return reflect.DeepEqual(args, want)
}

func isConntrackEstablishedRelatedCall(args []string) bool {
	want := []string{"-A", "REAUTH_FW", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"}
	return reflect.DeepEqual(args, want)
}

func callContains(calls [][]string, parts ...string) bool {
	for _, call := range calls {
		if reflect.DeepEqual(call[1:], parts) {
			return true
		}
	}
	return false
}

func TestAppendEstablishedRelatedRuleUsesStateFirst(t *testing.T) {
	runner := &baseRuleRunner{}
	manager := NewManager(Options{ChainName: "REAUTH_FW", Tables: []string{"iptables"}})
	manager.runner = runner

	ruleAdded, err := manager.appendEstablishedRelatedRule("iptables")
	if err != nil {
		t.Fatalf("appendEstablishedRelatedRule returned error: %v", err)
	}
	if !ruleAdded {
		t.Fatal("appendEstablishedRelatedRule reported rule not added")
	}
	if len(runner.calls) != 1 {
		t.Fatalf("got %d calls, want 1: %#v", len(runner.calls), runner.calls)
	}
	want := []string{"iptables", "-A", "REAUTH_FW", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"}
	if !reflect.DeepEqual(runner.calls[0], want) {
		t.Fatalf("first call = %#v, want %#v", runner.calls[0], want)
	}
}

func TestApplyBaseRulesFallsBackToConntrackWhenStateMatchIsUnavailable(t *testing.T) {
	runner := &baseRuleRunner{
		stateOutput: "iptables v1.8.10 (nf_tables): Couldn't load match `state': No such file or directory\n",
		stateErr:    errors.New("exit status 2"),
	}
	manager := NewManager(Options{ChainName: "REAUTH_FW", Tables: []string{"iptables"}})
	manager.runner = runner

	if err := manager.applyBaseRules("iptables"); err != nil {
		t.Fatalf("applyBaseRules returned error: %v", err)
	}
	if !callContains(runner.calls, "-A", "REAUTH_FW", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT") {
		t.Fatalf("state rule was not attempted: %#v", runner.calls)
	}
	if !callContains(runner.calls, "-A", "REAUTH_FW", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT") {
		t.Fatalf("conntrack fallback was not attempted: %#v", runner.calls)
	}
	if !callContains(runner.calls, "-A", "REAUTH_FW", "-j", "DROP") {
		t.Fatalf("applyBaseRules did not continue through default DROP: %#v", runner.calls)
	}
}

func TestApplyBaseRulesSkipsFirewallWhenStateAndConntrackAreUnavailable(t *testing.T) {
	runner := &baseRuleRunner{
		stateOutput:     "iptables v1.8.10 (nf_tables): Couldn't load match `state': No such file or directory\n",
		stateErr:        errors.New("exit status 2"),
		conntrackOutput: "Warning: Extension conntrack is not supported, missing kernel module?\niptables v1.8.10 (nf_tables): Couldn't load match `conntrack': No such file or directory\n",
		conntrackErr:    errors.New("exit status 2"),
	}
	manager := NewManager(Options{ChainName: "REAUTH_FW", Tables: []string{"iptables"}})
	manager.runner = runner

	if err := manager.applyBaseRules("iptables"); err != nil {
		t.Fatalf("applyBaseRules returned error: %v", err)
	}
	if !callContains(runner.calls, "-A", "REAUTH_FW", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT") {
		t.Fatalf("state rule was not attempted: %#v", runner.calls)
	}
	if !callContains(runner.calls, "-A", "REAUTH_FW", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT") {
		t.Fatalf("conntrack fallback was not attempted: %#v", runner.calls)
	}
	if callContains(runner.calls, "-A", "REAUTH_FW", "-j", "DROP") {
		t.Fatalf("default DROP should not be added when firewall is skipped: %#v", runner.calls)
	}
	if got := manager.baseRuleCountForTable("iptables"); got != 1 {
		t.Fatalf("baseRuleCountForTable after skip = %d, want 1", got)
	}
}

func TestAppendEstablishedRelatedRuleDoesNotFallbackForOtherStateErrors(t *testing.T) {
	runner := &baseRuleRunner{
		stateOutput: "iptables: Permission denied (you must be root)\n",
		stateErr:    errors.New("exit status 4"),
	}
	manager := NewManager(Options{ChainName: "REAUTH_FW", Tables: []string{"iptables"}})
	manager.runner = runner

	ruleAdded, err := manager.appendEstablishedRelatedRule("iptables")
	if err == nil {
		t.Fatal("appendEstablishedRelatedRule returned nil, want error")
	}
	if ruleAdded {
		t.Fatal("appendEstablishedRelatedRule reported rule added on error")
	}
	if !strings.Contains(err.Error(), "Permission denied") {
		t.Fatalf("error = %q, want original permission failure", err.Error())
	}
	if len(runner.calls) != 1 {
		t.Fatalf("got %d calls, want no fallback after first failure: %#v", len(runner.calls), runner.calls)
	}
}

func TestAppendEstablishedRelatedRuleDoesNotSkipForOtherConntrackErrors(t *testing.T) {
	runner := &baseRuleRunner{
		stateOutput:     "iptables v1.8.10 (nf_tables): Couldn't load match `state': No such file or directory\n",
		stateErr:        errors.New("exit status 2"),
		conntrackOutput: "iptables: Permission denied (you must be root)\n",
		conntrackErr:    errors.New("exit status 4"),
	}
	manager := NewManager(Options{ChainName: "REAUTH_FW", Tables: []string{"iptables"}})
	manager.runner = runner

	ruleAdded, err := manager.appendEstablishedRelatedRule("iptables")
	if err == nil {
		t.Fatal("appendEstablishedRelatedRule returned nil, want error")
	}
	if ruleAdded {
		t.Fatal("appendEstablishedRelatedRule reported rule added on error")
	}
	if !strings.Contains(err.Error(), "Permission denied") {
		t.Fatalf("error = %q, want original permission failure", err.Error())
	}
	if len(runner.calls) != 2 {
		t.Fatalf("got %d calls, want state plus conntrack: %#v", len(runner.calls), runner.calls)
	}
}

func TestParseRuleLineMatchesLegacy(t *testing.T) {
	cases := []string{
		"",
		"not a rule",
		"-A REAUTH_FW -s 192.0.2.10/32 -j ACCEPT",
		"-A REAUTH_FW -p tcp -s 198.51.100.7/32 --dport 443 -j DROP",
		" -A REAUTH_FW\t-s\t2001:db8::1/128 -p TCP --dport 8443 -j ACCEPT ",
		"-A OTHER -s 192.0.2.1/32 -j ACCEPT",
		"-A REAUTH_FW -s 203.0.113.10/32 --dport not-a-port -j ACCEPT",
		"-A REAUTH_FW -s 203.0.113.10/32 --dport 70000 -j ACCEPT",
		"-A REAUTH_FW -s 203.0.113.10/32 -j RETURN",
		"-A REAUTH_FW -j ACCEPT",
		"-A REAUTH_FW -s 203.0.113.10/32 -p TĊP -j ACCEPT",
	}

	for _, line := range cases {
		t.Run(line, func(t *testing.T) {
			gotRule, gotOK := parseRuleLine(line)
			wantRule, wantOK := parseRuleLineLegacyForBenchmark(line)
			if gotOK != wantOK || gotRule != wantRule {
				t.Fatalf("parseRuleLine(%q) = (%#v, %v), want (%#v, %v)", line, gotRule, gotOK, wantRule, wantOK)
			}
		})
	}
}

func TestParseRulesMatchesLegacy(t *testing.T) {
	output := makeIptablesRulesOutput(250)
	manager := NewManager(Options{ChainName: "REAUTH_FW", Tables: []string{"iptables"}})
	manager.runner = parseRulesRunner{output: output}

	got, err := manager.ParseRules()
	if err != nil {
		t.Fatalf("ParseRules returned error: %v", err)
	}
	want := parseRulesLegacyForBenchmark(output)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ParseRules() got %d rules, want %d\nfirst got=%#v\nfirst want=%#v", len(got), len(want), firstRule(got), firstRule(want))
	}
}

func TestParentJumpDeleteArgsMatchesLegacy(t *testing.T) {
	cases := []string{
		"",
		"-A INPUT -j REAUTH_FW",
		"-A INPUT -p tcp --dport 443 -j REAUTH_FW",
		" -A\tINPUT\t-s 198.51.100.7/32\t-j\tREAUTH_FW ",
		"-A OUTPUT -j REAUTH_FW",
		"-A INPUT -j OTHER",
		"-A INPUT -j",
		"-I INPUT -j REAUTH_FW",
	}

	for _, line := range cases {
		t.Run(line, func(t *testing.T) {
			gotArgs, gotOK := parentJumpDeleteArgs(line, "INPUT", "REAUTH_FW")
			wantArgs, wantOK := parentJumpDeleteArgsLegacyForBenchmark(line, "INPUT", "REAUTH_FW")
			if gotOK != wantOK || !reflect.DeepEqual(gotArgs, wantArgs) {
				t.Fatalf("parentJumpDeleteArgs(%q) = (%#v, %v), want (%#v, %v)", line, gotArgs, gotOK, wantArgs, wantOK)
			}
		})
	}
}

func BenchmarkParseRuleLine(b *testing.B) {
	line := "-A REAUTH_FW -p tcp -m tcp -s 198.51.100.7/32 --dport 443 -j DROP"
	b.ReportAllocs()
	for b.Loop() {
		rule, ok := parseRuleLine(line)
		iptablesRuleSink = rule
		iptablesBoolSink = ok
	}
}

func BenchmarkParseRuleLineOld(b *testing.B) {
	line := "-A REAUTH_FW -p tcp -m tcp -s 198.51.100.7/32 --dport 443 -j DROP"
	b.ReportAllocs()
	for b.Loop() {
		rule, ok := parseRuleLineLegacyForBenchmark(line)
		iptablesRuleSink = rule
		iptablesBoolSink = ok
	}
}

func BenchmarkParentJumpDeleteArgsNoMatch(b *testing.B) {
	line := "-A INPUT -p tcp -m tcp -s 198.51.100.7/32 --dport 443 -j OTHER_CHAIN"
	b.ReportAllocs()
	for b.Loop() {
		args, ok := parentJumpDeleteArgs(line, "INPUT", "REAUTH_FW")
		iptablesArgsSink = args
		iptablesBoolSink = ok
	}
}

func BenchmarkParentJumpDeleteArgsNoMatchOld(b *testing.B) {
	line := "-A INPUT -p tcp -m tcp -s 198.51.100.7/32 --dport 443 -j OTHER_CHAIN"
	b.ReportAllocs()
	for b.Loop() {
		args, ok := parentJumpDeleteArgsLegacyForBenchmark(line, "INPUT", "REAUTH_FW")
		iptablesArgsSink = args
		iptablesBoolSink = ok
	}
}

func BenchmarkParentJumpDeleteArgsMatch(b *testing.B) {
	line := "-A INPUT -p tcp -m tcp -s 198.51.100.7/32 --dport 443 -j REAUTH_FW"
	b.ReportAllocs()
	for b.Loop() {
		args, ok := parentJumpDeleteArgs(line, "INPUT", "REAUTH_FW")
		iptablesArgsSink = args
		iptablesBoolSink = ok
	}
}

func BenchmarkParentJumpDeleteArgsMatchOld(b *testing.B) {
	line := "-A INPUT -p tcp -m tcp -s 198.51.100.7/32 --dport 443 -j REAUTH_FW"
	b.ReportAllocs()
	for b.Loop() {
		args, ok := parentJumpDeleteArgsLegacyForBenchmark(line, "INPUT", "REAUTH_FW")
		iptablesArgsSink = args
		iptablesBoolSink = ok
	}
}

func BenchmarkParseRules(b *testing.B) {
	output := makeIptablesRulesOutput(4000)
	manager := NewManager(Options{ChainName: "REAUTH_FW", Tables: []string{"iptables"}})
	manager.runner = parseRulesRunner{output: output}
	b.SetBytes(int64(len(output)))
	b.ReportAllocs()
	for b.Loop() {
		rules, err := manager.ParseRules()
		if err != nil {
			b.Fatal(err)
		}
		iptablesRulesSink = rules
	}
}

func BenchmarkParseRulesOld(b *testing.B) {
	output := makeIptablesRulesOutput(4000)
	b.SetBytes(int64(len(output)))
	b.ReportAllocs()
	for b.Loop() {
		iptablesRulesSink = parseRulesLegacyForBenchmark(output)
	}
}

func makeIptablesRulesOutput(count int) string {
	var builder strings.Builder
	for i := 0; i < count; i++ {
		ip := fmt.Sprintf("198.51.%d.%d/32", (i/250)%250, i%250)
		action := "ACCEPT"
		if i%3 == 0 {
			action = "DROP"
		}
		if i%5 == 0 {
			fmt.Fprintf(&builder, "-A REAUTH_FW -p tcp -m tcp -s %s --dport %d -j %s\n", ip, 8000+i%1000, action)
		} else {
			fmt.Fprintf(&builder, "-A REAUTH_FW -s %s -j %s\n", ip, action)
		}
		if i%37 == 0 {
			builder.WriteString("-A REAUTH_FW -s 0.0.0.0/0 -j DROP\n")
			builder.WriteString("-A REAUTH_FW -j RETURN\n")
		}
	}
	return builder.String()
}

func firstRule(rules []Rule) Rule {
	if len(rules) == 0 {
		return Rule{}
	}
	return rules[0]
}

func parseRulesLegacyForBenchmark(output string) []Rule {
	var rules []Rule
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		rule, ok := parseRuleLineLegacyForBenchmark(line)
		if !ok {
			continue
		}
		if rule.IP == "0.0.0.0/0" || rule.IP == "::/0" {
			continue
		}
		rules = append(rules, rule)
	}
	return rules
}

func parseRuleLineLegacyForBenchmark(line string) (Rule, bool) {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return Rule{}, false
	}

	var ip string
	var action string
	var protocol string
	var port int

	for index := 0; index < len(fields); index++ {
		field := fields[index]
		if index+1 >= len(fields) {
			continue
		}

		switch field {
		case "-s":
			ip = fields[index+1]
			ip = strings.TrimSuffix(ip, "/32")
			ip = strings.TrimSuffix(ip, "/128")
		case "-p":
			protocol = strings.ToLower(fields[index+1])
		case "--dport":
			parsed, err := strconv.Atoi(fields[index+1])
			if err == nil {
				port = parsed
			}
		case "-j":
			action = fields[index+1]
		}
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

func parentJumpDeleteArgsLegacyForBenchmark(line string, parent string, chain string) ([]string, bool) {
	fields := strings.Fields(line)
	if len(fields) < 4 || fields[0] != "-A" || fields[1] != parent {
		return nil, false
	}
	hasJump := false
	for index := 2; index+1 < len(fields); index++ {
		if fields[index] == "-j" && fields[index+1] == chain {
			hasJump = true
			break
		}
	}
	if !hasJump {
		return nil, false
	}
	args := append([]string{"-D", parent}, fields[2:]...)
	return args, true
}
