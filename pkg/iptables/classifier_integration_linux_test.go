package iptables

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Opt-in only. The parent test always enters a fresh network AND mount namespace
// before touching firewall state. Requires unshare, ip, nft, iptables/ip6tables,
// their restore tools, CAP_SYS_ADMIN and CAP_NET_ADMIN. See the firewall README.
func TestClassifierFirewallIntegration(t *testing.T) {
	mode := os.Getenv("FN_KNOCK_FIREWALL_INTEGRATION")
	if mode == "" {
		t.Skip("set FN_KNOCK_FIREWALL_INTEGRATION=1 to run in isolated Linux namespaces")
	}
	if mode != "isolated" {
		binary, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("unshare", "--net", "--mount", "--propagation", "private", binary,
			"-test.run=^TestClassifierFirewallIntegration$", "-test.v", "-test.timeout=120s")
		cmd.Env = append(os.Environ(), "FN_KNOCK_FIREWALL_INTEGRATION=isolated")
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("isolated integration test: %v\n%s", err, output)
		}
		t.Log(string(output))
		return
	}

	run := func(command string, args ...string) string {
		t.Helper()
		output, err := exec.Command(command, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("%s %v: %v\n%s", command, args, err, output)
		}
		return string(output)
	}
	run("ip", "link", "set", "lo", "up")
	run("ip", "netns", "add", "fnk-client")
	t.Cleanup(func() { run("ip", "netns", "del", "fnk-client") })
	run("ip", "link", "add", "fnk-server", "type", "veth", "peer", "name", "fnk-peer")
	run("ip", "link", "set", "fnk-peer", "netns", "fnk-client")
	run("ip", "addr", "add", "198.51.100.1/24", "dev", "fnk-server")
	run("ip", "-6", "addr", "add", "2001:db8::1/64", "dev", "fnk-server", "nodad")
	run("ip", "link", "set", "fnk-server", "up")
	run("ip", "-n", "fnk-client", "addr", "add", "198.51.100.2/24", "dev", "fnk-peer")
	run("ip", "-n", "fnk-client", "-6", "addr", "add", "2001:db8::2/64", "dev", "fnk-peer", "nodad")
	run("ip", "-n", "fnk-client", "link", "set", "fnk-peer", "up")
	run("ip", "-n", "fnk-client", "link", "set", "lo", "up")

	var ports []int
	for _, address := range []string{"0.0.0.0:0", "[::]:0"} {
		network := "tcp4"
		if strings.HasPrefix(address, "[") {
			network = "tcp6"
		}
		listener, err := net.Listen(network, address)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { listener.Close() })
		ports = append(ports, listener.Addr().(*net.TCPAddr).Port)
		go func() {
			for {
				connection, err := listener.Accept()
				if err != nil {
					return
				}
				connection.Close()
			}
		}()
	}
	for _, table := range []string{"iptables", "ip6tables"} {
		run(table, "-N", "FNK-FOREIGN-TEST")
		run(table, "-A", "INPUT", "-j", "FNK-FOREIGN-TEST")
		run(table, "-A", "INPUT", "-m", "comment", "--comment", "unrelated -j REAUTH_FW text", "-j", "FNK-FOREIGN-TEST")
	}
	newManager := func() *Manager {
		m := NewManager(Options{ParentChain: []string{"INPUT"}})
		m.runner = execRunner{}
		return m
	}
	// A referenced chain must retain its rules when deletion fails. Exercise
	// actual restore rollback, not just a fake command runner's return value.
	for _, table := range []string{"iptables", "ip6tables"} {
		chain := "FNK-CLEANUP-TEST"
		run(table, "-N", chain)
		run(table, "-A", chain, "-j", "DROP")
		run(table, "-A", "INPUT", "-j", chain)
		if err := newManager().removeUnusedChain(table, chain); err == nil {
			t.Fatal("referenced chain deletion unexpectedly succeeded")
		}
		run(table, "-C", chain, "-j", "DROP")
		run(table, "-D", "INPUT", "-j", chain)
		if err := newManager().removeUnusedChain(table, chain); err != nil {
			t.Fatal(err)
		}
	}
	for _, scenario := range []string{"native", "missing-MARK-v4", "missing-MARK-v6", "missing-mark-match", "no-nft"} {
		t.Run(scenario, func(t *testing.T) {
			check := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			traffic := func(allow4, allow6 bool) {
				t.Helper()
				binary, err := os.Executable()
				check(err)
				for i, address := range []string{"198.51.100.1", "2001:db8::1"} {
					cmd := exec.Command("ip", "netns", "exec", "fnk-client", binary, "-test.run=^TestClassifierPacketClient$")
					cmd.Env = append(os.Environ(), "FN_KNOCK_PACKET_TARGET="+net.JoinHostPort(address, strconv.Itoa(ports[i])))
					output, err := cmd.CombinedOutput()
					want := []bool{allow4, allow6}[i]
					if (err == nil) != want {
						t.Fatalf("%s allowed=%v, want %v: %v\n%s", address, err == nil, want, err, output)
					}
				}
			}
			newScenarioManager := func() *Manager {
				m := newManager()
				if scenario == "no-nft" {
					m.nftCommand = ""
				} else if scenario != "native" {
					m.runner = integrationMissingMarkRunner{scenario: scenario}
				}
				return m
			}
			// A first install publishes an empty whitelist before the base
			// firewall chain exists. It must also work without MARK support.
			fresh := newScenarioManager()
			check(fresh.SyncWhitelistIPSet(nil))
			check(fresh.Init())
			check(fresh.BlockAll())
			traffic(false, false)
			check(fresh.Destroy())
			// Seed the previous release's classifier rules, then use a fresh
			// Manager with a missing extension, as happens after an OS upgrade.
			seed := newManager()
			t.Cleanup(func() { check(seed.Destroy()) })
			check(seed.Init())
			for _, table := range seed.tables {
				run(table, "-A", "INPUT", "-m", "comment", "--comment", `owned  spacing and "quotes"`, "-j", seed.Chain)
			}
			check(seed.SyncWhitelistIPSet([]string{"198.51.100.2", "2001:db8::2"}))
			check(seed.BlockAll())
			traffic(true, true)

			m := newScenarioManager()
			check(m.SyncWhitelistIPSet(nil))
			check(m.Init())
			check(m.BlockAll())
			traffic(false, false)
			check(m.SyncWhitelistIPSet([]string{"198.51.100.2", "2001:db8::2"}))
			traffic(true, true)
			check(m.SyncWhitelistIPSet([]string{"2001:db8::2"}))
			traffic(false, true)
			check(m.ClearWhitelistIPSet())
			traffic(false, false)
			check(m.SyncWhitelistIPSet([]string{"198.51.100.2", "2001:db8::2"}))
			check(m.Init())
			check(m.Flush())
			check(m.BlockAll())
			traffic(true, true)
			check(m.ClearWhitelistIPSet())

			policy := TCPPortAccessPolicy{Ports: ports, IncludeLocalCIDRs: true, DefaultAction: "DROP",
				AllowSources: []string{"198.51.100.2", "2001:db8::2"}}
			for i := range 300 {
				policy.AllowSources = append(policy.AllowSources, "192.0."+strconv.Itoa(i/256)+"."+strconv.Itoa(i%256))
			}
			check(seed.SyncTCPPortAccessPolicy(policy))
			traffic(true, true)
			policy.BlockSources = []string{"198.51.100.2"}
			check(m.SyncTCPPortAccessPolicy(policy))
			traffic(false, true)
			if scenario != "native" {
				for _, table := range m.tables {
					for _, chain := range []string{m.Chain, DefaultSSHFirewallChain} {
						rules := run(table, "-S", chain)
						if strings.Contains(rules, "-m mark") || strings.Contains(rules, "-j MARK") {
							t.Fatalf("fallback retained mark rules: %s", rules)
						}
					}
				}
			}
			check(m.ClearTCPPortAccessPolicy("", nil))
			traffic(false, false)
			check(m.AllowAll())
			policy.AllowSources = policy.AllowSources[2:]
			policy.BlockSources = nil
			policy.DefaultAction = "RETURN"
			check(m.SyncTCPPortAccessPolicy(policy))
			traffic(true, true)
			policy.DefaultAction = "DROP"
			check(m.SyncTCPPortAccessPolicy(policy))
			traffic(false, false)
			connection, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(ports[0])), time.Second)
			check(err)
			connection.Close()
			check(m.Destroy())
			for _, table := range m.tables {
				run(table, "-C", "INPUT", "-j", "FNK-FOREIGN-TEST")
				run(table, "-C", "INPUT", "-m", "comment", "--comment", "unrelated -j REAUTH_FW text", "-j", "FNK-FOREIGN-TEST")
				if rules := run(table, "-S"); strings.Contains(rules, "FNK-PROBE-") || strings.Contains(rules, "FNK-WL-") || strings.Contains(rules, "FNK-SSH-") {
					t.Fatalf("owned chains leaked after destroy: %s", rules)
				}
			}
		})
	}
}

func TestClassifierPacketClient(t *testing.T) {
	address := os.Getenv("FN_KNOCK_PACKET_TARGET")
	if address == "" {
		t.Skip("packet client helper")
	}
	connection, err := net.DialTimeout("tcp", address, 300*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	connection.Close()
}

// Fail every use of the extension, including restore, rather than just the
// capability probe. All non-MARK commands still reach the real Linux kernel.
type integrationMissingMarkRunner struct {
	execRunner
	scenario string
}

func (r integrationMissingMarkRunner) unavailable(command, input string) bool {
	if r.scenario == "missing-mark-match" {
		return strings.Contains(input, "-m mark")
	}
	family := "iptables"
	if r.scenario == "missing-MARK-v6" {
		family = "ip6tables"
	}
	return (command == family || command == family+"-restore") && strings.Contains(input, "-j MARK")
}

func (r integrationMissingMarkRunner) CombinedOutput(command string, args ...string) ([]byte, error) {
	if r.unavailable(command, strings.Join(args, " ")) {
		return []byte(issue63MarkError), errors.New("missing extension")
	}
	return r.execRunner.CombinedOutput(command, args...)
}

func (r integrationMissingMarkRunner) CombinedOutputWithInput(input, command string, args ...string) ([]byte, error) {
	if r.unavailable(command, input) {
		return []byte(issue63MarkError), errors.New("missing extension")
	}
	return r.execRunner.CombinedOutputWithInput(input, command, args...)
}
