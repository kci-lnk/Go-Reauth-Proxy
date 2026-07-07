package stream

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"go-reauth-proxy/pkg/config"
	"go-reauth-proxy/pkg/models"
	"go-reauth-proxy/pkg/proxy"
)

func TestNewManagerInitializesMaps(t *testing.T) {
	manager := NewManager(nil)
	if manager.listeners == nil || manager.rules == nil {
		t.Fatalf("manager maps not initialized: %#v", manager)
	}
}

func TestStreamRuleKeyStringUsesProtocolAndPort(t *testing.T) {
	if got := (streamRuleKey{Protocol: "udp", ListenPort: 5353}).String(); got != "udp/5353" {
		t.Fatalf("String() = %q", got)
	}
}

func TestDebugStreamKeysIncludesKey(t *testing.T) {
	got := debugStreamKeys([]streamRuleKey{{Protocol: "tcp", ListenPort: 3306}})
	if len(got) != 1 || got[0]["key"] != "tcp/3306" {
		t.Fatalf("debugStreamKeys() = %#v", got)
	}
}

func TestDebugSanitizeStringsPreservesCount(t *testing.T) {
	got := debugSanitizeStrings([]string{"a", "b"})
	if len(got) != 2 {
		t.Fatalf("debugSanitizeStrings() = %#v", got)
	}
}

func TestNormalizeStreamProtocolDefaultsToTCP(t *testing.T) {
	got, err := normalizeStreamProtocol(" ")
	if err != nil || got != models.StreamProtocolTCP {
		t.Fatalf("normalizeStreamProtocol() = %q, %v", got, err)
	}
}

func TestNormalizeStreamProtocolAcceptsUDPCaseInsensitively(t *testing.T) {
	got, err := normalizeStreamProtocol(" UDP ")
	if err != nil || got != models.StreamProtocolUDP {
		t.Fatalf("normalizeStreamProtocol() = %q, %v", got, err)
	}
}

func TestNormalizeStreamProtocolRejectsUnknown(t *testing.T) {
	if _, err := normalizeStreamProtocol("icmp"); err == nil {
		t.Fatal("normalizeStreamProtocol() accepted unknown protocol")
	}
}

func TestFallbackStreamProtocolDefaultsToTCP(t *testing.T) {
	if got := fallbackStreamProtocol(" "); got != models.StreamProtocolTCP {
		t.Fatalf("fallbackStreamProtocol() = %q", got)
	}
}

func TestFallbackStreamProtocolLowercasesUnknown(t *testing.T) {
	if got := fallbackStreamProtocol(" UDP "); got != "udp" {
		t.Fatalf("fallbackStreamProtocol() = %q", got)
	}
}

func TestParseStreamTargetAcceptsIPv6HostPort(t *testing.T) {
	host, port, err := parseStreamTarget("[::1]:3306")
	if err != nil || host != "::1" || port != 3306 {
		t.Fatalf("parseStreamTarget() = %q %d %v", host, port, err)
	}
}

func TestParseStreamTargetRejectsMissingPort(t *testing.T) {
	if _, _, err := parseStreamTarget("127.0.0.1"); err == nil {
		t.Fatal("parseStreamTarget() accepted target without port")
	}
}

func TestParseStreamTargetRejectsInvalidPort(t *testing.T) {
	if _, _, err := parseStreamTarget("127.0.0.1:70000"); err == nil {
		t.Fatal("parseStreamTarget() accepted invalid port")
	}
}

func TestNormalizeRuleTrimsTargetAndProtocol(t *testing.T) {
	manager := NewManager(nil)
	rule, err := manager.normalizeRule(models.StreamRule{Protocol: " UDP ", ListenPort: 5353, Target: " 127.0.0.1:5354 "})
	if err != nil {
		t.Fatalf("normalizeRule() returned error: %v", err)
	}
	if rule.Protocol != models.StreamProtocolUDP || rule.Target != "127.0.0.1:5354" {
		t.Fatalf("normalized rule = %#v", rule)
	}
}

func TestNormalizeRuleRejectsEmptyTarget(t *testing.T) {
	if _, err := NewManager(nil).normalizeRule(models.StreamRule{ListenPort: 1234}); err == nil {
		t.Fatal("normalizeRule() accepted empty target")
	}
}

func TestNormalizeRuleRejectsSameLocalPort(t *testing.T) {
	_, err := NewManager(nil).normalizeRule(models.StreamRule{Protocol: "udp", ListenPort: 5353, Target: "127.0.0.1:5353"})
	if err == nil {
		t.Fatal("normalizeRule() accepted same local listen and target port")
	}
}

func TestNormalizeRulesRejectsDuplicateKeys(t *testing.T) {
	_, err := NewManager(nil).normalizeRules([]models.StreamRule{
		{Protocol: "tcp", ListenPort: 3306, Target: "127.0.0.1:3307"},
		{Protocol: "TCP", ListenPort: 3306, Target: "127.0.0.1:3308"},
	})
	if err == nil {
		t.Fatal("normalizeRules() accepted duplicate keys")
	}
}

func TestReservedPortNameDetectsAdminPort(t *testing.T) {
	manager := NewManager(newStreamTestProxyHandler(t))
	name := manager.reservedPortName(models.StreamRule{Protocol: "tcp", ListenPort: 7996})
	if name != "admin API" {
		t.Fatalf("reservedPortName() = %q", name)
	}
}

func TestReservedPortNameIgnoresUDPProxyPort(t *testing.T) {
	manager := NewManager(newStreamTestProxyHandler(t))
	if got := manager.reservedPortName(models.StreamRule{Protocol: "udp", ListenPort: 7999}); got != "" {
		t.Fatalf("reservedPortName() = %q", got)
	}
}

func TestCompareStreamRuleKeysSortsByProtocolThenPort(t *testing.T) {
	if got := compareStreamRuleKeys(streamRuleKey{Protocol: "tcp", ListenPort: 2}, streamRuleKey{Protocol: "udp", ListenPort: 1}); got >= 0 {
		t.Fatalf("compareStreamRuleKeys protocol result = %d", got)
	}
	if got := compareStreamRuleKeys(streamRuleKey{Protocol: "tcp", ListenPort: 2}, streamRuleKey{Protocol: "tcp", ListenPort: 3}); got >= 0 {
		t.Fatalf("compareStreamRuleKeys port result = %d", got)
	}
}

func TestNewStreamEntrySetsRouteMetadata(t *testing.T) {
	entry := newStreamEntry(streamRuleKey{Protocol: "tcp", ListenPort: 3306}, "127.0.0.1:1", "127.0.0.1")
	if entry.Method != "STREAM" || entry.RouteKey != "tcp/3306" || !entry.Matched || entry.AuthDecision != "bypassed" {
		t.Fatalf("entry = %#v", entry)
	}
}

func TestIsLoopbackOrUnspecifiedHostAcceptsUnspecifiedIPv4(t *testing.T) {
	if !isLoopbackOrUnspecifiedHost("0.0.0.0") {
		t.Fatal("0.0.0.0 was not treated as unspecified")
	}
}

func TestIsTimeoutErrAcceptsContextDeadlineExceeded(t *testing.T) {
	if !isTimeoutErr(context.DeadlineExceeded) {
		t.Fatal("context deadline was not treated as timeout")
	}
}

func TestExtractRemoteIPHandlesTCPAddr(t *testing.T) {
	addr := &net.TCPAddr{IP: net.ParseIP("198.51.100.7"), Port: 1234}
	if got := extractRemoteIP(addr); got != "198.51.100.7" {
		t.Fatalf("extractRemoteIP() = %q", got)
	}
}

func TestAddrStringHandlesNilAddr(t *testing.T) {
	if got := addrString(nil); got != "" {
		t.Fatalf("addrString(nil) = %q", got)
	}
}

func TestReconcileStartsAndStopsTCPListener(t *testing.T) {
	manager := NewManager(newStreamTestProxyHandler(t))
	port := freeTCPPort(t)
	err := manager.Reconcile([]models.StreamRule{{Protocol: "tcp", ListenPort: port, Target: "127.0.0.1:1"}})
	if err != nil {
		t.Fatalf("Reconcile() returned error: %v", err)
	}
	key := streamRuleKey{Protocol: "tcp", ListenPort: port}
	if _, ok := manager.currentRule(key); !ok {
		t.Fatalf("currentRule(%v) missing", key)
	}
	manager.Stop()
	if err := manager.Reconcile(nil); err == nil {
		t.Fatal("Reconcile() returned nil after Stop")
	}
}

func TestReconcileRemovesListenersNoLongerConfigured(t *testing.T) {
	manager := NewManager(newStreamTestProxyHandler(t))
	defer manager.Stop()
	port := freeTCPPort(t)
	if err := manager.Reconcile([]models.StreamRule{{Protocol: "tcp", ListenPort: port, Target: "127.0.0.1:1"}}); err != nil {
		t.Fatalf("Reconcile(add) returned error: %v", err)
	}
	if err := manager.Reconcile(nil); err != nil {
		t.Fatalf("Reconcile(remove) returned error: %v", err)
	}
	if _, ok := manager.currentRule(streamRuleKey{Protocol: "tcp", ListenPort: port}); ok {
		t.Fatal("removed rule still present")
	}
}

func TestReconcileBestEffortSkipsInvalidRuleAndStartsValidRule(t *testing.T) {
	manager := NewManager(newStreamTestProxyHandler(t))
	defer manager.Stop()
	port := freeTCPPort(t)
	started, warnings := manager.ReconcileBestEffort([]models.StreamRule{
		{Protocol: "tcp", ListenPort: 0, Target: "127.0.0.1:1"},
		{Protocol: "tcp", ListenPort: port, Target: "127.0.0.1:1"},
	})
	if len(started) != 1 || len(warnings) != 1 {
		t.Fatalf("started=%#v warnings=%#v", started, warnings)
	}
}

func TestNormalizeRelayErrorKeepsUnexpectedError(t *testing.T) {
	err := errors.New("permission denied")
	if got := normalizeRelayError(err); got != err {
		t.Fatalf("normalizeRelayError() = %v, want original", got)
	}
}

func TestStreamRuleKeyFromRuleUsesNormalizedFields(t *testing.T) {
	key := streamRuleKeyFromRule(models.StreamRule{Protocol: "udp", ListenPort: 53})
	if !reflect.DeepEqual(key, streamRuleKey{Protocol: "udp", ListenPort: 53}) {
		t.Fatalf("key = %#v", key)
	}
}

func TestLocalServiceURLAddsMissingSlash(t *testing.T) {
	if got := localServiceURL(7997, "login"); !strings.HasSuffix(got, "/login") {
		t.Fatalf("localServiceURL() = %q", got)
	}
}

func newStreamTestProxyHandler(t *testing.T) *proxy.Handler {
	t.Helper()
	manager := config.NewManager(filepath.Join(t.TempDir(), "config.json"))
	cfg, err := manager.Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	return proxy.NewHandler(7996, 7999, manager, cfg, filepath.Join(t.TempDir(), "logs"), nil)
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}
