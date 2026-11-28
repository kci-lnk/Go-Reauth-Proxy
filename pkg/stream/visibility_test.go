package stream

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"

	compiledipset "go-reauth-proxy/pkg/ipset"
	"go-reauth-proxy/pkg/models"
)

type streamVisibilityTestConn struct {
	net.Conn
	remote net.Addr
}

func (c streamVisibilityTestConn) RemoteAddr() net.Addr { return c.remote }

func TestStreamVisibilityGatesTCPAndUDPBeforeAuthBypass(t *testing.T) {
	handler := newStreamTestProxyHandler(t)
	gateway := models.GatewayVisibilityConfig{Enabled: true, CIDRs: []string{"198.51.100.0/24"}}
	if err := handler.SetGatewayVisibility(gateway); err != nil {
		t.Fatal(err)
	}
	manager := NewManager(handler)
	t.Cleanup(manager.Stop)

	upstreamTCP, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = upstreamTCP.Close() })
	go func() {
		for {
			conn, err := upstreamTCP.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	upstreamUDP, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = upstreamUDP.Close() })

	custom, err := compiledipset.Compile([]string{"203.0.113.0/24", "2001:db8:1::/48"})
	if err != nil {
		t.Fatal(err)
	}
	bypass, err := compiledipset.Compile([]string{"0.0.0.0/0", "::/0"})
	if err != nil {
		t.Fatal(err)
	}
	policies := map[string]models.CompiledIPSet{custom.ID: custom, bypass.ID: bypass}
	bypassConfig := models.StreamBypassPolicy{
		Enabled: true, BroadRuleConfirmed: true,
		Groups: []models.StreamBypassGroup{{ID: "trusted", Conditions: []models.StreamBypassCondition{{
			ID: "ip", Target: "source_ip", Operator: "in_cidr", PolicyID: bypass.ID,
		}}}},
	}
	rules := []models.StreamRule{
		{Protocol: models.StreamProtocolTCP, ListenPort: freeTCPPort(t), Target: upstreamTCP.Addr().String(), UseAuth: true, BypassPolicy: bypassConfig},
		{Protocol: models.StreamProtocolUDP, ListenPort: freeUDPPort(t), Target: upstreamUDP.LocalAddr().String(), UseAuth: true, BypassPolicy: bypassConfig},
	}
	tcpKey, udpKey := streamRuleKeyFromRule(rules[0]), streamRuleKeyFromRule(rules[1])
	apply := func(t *testing.T, mode string) {
		t.Helper()
		for i := range rules {
			rules[i].Visibility = models.HostRuleVisibility{Mode: mode}
			if mode == models.HostVisibilityModeCustom {
				rules[i].Visibility.PolicyID = custom.ID
			}
		}
		if err := manager.ReconcileConfigBundle(rules, nil, policies); err != nil {
			t.Fatal(err)
		}
	}
	dialTCP := func(t *testing.T, ip string) net.Conn {
		t.Helper()
		peer, client := net.Pipe()
		if err := peer.SetDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		go manager.handleConn(streamVisibilityTestConn{
			Conn: client, remote: &net.TCPAddr{IP: net.ParseIP(ip), Port: 50001},
		}, tcpKey)
		return peer
	}
	checkTCP := func(t *testing.T, peer net.Conn, allowed bool) {
		t.Helper()
		_, err := peer.Write([]byte("x"))
		if !allowed {
			if err == nil {
				t.Fatal("a denied TCP client sent data upstream")
			}
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				t.Fatalf("TCP connection was not closed after denial: %v", err)
			}
			return
		}
		received := make([]byte, 1)
		if err != nil {
			t.Fatalf("write to allowed TCP connection: %v", err)
		}
		if _, err := io.ReadFull(peer, received); err != nil || string(received) != "x" {
			t.Fatalf("TCP upstream echo = %q, %v", received, err)
		}
	}
	udpListener := &udpListenerState{sessions: make(map[string]*udpSession)}
	initUDP := func(t *testing.T, ip string, port int, allowed bool) *udpSession {
		t.Helper()
		rule, _, visibility, ok := manager.currentRuleConfig(udpKey)
		if !ok {
			t.Fatal("missing UDP rule")
		}
		session, loaded, ok := udpListener.getOrCreateSession(upstreamUDP, &net.UDPAddr{IP: net.ParseIP(ip), Port: port}, rule)
		if !ok || loaded {
			t.Fatal("expected a new UDP session")
		}
		t.Cleanup(func() {
			session.close()
			udpListener.removeSession(session.id, session)
		})
		if got := manager.initializeUDPSession(session, visibility); got != allowed {
			t.Fatalf("UDP visibility for %s = %v, want %v", ip, got, allowed)
		}
		if !allowed && session.snapshotEntry().AuthDecision != "visibility_denied" {
			t.Fatalf("unexpected UDP denial: %#v", session.snapshotEntry())
		}
		return session
	}

	for i, tc := range []struct {
		name    string
		mode    string
		ip      string
		allowed bool
	}{
		{"legacy inherits allow", "", "198.51.100.4", true},
		{"inherited denial beats bypass", "inherit", "203.0.113.5", false},
		{"custom replaces gateway", "custom", "203.0.113.5", true},
		{"custom admits IPv6", "custom", "2001:db8:1::5", true},
		{"custom denies gateway-only address", "custom", "198.51.100.4", false},
		{"custom keeps local exemption", "custom", "100.64.0.5", true},
		{"disabled bypasses visibility", "disabled", "192.0.2.5", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			apply(t, tc.mode)
			peer := dialTCP(t, tc.ip)
			defer peer.Close()
			checkTCP(t, peer, tc.allowed)
			initUDP(t, tc.ip, 50002+i, tc.allowed)
		})
	}

	apply(t, "inherit")
	establishedTCP := dialTCP(t, "198.51.100.4")
	defer establishedTCP.Close()
	checkTCP(t, establishedTCP, true)
	establishedUDP := initUDP(t, "198.51.100.4", 50020, true)
	apply(t, "custom")
	checkTCP(t, establishedTCP, true)
	rule, _, _, _ := manager.currentRuleConfig(udpKey)
	session, reused, ok := udpListener.getOrCreateSession(upstreamUDP, establishedUDP.clientAddr, rule)
	if !ok || !reused || session != establishedUDP || session.upstreamConn() == nil {
		t.Fatal("existing UDP session was not preserved")
	}
	newTCP := dialTCP(t, "198.51.100.4")
	defer newTCP.Close()
	checkTCP(t, newTCP, false)
	initUDP(t, "198.51.100.4", 50021, false)

	candidate := append([]models.StreamRule(nil), rules...)
	for i := range candidate {
		candidate[i].Visibility = models.HostRuleVisibility{Mode: models.HostVisibilityModeDisabled}
	}
	persistErr := errors.New("simulated persistence failure")
	var tcpDuringCommit, udpDuringCommit models.StreamRule
	err = manager.ReconcileConfigBundleWithCommit(candidate, nil, policies, func() error {
		tcpDuringCommit, _ = manager.currentRule(tcpKey)
		udpDuringCommit, _ = manager.currentRule(udpKey)
		return persistErr
	})
	if !errors.Is(err, persistErr) {
		t.Fatalf("visibility commit error = %v", err)
	}
	if tcpDuringCommit.Visibility.PolicyID != custom.ID || udpDuringCommit.Visibility.PolicyID != custom.ID {
		t.Fatal("candidate visibility was published before persistence")
	}
	peer := dialTCP(t, "198.51.100.4")
	defer peer.Close()
	checkTCP(t, peer, false)
	initUDP(t, "198.51.100.4", 50023, false)

	candidate[0].Visibility.Mode = "custm"
	started, warnings := manager.ReconcileBestEffort(candidate[:1])
	if len(started) != 0 || len(warnings) != 1 {
		t.Fatalf("invalid startup visibility was accepted: %v, %v", started, warnings)
	}

	if err := handler.SetGatewayVisibility(models.GatewayVisibilityConfig{}); err != nil {
		t.Fatal(err)
	}
	gatewayOffTCP := dialTCP(t, "198.51.100.4")
	defer gatewayOffTCP.Close()
	checkTCP(t, gatewayOffTCP, true)
	initUDP(t, "198.51.100.4", 50022, true)

	delete(policies, custom.ID)
	if err := manager.ReconcileConfigBundle(rules, nil, policies); err == nil {
		t.Fatal("accepted a custom visibility rule with a missing compiled policy")
	}
}
