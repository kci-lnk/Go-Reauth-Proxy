package proxy

import (
	"errors"
	"net"
	"reflect"
	"strings"
	"testing"

	"go-reauth-proxy/pkg/models"
)

func TestNormalizeGatewayProxyProtocolConfig(t *testing.T) {
	got, _, _, err := normalizeGatewayProxyProtocolConfig(models.GatewayProxyProtocolConfig{
		Enabled: true,
		TrustedSources: []string{
			" 192.0.2.10 ",
			"192.0.2.10",
			"10.0.0.9/24",
			"2001:db8::1/64",
			"::ffff:192.0.2.10",
		},
	})
	if err != nil {
		t.Fatalf("normalizeGatewayProxyProtocolConfig() error = %v", err)
	}
	want := models.GatewayProxyProtocolConfig{
		Enabled:        true,
		TrustedSources: []string{"10.0.0.0/24", "192.0.2.10", "2001:db8::/64"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalized config = %#v, want %#v", got, want)
	}
}

func TestSetGatewayProxyProtocolConfigReportsListenerRollbackFailure(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	calls := 0
	handler.SetProxyProtocolForceChangeHook(func() error {
		calls++
		return errors.New("bind failed")
	})

	err := handler.SetGatewayProxyProtocolConfig(models.GatewayProxyProtocolConfig{
		Enabled:        true,
		TrustedSources: []string{"192.0.2.10"},
	})
	if err == nil || !strings.Contains(err.Error(), "restore previous listener") {
		t.Fatalf("SetGatewayProxyProtocolConfig() error = %v, want rollback failure", err)
	}
	if calls != 2 {
		t.Fatalf("hook calls = %d, want apply plus rollback", calls)
	}
}

func TestNormalizeGatewayProxyProtocolConfigRejectsUnsafeSources(t *testing.T) {
	tests := []models.GatewayProxyProtocolConfig{
		{Enabled: true},
		{Enabled: true, TrustedSources: []string{"proxy.example.com"}},
		{Enabled: true, TrustedSources: []string{"0.0.0.0/0"}},
		{Enabled: true, TrustedSources: []string{"::/0"}},
	}
	for _, candidate := range tests {
		if _, _, _, err := normalizeGatewayProxyProtocolConfig(candidate); err == nil {
			t.Fatalf("normalizeGatewayProxyProtocolConfig(%#v) succeeded", candidate)
		}
	}
}

func TestGatewayProxyProtocolRuntimeMatchesOnlyEnabledTrustedPeers(t *testing.T) {
	runtime, err := newGatewayProxyProtocolRuntime(models.GatewayProxyProtocolConfig{
		Enabled:        true,
		TrustedSources: []string{"192.0.2.10", "2001:db8::/64"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range []net.Addr{
		&net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 443},
		&net.TCPAddr{IP: net.ParseIP("2001:db8::123"), Port: 443},
	} {
		if !runtime.contains(address) {
			t.Fatalf("trusted peer %s did not match", address)
		}
	}
	if runtime.contains(&net.TCPAddr{IP: net.ParseIP("192.0.2.11"), Port: 443}) {
		t.Fatal("untrusted peer matched")
	}
	if err := runtime.updateConfig(models.GatewayProxyProtocolConfig{TrustedSources: []string{"192.0.2.10"}}); err != nil {
		t.Fatal(err)
	}
	if runtime.contains(&net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 443}) {
		t.Fatal("disabled runtime accepted a trusted peer")
	}
}

func TestManagedProxyProtocolTrustsOnlyLoopback(t *testing.T) {
	if !isLoopbackProxyProtocolSource(&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}) {
		t.Fatal("IPv4 loopback was not trusted")
	}
	if !isLoopbackProxyProtocolSource(&net.TCPAddr{IP: net.ParseIP("::1"), Port: 1234}) {
		t.Fatal("IPv6 loopback was not trusted")
	}
	if isLoopbackProxyProtocolSource(&net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 1234}) {
		t.Fatal("non-loopback peer was trusted")
	}
}

func TestSetGatewayProxyProtocolConfigRollsBackWhenRebindFails(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	before := handler.GetGatewayProxyProtocolConfig()
	calls := 0
	handler.SetProxyProtocolForceChangeHook(func() error {
		calls++
		if calls == 1 {
			return errors.New("bind failed")
		}
		return nil
	})
	err := handler.SetGatewayProxyProtocolConfig(models.GatewayProxyProtocolConfig{
		Enabled:        true,
		TrustedSources: []string{"192.0.2.10"},
	})
	if err == nil {
		t.Fatal("SetGatewayProxyProtocolConfig() returned nil error")
	}
	if got := handler.GetGatewayProxyProtocolConfig(); !reflect.DeepEqual(got, before) {
		t.Fatalf("config after rollback = %#v, want %#v", got, before)
	}
	if calls != 2 {
		t.Fatalf("hook calls = %d, want failed apply plus rollback", calls)
	}
}

func TestSetGatewayProxyProtocolConfigRollsBackWhenPersistenceFails(t *testing.T) {
	handler, manager := newAdditionalProxyTestHandler(t)
	before := handler.GetGatewayProxyProtocolConfig()
	calls := 0
	handler.SetProxyProtocolForceChangeHook(func() error { calls++; return nil })
	breakConfigPersistence(t, manager)
	err := handler.SetGatewayProxyProtocolConfig(models.GatewayProxyProtocolConfig{
		Enabled:        true,
		TrustedSources: []string{"192.0.2.10"},
	})
	if err == nil {
		t.Fatal("SetGatewayProxyProtocolConfig() returned nil error")
	}
	if got := handler.GetGatewayProxyProtocolConfig(); !reflect.DeepEqual(got, before) {
		t.Fatalf("config after rollback = %#v, want %#v", got, before)
	}
	if calls != 2 {
		t.Fatalf("hook calls = %d, want apply plus rollback", calls)
	}
}
