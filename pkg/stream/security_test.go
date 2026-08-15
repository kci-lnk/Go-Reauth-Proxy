package stream

import (
	"net"
	"testing"
	"time"

	compiledipset "go-reauth-proxy/pkg/ipset"
	"go-reauth-proxy/pkg/models"
	"go-reauth-proxy/pkg/streamprobe"
)

func TestValidateTCPInitialHandlesFragmentedRFBAndPreservesBytes(t *testing.T) {
	server, peer := net.Pipe()
	defer server.Close()
	defer peer.Close()
	go func() {
		_, _ = peer.Write([]byte("RFB 003."))
		time.Sleep(10 * time.Millisecond)
		_, _ = peer.Write([]byte("008\n"))
	}()

	payload, detected, evidence, err := validateTCPInitial(server, "rfb", streamprobe.DirectionServer)
	if err != nil {
		t.Fatalf("validateTCPInitial: %v", err)
	}
	if string(payload) != "RFB 003.008\n" || detected != "rfb" || evidence != "rfb_version_banner" {
		t.Fatalf("validation result = %q, %q, %q", payload, detected, evidence)
	}
}

func TestStreamBypassUsesCompiledSetAndInvalidIPNeverMatchesNegative(t *testing.T) {
	policy, err := compiledipset.Compile([]string{"192.0.2.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	set, err := compiledipset.Decode(policy)
	if err != nil {
		t.Fatal(err)
	}
	manager := NewManager(nil)
	manager.ruleSnapshot.Store(&streamRuleSnapshot{
		rules:                  map[streamRuleKey]models.StreamRule{},
		compiledAccessPolicies: map[string]*compiledipset.Set{policy.ID: set},
	})
	rule := models.StreamRule{UseAuth: true, BypassPolicy: models.StreamBypassPolicy{
		Enabled: true,
		Groups: []models.StreamBypassGroup{{ID: "trusted", Conditions: []models.StreamBypassCondition{{
			ID: "ip", Target: "source_ip", Operator: "in_cidr", PolicyID: policy.ID,
		}}}},
	}}
	if matched, group := manager.matchStreamBypass(rule, "192.0.2.44"); !matched || group != "trusted" {
		t.Fatalf("match = %v, %q", matched, group)
	}
	rule.BypassPolicy.Groups[0].Conditions[0].Operator = "not_in_cidr"
	if matched, _ := manager.matchStreamBypass(rule, "not-an-ip"); matched {
		t.Fatal("invalid client IP satisfied a negative condition")
	}
}

func TestValidateUDPInitialRejectsProbableRTP(t *testing.T) {
	rule := models.StreamRule{ServiceProfile: models.StreamServiceProfile{ServiceID: "rtp"}}
	packet := append([]byte{0x80, 0x60, 0, 1, 0, 0, 0, 1, 0, 0, 0, 2}, make([]byte, 20)...)
	_, _, err := validateUDPInitial(rule, packet)
	if err == nil {
		t.Fatal("probable RTP was accepted as a strict match")
	}
}
