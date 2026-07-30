package proxy

import (
	"go-reauth-proxy/pkg/models"
	"testing"
)

func TestCommonLocationExemptionsBypassesWAFForConfiguredCIDR(t *testing.T) {
	runtime := newCommonLocationExemptionsRuntime(models.CommonLocationExemptionsRuntime{
		Enabled:    true,
		WAFEnabled: true,
		CIDRs: []string{
			"203.0.113.42/24",
			"not-a-cidr",
			"2001:db8:abcd::1/64",
		},
		UpdatedAt: "2026-05-22T00:00:00Z",
	})

	if !runtime.shouldBypassWAF("203.0.113.10") {
		t.Fatal("expected IPv4 CIDR match to bypass WAF")
	}
	if !runtime.shouldBypassWAF("2001:db8:abcd::99") {
		t.Fatal("expected IPv6 CIDR match to bypass WAF")
	}
	if runtime.shouldBypassWAF("198.51.100.10") {
		t.Fatal("unexpected bypass for IP outside configured CIDRs")
	}

	config := runtime.getConfig()
	if len(config.CIDRs) != 0 || config.Policy == nil || config.PolicyID == "" {
		t.Fatalf("expected compact compiled policy, got %#v", config)
	}
}

func TestCommonLocationExemptionsRequiresWAFSwitch(t *testing.T) {
	runtime := newCommonLocationExemptionsRuntime(models.CommonLocationExemptionsRuntime{
		Enabled:    true,
		WAFEnabled: false,
		CIDRs:      []string{"203.0.113.0/24"},
	})

	if runtime.shouldBypassWAF("203.0.113.10") {
		t.Fatal("expected WAF switch to control WAF bypass")
	}
}

func TestCommonLocationExemptionsAcceptsClockRollbackRevocation(t *testing.T) {
	runtime := newCommonLocationExemptionsRuntime(models.CommonLocationExemptionsRuntime{
		Enabled:    true,
		WAFEnabled: true,
		CIDRs:      []string{"203.0.113.0/24"},
		UpdatedAt:  "2026-07-31T01:00:00Z",
	})
	if !runtime.shouldBypassWAF("203.0.113.10") {
		t.Fatal("initial WAF exemption was not active")
	}

	updated, err := runtime.updateConfig(models.CommonLocationExemptionsRuntime{
		Enabled:    false,
		WAFEnabled: false,
		UpdatedAt:  "2026-07-31T00:59:59Z",
	})
	if err != nil || !updated {
		t.Fatalf("authoritative WAF exemption revocation was rejected after clock rollback: updated=%v err=%v", updated, err)
	}
	if runtime.shouldBypassWAF("203.0.113.10") {
		t.Fatal("clock rollback preserved a revoked WAF exemption")
	}
}
