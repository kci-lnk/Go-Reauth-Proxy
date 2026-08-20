package waf

import (
	"net/http/httptest"
	"testing"

	"go-reauth-proxy/pkg/models"
)

func TestIsPrivateOrLocalIP(t *testing.T) {
	cases := []struct {
		value string
		want  bool
	}{
		{"127.0.0.1", true},
		{"192.168.31.2", true},
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"172.31.255.254", true},
		{"169.254.10.1", true},
		{"100.64.0.1", true},
		{"100.127.255.254", true},
		{"0.0.0.0", true},
		{"::1", true},
		{"fd7a:115c:a1e0::1", true},
		{"fe80::1", true},
		{"192.168.1.2:443", true},
		{"[fd00::1]:443", true},
		{"8.8.8.8", false},
		{"100.128.0.1", false},
		{"203.0.113.10", false},
		{"172.32.0.1", false},
		{"2001:db8::1", false},
		{"", false},
		{"not-an-ip", false},
	}

	for _, tc := range cases {
		if got := isPrivateOrLocalIP(tc.value); got != tc.want {
			t.Errorf("isPrivateOrLocalIP(%q) = %v, want %v", tc.value, got, tc.want)
		}
	}
}

func TestEvaluateSkipsPrivateIPWhenExemptionEnabled(t *testing.T) {
	rulesDir := t.TempDir()
	writeTestRule(t, rulesDir, `SecRule ARGS:test "@streq attack" "id:1002,phase:2,deny,status:403,msg:'test block',log"`)

	cfg := testConfig(rulesDir, ModeBlocking)
	cfg.PrivateIPExemptEnabled = true
	rt := NewRuntime(cfg, t.TempDir())
	if _, err := rt.Reload(rt.Config(), "", ""); err != nil {
		t.Fatalf("reload WAF: %v", err)
	}

	exempted := httptest.NewRequest("GET", "https://app.example.test/search?test=attack", nil)
	if decision := rt.Evaluate(exempted, EvaluateContext{ClientIP: "192.168.1.10"}); !decision.Allowed {
		t.Fatalf("expected private client IP to skip WAF, got %#v", decision)
	}

	publicReq := httptest.NewRequest("GET", "https://app.example.test/search?test=attack", nil)
	if decision := rt.Evaluate(publicReq, EvaluateContext{ClientIP: "203.0.113.10"}); decision.Allowed {
		t.Fatalf("expected public client IP to be evaluated, got %#v", decision)
	}
}

func TestEvaluateDoesNotSkipPrivateIPWhenExemptionDisabled(t *testing.T) {
	rulesDir := t.TempDir()
	writeTestRule(t, rulesDir, `SecRule ARGS:test "@streq attack" "id:1002,phase:2,deny,status:403,msg:'test block',log"`)

	cfg := testConfig(rulesDir, ModeBlocking)
	cfg.PrivateIPExemptEnabled = false
	rt := NewRuntime(cfg, t.TempDir())
	if _, err := rt.Reload(rt.Config(), "", ""); err != nil {
		t.Fatalf("reload WAF: %v", err)
	}

	req := httptest.NewRequest("GET", "https://app.example.test/search?test=attack", nil)
	if decision := rt.Evaluate(req, EvaluateContext{ClientIP: "192.168.1.10"}); decision.Allowed {
		t.Fatalf("expected private client IP to be evaluated when exemption is disabled, got %#v", decision)
	}
}

func TestEvaluateSkipsPrivateRemoteAddrWhenClientIPEmpty(t *testing.T) {
	rulesDir := t.TempDir()
	writeTestRule(t, rulesDir, `SecRule ARGS:test "@streq attack" "id:1002,phase:2,deny,status:403,msg:'test block',log"`)

	cfg := testConfig(rulesDir, ModeBlocking)
	cfg.PrivateIPExemptEnabled = true
	rt := NewRuntime(cfg, t.TempDir())
	if _, err := rt.Reload(rt.Config(), "", ""); err != nil {
		t.Fatalf("reload WAF: %v", err)
	}

	// When ClientIP is empty, Evaluate falls back to RemoteAddr. A private
	// RemoteAddr must still be exempted so the LAN exemption is consistent
	// with the address the WAF engine actually inspects.
	req := httptest.NewRequest("GET", "https://app.example.test/search?test=attack", nil)
	req.RemoteAddr = "192.168.1.5:8080"
	if decision := rt.Evaluate(req, EvaluateContext{}); !decision.Allowed {
		t.Fatalf("expected private RemoteAddr to skip WAF, got %#v", decision)
	}
}

func TestCopyConfigPreservesPrivateIPExemptFlag(t *testing.T) {
	original := models.WAFConfig{
		Enabled:                true,
		PrivateIPExemptEnabled: true,
	}
	copied := CopyConfig(original)
	if !copied.PrivateIPExemptEnabled {
		t.Fatalf("expected copied config to preserve private_ip_exempt_enabled")
	}
}
