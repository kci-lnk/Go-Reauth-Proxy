package proxy

import (
	"strings"
	"testing"

	compiledipset "go-reauth-proxy/pkg/ipset"
	"go-reauth-proxy/pkg/models"
	"go-reauth-proxy/pkg/streamprobe"
)

func TestValidateStreamRulesDoesNotSilentlyDisableInvalidStrictRule(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	rule := models.StreamRule{
		Protocol:       models.StreamProtocolTCP,
		ListenPort:     43998,
		Target:         "127.0.0.1:43999",
		ValidationMode: models.StreamValidationStrict,
		ServiceProfile: models.StreamServiceProfile{ServiceID: "ssh"},
	}

	if normalized, _, err := handler.ValidateStreamRulesBundle([]models.StreamRule{rule}, nil); err == nil {
		t.Fatalf("invalid enabled strict rule was silently accepted: %#v", normalized)
	} else if !strings.Contains(err.Error(), "invalid strict stream profile") {
		t.Fatalf("strict validation error = %v", err)
	}

	rule.Disabled = true
	normalized, _, err := handler.ValidateStreamRulesBundle([]models.StreamRule{rule}, nil)
	if err != nil {
		t.Fatalf("explicitly disabled strict draft was rejected: %v", err)
	}
	if len(normalized) != 1 || !normalized[0].Disabled {
		t.Fatalf("disabled strict draft = %#v", normalized)
	}
}

func TestValidateStreamRulesDerivesStrictCapabilityFromCatalog(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	target := "127.0.0.1:44001"
	rule := models.StreamRule{
		Protocol:       models.StreamProtocolTCP,
		ListenPort:     44000,
		Target:         target,
		ValidationMode: models.StreamValidationStrict,
		ProbeStatus:    "manual",
		ServiceProfile: models.StreamServiceProfile{
			ServiceID:         "ssh",
			Source:            "manual",
			TargetFingerprint: streamprobe.TargetFingerprint(models.StreamProtocolTCP, target),
			// StrictCapable is deliberately omitted to model an older control plane.
		},
	}

	normalized, _, err := handler.ValidateStreamRulesBundle([]models.StreamRule{rule}, nil)
	if err != nil {
		t.Fatalf("catalog-backed strict profile was rejected: %v", err)
	}
	if len(normalized) != 1 || normalized[0].Disabled || !normalized[0].ServiceProfile.StrictCapable {
		t.Fatalf("normalized strict rule = %#v", normalized)
	}
}

func TestValidateStreamRulesAllowsDisabledNegativeOnlyDraft(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	policy, err := compiledipset.Compile([]string{"192.0.2.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	rule := models.StreamRule{
		Protocol:   models.StreamProtocolTCP,
		ListenPort: 44000,
		Target:     "127.0.0.1:44001",
		UseAuth:    true,
		BypassPolicy: models.StreamBypassPolicy{
			Enabled: false,
			Groups: []models.StreamBypassGroup{{
				ID: "negative-draft",
				Conditions: []models.StreamBypassCondition{{
					ID: "outside-office", Target: "source_ip", Operator: "not_in_cidr", PolicyID: policy.ID,
				}},
			}},
		},
	}
	if _, _, err := handler.ValidateStreamRulesBundle(
		[]models.StreamRule{rule},
		map[string]models.CompiledIPSet{policy.ID: policy},
	); err != nil {
		t.Fatalf("disabled negative-only draft was rejected: %v", err)
	}

	rule.BypassPolicy.Enabled = true
	rule.BypassPolicy.PolicyVersion = "v1"
	if _, _, err := handler.ValidateStreamRulesBundle(
		[]models.StreamRule{rule},
		map[string]models.CompiledIPSet{policy.ID: policy},
	); err == nil || !strings.Contains(err.Error(), "broad_rule_confirmed") {
		t.Fatalf("enabled negative-only policy error = %v", err)
	}
}

func TestNormalizeStreamBypassPolicyRejectsInvalidShape(t *testing.T) {
	tests := []struct {
		name   string
		policy models.StreamBypassPolicy
		match  string
	}{
		{
			name: "operator does not belong to target",
			policy: models.StreamBypassPolicy{Groups: []models.StreamBypassGroup{{
				ID: "g1", Conditions: []models.StreamBypassCondition{{ID: "c1", Target: "source_ip", Operator: "in"}},
			}}},
			match: "source_ip operator",
		},
		{
			name: "duplicate group id",
			policy: models.StreamBypassPolicy{Groups: []models.StreamBypassGroup{
				{ID: "duplicate"}, {ID: "duplicate"},
			}},
			match: "duplicate stream bypass group",
		},
		{
			name: "duplicate condition id",
			policy: models.StreamBypassPolicy{Groups: []models.StreamBypassGroup{{
				ID: "g1",
				Conditions: []models.StreamBypassCondition{
					{ID: "duplicate", Target: "source_ip", Operator: "equals"},
					{ID: "duplicate", Target: "source_ip", Operator: "equals"},
				},
			}}},
			match: "duplicate stream bypass condition",
		},
		{
			name: "too many groups",
			policy: models.StreamBypassPolicy{
				Groups: make([]models.StreamBypassGroup, maxStreamBypassGroups+1),
			},
			match: "at most 16 groups",
		},
		{
			name: "too many conditions",
			policy: models.StreamBypassPolicy{Groups: []models.StreamBypassGroup{{
				ID:         "g1",
				Conditions: make([]models.StreamBypassCondition, maxStreamBypassConditions+1),
			}}},
			match: "at most 16 conditions",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := normalizeStreamBypassPolicy(test.policy)
			if err == nil || !strings.Contains(err.Error(), test.match) {
				t.Fatalf("normalizeStreamBypassPolicy error = %v, want %q", err, test.match)
			}
		})
	}
}

func TestValidateStreamRulesRequiresConfirmationForBroadCompiledSet(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	policy, err := compiledipset.Compile([]string{"0.0.0.0/1"})
	if err != nil {
		t.Fatal(err)
	}
	rule := models.StreamRule{
		Protocol:   models.StreamProtocolTCP,
		ListenPort: 44002,
		Target:     "127.0.0.1:44003",
		UseAuth:    true,
		BypassPolicy: models.StreamBypassPolicy{
			Enabled:       true,
			PolicyVersion: "v1",
			Groups: []models.StreamBypassGroup{{ID: "broad", Conditions: []models.StreamBypassCondition{{
				ID: "half-internet", Target: "source_ip", Operator: "in_cidr", PolicyID: policy.ID,
			}}}},
		},
	}
	if _, _, err := handler.ValidateStreamRulesBundle(
		[]models.StreamRule{rule},
		map[string]models.CompiledIPSet{policy.ID: policy},
	); err == nil || !strings.Contains(err.Error(), "broad_rule_confirmed") {
		t.Fatalf("broad compiled policy error = %v", err)
	}
	rule.BypassPolicy.BroadRuleConfirmed = true
	if _, _, err := handler.ValidateStreamRulesBundle(
		[]models.StreamRule{rule},
		map[string]models.CompiledIPSet{policy.ID: policy},
	); err != nil {
		t.Fatalf("confirmed broad compiled policy was rejected: %v", err)
	}
}
