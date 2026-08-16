package proxy

import (
	"fmt"
	"net/netip"
	"strings"

	"go-reauth-proxy/pkg/models"
	"go-reauth-proxy/pkg/streamprobe"
)

const (
	maxStreamBypassGroups     = 16
	maxStreamBypassConditions = 16
)

func (h *Handler) normalizeStreamRule(newRule models.StreamRule) (models.StreamRule, error) {
	newRule.Target = strings.TrimSpace(newRule.Target)
	var err error
	newRule.Protocol, err = normalizeStreamProtocol(newRule.Protocol)
	if err != nil {
		return models.StreamRule{}, err
	}
	if newRule.ListenPort <= 0 || newRule.ListenPort > 65535 {
		return models.StreamRule{}, fmt.Errorf("listen_port must be between 1 and 65535")
	}
	if reservedName := h.reservedStreamPortName(newRule); reservedName != "" {
		return models.StreamRule{}, fmt.Errorf("listen_port %d is reserved for the %s", newRule.ListenPort, reservedName)
	}
	if newRule.Target == "" {
		return models.StreamRule{}, fmt.Errorf("cannot add stream rule with empty target")
	}
	targetHost, targetPort, err := h.checkSafeStreamTarget(newRule.Protocol, newRule.Target)
	if err != nil {
		return models.StreamRule{}, fmt.Errorf("invalid target: %v", err)
	}
	if newRule.ListenPort == targetPort && isLoopbackOrUnspecifiedHost(targetHost) {
		return models.StreamRule{}, fmt.Errorf("cannot target the same local listen_port %d", newRule.ListenPort)
	}

	newRule.ValidationMode = strings.ToLower(strings.TrimSpace(newRule.ValidationMode))
	if newRule.ValidationMode == "" {
		newRule.ValidationMode = models.StreamValidationOff
	}
	if newRule.ValidationMode != models.StreamValidationOff && newRule.ValidationMode != models.StreamValidationStrict {
		return models.StreamRule{}, fmt.Errorf("validation_mode must be off or strict")
	}
	profile := newRule.ServiceProfile
	profile.ServiceID = strings.ToLower(strings.TrimSpace(profile.ServiceID))
	profile.ServiceFamily = strings.TrimSpace(profile.ServiceFamily)
	profile.DeviceRole = strings.TrimSpace(profile.DeviceRole)
	profile.ServiceConfidence = strings.ToLower(strings.TrimSpace(profile.ServiceConfidence))
	profile.RoleConfidence = strings.ToLower(strings.TrimSpace(profile.RoleConfidence))
	profile.Source = strings.ToLower(strings.TrimSpace(profile.Source))
	profile.ObservedAt = strings.TrimSpace(profile.ObservedAt)
	profile.ClassifierVersion = strings.TrimSpace(profile.ClassifierVersion)
	profile.TargetFingerprint = strings.TrimSpace(profile.TargetFingerprint)
	profile.EvidenceCodes = append([]string(nil), profile.EvidenceCodes...)
	profile.Metadata = copyStringMap(profile.Metadata)
	newRule.ServiceProfile = profile
	newRule.ProbeStatus = strings.ToLower(strings.TrimSpace(newRule.ProbeStatus))

	policy, err := normalizeStreamBypassPolicy(newRule.BypassPolicy)
	if err != nil {
		return models.StreamRule{}, err
	}
	newRule.BypassPolicy = policy
	if !newRule.UseAuth {
		newRule.BypassPolicy.Enabled = false
	}

	if newRule.ValidationMode == models.StreamValidationStrict {
		if descriptor, _, _, known := streamprobe.Definition(profile.ServiceID); known {
			// This is catalog-owned capability metadata. Do not require every
			// control-plane version to echo the duplicated boolean back.
			newRule.ServiceProfile.StrictCapable = descriptor.StrictCapable
		}
		if strictErr := streamprobe.ValidateStrictProfile(
			newRule.ServiceProfile,
			newRule.Protocol,
			newRule.Target,
			newRule.ProbeStatus,
		); strictErr != nil && !newRule.Disabled {
			// Silently changing an enabled rule to disabled removes its listener
			// and turns a recoverable configuration error into connection refused.
			// Explicitly disabled rules remain valid as editable drafts.
			return models.StreamRule{}, fmt.Errorf("invalid strict stream profile: %w", strictErr)
		}
	}
	return newRule, nil
}

func (h *Handler) ValidateStreamRulesBundle(
	rules []models.StreamRule,
	policies map[string]models.CompiledIPSet,
) ([]models.StreamRule, map[string]models.CompiledIPSet, error) {
	normalizedPolicies, decodedPolicies, err := decodeVisibilityPolicies(policies)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid stream access policy: %w", err)
	}
	normalized := make([]models.StreamRule, 0, len(rules))
	seenRules := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		nextRule, err := h.normalizeStreamRule(rule)
		if err != nil {
			return nil, nil, err
		}
		for groupIndex := range nextRule.BypassPolicy.Groups {
			group := &nextRule.BypassPolicy.Groups[groupIndex]
			positive := false
			for conditionIndex := range group.Conditions {
				condition := &group.Conditions[conditionIndex]
				if condition.PolicyID == "" && len(condition.CIDRs) > 0 {
					policyID, compileErr := addLegacyVisibilityPolicy(condition.CIDRs, normalizedPolicies, decodedPolicies)
					if compileErr != nil {
						return nil, nil, fmt.Errorf("compile stream bypass condition %s: %w", condition.ID, compileErr)
					}
					condition.PolicyID = policyID
				}
				if condition.PolicyID == "" || decodedPolicies[condition.PolicyID] == nil {
					return nil, nil, fmt.Errorf("stream bypass condition %s references a missing compiled IP set", condition.ID)
				}
				if nextRule.BypassPolicy.Enabled && !nextRule.BypassPolicy.BroadRuleConfirmed && isBroadStreamAccessSet(decodedPolicies[condition.PolicyID]) {
					return nil, nil, fmt.Errorf("stream bypass condition %s covers at least half of an address family; broad_rule_confirmed is required", condition.ID)
				}
				condition.CIDRs = nil
				if condition.Operator == "equals" || condition.Operator == "in" || condition.Operator == "in_cidr" {
					positive = true
				}
			}
			if len(group.Conditions) == 0 {
				return nil, nil, fmt.Errorf("stream bypass group %s must contain at least one condition", group.ID)
			}
			if nextRule.BypassPolicy.Enabled && !positive && !nextRule.BypassPolicy.BroadRuleConfirmed {
				return nil, nil, fmt.Errorf("stream bypass group %s contains only negative conditions; broad_rule_confirmed is required", group.ID)
			}
		}
		key := streamRuleMapKey(nextRule)
		if _, exists := seenRules[key]; exists {
			return nil, nil, fmt.Errorf("duplicate stream rule for %s", key)
		}
		seenRules[key] = struct{}{}
		normalized = append(normalized, nextRule)
	}
	return normalized, normalizedPolicies, nil
}

func isBroadStreamAccessSet(set interface{ Prefixes() []string }) bool {
	for _, value := range set.Prefixes() {
		prefix, err := netip.ParsePrefix(value)
		if err == nil && prefix.Bits() <= 1 {
			return true
		}
	}
	return false
}

func (h *Handler) ValidateStreamRules(rules []models.StreamRule) ([]models.StreamRule, error) {
	h.mu.RLock()
	policies := copyVisibilityPolicies(h.StreamAccessPolicies)
	h.mu.RUnlock()
	normalized, _, err := h.ValidateStreamRulesBundle(rules, policies)
	return normalized, err
}

func normalizeStreamBypassPolicy(value models.StreamBypassPolicy) (models.StreamBypassPolicy, error) {
	value.PolicyVersion = strings.TrimSpace(value.PolicyVersion)
	if len(value.Groups) > maxStreamBypassGroups {
		return models.StreamBypassPolicy{}, fmt.Errorf("stream bypass policy supports at most %d groups", maxStreamBypassGroups)
	}
	groups := make([]models.StreamBypassGroup, 0, len(value.Groups))
	seenGroups := make(map[string]struct{}, len(value.Groups))
	for groupIndex, group := range value.Groups {
		group.ID = strings.TrimSpace(group.ID)
		if group.ID == "" {
			group.ID = fmt.Sprintf("group-%d", groupIndex+1)
		}
		if _, exists := seenGroups[group.ID]; exists {
			return models.StreamBypassPolicy{}, fmt.Errorf("duplicate stream bypass group id %q", group.ID)
		}
		seenGroups[group.ID] = struct{}{}
		if len(group.Conditions) > maxStreamBypassConditions {
			return models.StreamBypassPolicy{}, fmt.Errorf("stream bypass group %s supports at most %d conditions", group.ID, maxStreamBypassConditions)
		}
		conditions := make([]models.StreamBypassCondition, 0, len(group.Conditions))
		seenConditions := make(map[string]struct{}, len(group.Conditions))
		for conditionIndex, condition := range group.Conditions {
			condition.ID = strings.TrimSpace(condition.ID)
			if condition.ID == "" {
				condition.ID = fmt.Sprintf("condition-%d", conditionIndex+1)
			}
			if _, exists := seenConditions[condition.ID]; exists {
				return models.StreamBypassPolicy{}, fmt.Errorf("duplicate stream bypass condition id %q in group %s", condition.ID, group.ID)
			}
			seenConditions[condition.ID] = struct{}{}
			condition.Target = strings.ToLower(strings.TrimSpace(condition.Target))
			condition.Operator = strings.ToLower(strings.TrimSpace(condition.Operator))
			condition.PolicyID = strings.TrimSpace(condition.PolicyID)
			switch condition.Target {
			case "source_ip":
				if condition.Operator != "equals" && condition.Operator != "not_equals" && condition.Operator != "in_cidr" && condition.Operator != "not_in_cidr" {
					return models.StreamBypassPolicy{}, fmt.Errorf("unsupported source_ip operator %q", condition.Operator)
				}
			case "source_region":
				if condition.Operator != "in" && condition.Operator != "not_in" {
					return models.StreamBypassPolicy{}, fmt.Errorf("unsupported source_region operator %q", condition.Operator)
				}
			default:
				return models.StreamBypassPolicy{}, fmt.Errorf("stream bypass conditions only support source_ip and source_region")
			}
			condition.CIDRs = trimNonEmptyStrings(condition.CIDRs)
			conditions = append(conditions, condition)
		}
		group.Conditions = conditions
		groups = append(groups, group)
	}
	value.Groups = groups
	if value.Enabled && (value.PolicyVersion == "" || len(value.Groups) == 0) {
		return models.StreamBypassPolicy{}, fmt.Errorf("enabled stream bypass policy requires policy_version and at least one group")
	}
	return value, nil
}

func trimNonEmptyStrings(values []string) []string {
	trimmed := make([]string, 0, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			trimmed = append(trimmed, value)
		}
	}
	return trimmed
}
