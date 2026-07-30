package proxy

import (
	"fmt"
	"strings"

	compiledipset "go-reauth-proxy/pkg/ipset"
	"go-reauth-proxy/pkg/models"
)

func copyVisibilityPolicy(value models.CompiledIPSet) models.CompiledIPSet {
	value.ID = strings.TrimSpace(value.ID)
	value.IPv4Ranges = append(models.Base64URLBytes(nil), value.IPv4Ranges...)
	value.IPv6Ranges = append(models.Base64URLBytes(nil), value.IPv6Ranges...)
	return value
}

func copyVisibilityPolicies(values map[string]models.CompiledIPSet) map[string]models.CompiledIPSet {
	copied := make(map[string]models.CompiledIPSet, len(values))
	for id, value := range values {
		value = copyVisibilityPolicy(value)
		if value.ID == "" {
			value.ID = strings.TrimSpace(id)
		}
		copied[id] = value
	}
	return copied
}

func decodeVisibilityPolicies(values map[string]models.CompiledIPSet) (map[string]models.CompiledIPSet, map[string]*compiledipset.Set, error) {
	policies := make(map[string]models.CompiledIPSet, len(values))
	sets := make(map[string]*compiledipset.Set, len(values))
	for rawID, rawPolicy := range values {
		id := strings.TrimSpace(rawID)
		policy := copyVisibilityPolicy(rawPolicy)
		if policy.ID == "" {
			policy.ID = id
		}
		if id == "" || policy.ID != id {
			return nil, nil, fmt.Errorf("compiled visibility policy key %q does not match id %q", rawID, policy.ID)
		}
		set, err := compiledipset.Decode(policy)
		if err != nil {
			return nil, nil, fmt.Errorf("decode visibility policy %s: %w", id, err)
		}
		policies[id] = policy
		sets[id] = set
	}
	return policies, sets, nil
}

func addLegacyVisibilityPolicy(cidrs []string, policies map[string]models.CompiledIPSet, sets map[string]*compiledipset.Set) (string, error) {
	policy, err := compiledipset.Compile(cidrs)
	if err != nil {
		return "", err
	}
	set, err := compiledipset.Decode(policy)
	if err != nil {
		return "", err
	}
	policies[policy.ID] = copyVisibilityPolicy(policy)
	sets[policy.ID] = set
	return policy.ID, nil
}

func prepareHostVisibilityPolicy(
	visibility models.HostRuleVisibility,
	policies map[string]models.CompiledIPSet,
	sets map[string]*compiledipset.Set,
) (models.HostRuleVisibility, error) {
	normalized, err := normalizeHostRuleVisibility(visibility)
	if err != nil {
		return models.HostRuleVisibility{}, err
	}
	if normalized.Mode != models.HostVisibilityModeCustom {
		normalized.PolicyID = ""
		normalized.CIDRs = nil
		return normalized, nil
	}
	policyID := strings.TrimSpace(normalized.PolicyID)
	legacyCIDRs := len(normalized.CIDRs) > 0
	if policyID == "" {
		policyID, err = addLegacyVisibilityPolicy(normalized.CIDRs, policies, sets)
		if err != nil {
			return models.HostRuleVisibility{}, err
		}
	}
	if sets[policyID] == nil {
		return models.HostRuleVisibility{}, fmt.Errorf("custom host visibility references missing policy %s", policyID)
	}
	normalized.PolicyID = policyID
	if !legacyCIDRs {
		normalized.CIDRs = nil
	}
	return normalized, nil
}

func prepareGatewayVisibilityPolicy(
	cfg models.GatewayVisibilityConfig,
	policies map[string]models.CompiledIPSet,
	sets map[string]*compiledipset.Set,
) (models.GatewayVisibilityConfig, *compiledipset.Set, error) {
	normalized, err := normalizeGatewayVisibilityConfig(cfg)
	if err != nil {
		return models.GatewayVisibilityConfig{}, nil, err
	}
	if !normalized.Enabled {
		normalized.PolicyID = ""
		normalized.Policy = nil
		normalized.CIDRs = nil
		return normalized, nil, nil
	}
	if cfg.Policy != nil {
		policy := copyVisibilityPolicy(*cfg.Policy)
		if policy.ID == "" {
			policy.ID = strings.TrimSpace(cfg.PolicyID)
		}
		set, decodeErr := compiledipset.Decode(policy)
		if decodeErr != nil {
			return models.GatewayVisibilityConfig{}, nil, decodeErr
		}
		policies[policy.ID] = policy
		sets[policy.ID] = set
		normalized.PolicyID = policy.ID
	}
	policyID := strings.TrimSpace(normalized.PolicyID)
	legacyCIDRs := policyID == "" && cfg.Policy == nil
	if policyID == "" {
		policyID, err = addLegacyVisibilityPolicy(normalized.CIDRs, policies, sets)
		if err != nil {
			return models.GatewayVisibilityConfig{}, nil, err
		}
	}
	set := sets[policyID]
	if set == nil {
		return models.GatewayVisibilityConfig{}, nil, fmt.Errorf("gateway visibility references missing policy %s", policyID)
	}
	normalized.PolicyID = policyID
	normalized.Policy = nil
	if !legacyCIDRs {
		normalized.CIDRs = nil
	}
	return normalized, set, nil
}

func pruneVisibilityPolicies(
	rules []models.HostRule,
	global models.GatewayVisibilityConfig,
	policies map[string]models.CompiledIPSet,
	sets map[string]*compiledipset.Set,
) {
	referenced := make(map[string]struct{}, len(rules)+1)
	if global.Enabled && strings.TrimSpace(global.PolicyID) != "" {
		referenced[strings.TrimSpace(global.PolicyID)] = struct{}{}
	}
	for _, rule := range rules {
		if rule.Visibility.Mode == models.HostVisibilityModeCustom &&
			strings.TrimSpace(rule.Visibility.PolicyID) != "" {
			referenced[strings.TrimSpace(rule.Visibility.PolicyID)] = struct{}{}
		}
		for _, group := range rule.AdvancedAuth.Groups {
			for _, condition := range group.Conditions {
				if id := strings.TrimSpace(condition.PolicyID); id != "" {
					referenced[id] = struct{}{}
				}
			}
		}
	}
	for id := range policies {
		if _, ok := referenced[id]; !ok {
			delete(policies, id)
			delete(sets, id)
		}
	}
}
