package proxy

import (
	"fmt"
	compiledipset "go-reauth-proxy/pkg/ipset"
	"go-reauth-proxy/pkg/models"
	"net/netip"
	"strings"
	"sync"
)

var visibilityExemptPrefixes = []netip.Prefix{
	mustParseVisibilityPrefix("100.64.0.0/10"),
}

func mustParseVisibilityPrefix(value string) netip.Prefix {
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		panic(err)
	}
	return prefix.Masked()
}

type gatewayVisibility struct {
	mu     sync.RWMutex
	config models.GatewayVisibilityConfig
	set    *compiledipset.Set
}

func normalizeGatewayVisibilityConfig(cfg models.GatewayVisibilityConfig) (models.GatewayVisibilityConfig, error) {
	normalized := models.GatewayVisibilityConfig{
		Enabled:   cfg.Enabled,
		UpdatedAt: strings.TrimSpace(cfg.UpdatedAt),
		PolicyID:  strings.TrimSpace(cfg.PolicyID),
		Policy:    cfg.Policy,
	}
	cidrs, err := normalizeVisibilityCIDRs(cfg.CIDRs, "visibility")
	if err != nil {
		return models.GatewayVisibilityConfig{}, err
	}
	normalized.CIDRs = cidrs
	return normalized, nil
}

func newGatewayVisibility(cfg models.GatewayVisibilityConfig) (*gatewayVisibility, error) {
	normalized, err := normalizeGatewayVisibilityConfig(cfg)
	if err != nil {
		return nil, err
	}
	_, set, err := compiledipset.Resolve("", nil, normalized.CIDRs)
	if err != nil {
		return nil, err
	}
	return &gatewayVisibility{config: normalized, set: set}, nil
}

func newCompiledGatewayVisibility(cfg models.GatewayVisibilityConfig, set *compiledipset.Set) *gatewayVisibility {
	return &gatewayVisibility{config: cfg, set: set}
}

func (v *gatewayVisibility) updateConfig(cfg models.GatewayVisibilityConfig) error {
	if v == nil {
		return nil
	}

	normalized, err := normalizeGatewayVisibilityConfig(cfg)
	if err != nil {
		return err
	}
	_, set, err := compiledipset.Resolve("", nil, normalized.CIDRs)
	if err != nil {
		return err
	}

	v.mu.Lock()
	v.config = normalized
	v.set = set
	v.mu.Unlock()
	return nil
}

func (v *gatewayVisibility) getConfig() models.GatewayVisibilityConfig {
	if v == nil {
		return models.GatewayVisibilityConfig{
			Enabled:   false,
			CIDRs:     []string{},
			UpdatedAt: "",
		}
	}

	v.mu.RLock()
	defer v.mu.RUnlock()

	cidrs := make([]string, len(v.config.CIDRs))
	copy(cidrs, v.config.CIDRs)

	return models.GatewayVisibilityConfig{
		Enabled:   v.config.Enabled,
		CIDRs:     cidrs,
		UpdatedAt: v.config.UpdatedAt,
		PolicyID:  v.config.PolicyID,
	}
}

func (v *gatewayVisibility) contains(clientIP string) bool {
	if v == nil {
		return true
	}
	v.mu.RLock()
	enabled := v.config.Enabled
	set := v.set
	v.mu.RUnlock()
	if !enabled {
		return true
	}
	addr, ok := visibilityClientAddr(clientIP)
	if !ok {
		return false
	}
	if isVisibilityExemptAddr(addr) {
		return true
	}
	if set != nil {
		return set.Contains(addr)
	}
	return false
}

func (v *gatewayVisibility) enabled() bool {
	if v == nil {
		return false
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.config.Enabled
}

func normalizeHostRuleVisibility(cfg models.HostRuleVisibility) (models.HostRuleVisibility, error) {
	mode := models.NormalizeHostVisibilityMode(cfg.Mode)
	policyID := strings.TrimSpace(cfg.PolicyID)
	cidrs, err := normalizeVisibilityCIDRs(cfg.CIDRs, "host visibility")
	if err != nil {
		return models.HostRuleVisibility{}, err
	}
	if mode == models.HostVisibilityModeCustom && len(cidrs) == 0 && policyID == "" {
		return models.HostRuleVisibility{}, fmt.Errorf("custom host visibility requires a policy or at least one cidr")
	}
	return models.HostRuleVisibility{Mode: mode, CIDRs: cidrs, PolicyID: policyID}, nil
}

func normalizeVisibilityCIDRs(values []string, label string) ([]string, error) {
	cidrs := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, fmt.Errorf("invalid %s cidr %q: %w", label, value, err)
		}
		prefix = prefix.Masked()
		value = prefix.String()
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		cidrs = append(cidrs, value)
	}
	return cidrs, nil
}

func isVisibilityExemptAddr(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}

	if addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() {
		return true
	}

	for _, prefix := range visibilityExemptPrefixes {
		if prefix.Contains(addr) {
			return true
		}
	}

	return false
}

func visibilityClientAddr(clientIP string) (netip.Addr, bool) {
	normalizedIP := normalizeClientIP(clientIP)
	if normalizedIP == "" {
		return netip.Addr{}, false
	}
	addr, err := netip.ParseAddr(normalizedIP)
	return addr, err == nil
}
