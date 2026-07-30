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
	mu       sync.RWMutex
	config   models.GatewayVisibilityConfig
	set      *compiledipset.Set
	prefixes []netip.Prefix
}

func normalizeGatewayVisibilityConfig(cfg models.GatewayVisibilityConfig) (models.GatewayVisibilityConfig, []netip.Prefix, error) {
	normalized := models.GatewayVisibilityConfig{
		Enabled:   cfg.Enabled,
		CIDRs:     make([]string, 0, len(cfg.CIDRs)),
		UpdatedAt: strings.TrimSpace(cfg.UpdatedAt),
		PolicyID:  strings.TrimSpace(cfg.PolicyID),
		Policy:    cfg.Policy,
	}

	seen := make(map[string]struct{}, len(cfg.CIDRs))
	prefixes := make([]netip.Prefix, 0, len(cfg.CIDRs))

	for _, rawCIDR := range cfg.CIDRs {
		cidr := strings.TrimSpace(rawCIDR)
		if cidr == "" {
			continue
		}

		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return models.GatewayVisibilityConfig{}, nil, fmt.Errorf("invalid visibility cidr %q: %w", cidr, err)
		}

		prefix = prefix.Masked()
		text := prefix.String()
		if _, exists := seen[text]; exists {
			continue
		}
		seen[text] = struct{}{}
		normalized.CIDRs = append(normalized.CIDRs, text)
		prefixes = append(prefixes, prefix)
	}

	return normalized, prefixes, nil
}

func newGatewayVisibility(cfg models.GatewayVisibilityConfig) (*gatewayVisibility, error) {
	normalized, prefixes, err := normalizeGatewayVisibilityConfig(cfg)
	if err != nil {
		return nil, err
	}

	return &gatewayVisibility{
		config:   normalized,
		prefixes: prefixes,
	}, nil
}

func newCompiledGatewayVisibility(cfg models.GatewayVisibilityConfig, set *compiledipset.Set) *gatewayVisibility {
	return &gatewayVisibility{config: cfg, set: set}
}

func (v *gatewayVisibility) updateConfig(cfg models.GatewayVisibilityConfig) error {
	if v == nil {
		return nil
	}

	normalized, prefixes, err := normalizeGatewayVisibilityConfig(cfg)
	if err != nil {
		return err
	}

	v.mu.Lock()
	v.config = normalized
	v.prefixes = prefixes
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
	v.mu.RLock()
	defer v.mu.RUnlock()
	for _, prefix := range v.prefixes {
		if prefix.Contains(addr) {
			return true
		}
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

func (v *gatewayVisibility) containsPrefixes(clientIP string, override []netip.Prefix, custom bool) bool {
	if v == nil {
		return true
	}

	v.mu.RLock()
	enabled := v.config.Enabled
	v.mu.RUnlock()

	if !enabled {
		return true
	}

	normalizedIP := normalizeClientIP(clientIP)
	if normalizedIP == "" {
		return false
	}

	addr, err := netip.ParseAddr(normalizedIP)
	if err != nil {
		return false
	}
	if isVisibilityExemptAddr(addr) {
		return true
	}

	prefixes := override
	if !custom {
		v.mu.RLock()
		defer v.mu.RUnlock()
		prefixes = v.prefixes
	}

	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}

	return false
}

func normalizeHostRuleVisibility(cfg models.HostRuleVisibility) (models.HostRuleVisibility, []netip.Prefix, error) {
	mode := models.NormalizeHostVisibilityMode(cfg.Mode)
	policyID := strings.TrimSpace(cfg.PolicyID)
	prefixes := make([]netip.Prefix, 0, len(cfg.CIDRs))
	cidrs := make([]string, 0, len(cfg.CIDRs))
	seen := make(map[string]struct{}, len(cfg.CIDRs))
	for _, raw := range cfg.CIDRs {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return models.HostRuleVisibility{}, nil, fmt.Errorf("invalid host visibility cidr %q: %w", value, err)
		}
		prefix = prefix.Masked()
		value = prefix.String()
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		cidrs = append(cidrs, value)
		prefixes = append(prefixes, prefix)
	}
	if mode == models.HostVisibilityModeCustom && len(prefixes) == 0 && policyID == "" {
		return models.HostRuleVisibility{}, nil, fmt.Errorf("custom host visibility requires a policy or at least one cidr")
	}
	return models.HostRuleVisibility{Mode: mode, CIDRs: cidrs, PolicyID: policyID}, prefixes, nil
}

func visibilityPrefixes(cidrs []string) []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(cidrs))
	for _, cidr := range cidrs {
		if prefix, err := netip.ParsePrefix(cidr); err == nil {
			prefixes = append(prefixes, prefix.Masked())
		}
	}
	return prefixes
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
