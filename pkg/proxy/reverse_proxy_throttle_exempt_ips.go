package proxy

import (
	"fmt"
	compiledipset "go-reauth-proxy/pkg/ipset"
	"go-reauth-proxy/pkg/models"
	"net/netip"
	"strings"
	"sync"
)

type reverseProxyThrottleExemptIPsRuntime struct {
	mu     sync.RWMutex
	config models.ReverseProxyThrottleExemptIPsRuntime
	ips    map[string]struct{}
	set    *compiledipset.Set
}

func newReverseProxyThrottleExemptIPsRuntime(cfg models.ReverseProxyThrottleExemptIPsRuntime) *reverseProxyThrottleExemptIPsRuntime {
	runtime := &reverseProxyThrottleExemptIPsRuntime{
		ips: make(map[string]struct{}),
	}
	if _, err := runtime.updateConfig(cfg); err != nil {
		runtime.config = models.ReverseProxyThrottleExemptIPsRuntime{}
	}
	return runtime
}

func (r *reverseProxyThrottleExemptIPsRuntime) getConfig() models.ReverseProxyThrottleExemptIPsRuntime {
	if r == nil {
		return models.ReverseProxyThrottleExemptIPsRuntime{}
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	ips := append([]string(nil), r.config.IPs...)
	var policy *models.CompiledIPSet
	if r.config.Policy != nil {
		copied := compiledipset.Clone(*r.config.Policy)
		policy = &copied
	}
	return models.ReverseProxyThrottleExemptIPsRuntime{
		Enabled:   r.config.Enabled,
		IPs:       ips,
		CIDRs:     []string{},
		UpdatedAt: r.config.UpdatedAt,
		PolicyID:  r.config.PolicyID,
		Policy:    policy,
	}
}

func (r *reverseProxyThrottleExemptIPsRuntime) updateConfig(cfg models.ReverseProxyThrottleExemptIPsRuntime) (bool, error) {
	normalized, ipSet, set, err := normalizeReverseProxyThrottleExemptIPsRuntime(cfg)
	if err != nil {
		return false, err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// This is an authoritative full snapshot published by the serialized
	// control-plane whitelist transaction. Wall-clock timestamps are metadata,
	// not ordering tokens: rejecting an older timestamp after a clock rollback
	// can preserve a revoked security exemption indefinitely.
	r.config = normalized
	r.ips = ipSet
	r.set = set
	return true, nil
}

func (r *reverseProxyThrottleExemptIPsRuntime) shouldBypass(clientIP string) bool {
	normalizedIP, addr, ok := normalizeReverseProxyThrottleExemptIP(clientIP)
	if !ok {
		return false
	}

	if isVisibilityExemptAddr(addr) {
		return true
	}

	if r == nil {
		return false
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	if !r.config.Enabled {
		return false
	}
	if _, exists := r.ips[normalizedIP]; exists {
		return true
	}
	return r.set != nil && r.set.Contains(addr)
}

func normalizeReverseProxyThrottleExemptIPsRuntime(cfg models.ReverseProxyThrottleExemptIPsRuntime) (models.ReverseProxyThrottleExemptIPsRuntime, map[string]struct{}, *compiledipset.Set, error) {
	ips := make([]string, 0, len(cfg.IPs))
	ipSet := make(map[string]struct{}, len(cfg.IPs))
	for _, rawIP := range cfg.IPs {
		normalizedIP, addr, ok := normalizeReverseProxyThrottleExemptIP(rawIP)
		if !ok || isVisibilityExemptAddr(addr) {
			continue
		}
		if _, exists := ipSet[normalizedIP]; exists {
			continue
		}
		ipSet[normalizedIP] = struct{}{}
		ips = append(ips, normalizedIP)
	}

	legacyCIDRs := cfg.CIDRs
	if cfg.Policy == nil {
		legacyCIDRs = normalizeLegacyCompiledCIDRs(cfg.CIDRs)
	}
	compiled, set, err := compiledipset.Resolve(cfg.PolicyID, cfg.Policy, legacyCIDRs)
	if err != nil {
		return models.ReverseProxyThrottleExemptIPsRuntime{}, nil, nil, fmt.Errorf(
			"invalid reverse proxy throttle exemption policy: %w",
			err,
		)
	}
	return models.ReverseProxyThrottleExemptIPsRuntime{
		Enabled:   cfg.Enabled,
		IPs:       ips,
		CIDRs:     []string{},
		UpdatedAt: strings.TrimSpace(cfg.UpdatedAt),
		PolicyID:  compiled.ID,
		Policy:    &compiled,
	}, ipSet, set, nil
}

func normalizeReverseProxyThrottleExemptIP(value string) (string, netip.Addr, bool) {
	normalizedIP := normalizeIPAddress(value)
	if normalizedIP == "" {
		return "", netip.Addr{}, false
	}

	addr, err := netip.ParseAddr(normalizedIP)
	if err != nil {
		return "", netip.Addr{}, false
	}

	return normalizedIP, addr, true
}
