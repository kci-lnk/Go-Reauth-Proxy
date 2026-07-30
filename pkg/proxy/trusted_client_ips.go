package proxy

import (
	"fmt"
	"net/netip"
	"strings"
	"sync"

	compiledipset "go-reauth-proxy/pkg/ipset"
	"go-reauth-proxy/pkg/models"
)

var (
	gatewayTrustedIPv4Loopback = netip.MustParseAddr("127.0.0.1")
	gatewayTrustedIPv6Loopback = netip.MustParseAddr("::1")
)

type gatewayTrustedClientIPsRuntime struct {
	mu      sync.RWMutex
	config  models.GatewayTrustedClientIPsRuntime
	ips     map[string]struct{}
	cidrSet *compiledipset.Set
}

func newGatewayTrustedClientIPsRuntime(cfg models.GatewayTrustedClientIPsRuntime) *gatewayTrustedClientIPsRuntime {
	runtime := &gatewayTrustedClientIPsRuntime{
		ips: make(map[string]struct{}),
	}
	if _, err := runtime.updateConfig(cfg); err != nil {
		runtime.config = models.GatewayTrustedClientIPsRuntime{}
	}
	return runtime
}

func (r *gatewayTrustedClientIPsRuntime) getConfig() models.GatewayTrustedClientIPsRuntime {
	if r == nil {
		return models.GatewayTrustedClientIPsRuntime{
			IPs:       []string{},
			CIDRs:     []string{},
			UpdatedAt: "",
			PolicyID:  "",
		}
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	ips := append([]string(nil), r.config.IPs...)
	var policy *models.CompiledIPSet
	if r.config.Policy != nil {
		copied := compiledipset.Clone(*r.config.Policy)
		policy = &copied
	}
	return models.GatewayTrustedClientIPsRuntime{
		IPs:       ips,
		CIDRs:     []string{},
		UpdatedAt: r.config.UpdatedAt,
		PolicyID:  r.config.PolicyID,
		Policy:    policy,
	}
}

func (r *gatewayTrustedClientIPsRuntime) updateConfig(cfg models.GatewayTrustedClientIPsRuntime) (bool, error) {
	normalized, ips, cidrSet, err := normalizeGatewayTrustedClientIPsRuntime(cfg)
	if err != nil {
		return false, err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// The Rust control plane serializes and publishes this authoritative full
	// snapshot. UpdatedAt is diagnostic metadata rather than an ordering token;
	// using wall time to reject it can keep a revoked IP trusted after a clock
	// rollback or backup restore.
	r.config = normalized
	r.ips = ips
	r.cidrSet = cidrSet
	return true, nil
}

func (r *gatewayTrustedClientIPsRuntime) contains(clientIP string) bool {
	if r == nil {
		return false
	}
	normalizedIP, addr, ok := normalizeGatewayTrustedClientIP(clientIP)
	if !ok {
		return false
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	if _, exists := r.ips[normalizedIP]; exists {
		return true
	}
	if r.cidrSet != nil && r.cidrSet.Contains(addr) {
		return true
	}
	if equivalentLoopback, ok := gatewayTrustedEquivalentLoopback(addr); ok &&
		r.cidrSet != nil && r.cidrSet.Contains(equivalentLoopback) {
		return true
	}
	return false
}

func normalizeGatewayTrustedClientIPsRuntime(cfg models.GatewayTrustedClientIPsRuntime) (models.GatewayTrustedClientIPsRuntime, map[string]struct{}, *compiledipset.Set, error) {
	ips := make([]string, 0, len(cfg.IPs))
	ipSet := make(map[string]struct{}, len(cfg.IPs))
	for _, rawIP := range cfg.IPs {
		normalizedIP, _, ok := normalizeGatewayTrustedClientIP(rawIP)
		if !ok {
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
	compiled, compiledCIDRs, err := compiledipset.Resolve(cfg.PolicyID, cfg.Policy, legacyCIDRs)
	if err != nil {
		return models.GatewayTrustedClientIPsRuntime{}, nil, nil, fmt.Errorf(
			"invalid gateway trusted client IP policy: %w",
			err,
		)
	}

	return models.GatewayTrustedClientIPsRuntime{
		IPs:       ips,
		CIDRs:     []string{},
		UpdatedAt: strings.TrimSpace(cfg.UpdatedAt),
		PolicyID:  compiled.ID,
		Policy:    &compiled,
	}, ipSet, compiledCIDRs, nil
}

func normalizeGatewayTrustedClientIP(value string) (string, netip.Addr, bool) {
	_, addr, ok := normalizeReverseProxyThrottleExemptIP(value)
	if !ok {
		return "", netip.Addr{}, false
	}
	addr = addr.Unmap()
	if addr.Zone() != "" {
		addr = addr.WithZone("")
	}
	if addr == gatewayTrustedIPv6Loopback {
		addr = gatewayTrustedIPv4Loopback
	}
	return addr.String(), addr, true
}

func gatewayTrustedEquivalentLoopback(addr netip.Addr) (netip.Addr, bool) {
	switch addr {
	case gatewayTrustedIPv4Loopback:
		return gatewayTrustedIPv6Loopback, true
	case gatewayTrustedIPv6Loopback:
		return gatewayTrustedIPv4Loopback, true
	default:
		return netip.Addr{}, false
	}
}
