package proxy

import (
	"net/netip"
	"strings"
	"sync"
	"time"

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
	runtime.updateConfig(cfg)
	return runtime
}

func (r *gatewayTrustedClientIPsRuntime) getConfig() models.GatewayTrustedClientIPsRuntime {
	if r == nil {
		return models.GatewayTrustedClientIPsRuntime{
			IPs:       []string{},
			CIDRs:     []string{},
			UpdatedAt: "",
		}
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	ips := append([]string(nil), r.config.IPs...)
	cidrs := append([]string(nil), r.config.CIDRs...)
	return models.GatewayTrustedClientIPsRuntime{
		IPs:       ips,
		CIDRs:     cidrs,
		UpdatedAt: r.config.UpdatedAt,
	}
}

func (r *gatewayTrustedClientIPsRuntime) updateConfig(cfg models.GatewayTrustedClientIPsRuntime) bool {
	normalized, ips, cidrSet := normalizeGatewayTrustedClientIPsRuntime(cfg)

	r.mu.Lock()
	defer r.mu.Unlock()

	if shouldIgnoreGatewayTrustedClientIPsUpdate(r.config.UpdatedAt, normalized.UpdatedAt) {
		return false
	}

	r.config = normalized
	r.ips = ips
	r.cidrSet = cidrSet
	return true
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
	if r.cidrSet.Contains(addr) {
		return true
	}
	if equivalentLoopback, ok := gatewayTrustedEquivalentLoopback(addr); ok &&
		r.cidrSet.Contains(equivalentLoopback) {
		return true
	}
	return false
}

func normalizeGatewayTrustedClientIPsRuntime(cfg models.GatewayTrustedClientIPsRuntime) (models.GatewayTrustedClientIPsRuntime, map[string]struct{}, *compiledipset.Set) {
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

	cidrs := make([]string, 0, len(cfg.CIDRs))
	cidrSet := make(map[string]struct{}, len(cfg.CIDRs))
	for _, rawCIDR := range cfg.CIDRs {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(rawCIDR))
		if err != nil {
			continue
		}
		prefix = prefix.Masked()
		text := prefix.String()
		if _, exists := cidrSet[text]; exists {
			continue
		}
		cidrSet[text] = struct{}{}
		cidrs = append(cidrs, text)
	}

	compiled, err := compiledipset.Compile(cidrs)
	if err != nil {
		return models.GatewayTrustedClientIPsRuntime{}, map[string]struct{}{}, nil
	}
	compiledCIDRs, err := compiledipset.Decode(compiled)
	if err != nil {
		return models.GatewayTrustedClientIPsRuntime{}, map[string]struct{}{}, nil
	}

	return models.GatewayTrustedClientIPsRuntime{
		IPs:       ips,
		CIDRs:     cidrs,
		UpdatedAt: strings.TrimSpace(cfg.UpdatedAt),
	}, ipSet, compiledCIDRs
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

func shouldIgnoreGatewayTrustedClientIPsUpdate(currentUpdatedAt string, nextUpdatedAt string) bool {
	currentTime, okCurrent := parseGatewayTrustedClientIPsUpdatedAt(currentUpdatedAt)
	nextTime, okNext := parseGatewayTrustedClientIPsUpdatedAt(nextUpdatedAt)
	return okCurrent && okNext && nextTime.Before(currentTime)
}

func parseGatewayTrustedClientIPsUpdatedAt(value string) (time.Time, bool) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339Nano, trimmed)
	if err == nil {
		return parsed, true
	}
	parsed, err = time.Parse(time.RFC3339, trimmed)
	return parsed, err == nil
}
