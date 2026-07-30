package proxy

import (
	"fmt"
	compiledipset "go-reauth-proxy/pkg/ipset"
	"go-reauth-proxy/pkg/models"
	"net/netip"
	"strings"
	"sync"
)

type commonLocationExemptionsRuntime struct {
	mu     sync.RWMutex
	config models.CommonLocationExemptionsRuntime
	set    *compiledipset.Set
}

func newCommonLocationExemptionsRuntime(cfg models.CommonLocationExemptionsRuntime) *commonLocationExemptionsRuntime {
	runtime := &commonLocationExemptionsRuntime{}
	if _, err := runtime.updateConfig(cfg); err != nil {
		runtime.config = models.CommonLocationExemptionsRuntime{}
	}
	return runtime
}

func (r *commonLocationExemptionsRuntime) getConfig() models.CommonLocationExemptionsRuntime {
	if r == nil {
		return models.CommonLocationExemptionsRuntime{}
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	var policy *models.CompiledIPSet
	if r.config.Policy != nil {
		copied := compiledipset.Clone(*r.config.Policy)
		policy = &copied
	}
	return models.CommonLocationExemptionsRuntime{
		Enabled:    r.config.Enabled,
		WAFEnabled: r.config.WAFEnabled,
		CIDRs:      []string{},
		UpdatedAt:  r.config.UpdatedAt,
		PolicyID:   r.config.PolicyID,
		Policy:     policy,
	}
}

func (r *commonLocationExemptionsRuntime) updateConfig(cfg models.CommonLocationExemptionsRuntime) (bool, error) {
	normalized, set, err := normalizeCommonLocationExemptionsRuntime(cfg)
	if err != nil {
		return false, err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// This is an authoritative full snapshot from the serialized Rust control
	// plane. UpdatedAt is diagnostic metadata, not an ordering token: rejecting
	// it after a clock rollback can preserve a revoked WAF exemption forever.
	r.config = normalized
	r.set = set
	return true, nil
}

func (r *commonLocationExemptionsRuntime) shouldBypassWAF(clientIP string) bool {
	if r == nil {
		return false
	}

	normalizedIP := normalizeClientIP(clientIP)
	if normalizedIP == "" {
		return false
	}

	addr, err := netip.ParseAddr(normalizedIP)
	if err != nil {
		return false
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.config.Enabled &&
		r.config.WAFEnabled &&
		r.set != nil &&
		r.set.Contains(addr)
}

func normalizeCommonLocationExemptionsRuntime(cfg models.CommonLocationExemptionsRuntime) (models.CommonLocationExemptionsRuntime, *compiledipset.Set, error) {
	legacyCIDRs := cfg.CIDRs
	if cfg.Policy == nil {
		legacyCIDRs = normalizeLegacyCompiledCIDRs(cfg.CIDRs)
	}
	compiled, set, err := compiledipset.Resolve(cfg.PolicyID, cfg.Policy, legacyCIDRs)
	if err != nil {
		return models.CommonLocationExemptionsRuntime{}, nil, fmt.Errorf(
			"invalid common location exemption policy: %w",
			err,
		)
	}
	return models.CommonLocationExemptionsRuntime{
		Enabled:    cfg.Enabled,
		WAFEnabled: cfg.WAFEnabled,
		CIDRs:      []string{},
		UpdatedAt:  strings.TrimSpace(cfg.UpdatedAt),
		PolicyID:   compiled.ID,
		Policy:     &compiled,
	}, set, nil
}

func normalizeLegacyCompiledCIDRs(values []string) []string {
	normalized := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, raw := range values {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil {
			continue
		}
		text := prefix.Masked().String()
		if _, exists := seen[text]; exists {
			continue
		}
		seen[text] = struct{}{}
		normalized = append(normalized, text)
	}
	return normalized
}
