package proxy

import (
	"go-reauth-proxy/pkg/models"
	"net/url"
	"strings"
	"sync"
)

type preserveHostConfig struct {
	mu          sync.RWMutex
	config      models.PreserveHostConfig
	omitTargets map[string]struct{}
}

func newPreserveHostConfig(cfg models.PreserveHostConfig) *preserveHostConfig {
	runtime := &preserveHostConfig{
		omitTargets: make(map[string]struct{}),
	}
	runtime.updateConfig(cfg)
	return runtime
}

func (c *preserveHostConfig) updateConfig(cfg models.PreserveHostConfig) {
	normalized, omitTargets := normalizePreserveHostConfig(cfg)

	c.mu.Lock()
	c.config = normalized
	c.omitTargets = omitTargets
	c.mu.Unlock()
}

func (c *preserveHostConfig) shouldOmit(target *url.URL) bool {
	if c == nil {
		return false
	}

	key, ok := forwardedHeadersTargetKeyForURL(target)
	if !ok {
		return false
	}

	return c.shouldOmitKey(key)
}

func (c *preserveHostConfig) shouldOmitKey(key string) bool {
	if c == nil || key == "" {
		return false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.config.Enabled {
		return false
	}
	_, exists := c.omitTargets[key]
	return exists
}

func (c *preserveHostConfig) getConfig() models.PreserveHostConfig {
	if c == nil {
		return models.PreserveHostConfig{
			Enabled:     true,
			OmitTargets: []string{},
			UpdatedAt:   "",
		}
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	omitTargets := make([]string, len(c.config.OmitTargets))
	copy(omitTargets, c.config.OmitTargets)

	return models.PreserveHostConfig{
		Enabled:     c.config.Enabled,
		OmitTargets: omitTargets,
		UpdatedAt:   c.config.UpdatedAt,
	}
}

func normalizePreserveHostConfig(cfg models.PreserveHostConfig) (models.PreserveHostConfig, map[string]struct{}) {
	omitTargets := make([]string, 0, len(cfg.OmitTargets))
	omitTargetSet := make(map[string]struct{}, len(cfg.OmitTargets))

	for _, rawTarget := range cfg.OmitTargets {
		normalized, ok := normalizeForwardedHeadersTarget(rawTarget)
		if !ok {
			continue
		}
		if _, exists := omitTargetSet[normalized]; exists {
			continue
		}
		omitTargetSet[normalized] = struct{}{}
		omitTargets = append(omitTargets, normalized)
	}

	return models.PreserveHostConfig{
		Enabled:     cfg.Enabled,
		OmitTargets: omitTargets,
		UpdatedAt:   strings.TrimSpace(cfg.UpdatedAt),
	}, omitTargetSet
}
