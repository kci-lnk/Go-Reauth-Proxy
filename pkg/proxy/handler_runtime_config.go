package proxy

import (
	compiledipset "go-reauth-proxy/pkg/ipset"
	"go-reauth-proxy/pkg/logger"
	"go-reauth-proxy/pkg/models"
)

// commitConfigMutationLocked serializes the shared protocol for persisted
// settings that also have a lock-free runtime representation. The caller must
// hold h.mu. Runtime publication happens only after persistence succeeds, and
// a failed save restores the handler's previous configuration.
func (h *Handler) commitConfigMutationLocked(
	apply func(),
	rollback func(),
	publishRuntime func(),
) error {
	apply()
	if err := h.saveConfigLocked(); err != nil {
		rollback()
		return err
	}
	if publishRuntime != nil {
		publishRuntime()
	}
	return nil
}

func (h *Handler) SetReverseProxyThrottle(cfg models.ReverseProxyThrottleConfig) error {
	normalized := normalizeReverseProxyThrottleConfig(cfg)

	h.mu.Lock()
	previous := h.ReverseProxyThrottle
	throttle := h.reverseProxyThrottle
	if throttle == nil {
		throttle = newReverseProxyThrottle(previous)
	}
	saveErr := h.commitConfigMutationLocked(
		func() {
			h.ReverseProxyThrottle = normalized
		},
		func() {
			h.ReverseProxyThrottle = previous
		},
		func() {
			throttle.updateConfig(normalized)
			h.reverseProxyThrottle = throttle
		},
	)
	h.mu.Unlock()
	if saveErr != nil {
		return saveErr
	}
	if event := debugProxyEvent("reverse_proxy_throttle_set", ""); event != nil {
		event.Bool("enabled", normalized.Enabled).
			Int("requests_per_second", normalized.RequestsPerSecond).
			Int("burst", normalized.Burst).
			Int("block_seconds", normalized.BlockSeconds).
			Send()
	}
	return saveErr
}

func (h *Handler) SetGatewayVisibility(cfg models.GatewayVisibilityConfig) error {
	h.mu.Lock()
	candidatePolicies := copyVisibilityPolicies(h.VisibilityPolicies)
	candidateSets := make(map[string]*compiledipset.Set, len(h.compiledVisibilityPolicies)+1)
	for id, set := range h.compiledVisibilityPolicies {
		candidateSets[id] = set
	}
	normalized, set, err := prepareGatewayVisibilityPolicy(cfg, candidatePolicies, candidateSets)
	if err != nil {
		h.mu.Unlock()
		return err
	}
	pruneVisibilityPolicies(h.HostRules, normalized, candidatePolicies, candidateSets)
	if err := h.persistGatewayVisibilityAndPoliciesLocked(normalized, candidatePolicies); err != nil {
		h.mu.Unlock()
		return err
	}
	h.GatewayVisibility = normalized
	h.VisibilityPolicies = candidatePolicies
	h.compiledVisibilityPolicies = candidateSets
	// Keep the runtime and request snapshot publication inside the handler lock
	// so concurrent setters cannot apply their runtime updates out of order.
	visibility := h.gatewayVisibility
	if visibility == nil {
		visibility = newCompiledGatewayVisibility(normalized, set)
		h.gatewayVisibility = visibility
	} else {
		visibility.setCompiledConfig(normalized, set)
	}
	h.publishRequestSnapshotLocked()
	h.mu.Unlock()

	rangeCount := 0
	if set != nil {
		rangeCount = set.RangeCount()
	}
	if event := debugProxyEvent("gateway_visibility_set", ""); event != nil {
		event.Bool("enabled", normalized.Enabled).
			Int("range_count", rangeCount).
			Str("updated_at", logger.SanitizeLogString(normalized.UpdatedAt)).
			Send()
	}
	return nil
}

func (h *Handler) SetForwardedHeadersConfig(cfg models.ForwardedHeadersConfig) error {
	normalized, _ := normalizeForwardedHeadersConfig(cfg)

	h.mu.Lock()
	previous := h.ForwardedHeaders
	forwardedHeaders := h.forwardedHeaders
	if forwardedHeaders == nil {
		forwardedHeaders = newForwardedHeadersConfig(previous)
	}
	saveErr := h.commitConfigMutationLocked(
		func() {
			h.ForwardedHeaders = normalized
		},
		func() {
			h.ForwardedHeaders = previous
		},
		func() {
			forwardedHeaders.updateConfig(normalized)
			h.forwardedHeaders = forwardedHeaders
		},
	)
	h.mu.Unlock()
	if saveErr != nil {
		return saveErr
	}

	if event := debugProxyEvent("forwarded_headers_config_set", ""); event != nil {
		event.Bool("enabled", normalized.Enabled).
			Int("omit_target_count", len(normalized.OmitTargets)).
			Str("updated_at", logger.SanitizeLogString(normalized.UpdatedAt)).
			Send()
	}
	return nil
}

func (h *Handler) SetPreserveHostConfig(cfg models.PreserveHostConfig) error {
	normalized, _ := normalizePreserveHostConfig(cfg)

	h.mu.Lock()
	previous := h.PreserveHost
	preserveHost := h.preserveHost
	if preserveHost == nil {
		preserveHost = newPreserveHostConfig(previous)
	}
	saveErr := h.commitConfigMutationLocked(
		func() {
			h.PreserveHost = normalized
		},
		func() {
			h.PreserveHost = previous
		},
		func() {
			preserveHost.updateConfig(normalized)
			h.preserveHost = preserveHost
		},
	)
	h.mu.Unlock()
	if saveErr != nil {
		return saveErr
	}

	if event := debugProxyEvent("preserve_host_config_set", ""); event != nil {
		event.Bool("enabled", normalized.Enabled).
			Int("omit_target_count", len(normalized.OmitTargets)).
			Str("updated_at", logger.SanitizeLogString(normalized.UpdatedAt)).
			Send()
	}
	return nil
}
