package proxy

import (
	"context"
	"reflect"
	"time"

	"go-reauth-proxy/pkg/config"
	compiledipset "go-reauth-proxy/pkg/ipset"
	"go-reauth-proxy/pkg/logger"
	"go-reauth-proxy/pkg/models"
)

const gatewayVisibilityLockRetryInterval = 5 * time.Millisecond

// commitConfigMutationLocked serializes the shared protocol for persisted
// settings that also have a lock-free runtime representation. The caller must
// hold h.mu. Runtime publication happens only after persistence succeeds, and
// a failed save restores the handler's previous configuration.
func (h *Handler) commitConfigMutationLocked(
	apply func(),
	rollback func(),
	persist func(*config.AppConfig),
	publishRuntime func(),
) error {
	apply()
	if err := h.saveConfigMutationLocked(persist); err != nil {
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
		func(conf *config.AppConfig) {
			conf.ReverseProxyThrottle = h.ReverseProxyThrottle
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

func gatewayVisibilityConfigurationEqual(
	current models.GatewayVisibilityConfig,
	next models.GatewayVisibilityConfig,
	currentPolicies map[string]models.CompiledIPSet,
	nextPolicies map[string]models.CompiledIPSet,
) bool {
	// Runtime requests may carry the compiled policy inline, while persistence
	// stores it in VisibilityPolicies. Compare the durable representations so an
	// idempotent startup replay does not force an atomic config rewrite.
	current.Policy = nil
	next.Policy = nil
	current.CIDRs = nil
	next.CIDRs = nil
	return reflect.DeepEqual(current, next) && reflect.DeepEqual(
		copyVisibilityPolicies(currentPolicies),
		copyVisibilityPolicies(nextPolicies),
	)
}

func (h *Handler) SetGatewayVisibility(cfg models.GatewayVisibilityConfig) error {
	return h.SetGatewayVisibilityContext(context.Background(), cfg)
}

func (h *Handler) lockGatewayVisibilityContext(ctx context.Context) error {
	if ctx == nil || ctx.Done() == nil {
		h.mu.Lock()
		return nil
	}

	ticker := time.NewTicker(gatewayVisibilityLockRetryInterval)
	defer ticker.Stop()
	for {
		if h.mu.TryLock() {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (h *Handler) SetGatewayVisibilityContext(
	ctx context.Context,
	cfg models.GatewayVisibilityConfig,
) error {
	if ctx == nil {
		ctx = context.Background()
	}
	// A gRPC request can expire while waiting behind a slow disk flush. Stop the
	// wait promptly instead of retaining a cancelled server goroutine until the
	// shared handler lock eventually becomes available.
	if err := h.lockGatewayVisibilityContext(ctx); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		h.mu.Unlock()
		return err
	}
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
	if gatewayVisibilityConfigurationEqual(
		h.GatewayVisibility,
		normalized,
		h.VisibilityPolicies,
		candidatePolicies,
	) {
		h.mu.Unlock()
		return nil
	}
	if err := ctx.Err(); err != nil {
		h.mu.Unlock()
		return err
	}
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
		func(conf *config.AppConfig) {
			conf.ForwardedHeaders = h.ForwardedHeaders
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
		func(conf *config.AppConfig) {
			conf.PreserveHost = h.PreserveHost
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
