package proxy

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"

	"go-reauth-proxy/pkg/config"
	"go-reauth-proxy/pkg/models"
)

type proxyProtocolClientAddressContextKey struct{}

// WithProxyProtocolClientAddress marks a request context whose connection
// address came from an accepted PROXY protocol header. HTTP-layer forwarding
// headers must never override this transport-authenticated address.
func WithProxyProtocolClientAddress(ctx context.Context) context.Context {
	return context.WithValue(ctx, proxyProtocolClientAddressContextKey{}, true)
}

func requestUsesProxyProtocolClientAddress(ctx context.Context) bool {
	used, _ := ctx.Value(proxyProtocolClientAddressContextKey{}).(bool)
	return used
}

type gatewayProxyProtocolRuntime struct {
	mu        sync.RWMutex
	config    models.GatewayProxyProtocolConfig
	addresses map[netip.Addr]struct{}
	prefixes  []netip.Prefix
}

func newGatewayProxyProtocolRuntime(cfg models.GatewayProxyProtocolConfig) (*gatewayProxyProtocolRuntime, error) {
	runtime := &gatewayProxyProtocolRuntime{}
	if err := runtime.updateConfig(cfg); err != nil {
		return nil, err
	}
	return runtime, nil
}

func normalizeGatewayProxyProtocolConfig(cfg models.GatewayProxyProtocolConfig) (models.GatewayProxyProtocolConfig, map[netip.Addr]struct{}, []netip.Prefix, error) {
	addresses := make(map[netip.Addr]struct{})
	prefixSet := make(map[netip.Prefix]struct{})
	canonical := make([]string, 0, len(cfg.TrustedSources))
	seen := make(map[string]struct{}, len(cfg.TrustedSources))

	for _, raw := range cfg.TrustedSources {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue
		}

		if addr, err := netip.ParseAddr(value); err == nil {
			if addr.Zone() != "" {
				return models.GatewayProxyProtocolConfig{}, nil, nil, fmt.Errorf("trusted source %q must not contain an IPv6 zone", value)
			}
			addr = addr.Unmap()
			key := addr.String()
			if _, exists := seen[key]; !exists {
				seen[key] = struct{}{}
				canonical = append(canonical, key)
				addresses[addr] = struct{}{}
			}
			continue
		}

		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return models.GatewayProxyProtocolConfig{}, nil, nil, fmt.Errorf("trusted source %q must be an IP address or CIDR", value)
		}
		if prefix.Addr().Zone() != "" {
			return models.GatewayProxyProtocolConfig{}, nil, nil, fmt.Errorf("trusted source %q must not contain an IPv6 zone", value)
		}
		prefix = prefix.Masked()
		if prefix.Bits() == 0 {
			return models.GatewayProxyProtocolConfig{}, nil, nil, fmt.Errorf("trusted source %q must not cover every address", value)
		}
		key := prefix.String()
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		canonical = append(canonical, key)
		prefixSet[prefix] = struct{}{}
	}

	if cfg.Enabled && len(canonical) == 0 {
		return models.GatewayProxyProtocolConfig{}, nil, nil, fmt.Errorf("at least one trusted source is required when PROXY protocol is enabled")
	}
	slices.Sort(canonical)
	prefixes := make([]netip.Prefix, 0, len(prefixSet))
	for prefix := range prefixSet {
		prefixes = append(prefixes, prefix)
	}
	return models.GatewayProxyProtocolConfig{Enabled: cfg.Enabled, TrustedSources: canonical}, addresses, prefixes, nil
}

// ValidateGatewayProxyProtocolConfig validates and canonicalizes external
// trusted sources without changing the running listener.
func ValidateGatewayProxyProtocolConfig(cfg models.GatewayProxyProtocolConfig) (models.GatewayProxyProtocolConfig, error) {
	normalized, _, _, err := normalizeGatewayProxyProtocolConfig(cfg)
	return normalized, err
}

func (r *gatewayProxyProtocolRuntime) updateConfig(cfg models.GatewayProxyProtocolConfig) error {
	normalized, addresses, prefixes, err := normalizeGatewayProxyProtocolConfig(cfg)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.config = normalized
	r.addresses = addresses
	r.prefixes = prefixes
	r.mu.Unlock()
	return nil
}

func (r *gatewayProxyProtocolRuntime) getConfig() models.GatewayProxyProtocolConfig {
	if r == nil {
		return models.GatewayProxyProtocolConfig{TrustedSources: []string{}}
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return models.GatewayProxyProtocolConfig{
		Enabled:        r.config.Enabled,
		TrustedSources: append([]string(nil), r.config.TrustedSources...),
	}
}

func (r *gatewayProxyProtocolRuntime) contains(address net.Addr) bool {
	if r == nil || address == nil {
		return false
	}
	host, _, err := net.SplitHostPort(address.String())
	if err != nil {
		return false
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(host))
	if err != nil {
		return false
	}
	addr = addr.Unmap()

	r.mu.RLock()
	defer r.mu.RUnlock()
	if !r.config.Enabled {
		return false
	}
	if _, ok := r.addresses[addr]; ok {
		return true
	}
	for _, prefix := range r.prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func isLoopbackProxyProtocolSource(address net.Addr) bool {
	if address == nil {
		return false
	}
	host, _, err := net.SplitHostPort(address.String())
	if err != nil {
		return false
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(host))
	return err == nil && addr.IsLoopback()
}

func (h *Handler) GetProxyProtocolForce() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.ProxyProtocolForce
}

func (h *Handler) SetProxyProtocolForce(force bool) error {
	h.listenerChangeMu.Lock()
	defer h.listenerChangeMu.Unlock()

	h.mu.Lock()
	previous := h.ProxyProtocolForce
	changed := previous != force
	if !changed {
		h.mu.Unlock()
		return nil
	}
	h.ProxyProtocolForce = force
	h.publishRequestSnapshotLocked()
	hook := h.getProxyProtocolForceChangeHook()
	h.mu.Unlock()

	if hook != nil {
		if err := hook(); err != nil {
			h.mu.Lock()
			h.ProxyProtocolForce = previous
			h.publishRequestSnapshotLocked()
			h.mu.Unlock()
			if rollbackErr := hook(); rollbackErr != nil {
				return fmt.Errorf("apply managed PROXY protocol mode: %w; restore previous listener: %v", err, rollbackErr)
			}
			return fmt.Errorf("apply managed PROXY protocol mode: %w", err)
		}
	}
	if err := h.persistProxyProtocolConfig(force, h.GetGatewayProxyProtocolConfig()); err != nil {
		h.mu.Lock()
		h.ProxyProtocolForce = previous
		h.publishRequestSnapshotLocked()
		h.mu.Unlock()
		if hook != nil {
			if rollbackErr := hook(); rollbackErr != nil {
				return fmt.Errorf("persist managed PROXY protocol mode: %w; restore previous listener: %v", err, rollbackErr)
			}
		}
		return fmt.Errorf("persist managed PROXY protocol mode: %w", err)
	}
	if event := debugProxyEvent("proxy_protocol_force_set", ""); event != nil {
		event.Bool("enabled", force).Bool("changed", changed).Send()
	}
	return nil
}

func (h *Handler) GetGatewayProxyProtocolConfig() models.GatewayProxyProtocolConfig {
	if h == nil || h.proxyProtocol == nil {
		return models.GatewayProxyProtocolConfig{TrustedSources: []string{}}
	}
	return h.proxyProtocol.getConfig()
}

func (h *Handler) SetGatewayProxyProtocolConfig(candidate models.GatewayProxyProtocolConfig) error {
	normalized, _, _, err := normalizeGatewayProxyProtocolConfig(candidate)
	if err != nil {
		return err
	}

	h.listenerChangeMu.Lock()
	defer h.listenerChangeMu.Unlock()

	previous := h.GetGatewayProxyProtocolConfig()
	if previous.Enabled == normalized.Enabled && slices.Equal(previous.TrustedSources, normalized.TrustedSources) {
		return nil
	}
	if err := h.proxyProtocol.updateConfig(normalized); err != nil {
		return err
	}
	h.mu.Lock()
	h.ProxyProtocol = normalized
	hook := h.getProxyProtocolForceChangeHook()
	force := h.ProxyProtocolForce
	h.mu.Unlock()

	rollbackRuntime := func() error {
		if err := h.proxyProtocol.updateConfig(previous); err != nil {
			return fmt.Errorf("restore previous PROXY protocol runtime config: %w", err)
		}
		h.mu.Lock()
		h.ProxyProtocol = previous
		h.mu.Unlock()
		return nil
	}
	if hook != nil {
		if err := hook(); err != nil {
			rollbackErr := rollbackRuntime()
			listenerRollbackErr := hook()
			result := fmt.Errorf("apply PROXY protocol config: %w", err)
			if rollbackErr != nil {
				result = fmt.Errorf("%w; %v", result, rollbackErr)
			}
			if listenerRollbackErr != nil {
				result = fmt.Errorf("%w; restore previous listener: %v", result, listenerRollbackErr)
			}
			return result
		}
	}
	if err := h.persistProxyProtocolConfig(force, normalized); err != nil {
		rollbackErr := rollbackRuntime()
		var listenerRollbackErr error
		if hook != nil {
			listenerRollbackErr = hook()
		}
		result := fmt.Errorf("persist PROXY protocol config: %w", err)
		if rollbackErr != nil {
			result = fmt.Errorf("%w; %v", result, rollbackErr)
		}
		if listenerRollbackErr != nil {
			result = fmt.Errorf("%w; restore previous listener: %v", result, listenerRollbackErr)
		}
		return result
	}
	return nil
}

func (h *Handler) ProxyProtocolEnabled() bool {
	return h.GetProxyProtocolForce() || h.GetGatewayProxyProtocolConfig().Enabled
}

func (h *Handler) IsProxyProtocolTrustedSource(address net.Addr) bool {
	if h.GetProxyProtocolForce() && isLoopbackProxyProtocolSource(address) {
		return true
	}
	return h.proxyProtocol != nil && h.proxyProtocol.contains(address)
}

func (h *Handler) persistProxyProtocolConfig(force bool, external models.GatewayProxyProtocolConfig) error {
	if h.configManager == nil {
		return nil
	}
	return h.configManager.Update(func(conf *config.AppConfig) error {
		conf.ProxyProtocolForce = force
		conf.ProxyProtocol = external
		return nil
	})
}
