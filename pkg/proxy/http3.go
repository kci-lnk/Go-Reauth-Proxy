package proxy

import (
	"fmt"
	"go-reauth-proxy/pkg/config"
	"go-reauth-proxy/pkg/models"
	"net/http"
)

func (h *Handler) SetHTTP3Hooks(apply func(models.GatewayHttp3Config) error, status func() models.GatewayHttp3Status) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.http3Apply, h.http3Status = apply, status
}
func (h *Handler) GetGatewayHttp3Config() models.GatewayHttp3Config {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.GatewayHttp3
}
func (h *Handler) GetGatewayHttp3Status() models.GatewayHttp3Status {
	// Read runtime and persisted configuration from one completed transition.
	h.listenerChangeMu.Lock()
	defer h.listenerChangeMu.Unlock()
	h.mu.RLock()
	fn, cfg := h.http3Status, h.GatewayHttp3
	h.mu.RUnlock()
	result := models.GatewayHttp3Status{State: "disabled", ListenAddresses: []string{}}
	if fn != nil {
		result = fn()
	}
	result.Config = cfg
	return result
}

// Serialized with listener / PROXY policy changes. The admin layer additionally
// holds streamConfigMu so a UDP stream cannot race this reservation.
func (h *Handler) SetGatewayHttp3Config(cfg models.GatewayHttp3Config) error {
	if cfg.AdvertisedPort < 0 || cfg.AdvertisedPort > 65535 {
		return fmt.Errorf("advertised_port must be between 0 and 65535")
	}
	h.listenerChangeMu.Lock()
	defer h.listenerChangeMu.Unlock()
	h.mu.RLock()
	previous, apply := h.GatewayHttp3, h.http3Apply
	h.mu.RUnlock()
	if cfg.Enabled {
		if !h.HasSSLCertificates() && !previous.Enabled {
			return fmt.Errorf("HTTP/3 requires an installed TLS certificate")
		}
		rules, _, _ := h.GetStreamRulesBundle()
		for _, rule := range rules {
			if rule.Protocol == models.StreamProtocolUDP && rule.ListenPort == h.ProxyPort {
				return fmt.Errorf("UDP port %d is reserved by a stream rule", h.ProxyPort)
			}
		}
	}
	if apply != nil {
		if err := apply(cfg); err != nil {
			return err
		}
	}
	if cfg == previous {
		return nil
	}
	h.mu.Lock()
	err := h.saveConfigMutationLocked(func(conf *config.AppConfig) { conf.GatewayHttp3 = cfg })
	if err == nil {
		h.GatewayHttp3 = cfg
	}
	h.mu.Unlock()
	if err != nil && apply != nil {
		if rollback := apply(previous); rollback != nil {
			return fmt.Errorf("save HTTP/3 config: %w; restore runtime: %v", err, rollback)
		}
	}
	return err
}

// Only the direct HTTPS listener owns native Alt-Svc. Dedicated tunnel ingresses
// and authenticated TCP proxy connections advertise their own edge protocols.
func (h *Handler) CanAdvertiseHTTP3(r *http.Request) bool {
	if r.TLS == nil || fnosConnectContext(r) != nil || isManagedCloudflareTunnelIngress(r) || requestUsesProxyProtocolClientAddress(r.Context()) {
		return false
	}
	cfg := h.GetAuthConfig()
	return !cfg.TencentEdgeOneActive() && !cfg.AliyunESAActive()
}

func (h *Handler) abortConnection(w http.ResponseWriter) {
	for current := w; current != nil; {
		if closer, ok := current.(interface{ AbortHTTP3() }); ok {
			closer.AbortHTTP3()
			panic(http.ErrAbortHandler)
		}
		if unwrapper, ok := current.(interface{ Unwrap() http.ResponseWriter }); ok {
			current = unwrapper.Unwrap()
		} else {
			break
		}
	}

	rc := http.NewResponseController(w)
	conn, _, err := rc.Hijack()
	if err == nil && conn != nil {
		if tcpConn := unwrapTCPConn(conn); tcpConn != nil {
			_ = tcpConn.SetLinger(0)
			_ = tcpConn.Close()
			return
		}
		_ = conn.Close()
		return
	}
	panic(http.ErrAbortHandler)
}

// WithGatewayListenerChange serializes external policy refreshes with listener
// changes, including their persistence and rollback. The callback must not call
// listener configuration setters, which acquire this same lock.
func (h *Handler) WithGatewayListenerChange(refresh func() error) error {
	h.listenerChangeMu.Lock()
	defer h.listenerChangeMu.Unlock()
	return refresh()
}
