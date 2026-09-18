package proxy

import (
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const authResponseHeaderTimeout = 30 * time.Second

// Authentication endpoints must not hold gateway requests forever when Rust
// is alive but stalled. This deadline ends at headers, preserving streaming
// bodies, and does not change ordinary business-upstream timeouts.
func (h *Handler) authTransport() *http.Transport {
	h.authTransportOnce.Do(func() {
		if h.proxyTransport != nil {
			h.authProxyTransport = h.proxyTransport.Clone()
		} else {
			h.authProxyTransport = newProxyTransport()
		}
		h.authProxyTransport.ResponseHeaderTimeout = authResponseHeaderTimeout
	})
	return h.authProxyTransport
}

func isInternalAuthTarget(target *url.URL, authPort int) bool {
	if target == nil || target.Scheme != "http" || authPort <= 0 {
		return false
	}
	ip := net.ParseIP(target.Hostname())
	return (strings.EqualFold(target.Hostname(), "localhost") || (ip != nil && ip.IsLoopback())) && target.Port() == strconv.Itoa(authPort)
}
