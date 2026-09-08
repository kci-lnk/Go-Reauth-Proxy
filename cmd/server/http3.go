package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"go-reauth-proxy/pkg/models"
	"go-reauth-proxy/pkg/proxy"
)

type http3ConnectionKey struct{}
type http3AttemptKey struct{}
type http3Peer struct {
	conn *quic.Conn
	ip   string
}
type http3Binding struct {
	server    *http3.Server
	transport *quic.Transport
	socket    *net.UDPConn
}
type http3Runtime struct {
	closed         atomic.Bool
	started        atomic.Bool
	mu             sync.Mutex
	handler        *proxy.Handler
	port           int
	host           string
	bindings       []*http3Binding
	state, failure string
	ready          atomic.Bool
	advertised     atomic.Int64
	active         atomic.Uint64
	failures       atomic.Uint64
	drainContext   context.Context
	cancelDrain    context.CancelFunc
}

func newHTTP3Runtime(h *proxy.Handler, port int) *http3Runtime {
	ctx, cancel := context.WithCancel(context.Background())
	return &http3Runtime{handler: h, port: port, state: "disabled", drainContext: ctx, cancelDrain: cancel}
}
func (m *http3Runtime) Status() models.GatewayHttp3Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := models.GatewayHttp3Status{State: m.state, Error: m.failure, ListenAddresses: []string{}, ActiveConnections: m.active.Load(), HandshakeFailures: m.failures.Load()}
	for _, b := range m.bindings {
		s.ListenAddresses = append(s.ListenAddresses, b.socket.LocalAddr().String())
	}
	return s
}
func (m *http3Runtime) desiredHost() string {
	if m.handler.GetProxyProtocolForce() || m.handler.GetGatewayListenerConfig().Scope == models.GatewayListenerScopeLoopback {
		return "127.0.0.1"
	}
	return "0.0.0.0"
}
func (m *http3Runtime) Apply(cfg models.GatewayHttp3Config) error {
	return m.ApplyHost(cfg, m.desiredHost(), false)
}

// Refresh is called by hooks already holding the listener transaction lock.
func (m *http3Runtime) Refresh() error {
	return m.ApplyHost(m.handler.GetGatewayHttp3Config(), m.desiredHost(), true)
}

// RefreshPolicy serializes certificate/protocol refreshes with configuration
// persistence, so a refresh cannot reapply an uncommitted configuration snapshot.
func (m *http3Runtime) RefreshPolicy() error {
	return m.handler.WithGatewayListenerChange(m.Refresh)
}
func (m *http3Runtime) ApplyHost(cfg models.GatewayHttp3Config, host string, rotate bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed.Load() {
		return net.ErrClosed
	}
	if cfg.AdvertisedPort < 0 || cfg.AdvertisedPort > 65535 {
		return fmt.Errorf("HTTP/3 advertised port must be between 0 and 65535")
	}
	previousPort := m.advertised.Swap(int64(cfg.AdvertisedPort))
	state := "running"
	if !m.started.Load() {
		m.state = "disabled"
		if cfg.Enabled {
			m.state = "waiting_bridge"
		}
		return nil
	}
	if !cfg.Enabled {
		state = "disabled"
	} else if m.handler.GetProxyProtocolForce() {
		state = "suspended_frp"
	} else if !m.handler.HasSSLCertificates() {
		state = "waiting_certificate"
	}
	if state != "running" {
		m.stopLocked(m.drainContext)
		m.state, m.failure = state, ""
		return nil
	}
	if len(m.bindings) > 0 && m.host == host && !rotate && m.ready.Load() {
		return nil
	}
	oldHost, hadBindings := m.host, len(m.bindings) > 0
	m.stopLocked(m.drainContext)
	if m.closed.Load() {
		return net.ErrClosed
	}
	if err := m.startLocked(host); err != nil {
		m.advertised.Store(previousPort)
		m.state, m.failure = "error", err.Error()
		if hadBindings {
			if rollback := m.startLocked(oldHost); rollback != nil {
				m.failure += "; rollback: " + rollback.Error()
			}
		}
		return err
	}
	return nil
}
func (m *http3Runtime) startLocked(host string) error {
	targets := []string{host}
	if host == "0.0.0.0" {
		targets = append(targets, "::")
	} else if host == "127.0.0.1" {
		targets = append(targets, "::1")
	}
	var bindings []*http3Binding
	cleanup := func() {
		for _, b := range bindings {
			_ = b.server.Close()
			_ = b.transport.Close()
			_ = b.socket.Close()
		}
	}
	for _, addr := range targets {
		network := "udp4"
		if strings.Contains(addr, ":") {
			network = "udp6"
		}
		socket, err := net.ListenUDP(network, &net.UDPAddr{IP: net.ParseIP(addr), Port: m.port})
		if err != nil {
			if network == "udp6" && (errors.Is(err, syscall.EAFNOSUPPORT) || errors.Is(err, syscall.EADDRNOTAVAIL)) {
				continue
			}
			cleanup()
			return fmt.Errorf("HTTP/3 bind %s: %w", addr, err)
		}
		transport := &quic.Transport{Conn: socket}
		transport.ConnContext = func(ctx context.Context, _ *quic.ClientInfo) (context.Context, error) {
			completed := &atomic.Bool{}
			ctx = context.WithValue(ctx, http3AttemptKey{}, completed)
			context.AfterFunc(ctx, func() {
				if !completed.Load() {
					m.failures.Add(1)
				}
			})
			return ctx, nil
		}
		server := &http3.Server{
			DisableExtendedConnect: true,
			Handler:                http.HandlerFunc(m.serveHTTP3),
			IdleTimeout:            120 * time.Second, MaxHeaderBytes: 1 << 20,
			ConnContext: func(ctx context.Context, c *quic.Conn) context.Context {
				if completed, ok := ctx.Value(http3AttemptKey{}).(*atomic.Bool); ok {
					completed.Store(true)
				}
				m.active.Add(1)
				context.AfterFunc(c.Context(), func() { m.active.Add(^uint64(0)) })
				peer := http3Peer{c, peerIP(c.RemoteAddr().String())}
				go func() {
					ticker := time.NewTicker(250 * time.Millisecond)
					defer ticker.Stop()
					for {
						select {
						case <-c.Context().Done():
							return
						case <-ticker.C:
							if peerIP(c.RemoteAddr().String()) != peer.ip {
								_ = c.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeRequestRejected), "client IP changed")
								return
							}
						}
					}
				}()
				return context.WithValue(ctx, http3ConnectionKey{}, peer)
			},
		}
		tlsConfig := http3.ConfigureTLSConfig(&tls.Config{MinVersion: tls.VersionTLS13, GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if m.handler.GetHostProtocolMode(info.ServerName) != models.HostProtocolModeAuto {
				return nil, fmt.Errorf("HTTP/3 disabled for this server name")
			}
			cert := m.handler.GetCertificate(info)
			if cert == nil {
				return nil, fmt.Errorf("TLS certificate unavailable")
			}
			return cert, nil
		}})
		// A non-early listener keeps all application requests behind the handshake.
		listener, err := transport.Listen(tlsConfig, &quic.Config{Allow0RTT: false, HandshakeIdleTimeout: 10 * time.Second, MaxIdleTimeout: 120 * time.Second, MaxIncomingStreams: 100, MaxIncomingUniStreams: 10, InitialStreamReceiveWindow: 512 << 10, MaxStreamReceiveWindow: 2 << 20, InitialConnectionReceiveWindow: 1 << 20, MaxConnectionReceiveWindow: 8 << 20})
		if err != nil {
			_ = transport.Close()
			_ = socket.Close()
			cleanup()
			return err
		}
		binding := &http3Binding{server, transport, socket}
		bindings = append(bindings, binding)
		go func() {
			err := server.ServeListener(listener)
			_ = listener.Close()
			if err != nil && err != http.ErrServerClosed {
				m.mu.Lock()
				for _, current := range m.bindings {
					if current == binding {
						m.ready.Store(false)
						m.state = "error"
						m.failure = err.Error()
						break
					}
				}
				m.mu.Unlock()
			}
		}()
	}
	m.bindings, m.host, m.state, m.failure = bindings, host, "running", ""
	m.ready.Store(true)
	return nil
}
func peerIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	ip := net.ParseIP(host)
	if ip != nil {
		return ip.String()
	}
	return host
}
func (m *http3Runtime) stopLocked(parent context.Context) {
	m.ready.Store(false)
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	for _, b := range m.bindings {
		wg.Add(1)
		go func(b *http3Binding) {
			defer wg.Done()
			_ = b.server.Shutdown(ctx)
			_ = b.server.Close()
			_ = b.transport.Close()
			_ = b.socket.Close()
		}(b)
	}
	wg.Wait()
	m.bindings = nil
}
func (m *http3Runtime) Shutdown(ctx context.Context) {
	m.closed.Store(true)
	// Interrupt an in-progress configuration drain before waiting for its mutex.
	m.cancelDrain()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopLocked(ctx)
	m.state = "disabled"
}
func (m *http3Runtime) serveHTTP3(w http.ResponseWriter, r *http.Request) {
	peer, ok := r.Context().Value(http3ConnectionKey{}).(http3Peer)
	if !ok {
		http.Error(w, "Missing QUIC peer", http.StatusInternalServerError)
		return
	}
	current := peer.conn.RemoteAddr().String()
	if peerIP(current) != peer.ip {
		_ = peer.conn.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeRequestRejected), "client IP changed")
		return
	}
	r.RemoteAddr = current
	if !m.ready.Load() || m.handler.GetProxyProtocolForce() || !m.handler.HasSSLCertificates() {
		http.Error(w, "HTTP/3 unavailable", http.StatusServiceUnavailable)
		return
	}
	// A native QUIC request is a direct ingress. Preserve its authority and
	// TLS scheme; do not let forwarding headers select a different host policy.
	r.Header.Del("X-Forwarded-Host")
	r.Header.Del("X-Forwarded-Proto")
	r.Header.Del("Forwarded")
	// The shared handler enforces per-host protocol policy (including 421),
	// throttles rejected requests, and records them in the normal access log.
	if r.Method == http.MethodConnect {
		http.Error(w, "CONNECT is not supported", http.StatusMethodNotAllowed)
		return
	}
	m.handler.ServeHTTP(&altSvcWriter{ResponseWriter: &http3AbortWriter{ResponseWriter: w, conn: peer.conn}, value: func() string { return m.altSvcValue(r) }}, r)
}

type http3AbortWriter struct {
	http.ResponseWriter
	conn *quic.Conn
}

func (w *http3AbortWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *http3AbortWriter) AbortHTTP3() {
	_ = w.conn.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeRequestCanceled), "blocked by gateway policy")
}
func (w *http3AbortWriter) Flush() { _ = http.NewResponseController(w.ResponseWriter).Flush() }

func (m *http3Runtime) Advertise(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !m.handler.CanAdvertiseHTTP3(r) {
			next.ServeHTTP(w, r)
			return
		}
		writer := &altSvcWriter{ResponseWriter: w, value: func() string { return m.altSvcValue(r) }}
		next.ServeHTTP(writer, r)
		if !writer.wrote {
			writer.WriteHeader(http.StatusOK)
		}
	})
}

// Evaluate at response commit, after any concurrent disable or policy update.
func (m *http3Runtime) altSvcValue(r *http.Request) string {
	if !m.ready.Load() || m.handler.GetProxyProtocolForce() || !m.handler.HasSSLCertificates() || m.handler.GetHostProtocolMode(r.Host) != models.HostProtocolModeAuto {
		return "clear"
	}
	port := int(m.advertised.Load())
	if port == 0 {
		port = 443
		if _, raw, err := net.SplitHostPort(r.Host); err == nil {
			if p, err := strconv.Atoi(raw); err == nil && p > 0 && p <= 65535 {
				port = p
			}
		}
	}
	return fmt.Sprintf(`h3=":%d"; ma=300`, port)
}

type altSvcWriter struct {
	http.ResponseWriter
	value func() string
	wrote bool
}

func (w *altSvcWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *altSvcWriter) WriteHeader(code int) {
	if !w.wrote {
		w.Header().Set("Alt-Svc", w.value())
		if code >= 200 || code == http.StatusSwitchingProtocols {
			w.wrote = true
		}
	}
	w.ResponseWriter.WriteHeader(code)
}
func (w *altSvcWriter) Write(b []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}
func (w *altSvcWriter) Flush() {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	_ = http.NewResponseController(w.ResponseWriter).Flush()
}

func (w *altSvcWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, rw, err := http.NewResponseController(w.ResponseWriter).Hijack()
	if err == nil {
		w.wrote = true
	}
	return conn, rw, err
}
