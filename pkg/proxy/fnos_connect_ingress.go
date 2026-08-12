package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"go-reauth-proxy/pkg/models"
)

const (
	fnosConnectRouteKey        = "fn_connect"
	fnosConnectBindMaxAttempts = 8
)

type fnosConnectRequestContext struct {
	hostRule models.HostRule
}

type fnosConnectRequestContextKey struct{}

type fnosConnectConnMetadata struct {
	loopback       bool
	originalPort   int
	originalDstErr error
}

type fnosConnectConnMetadataKey struct{}

type fnosConnectOriginalDstFunc func(net.Conn) (int, error)

// FnosConnectIngressStatus is a snapshot of the protected FN Connect listener.
// The Rust control plane uses the listener port to build cgroup-scoped OUTPUT
// redirects for relay traffic and PREROUTING redirects for direct P2P traffic.
type FnosConnectIngressStatus struct {
	Enabled          bool
	ListenerActive   bool
	ListenPort       int
	UpstreamHTTPPort int
	IPv4Active       bool
	IPv6Active       bool
	LastError        string
}

type fnosConnectListenFunc func(network, address string) (net.Listener, error)

// FnosConnectIngress owns a protected dual-stack HTTP ingress. Loopback peers
// carry fnOS relay traffic. Non-loopback peers are accepted only when Linux
// reports that their connection was redirected from the configured fnOS HTTP
// port, so the random listener port is not a second public entry point.
// Requests enter the regular Handler pipeline through a synthetic, auth-free
// host rule, keeping WAF, throttling, blacklist checks, traffic counters and
// access logs consistent with ordinary reverse-proxy traffic.
type FnosConnectIngress struct {
	mu          sync.Mutex
	handler     *Handler
	listen      fnosConnectListenFunc
	originalDst fnosConnectOriginalDstFunc
	server      *http.Server
	listener    []net.Listener
	status      FnosConnectIngressStatus
}

func NewFnosConnectIngress(handler *Handler) *FnosConnectIngress {
	return newFnosConnectIngressWithListener(handler, net.Listen)
}

func newFnosConnectIngressWithListener(handler *Handler, listen fnosConnectListenFunc) *FnosConnectIngress {
	if listen == nil {
		listen = net.Listen
	}
	return &FnosConnectIngress{
		handler:     handler,
		listen:      listen,
		originalDst: fnosConnectOriginalDestinationPort,
	}
}

func (i *FnosConnectIngress) Status() FnosConnectIngressStatus {
	if i == nil {
		return FnosConnectIngressStatus{}
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.status
}

// Apply enables, updates or disables the ingress. Updating the upstream port is
// atomic and keeps the allocated listener port stable, which lets the control
// plane switch firewall rules without interrupting established connections.
func (i *FnosConnectIngress) Apply(enabled bool, upstreamHTTPPort int) (FnosConnectIngressStatus, error) {
	if i == nil || i.handler == nil {
		return FnosConnectIngressStatus{}, errors.New("FN Connect ingress is unavailable")
	}
	if enabled && (upstreamHTTPPort < 1 || upstreamHTTPPort > 65535) {
		return i.recordError(fmt.Errorf("upstream HTTP port must be between 1 and 65535"))
	}

	i.mu.Lock()
	defer i.mu.Unlock()

	if !enabled {
		err := i.closeLocked()
		i.status = FnosConnectIngressStatus{}
		return i.status, err
	}

	if i.status.ListenerActive {
		i.status.Enabled = true
		i.status.UpstreamHTTPPort = upstreamHTTPPort
		i.status.LastError = ""
		return i.status, nil
	}

	var ipv4 net.Listener
	var ipv6 net.Listener
	var port int
	var err error
	var ipv6Err error
	for attempt := 0; attempt < fnosConnectBindMaxAttempts; attempt++ {
		ipv4, err = i.listen("tcp4", "0.0.0.0:0")
		if err != nil {
			i.status.LastError = fmt.Sprintf("bind IPv4 FN Connect listener: %v", err)
			return i.status, errors.New(i.status.LastError)
		}
		tcpAddr, ok := ipv4.Addr().(*net.TCPAddr)
		if !ok || tcpAddr.Port < 1 || tcpAddr.Port > 65535 {
			_ = ipv4.Close()
			i.status.LastError = "bind IPv4 FN Connect listener returned an invalid TCP address"
			return i.status, errors.New(i.status.LastError)
		}
		port = tcpAddr.Port
		ipv6, ipv6Err = i.listen("tcp6", net.JoinHostPort("::", strconv.Itoa(port)))
		if ipv6Err == nil {
			break
		}
		_ = ipv4.Close()
		ipv4 = nil
	}
	if ipv6 == nil {
		i.status = FnosConnectIngressStatus{
			LastError: fmt.Sprintf(
				"bind IPv6 FN Connect listener after %d attempts: %v",
				fnosConnectBindMaxAttempts,
				ipv6Err,
			),
		}
		return i.status, errors.New(i.status.LastError)
	}

	server := &http.Server{
		Handler: http.HandlerFunc(i.serveHTTP),
		ConnContext: func(ctx context.Context, conn net.Conn) context.Context {
			return context.WithValue(
				ctx,
				fnosConnectConnMetadataKey{},
				i.connectionMetadata(conn),
			)
		},
		// FN Connect carries browser and websocket traffic. Keep header limits
		// bounded while allowing upgraded connections to remain open.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	i.server = server
	i.listener = []net.Listener{ipv4, ipv6}
	i.status = FnosConnectIngressStatus{
		Enabled:          true,
		ListenerActive:   true,
		ListenPort:       port,
		UpstreamHTTPPort: upstreamHTTPPort,
		IPv4Active:       true,
		IPv6Active:       true,
	}
	for _, listener := range i.listener {
		go func(l net.Listener) {
			err := server.Serve(l)
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				i.recordServeFailure(server, err)
			}
		}(listener)
	}
	return i.status, nil
}

func (i *FnosConnectIngress) recordServeFailure(server *http.Server, serveErr error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	// Ignore a delayed failure from a listener generation that has already
	// been replaced. Otherwise it could tear down a newly allocated ingress.
	if i.server != server {
		return
	}
	_ = i.closeLocked()
	i.status.Enabled = false
	i.status.ListenerActive = false
	i.status.IPv4Active = false
	i.status.IPv6Active = false
	i.status.LastError = serveErr.Error()
}

func (i *FnosConnectIngress) recordError(err error) (FnosConnectIngressStatus, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.status.LastError = err.Error()
	return i.status, err
}

func (i *FnosConnectIngress) connectionMetadata(conn net.Conn) fnosConnectConnMetadata {
	metadata := fnosConnectConnMetadata{}
	if conn == nil {
		metadata.originalDstErr = errors.New("FN Connect connection is unavailable")
		return metadata
	}
	metadata.loopback = clientAddressIsLoopback(conn.RemoteAddr().String())
	if metadata.loopback {
		return metadata
	}
	if i.originalDst == nil {
		metadata.originalDstErr = errors.New("FN Connect original destination resolver is unavailable")
		return metadata
	}
	metadata.originalPort, metadata.originalDstErr = i.originalDst(conn)
	return metadata
}

func (i *FnosConnectIngress) serveHTTP(w http.ResponseWriter, r *http.Request) {
	i.mu.Lock()
	port := i.status.UpstreamHTTPPort
	active := i.status.ListenerActive && i.status.Enabled
	i.mu.Unlock()

	loopback := clientAddressIsLoopback(r.RemoteAddr)
	if !loopback {
		metadata, ok := r.Context().Value(fnosConnectConnMetadataKey{}).(fnosConnectConnMetadata)
		if !ok || metadata.loopback || metadata.originalDstErr != nil || metadata.originalPort != port {
			http.Error(w, "FN Connect ingress requires a verified redirected connection", http.StatusForbidden)
			return
		}
	}
	if !active || port < 1 || port > 65535 {
		http.Error(w, "FN Connect ingress is not active", http.StatusServiceUnavailable)
		return
	}

	ctx := &fnosConnectRequestContext{
		hostRule: models.HostRule{
			Host:            fnosConnectRouteKey,
			Target:          "http://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
			UseAuth:         false,
			SuppressToolbar: true,
			PreserveHost:    true,
		},
	}
	i.handler.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), fnosConnectRequestContextKey{}, ctx)))
}

func (i *FnosConnectIngress) Close() error {
	if i == nil {
		return nil
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	err := i.closeLocked()
	i.status = FnosConnectIngressStatus{}
	return err
}

func (i *FnosConnectIngress) closeLocked() error {
	if i.server == nil {
		for _, listener := range i.listener {
			_ = listener.Close()
		}
		i.listener = nil
		return nil
	}
	server := i.server
	listeners := i.listener
	i.server = nil
	i.listener = nil

	serverErr := server.Close()
	var listenerErr error
	for _, listener := range listeners {
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			listenerErr = errors.Join(listenerErr, err)
		}
	}
	return errors.Join(serverErr, listenerErr)
}

func fnosConnectContext(r *http.Request) *fnosConnectRequestContext {
	if r == nil {
		return nil
	}
	ctx, _ := r.Context().Value(fnosConnectRequestContextKey{}).(*fnosConnectRequestContext)
	return ctx
}

func fnosConnectClientIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	if clientAddressIsLoopback(r.RemoteAddr) {
		if ip := firstForwardedClientIP(r.Header.Get("X-Forwarded-For")); ip != "" {
			return ip
		}
		if ip := normalizeIPAddress(r.Header.Get("X-Real-IP")); ip != "" {
			return ip
		}
	}
	return normalizeClientIP(r.RemoteAddr)
}

func applyFnosConnectForwardedHeaders(out, in *http.Request, clientIP string) {
	if out == nil || in == nil {
		return
	}
	loopback := clientAddressIsLoopback(in.RemoteAddr)
	if !loopback {
		for name := range out.Header {
			normalized := strings.ToLower(strings.TrimSpace(name))
			if normalized == "forwarded" || strings.HasPrefix(normalized, "x-forwarded-") {
				out.Header.Del(name)
			}
		}
	}
	out.Header.Set("X-Real-IP", clientIP)
	out.Header.Set("X-Forwarded-For", clientIP)

	forwardedHost := in.Host
	if loopback {
		if trusted := strings.TrimSpace(firstForwardedValue(in.Header.Get("X-Forwarded-Host"))); trusted != "" {
			forwardedHost = trusted
		}
	}
	out.Header.Set("X-Forwarded-Host", forwardedHost)

	forwardedProto := directRequestScheme(in)
	if loopback {
		if trusted := strings.ToLower(strings.TrimSpace(firstForwardedValue(in.Header.Get("X-Forwarded-Proto")))); trusted == "http" || trusted == "https" {
			forwardedProto = trusted
		}
	}
	out.Header.Set("X-Forwarded-Proto", forwardedProto)
}

func clientAddressIsLoopback(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(strings.TrimSpace(remoteAddr))
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func directRequestScheme(request *http.Request) string {
	if request != nil && request.TLS != nil {
		return "https"
	}
	return "http"
}

func wafRouteContextForRequest(
	r *http.Request,
	snapshot requestSnapshot,
	isAuthRoute bool,
	matchedHostRule *models.HostRule,
	matchedHostLocation *models.HostLocation,
	matchedRule *models.Rule,
) (string, string, string) {
	if ingress := fnosConnectContext(r); ingress != nil {
		return fnosConnectRouteKey, fnosConnectRouteKey, ingress.hostRule.Target
	}
	return wafRouteContext(
		r,
		snapshot,
		isAuthRoute,
		matchedHostRule,
		matchedHostLocation,
		matchedRule,
	)
}
