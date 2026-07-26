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

// FnosConnectIngressStatus is a snapshot of the private FN Connect listener.
// The Rust control plane uses the listener port to build cgroup-scoped
// iptables/ip6tables rules; it never exposes this listener on a non-loopback
// address.
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

// FnosConnectIngress owns a dual-stack loopback-only HTTP ingress. Requests
// enter the regular Handler pipeline through a synthetic, auth-free host rule,
// so WAF, throttling, blacklist checks, traffic counters and access logs stay
// consistent with ordinary reverse-proxy traffic.
type FnosConnectIngress struct {
	mu       sync.Mutex
	handler  *Handler
	listen   fnosConnectListenFunc
	server   *http.Server
	listener []net.Listener
	status   FnosConnectIngressStatus
}

func NewFnosConnectIngress(handler *Handler) *FnosConnectIngress {
	return newFnosConnectIngressWithListener(handler, net.Listen)
}

func newFnosConnectIngressWithListener(handler *Handler, listen fnosConnectListenFunc) *FnosConnectIngress {
	if listen == nil {
		listen = net.Listen
	}
	return &FnosConnectIngress{handler: handler, listen: listen}
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
		ipv4, err = i.listen("tcp4", "127.0.0.1:0")
		if err != nil {
			i.status.LastError = fmt.Sprintf("bind IPv4 loopback listener: %v", err)
			return i.status, errors.New(i.status.LastError)
		}
		tcpAddr, ok := ipv4.Addr().(*net.TCPAddr)
		if !ok || tcpAddr.Port < 1 || tcpAddr.Port > 65535 {
			_ = ipv4.Close()
			i.status.LastError = "bind IPv4 loopback listener returned an invalid TCP address"
			return i.status, errors.New(i.status.LastError)
		}
		port = tcpAddr.Port
		ipv6, ipv6Err = i.listen("tcp6", net.JoinHostPort("::1", strconv.Itoa(port)))
		if ipv6Err == nil {
			break
		}
		_ = ipv4.Close()
		ipv4 = nil
	}
	if ipv6 == nil {
		i.status = FnosConnectIngressStatus{
			LastError: fmt.Sprintf(
				"bind IPv6 loopback listener after %d attempts: %v",
				fnosConnectBindMaxAttempts,
				ipv6Err,
			),
		}
		return i.status, errors.New(i.status.LastError)
	}

	server := &http.Server{
		Handler: http.HandlerFunc(i.serveHTTP),
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
	_ = server.Close()
	i.server = nil
	i.listener = nil
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

func (i *FnosConnectIngress) serveHTTP(w http.ResponseWriter, r *http.Request) {
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err != nil || !net.ParseIP(host).IsLoopback() {
		http.Error(w, "FN Connect ingress only accepts loopback traffic", http.StatusForbidden)
		return
	}

	i.mu.Lock()
	port := i.status.UpstreamHTTPPort
	active := i.status.ListenerActive && i.status.Enabled
	i.mu.Unlock()
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
		i.listener = nil
		return nil
	}
	err := i.server.Close()
	i.server = nil
	i.listener = nil
	return err
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
	if ip := firstForwardedClientIP(r.Header.Get("X-Forwarded-For")); ip != "" {
		return ip
	}
	if ip := normalizeIPAddress(r.Header.Get("X-Real-IP")); ip != "" {
		return ip
	}
	return normalizeClientIP(r.RemoteAddr)
}

func applyFnosConnectForwardedHeaders(out, in *http.Request, clientIP string) {
	if out == nil || in == nil {
		return
	}
	out.Header.Set("X-Real-IP", clientIP)
	out.Header.Set("X-Forwarded-For", clientIP)

	forwardedHost := strings.TrimSpace(firstForwardedValue(in.Header.Get("X-Forwarded-Host")))
	if forwardedHost == "" {
		forwardedHost = in.Host
	}
	out.Header.Set("X-Forwarded-Host", forwardedHost)

	forwardedProto := strings.ToLower(strings.TrimSpace(firstForwardedValue(in.Header.Get("X-Forwarded-Proto"))))
	if forwardedProto != "http" && forwardedProto != "https" {
		forwardedProto = requestScheme(in)
	}
	out.Header.Set("X-Forwarded-Proto", forwardedProto)
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
