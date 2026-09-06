package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"go-reauth-proxy/pkg/admin"
	"go-reauth-proxy/pkg/config"
	"go-reauth-proxy/pkg/diagnostics"
	"go-reauth-proxy/pkg/events"
	"go-reauth-proxy/pkg/gatewaylog"
	"go-reauth-proxy/pkg/grpc/pb"
	"go-reauth-proxy/pkg/logger"
	"go-reauth-proxy/pkg/models"
	"go-reauth-proxy/pkg/proxy"
	"go-reauth-proxy/pkg/rpcbridge"
	"go-reauth-proxy/pkg/stream"
	"go-reauth-proxy/pkg/version"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pires/go-proxyproto"
	"github.com/soheilhy/cmux"
)

// @title Go-Reauth-Proxy
// @version 1.0
// @description API for managing proxy rules and iptables.
// @license.name MIT
// @license.url https://opensource.org/license/MIT
// @host localhost:7996
// @BasePath /

type proxyStack struct {
	mu          sync.Mutex
	host        string
	listenAddr  string
	proxyPort   int
	handler     *proxy.Handler
	httpServer  *http.Server
	httpsServer *http.Server

	stop     func()
	rebindCh chan proxyRebindRequest
	done     chan struct{}
	stopOnce sync.Once
}

const (
	defaultAuthBridgeStartupTimeout  = 150 * time.Second
	synologySupervisorShutdownMargin = 30 * time.Second
	minimumAuthBridgeStartupTimeout  = time.Second
)

// resolveAuthBridgeStartupTimeout keeps the gateway wait inside the same DSM
// startup budget used by the Rust management process. Non-DSM launches retain
// the established 150-second bound.
func resolveAuthBridgeStartupTimeout() time.Duration {
	raw := strings.TrimSpace(os.Getenv("FN_KNOCK_SYNOLOGY_START_TIMEOUT_SECONDS"))
	seconds, err := strconv.ParseUint(raw, 10, 64)
	const maxDurationSeconds = uint64(1<<63-1) / uint64(time.Second)
	if err != nil || seconds == 0 || seconds > maxDurationSeconds {
		return defaultAuthBridgeStartupTimeout
	}

	supervisorTimeout := time.Duration(seconds) * time.Second
	if supervisorTimeout <= synologySupervisorShutdownMargin {
		return minimumAuthBridgeStartupTimeout
	}
	return supervisorTimeout - synologySupervisorShutdownMargin
}

type proxyRebindRequest struct {
	host   string
	result chan error
}

type proxyServerStarter func(host string) (stop func(), listenAddr string, err error)

type trackedProxyConnState struct {
	mu         sync.Mutex
	state      http.ConnState
	serverName string
	retiring   bool
	closing    bool
	metrics    bool
}

type proxyConnTracker struct {
	m sync.Map
}

type tlsConnectionStateProvider interface {
	ConnectionState() tls.ConnectionState
}

type proxyConnStateContextKey struct{}

func (t *proxyConnTracker) connContext(ctx context.Context, c net.Conn) context.Context {
	ctx = proxyProtocolConnContext(ctx, c)
	tracked, _ := t.m.LoadOrStore(c, &trackedProxyConnState{state: http.StateNew, metrics: true})
	return context.WithValue(ctx, proxyConnStateContextKey{}, tracked)
}

func proxyConnectionRetirementHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor == 2 {
			if tracked, ok := r.Context().Value(proxyConnStateContextKey{}).(*trackedProxyConnState); ok {
				tracked.mu.Lock()
				retiring := tracked.retiring
				tracked.mu.Unlock()
				if retiring {
					// net/http consumes this internal signal, omits it from HTTP/2
					// headers, and sends GOAWAY while draining accepted streams.
					// A handler may replace the header; then a later request or
					// the idle timeout retires the connection without truncating it.
					w.Header().Set("Connection", "close")
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (t *proxyConnTracker) update(c net.Conn, state http.ConnState) {
	if t == nil || c == nil {
		return
	}
	if state == http.StateClosed || state == http.StateHijacked {
		if value, loaded := t.m.LoadAndDelete(c); loaded {
			if tracked, ok := value.(*trackedProxyConnState); ok && tracked != nil {
				tracked.mu.Lock()
				previous := tracked.state
				metrics := tracked.metrics
				tracked.mu.Unlock()
				if metrics {
					diagnostics.ObserveClientConnectionTransition(previous, state)
				}
			}
		}
		return
	}
	candidate := &trackedProxyConnState{state: http.StateNew, metrics: true}
	value, _ := t.m.LoadOrStore(c, candidate)
	tracked, ok := value.(*trackedProxyConnState)
	if !ok || tracked == nil {
		return
	}
	serverName := ""
	isHTTP2 := false
	if tlsConn, ok := c.(tlsConnectionStateProvider); ok && (state == http.StateActive || state == http.StateIdle) {
		tlsState := tlsConn.ConnectionState()
		isHTTP2 = tlsState.NegotiatedProtocol == "h2"
		if current := strings.TrimSpace(tlsState.ServerName); current != "" {
			serverName = strings.ToLower(current)
		}
	}
	tracked.mu.Lock()
	previous := tracked.state
	tracked.state = state
	if serverName != "" {
		tracked.serverName = serverName
	}
	// HTTP/2 reports StateIdle before its final buffered END_STREAM is flushed.
	// Let the next request signal graceful GOAWAY, or the server idle timeout
	// retire it; a raw Close here can truncate an otherwise complete response.
	shouldClose := state == http.StateIdle && !isHTTP2 && tracked.retiring && !tracked.closing
	if shouldClose {
		tracked.closing = true
	}
	metrics := tracked.metrics
	tracked.mu.Unlock()
	if metrics {
		diagnostics.ObserveClientConnectionTransition(previous, state)
	}
	if shouldClose {
		// Closing a TLS connection can block while close_notify is written. Keep
		// that I/O outside tracked.mu so retirement scans and other state updates
		// are never serialized behind a slow peer. ConnState invokes this callback
		// synchronously, so Close still happens before the idle transition returns.
		_ = c.Close()
	}
}

func (t *proxyConnTracker) retireForServerNames(serverNames []string) {
	if t == nil {
		return
	}
	closeAll := serverNames == nil
	filter := make(map[string]struct{}, len(serverNames))
	for _, serverName := range serverNames {
		if normalized := strings.ToLower(strings.TrimSpace(serverName)); normalized != "" {
			filter[normalized] = struct{}{}
		}
	}
	if !closeAll && len(filter) == 0 {
		return
	}
	t.m.Range(func(key, value any) bool {
		tracked, ok := value.(*trackedProxyConnState)
		if !ok || tracked == nil {
			return true
		}
		tracked.mu.Lock()
		if !closeAll {
			if _, affected := filter[strings.ToLower(strings.TrimSpace(tracked.serverName))]; !affected {
				tracked.mu.Unlock()
				return true
			}
		}
		// Do not close an observed-idle connection here: a new request can race
		// between observing StateIdle and Close. Mark it instead. ConnState calls
		// update synchronously before a handler starts, so the connection is closed
		// safely the next time HTTP/1 transitions back to StateIdle. HTTP/2 asks
		// net/http to drain gracefully on the next request instead. The request-level
		// 421 guard remains the fallback for that one reuse.
		tracked.retiring = true
		tracked.mu.Unlock()
		return true
	})
}

const (
	cmuxReadTimeout             = 2 * time.Second
	proxyProtoReadHeaderTimeout = 2 * time.Second
	targetNoFileLimit           = 1_048_576
)

func newProxyStack(proxyPort int, handler *proxy.Handler, httpServer *http.Server, httpsServer *http.Server) *proxyStack {
	return &proxyStack{
		proxyPort:   proxyPort,
		handler:     handler,
		httpServer:  httpServer,
		httpsServer: httpsServer,
		rebindCh:    make(chan proxyRebindRequest),
		done:        make(chan struct{}),
	}
}

func (s *proxyStack) desiredHost() string {
	return s.desiredHostForScope(s.handler.GetGatewayListenerConfig().Scope)
}

func (s *proxyStack) desiredHostForScope(scope string) string {
	if s.handler.GetProxyProtocolForce() || scope == models.GatewayListenerScopeLoopback {
		return "127.0.0.1"
	}
	return "0.0.0.0"
}

func (s *proxyStack) Start() error {
	if err := s.rebind(); err != nil {
		return err
	}
	go func() {
		for {
			select {
			case request := <-s.rebindCh:
				err := s.rebindToHost(request.host)
				if err != nil {
					log.Printf("Failed to rebind proxy listener: %v", err)
				}
				request.result <- err
			case <-s.done:
				return
			}
		}
	}()
	return nil
}

func (s *proxyStack) RequestRebind() error {
	return s.requestRebind(s.desiredHost())
}

func (s *proxyStack) RequestRebindForScope(scope string) error {
	return s.requestRebind(s.desiredHostForScope(scope))
}

func (s *proxyStack) requestRebind(host string) error {
	result := make(chan error, 1)
	select {
	case <-s.done:
		return net.ErrClosed
	case s.rebindCh <- proxyRebindRequest{host: host, result: result}:
	}
	select {
	case <-s.done:
		return net.ErrClosed
	case err := <-result:
		return err
	}
}

func (s *proxyStack) Stop() {
	s.stopOnce.Do(func() { close(s.done) })
	s.mu.Lock()
	stop := s.stop
	s.stop = nil
	s.mu.Unlock()
	if stop != nil {
		stop()
	}
}

func (s *proxyStack) ListenAddr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.listenAddr
}

func (s *proxyStack) IsServing() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stop != nil
}

func (s *proxyStack) rebind() error {
	return s.rebindToHost(s.desiredHost())
}

func (s *proxyStack) rebindToHost(desiredHost string) error {
	return s.rebindWithStarter(desiredHost, func(host string) (func(), string, error) {
		return startProxyServers(host, s.proxyPort, s.handler, s.httpServer, s.httpsServer)
	})
}

// rebindWithStarter changes a listener scope and restores the previous
// listener if the new bind fails. Binding wildcard and loopback sockets on the
// same port cannot be overlapped portably (notably on Windows), so rollback is
// the only safe way to preserve the live data plane on a failed transition.
func (s *proxyStack) rebindWithStarter(desiredHost string, start proxyServerStarter) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	previousHost := s.host
	previousStop := s.stop
	if previousStop != nil {
		previousStop()
		s.stop = nil
		s.host = ""
		s.listenAddr = ""
	}

	stop, listenAddr, err := start(desiredHost)
	if err == nil {
		s.host = desiredHost
		s.stop = stop
		s.listenAddr = listenAddr
		log.Printf("Reverse Proxy listening on %s", listenAddr)
		return nil
	}

	if previousStop == nil {
		return fmt.Errorf("bind proxy listener on %s: %w", desiredHost, err)
	}

	rollbackStop, rollbackAddr, rollbackErr := start(previousHost)
	if rollbackErr != nil {
		return fmt.Errorf(
			"bind proxy listener on %s: %w; restore previous listener on %s: %v",
			desiredHost,
			err,
			previousHost,
			rollbackErr,
		)
	}

	s.host = previousHost
	s.stop = rollbackStop
	s.listenAddr = rollbackAddr
	log.Printf("Reverse Proxy rebind to %s failed; restored listener on %s", desiredHost, rollbackAddr)
	return fmt.Errorf("bind proxy listener on %s: %w; restored previous listener on %s", desiredHost, err, previousHost)
}

func isClosedConnErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, net.ErrClosed) {
		return true
	}
	return strings.Contains(err.Error(), "use of closed network connection") ||
		strings.Contains(err.Error(), "mux: server closed")
}

func proxyProtocolConnPolicy(proxyHandler *proxy.Handler) proxyproto.ConnPolicyFunc {
	return func(options proxyproto.ConnPolicyOptions) (proxyproto.Policy, error) {
		if proxyHandler.IsProxyProtocolTrustedSource(options.Upstream) {
			return proxyproto.USE, nil
		}
		// Plain direct clients remain valid. A PROXY header from an
		// untrusted socket peer is rejected by the wrapper.
		return proxyproto.REJECT, nil
	}
}

func proxyProtocolConnectionUsed(connection net.Conn) bool {
	for connection != nil {
		switch current := connection.(type) {
		case *proxyproto.Conn:
			header := current.ProxyHeader()
			return header != nil && header.Command.IsProxy()
		case interface{ NetConn() net.Conn }:
			connection = current.NetConn()
		case *cmux.MuxConn:
			connection = current.Conn
		default:
			return false
		}
	}
	return false
}

func proxyProtocolConnContext(ctx context.Context, connection net.Conn) context.Context {
	if proxyProtocolConnectionUsed(connection) {
		return proxy.WithProxyProtocolClientAddress(ctx)
	}
	return ctx
}

type proxyListenTarget struct {
	host          string
	port          int
	proxyProtocol bool
}

func proxyListenTargets(host string, proxyPort int, useProxyProtocol bool) []proxyListenTarget {
	targets := []proxyListenTarget{{host: host, port: proxyPort, proxyProtocol: useProxyProtocol}}
	if host == "0.0.0.0" {
		targets = append(targets, proxyListenTarget{host: "::", port: proxyPort, proxyProtocol: useProxyProtocol})
	}
	if host == "127.0.0.1" {
		targets = append(targets, proxyListenTarget{host: "::1", port: proxyPort, proxyProtocol: useProxyProtocol})
	}
	managedCloudflarePort := proxy.ManagedCloudflarePort()
	if proxyPort == 0 {
		managedCloudflarePort = 0
	}
	// This dedicated loopback ingress authenticates Cloudflare through its own
	// edge headers and must remain a plain HTTP/TLS listener.
	return append(targets, proxyListenTarget{host: "127.0.0.1", port: managedCloudflarePort})
}

func startProxyServers(host string, proxyPort int, proxyHandler *proxy.Handler, httpServer *http.Server, httpsServer *http.Server) (func(), string, error) {
	useProxyProto := proxyHandler.ProxyProtocolEnabled()
	targets := proxyListenTargets(host, proxyPort, useProxyProto)

	var listeners []net.Listener
	var listenAddrs []string
	var listenerClosers []net.Listener
	var proxyProtocolByListener = make(map[net.Listener]bool, len(targets))
	for _, target := range targets {
		network := "tcp4"
		if strings.Contains(target.host, ":") {
			network = "tcp6"
		}
		addr := net.JoinHostPort(target.host, strconv.Itoa(target.port))
		tcpListener, err := net.Listen(network, addr)
		if err != nil {
			if network == "tcp6" {
				log.Printf("IPv6 listener unavailable on %s: %v", addr, err)
				continue
			}
			for _, l := range listeners {
				_ = l.Close()
			}
			return nil, "", err
		}
		listeners = append(listeners, tcpListener)
		proxyProtocolByListener[tcpListener] = target.proxyProtocol
		listenAddrs = append(listenAddrs, tcpListener.Addr().String())
	}
	if len(listeners) == 0 {
		return nil, "", fmt.Errorf("no proxy listeners started for host %s port %d", host, proxyPort)
	}

	var wg sync.WaitGroup
	httpsTLSConfig := httpsServer.TLSConfig
	for _, tcpListener := range listeners {
		var listenerForMux net.Listener = tcpListener
		if proxyProtocolByListener[tcpListener] {
			proxyListener := &proxyproto.Listener{
				Listener:          tcpListener,
				ReadHeaderTimeout: proxyProtoReadHeaderTimeout,
				ConnPolicy:        proxyProtocolConnPolicy(proxyHandler),
			}
			listenerForMux = proxyListener
		}
		listenerClosers = append(listenerClosers, listenerForMux)

		m := cmux.New(listenerForMux)
		m.SetReadTimeout(cmuxReadTimeout)
		tlsL := m.Match(cmux.TLS())
		httpL := m.Match(cmux.HTTP1Fast(), cmux.HTTP2())

		wg.Add(3)

		go func() {
			defer wg.Done()
			err := httpsServer.Serve(tls.NewListener(tlsL, httpsTLSConfig))
			if err != nil && err != http.ErrServerClosed && !isClosedConnErr(err) {
				log.Printf("HTTPS server failed: %v", err)
			}
		}()

		go func() {
			defer wg.Done()
			err := httpServer.Serve(httpL)
			if err != nil && err != http.ErrServerClosed && !isClosedConnErr(err) {
				log.Printf("HTTP server failed: %v", err)
			}
		}()

		go func() {
			defer wg.Done()
			err := m.Serve()
			if err != nil && !isClosedConnErr(err) {
				log.Printf("cmux server failed: %v", err)
			}
		}()
	}

	var once sync.Once
	stop := func() {
		once.Do(func() {
			for _, l := range listenerClosers {
				_ = l.Close()
			}
			wg.Wait()
		})
	}

	slices.Sort(listenAddrs)
	return stop, strings.Join(listenAddrs, ", "), nil
}

func envPortDefault(name string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}

	value, err := strconv.Atoi(raw)
	if err != nil || value <= 0 || value > 65535 {
		log.Printf("Invalid %s=%q; using default port %d", name, raw, fallback)
		return fallback
	}
	return value
}

type proxyTLSCertificateProvider interface {
	GetCertificate(*tls.ClientHelloInfo) *tls.Certificate
}

type proxyTLSProtocolProvider interface {
	GetHostProtocolMode(serverName string) string
}

func newProxyTLSConfig(provider proxyTLSCertificateProvider) *tls.Config {
	getCertificate := func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if provider == nil {
			return nil, fmt.Errorf("SSL not enabled")
		}
		cert := provider.GetCertificate(info)
		if cert == nil {
			return nil, fmt.Errorf("SSL not enabled")
		}
		return cert, nil
	}
	newLeafConfig := func(nextProtos ...string) *tls.Config {
		return &tls.Config{
			MinVersion:     tls.VersionTLS12,
			NextProtos:     nextProtos,
			GetCertificate: getCertificate,
		}
	}

	// These leaf configs are constructed once and never mutated after they can
	// be observed by a handshake. GetConfigForClient selects one using the
	// handler's atomically-published host-rule snapshot.
	autoConfig := newLeafConfig("h2", "http/1.1")
	http1Config := newLeafConfig("http/1.1")
	http2Config := newLeafConfig("h2")
	protocolProvider, _ := provider.(proxyTLSProtocolProvider)
	autoConfig.GetConfigForClient = func(info *tls.ClientHelloInfo) (*tls.Config, error) {
		if protocolProvider == nil {
			return nil, nil
		}
		serverName := ""
		if info != nil {
			serverName = info.ServerName
		}
		switch models.NormalizeHostProtocolMode(protocolProvider.GetHostProtocolMode(serverName)) {
		case models.HostProtocolModeHTTP1:
			return http1Config, nil
		case models.HostProtocolModeHTTP2:
			if info == nil || !slices.Contains(info.SupportedProtos, "h2") {
				return nil, fmt.Errorf("HTTP/2 is required for server name %q", serverName)
			}
			return http2Config, nil
		default:
			return nil, nil
		}
	}
	return autoConfig
}

type runOptions struct {
	Context          context.Context
	AdminPort        int
	ProxyPort        int
	ConfigPath       string
	LogsDir          string
	WAFDir           string
	InternalRPCToken string
	DiagnosticsAddr  string
}

func resolveConfigPath(configFlag string) (string, error) {
	if strings.TrimSpace(configFlag) == "" {
		execPath, err := os.Executable()
		if err != nil {
			return "", fmt.Errorf("get executable path: %w", err)
		}
		execDir := filepath.Dir(execPath)
		if strings.Contains(execDir, "go-build") {
			if pwd, err := os.Getwd(); err == nil {
				execDir = pwd
			}
		}
		return filepath.Join(execDir, "config.json"), nil
	}

	configPath := configFlag
	if !filepath.IsAbs(configPath) {
		pwd, err := os.Getwd()
		if err != nil {
			return "", fmt.Errorf("get working directory: %w", err)
		}
		configPath = filepath.Join(pwd, configPath)
	}
	info, err := os.Stat(configPath)
	if err == nil && info.IsDir() {
		return filepath.Join(configPath, "config.json"), nil
	}
	if err != nil && !os.IsNotExist(err) {
		return "", err
	}
	if os.IsNotExist(err) && strings.HasSuffix(configFlag, string(os.PathSeparator)) {
		configPath = filepath.Join(configPath, "config.json")
	}
	return configPath, nil
}

func shutdownHTTPServers(parent context.Context, httpServer *http.Server, httpsServer *http.Server) {
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	for _, server := range []*http.Server{httpServer, httpsServer} {
		if server == nil {
			continue
		}
		wg.Add(1)
		go func(s *http.Server) {
			defer wg.Done()
			if err := s.Shutdown(ctx); err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
				log.Printf("HTTP server graceful shutdown failed: %v", err)
			}
		}(server)
	}
	wg.Wait()
}

func run(options runOptions) error {
	parent := options.Context
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	if options.ProxyPort <= 0 || options.ProxyPort > 65535 {
		return fmt.Errorf("proxy port must be between 1 and 65535")
	}
	if strings.TrimSpace(options.ConfigPath) == "" {
		return fmt.Errorf("config path is required")
	}
	configDir := filepath.Dir(options.ConfigPath)
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		return fmt.Errorf("create config directory %s: %w", configDir, err)
	}
	logsDir := gatewaylog.DefaultLogsDir(configDir)
	if configured := strings.TrimSpace(options.LogsDir); configured != "" {
		if !filepath.IsAbs(configured) {
			return fmt.Errorf("logs directory must be absolute: %s", configured)
		}
		logsDir = filepath.Clean(configured)
	}
	cfgManager := config.NewManager(options.ConfigPath)
	initialCfg, err := cfgManager.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if configured := strings.TrimSpace(options.WAFDir); configured != "" {
		if !filepath.IsAbs(configured) {
			return fmt.Errorf("WAF directory must be absolute: %s", configured)
		}
		configured = filepath.Clean(configured)
		if initialCfg.WAF.RulesDir != configured {
			initialCfg.WAF.RulesDir = configured
			if err := cfgManager.Save(initialCfg); err != nil {
				return fmt.Errorf("persist managed WAF directory: %w", err)
			}
		}
	}

	resolvedAdminPort := options.AdminPort
	if resolvedAdminPort <= 0 {
		resolvedAdminPort = initialCfg.AdminPort
		if resolvedAdminPort <= 0 {
			resolvedAdminPort = 7996
		}
	}
	if resolvedAdminPort > 65535 {
		return fmt.Errorf("admin port must be between 1 and 65535")
	}
	logger.SetDebugAdminPortForRedaction(resolvedAdminPort)
	if event := logger.DebugEvent("server", "startup_config_loaded"); event != nil {
		event.Str("config_path", logger.SanitizeLogString(options.ConfigPath)).
			Str("runtime_dir", logger.SanitizeLogString(configDir)).
			Str("gateway_logs_dir", logger.SanitizeLogString(logsDir)).
			Interface("proxy_port", logger.SanitizePort(options.ProxyPort)).
			Int("path_rule_count", len(initialCfg.Rules)).
			Int("host_rule_count", len(initialCfg.HostRules)).
			Int("stream_rule_count", len(initialCfg.StreamRules)).
			Bool("proxy_protocol_force", initialCfg.ProxyProtocolForce).
			Str("listener_scope", initialCfg.GatewayListener.Scope).
			Bool("waf_enabled", initialCfg.WAF.Enabled).
			Send()
	}

	internalRPCToken, err := rpcbridge.ResolveInternalToken(options.InternalRPCToken)
	if err != nil {
		return fmt.Errorf("internal gRPC token is required: %w", err)
	}
	stopDiagnostics, diagnosticsAddr, err := startDiagnosticsServer(options.DiagnosticsAddr, internalRPCToken)
	if err != nil {
		return fmt.Errorf("start diagnostics server: %w", err)
	}
	if diagnosticsAddr != "" {
		log.Printf("Diagnostics server listening on %s", diagnosticsAddr)
	}

	var (
		proxyHandler       *proxy.Handler
		streamManager      *stream.Manager
		fnosConnectIngress *proxy.FnosConnectIngress
		grpcServer         *internalGRPCServer
		proxyStack         *proxyStack
		httpServer         *http.Server
		httpsServer        *http.Server
		shutdownOnce       sync.Once
	)
	shutdown := func() {
		shutdownOnce.Do(func() {
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer shutdownCancel()
			log.Println("Shutting down...")
			if event := logger.DebugEvent("server", "shutdown_started"); event != nil {
				event.Send()
			}
			if grpcServer != nil {
				grpcServer.SetServingStatus(healthGatewayDataplane, false)
				grpcServer.SetServingStatus(healthGatewayAuthBridge, false)
			}
			if proxyStack != nil {
				proxyStack.Stop()
			}
			if streamManager != nil {
				streamManager.Stop()
			}
			if fnosConnectIngress != nil {
				if err := fnosConnectIngress.Close(); err != nil {
					log.Printf("Failed to stop FN Connect ingress: %v", err)
				}
			}
			shutdownHTTPServers(shutdownCtx, httpServer, httpsServer)
			if grpcServer != nil {
				grpcServer.Stop(shutdownCtx)
			}
			stopDiagnostics()
			if proxyHandler != nil {
				proxyHandler.Close()
			}
			if event := logger.DebugEvent("server", "shutdown_completed"); event != nil {
				event.Send()
			}
			logger.FlushDebugLogger()
			logger.FlushDiagnosticLogger()
		})
	}
	defer shutdown()

	systemEventClient := events.NewClient(nil)
	authBridgeManager := rpcbridge.NewAuthBridgeManager(internalRPCToken)
	proxyHandler = proxy.NewHandler(resolvedAdminPort, options.ProxyPort, cfgManager, initialCfg, logsDir, systemEventClient)
	proxyHandler.SetAuthBridgeManager(authBridgeManager)
	fnosConnectIngress = proxy.NewFnosConnectIngress(proxyHandler)
	configuredStreamRules, _, configuredStreamPolicies := proxyHandler.GetStreamRulesBundle()
	normalizedStreamRules := configuredStreamRules
	if validatedStreamRules, validationErr := proxyHandler.ValidateStreamRules(configuredStreamRules); validationErr != nil {
		if event := logger.DebugEvent("server", "stream_initial_validation_failed"); event != nil {
			event.Str("error", logger.SanitizeLogString(validationErr.Error())).
				Int("stream_rule_count", len(configuredStreamRules)).
				Send()
		}
		log.Printf("Initial stream rules contain invalid entries and will be loaded in best-effort mode: %v", validationErr)
	} else {
		normalizedStreamRules = validatedStreamRules
		if setErr := proxyHandler.SetStreamRules(normalizedStreamRules); setErr != nil {
			if event := logger.DebugEvent("server", "stream_initial_normalize_failed"); event != nil {
				event.Str("error", logger.SanitizeLogString(setErr.Error())).
					Int("stream_rule_count", len(normalizedStreamRules)).
					Send()
			}
			log.Printf("Failed to normalize initial stream rules in config manager: %v", setErr)
		}
	}
	currentConfig := proxyHandler.GetAuthConfig()
	if setErr := proxyHandler.SetAuthConfig(currentConfig); setErr != nil {
		return fmt.Errorf("persist normalized auth config: %w", setErr)
	}

	streamManager = stream.NewManager(proxyHandler)
	if setErr := streamManager.SetAccessPolicies(configuredStreamPolicies); setErr != nil {
		return fmt.Errorf("configure initial stream access policies: %w", setErr)
	}
	if setErr := streamManager.SetAvailability(proxyHandler.GetStreamAvailability()); setErr != nil {
		return fmt.Errorf("configure initial stream availability: %w", setErr)
	}
	startedStreamRules, startupWarnings := streamManager.ReconcileBestEffort(normalizedStreamRules)
	for _, warning := range startupWarnings {
		if event := logger.DebugEvent("server", "stream_startup_warning"); event != nil {
			event.Str("warning", logger.SanitizeLogString(warning.Error())).Send()
		}
		log.Printf("Stream startup warning: %v", warning)
	}
	if len(startupWarnings) > 0 {
		if event := logger.DebugEvent("server", "stream_startup_partial"); event != nil {
			event.Int("started_rule_count", len(startedStreamRules)).
				Int("configured_rule_count", len(normalizedStreamRules)).
				Int("warning_count", len(startupWarnings)).
				Send()
		}
		log.Printf(
			"Stream manager started %d of %d configured rules; skipped rules can be fixed later from the admin UI",
			len(startedStreamRules),
			len(normalizedStreamRules),
		)
	}

	adminServer := admin.NewServer(proxyHandler, resolvedAdminPort, cfgManager, initialCfg, streamManager, fnosConnectIngress)
	controlServer := admin.NewGRPCServer(adminServer, internalRPCToken)
	controlServer.SetShutdownRequest(cancel)
	grpcServer, err = startInternalGRPCServer(resolvedAdminPort, internalRPCToken, controlServer, authBridgeManager)
	if err != nil {
		return fmt.Errorf("start internal gRPC server: %w", err)
	}
	authBridgeManager.SetReadyChangeHook(func(ready bool) {
		grpcServer.SetServingStatus(healthGatewayAuthBridge, ready)
	})

	httpsConns := &proxyConnTracker{}
	httpConns := &proxyConnTracker{}
	httpsServer = &http.Server{
		Handler:           proxyConnectionRetirementHandler(proxyHandler),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		TLSConfig:         newProxyTLSConfig(proxyHandler),
		ConnContext:       httpsConns.connContext,
	}
	httpServer = &http.Server{
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		ConnContext:       proxyProtocolConnContext,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if proxyHandler.HasSSLCertificates() && proxy.ShouldRedirectHTTPToHTTPS(r, proxyHandler.GetAuthConfig()) {
				target := proxy.BuildHTTPSRedirectURL(r, proxyHandler.GetAuthConfig())
				if target == "" {
					target = "https://" + r.Host + r.URL.String()
				}
				http.Redirect(w, r, target, http.StatusTemporaryRedirect)
				return
			}
			proxyHandler.ServeHTTP(w, r)
		}),
	}

	httpsServer.ConnState = httpsConns.update
	httpServer.ConnState = httpConns.update
	proxyHandler.SetSSLChangeHook(func() {
		httpsConns.retireForServerNames(nil)
		httpConns.retireForServerNames(nil)
	})
	proxyHandler.SetHostProtocolModeChangeHook(httpsConns.retireForServerNames)

	proxyStack = newProxyStack(options.ProxyPort, proxyHandler, httpServer, httpsServer)
	bridgeReadyCtx, bridgeReadyCancel := context.WithTimeout(ctx, resolveAuthBridgeStartupTimeout())
	defer bridgeReadyCancel()
	if err := authBridgeManager.WaitReady(bridgeReadyCtx); err != nil {
		return fmt.Errorf("wait for Rust auth bridge before opening proxy listeners: %w", err)
	}
	if err := proxyStack.Start(); err != nil {
		if event := logger.DebugEvent("server", "proxy_stack_start_failed"); event != nil {
			event.Interface("proxy_port", logger.SanitizePort(options.ProxyPort)).
				Str("error", logger.SanitizeLogString(err.Error())).
				Send()
		}
		return fmt.Errorf("start proxy stack: %w", err)
	}
	grpcServer.SetServingStatus(healthGatewayDataplane, true)
	logger.Diagnostic("INFO", "gateway_dataplane", "listener_bound", "proxy_stack_started", map[string]any{"status": "healthy"})
	if event := logger.DebugEvent("server", "proxy_stack_started"); event != nil {
		event.Interface("proxy_port", logger.SanitizePort(options.ProxyPort)).
			Str("listen_addr", logger.SanitizeLogString(proxyStack.ListenAddr())).
			Send()
	}
	proxyHandler.SetGatewayListenerConfigChangeHook(func(listener models.GatewayListenerConfig) error {
		if err := proxyStack.RequestRebindForScope(listener.Scope); err != nil {
			// A failed rebind may already have restored the prior listener. Reflect
			// the actual serving state instead of reporting the data plane down
			// merely because the requested scope could not be applied.
			grpcServer.SetServingStatus(healthGatewayDataplane, proxyStack.IsServing())
			log.Printf("Proxy listener scope rebind failed: %v", err)
			return err
		}
		grpcServer.SetServingStatus(healthGatewayDataplane, true)
		return nil
	})
	proxyHandler.SetProxyProtocolForceChangeHook(func() error {
		httpsConns.retireForServerNames(nil)
		httpConns.retireForServerNames(nil)
		if err := proxyStack.RequestRebind(); err != nil {
			grpcServer.SetServingStatus(healthGatewayDataplane, proxyStack.IsServing())
			log.Printf("Proxy listener rebind failed: %v", err)
			return err
		}
		grpcServer.SetServingStatus(healthGatewayDataplane, true)
		return nil
	})

	<-ctx.Done()
	return nil
}

func main() {
	logger.Setup()
	defer logger.CloseDiagnosticLogger()
	raiseNoFileLimit()

	adminPort := flag.Int("admin-port", 7996, "Port for the internal gRPC API (0 uses config or default 7996; loopback only)")
	proxyPort := flag.Int("proxy-port", envPortDefault("GO_REPROXY_PORT", 7999), "Port for the reverse proxy")
	configFlag := flag.String("c", "", "Path to config file (default: config.json in executable directory)")
	logsDir := flag.String("logs-dir", os.Getenv("FN_KNOCK_GATEWAY_LOGS_DIR"), "Absolute directory for gateway request logs")
	wafDir := flag.String("waf-dir", os.Getenv("FN_KNOCK_GATEWAY_WAF_DIR"), "Absolute directory for WAF rules and state")
	flag.Parse()
	logger.Diagnostic("INFO", "gateway_process", "started", "process_start", map[string]any{
		"version": version.Version, "commit": version.Commit,
		"pid": os.Getpid(), "protocol_version": int(pb.ControlApiVersion_CONTROL_API_VERSION_CURRENT),
	})

	configPath, err := resolveConfigPath(*configFlag)
	if err != nil {
		logger.Diagnostic("ERROR", "gateway_process", "startup_failed", "config_path_invalid", nil)
		log.Printf("Resolve config path failed: %v", err)
		logger.FlushDiagnosticLogger()
		os.Exit(1)
	}
	ctx, stopSignals := processSignalContext(context.Background())
	defer stopSignals()
	log.Printf("Starting Go Reauth Proxy Service...")
	if err := run(runOptions{
		Context:          ctx,
		AdminPort:        *adminPort,
		ProxyPort:        *proxyPort,
		ConfigPath:       configPath,
		LogsDir:          *logsDir,
		WAFDir:           *wafDir,
		InternalRPCToken: os.Getenv("FN_KNOCK_INTERNAL_RPC_TOKEN"),
		DiagnosticsAddr:  os.Getenv(diagnosticsAddrEnv),
	}); err != nil {
		logger.Diagnostic("ERROR", "gateway_process", "stopped", "runtime_error", map[string]any{"result": "failed"})
		log.Printf("Go Reauth Proxy failed: %v", err)
		logger.FlushDebugLogger()
		logger.FlushDiagnosticLogger()
		os.Exit(1)
	}
}
