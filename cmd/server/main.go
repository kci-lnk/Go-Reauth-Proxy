package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"go-reauth-proxy/pkg/admin"
	"go-reauth-proxy/pkg/config"
	"go-reauth-proxy/pkg/events"
	"go-reauth-proxy/pkg/gatewaylog"
	"go-reauth-proxy/pkg/logger"
	"go-reauth-proxy/pkg/proxy"
	"go-reauth-proxy/pkg/rpcbridge"
	"go-reauth-proxy/pkg/stream"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
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
	rebindCh chan struct{}
}

const (
	cmuxReadTimeout             = 2 * time.Second
	proxyProtoReadHeaderTimeout = 2 * time.Second
)

func newProxyStack(proxyPort int, handler *proxy.Handler, httpServer *http.Server, httpsServer *http.Server) *proxyStack {
	return &proxyStack{
		proxyPort:   proxyPort,
		handler:     handler,
		httpServer:  httpServer,
		httpsServer: httpsServer,
		rebindCh:    make(chan struct{}, 1),
	}
}

func (s *proxyStack) desiredHost() string {
	if s.handler.GetProxyProtocolForce() {
		return "127.0.0.1"
	}
	return "0.0.0.0"
}

func (s *proxyStack) Start() error {
	if err := s.rebind(); err != nil {
		return err
	}
	go func() {
		for range s.rebindCh {
			if err := s.rebind(); err != nil {
				log.Printf("Failed to rebind proxy listener: %v", err)
			}
		}
	}()
	return nil
}

func (s *proxyStack) RequestRebind() {
	select {
	case s.rebindCh <- struct{}{}:
	default:
	}
}

func (s *proxyStack) Stop() {
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

func (s *proxyStack) rebind() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	desiredHost := s.desiredHost()
	if s.host == desiredHost && s.stop != nil {
		return nil
	}

	if s.stop != nil {
		s.stop()
		s.stop = nil
	}

	stop, listenAddr, err := startProxyServers(desiredHost, s.proxyPort, s.handler, s.httpServer, s.httpsServer)
	if err != nil {
		return err
	}
	s.host = desiredHost
	s.stop = stop
	s.listenAddr = listenAddr
	log.Printf("Reverse Proxy listening on %s", listenAddr)
	return nil
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

func startProxyServers(host string, proxyPort int, proxyHandler *proxy.Handler, httpServer *http.Server, httpsServer *http.Server) (func(), string, error) {
	hosts := []string{host}
	if host == "0.0.0.0" {
		hosts = append(hosts, "::")
	}
	if host == "127.0.0.1" {
		hosts = append(hosts, "::1")
	}

	var listeners []net.Listener
	var listenAddrs []string
	var listenerClosers []net.Listener
	for _, listenHost := range hosts {
		network := "tcp4"
		if strings.Contains(listenHost, ":") {
			network = "tcp6"
		}
		addr := net.JoinHostPort(listenHost, strconv.Itoa(proxyPort))
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
		listenAddrs = append(listenAddrs, tcpListener.Addr().String())
	}
	if len(listeners) == 0 {
		return nil, "", fmt.Errorf("no proxy listeners started for host %s port %d", host, proxyPort)
	}

	var wg sync.WaitGroup
	useProxyProto := proxyHandler.GetProxyProtocolForce()
	httpsTLSConfig := httpsServer.TLSConfig
	for _, tcpListener := range listeners {
		var listenerForMux net.Listener = tcpListener
		if useProxyProto {
			proxyListener := &proxyproto.Listener{
				Listener:          tcpListener,
				ReadHeaderTimeout: proxyProtoReadHeaderTimeout,
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

func newProxyTLSConfig(provider proxyTLSCertificateProvider) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if provider == nil {
				return nil, fmt.Errorf("SSL not enabled")
			}
			cert := provider.GetCertificate(info)
			if cert == nil {
				return nil, fmt.Errorf("SSL not enabled")
			}
			return cert, nil
		},
	}
}

func main() {
	logger.Setup()

	adminPort := flag.Int("admin-port", 7996, "Port for the Admin API (0 uses config or default 7996, binds to localhost on 127.0.0.1 and ::1)")
	proxyPort := flag.Int("proxy-port", envPortDefault("GO_REPROXY_PORT", 7999), "Port for the Reverse Proxy (defaults to GO_REPROXY_PORT or 7999; binds to 0.0.0.0/:: or 127.0.0.1/::1 based on proxy_protocol_force)")
	configFlag := flag.String("c", "", "Path to config file (default: config.json in executable directory)")
	flag.Parse()

	log.Printf("Starting Go Reauth Proxy Service...")

	execPath, err := os.Executable()
	if err != nil {
		logger.Fatalf("Failed to get executable path: %v", err)
	}

	execDir := filepath.Dir(execPath)
	if strings.Contains(execDir, "go-build") || strings.Contains(execDir, "T") {
		pwd, _ := os.Getwd()
		execDir = pwd
	}

	var configPath string
	if *configFlag != "" {
		configPath = *configFlag
		if !filepath.IsAbs(configPath) {
			pwd, err := os.Getwd()
			if err == nil {
				configPath = filepath.Join(pwd, configPath)
			}
		}

		info, err := os.Stat(configPath)
		if err == nil && info.IsDir() {
			configPath = filepath.Join(configPath, "config.json")
		} else if err != nil && os.IsNotExist(err) && strings.HasSuffix(*configFlag, string(os.PathSeparator)) {
			configPath = filepath.Join(configPath, "config.json")
		}
	} else {
		configPath = filepath.Join(execDir, "config.json")
	}

	configDir := filepath.Dir(configPath)
	if err := os.MkdirAll(configDir, 0755); err != nil {
		logger.Fatalf("Failed to create config directory %s: %v", configDir, err)
	}
	logsDir := gatewaylog.DefaultLogsDir(configDir)

	cfgManager := config.NewManager(configPath)
	initialCfg, err := cfgManager.Load()
	if err != nil {
		logger.Fatalf("Failed to load config: %v", err)
	}

	resolvedAdminPort := *adminPort
	if resolvedAdminPort <= 0 {
		resolvedAdminPort = initialCfg.AdminPort
		if resolvedAdminPort <= 0 {
			resolvedAdminPort = 7996
		}
	}
	logger.SetDebugAdminPortForRedaction(resolvedAdminPort)
	if event := logger.DebugEvent("server", "startup_config_loaded"); event != nil {
		event.Str("config_path", logger.SanitizeLogString(configPath)).
			Str("runtime_dir", logger.SanitizeLogString(configDir)).
			Str("gateway_logs_dir", logger.SanitizeLogString(logsDir)).
			Interface("proxy_port", logger.SanitizePort(*proxyPort)).
			Int("path_rule_count", len(initialCfg.Rules)).
			Int("host_rule_count", len(initialCfg.HostRules)).
			Int("stream_rule_count", len(initialCfg.StreamRules)).
			Bool("proxy_protocol_force", initialCfg.ProxyProtocolForce).
			Bool("waf_enabled", initialCfg.WAF.Enabled).
			Send()
	}

	internalRPCToken, err := rpcbridge.ResolveInternalToken(os.Getenv("FN_KNOCK_INTERNAL_RPC_TOKEN"))
	if err != nil {
		logger.Fatalf("Internal gRPC token is required: %v", err)
	}

	systemEventClient := events.NewClient(nil)
	authBridgeManager := rpcbridge.NewAuthBridgeManager(internalRPCToken)
	proxyHandler := proxy.NewHandler(resolvedAdminPort, *proxyPort, cfgManager, initialCfg, logsDir, systemEventClient)
	proxyHandler.SetAuthBridgeManager(authBridgeManager)
	configuredStreamRules := proxyHandler.GetStreamRules()
	normalizedStreamRules := configuredStreamRules
	if validatedStreamRules, err := proxyHandler.ValidateStreamRules(configuredStreamRules); err != nil {
		if event := logger.DebugEvent("server", "stream_initial_validation_failed"); event != nil {
			event.Str("error", logger.SanitizeLogString(err.Error())).
				Int("stream_rule_count", len(configuredStreamRules)).
				Send()
		}
		log.Printf("Initial stream rules contain invalid entries and will be loaded in best-effort mode: %v", err)
	} else {
		normalizedStreamRules = validatedStreamRules
		if err := proxyHandler.SetStreamRules(normalizedStreamRules); err != nil {
			if event := logger.DebugEvent("server", "stream_initial_normalize_failed"); event != nil {
				event.Str("error", logger.SanitizeLogString(err.Error())).
					Int("stream_rule_count", len(normalizedStreamRules)).
					Send()
			}
			log.Printf("Failed to normalize initial stream rules in config manager: %v", err)
		}
	}

	currentConfig := proxyHandler.GetAuthConfig()
	proxyHandler.SetAuthConfig(currentConfig)

	streamManager := stream.NewManager(proxyHandler)
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

	adminServer := admin.NewServer(proxyHandler, resolvedAdminPort, cfgManager, initialCfg, streamManager)
	stopInternalGRPC, err := startInternalGRPCServer(
		resolvedAdminPort,
		internalRPCToken,
		admin.NewGRPCServer(adminServer, internalRPCToken),
		authBridgeManager,
	)
	if err != nil {
		logger.Fatalf("Internal gRPC server failed: %v", err)
	}

	httpsServer := &http.Server{
		Handler:           proxyHandler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		TLSConfig:         newProxyTLSConfig(proxyHandler),
	}

	httpServer := &http.Server{
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
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

	type connTracker struct {
		m sync.Map
	}

	closeIdle := func(ct *connTracker) {
		ct.m.Range(func(key, value any) bool {
			if state, ok := value.(http.ConnState); ok && state == http.StateIdle {
				_ = key.(net.Conn).Close()
			}
			return true
		})
	}

	httpsConns := &connTracker{}
	httpConns := &connTracker{}
	httpsServer.ConnState = func(c net.Conn, state http.ConnState) {
		if state == http.StateClosed || state == http.StateHijacked {
			httpsConns.m.Delete(c)
			return
		}
		httpsConns.m.Store(c, state)
	}
	httpServer.ConnState = func(c net.Conn, state http.ConnState) {
		if state == http.StateClosed || state == http.StateHijacked {
			httpConns.m.Delete(c)
			return
		}
		httpConns.m.Store(c, state)
	}

	proxyHandler.SetSSLChangeHook(func() {
		closeIdle(httpsConns)
		closeIdle(httpConns)
	})

	proxyStack := newProxyStack(*proxyPort, proxyHandler, httpServer, httpsServer)
	if err := proxyStack.Start(); err != nil {
		if event := logger.DebugEvent("server", "proxy_stack_start_failed"); event != nil {
			event.Interface("proxy_port", logger.SanitizePort(*proxyPort)).
				Str("error", logger.SanitizeLogString(err.Error())).
				Send()
		}
		logger.Fatalf("Failed to start proxy stack: %v", err)
	}
	if event := logger.DebugEvent("server", "proxy_stack_started"); event != nil {
		event.Interface("proxy_port", logger.SanitizePort(*proxyPort)).
			Str("listen_addr", logger.SanitizeLogString(proxyStack.ListenAddr())).
			Send()
	}

	proxyHandler.SetProxyProtocolForceChangeHook(func() {
		closeIdle(httpsConns)
		closeIdle(httpConns)
		proxyStack.RequestRebind()
	})

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down...")
	if event := logger.DebugEvent("server", "shutdown_started"); event != nil {
		event.Send()
	}
	streamManager.Stop()
	proxyStack.Stop()
	stopInternalGRPC()
	proxyHandler.Close()
	if event := logger.DebugEvent("server", "shutdown_completed"); event != nil {
		event.Send()
	}
	logger.FlushDebugLogger()
}
