package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"go-reauth-proxy/pkg/admin"
	"go-reauth-proxy/pkg/config"
	"go-reauth-proxy/pkg/middleware"
	"go-reauth-proxy/pkg/proxy"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/pires/go-proxyproto"
	"github.com/soheilhy/cmux"

	_ "go-reauth-proxy/cmd/server/docs"
)

// @title Go-Reauth-Proxy
// @version 1.0
// @description API for managing proxy rules and iptables.
// @license.name MIT
// @license.url https://opensource.org/license/MIT
// @host 127.0.0.1:7996
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
	return strings.Contains(err.Error(), "use of closed network connection")
}

func startProxyServers(host string, proxyPort int, proxyHandler *proxy.Handler, httpServer *http.Server, httpsServer *http.Server) (func(), string, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(proxyPort))
	tcpListener, err := net.Listen("tcp4", addr)
	if err != nil {
		return nil, "", err
	}

	proxyListener := &proxyproto.Listener{
		Listener: tcpListener,
	}

	m := cmux.New(proxyListener)
	tlsL := m.Match(cmux.TLS())
	httpL := m.Match(cmux.HTTP1Fast(), cmux.HTTP2())

	var wg sync.WaitGroup
	wg.Add(3)

	go func() {
		defer wg.Done()
		err := httpsServer.Serve(tls.NewListener(tlsL, httpsServer.TLSConfig))
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

	var once sync.Once
	stop := func() {
		once.Do(func() {
			_ = proxyListener.Close()
			wg.Wait()
		})
	}

	return stop, tcpListener.Addr().String(), nil
}

func main() {
	adminPort := flag.Int("admin-port", 7996, "Port for the Admin API (0 uses config or default 7996, binds to 127.0.0.1)")
	proxyPort := flag.Int("proxy-port", 7999, "Port for the Reverse Proxy (binds to 0.0.0.0 or 127.0.0.1 based on proxy_protocol_force)")
	configFlag := flag.String("c", "", "Path to config file (default: config.json in executable directory)")
	flag.Parse()

	log.Printf("Starting Go Reauth Proxy Service...")

	execPath, err := os.Executable()
	if err != nil {
		log.Fatalf("Failed to get executable path: %v", err)
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
		log.Fatalf("Failed to create config directory %s: %v", configDir, err)
	}

	cfgManager := config.NewManager(configPath)
	initialCfg, err := cfgManager.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	resolvedAdminPort := *adminPort
	if resolvedAdminPort <= 0 {
		resolvedAdminPort = initialCfg.AdminPort
		if resolvedAdminPort <= 0 {
			resolvedAdminPort = 7996
		}
	}

	proxyHandler := proxy.NewHandler(resolvedAdminPort, cfgManager, initialCfg)

	currentConfig := proxyHandler.GetAuthConfig()
	proxyHandler.SetAuthConfig(currentConfig)

	adminServer := admin.NewServer(proxyHandler, resolvedAdminPort, cfgManager, initialCfg)
	go func() {
		if err := adminServer.Start(); err != nil {
			log.Fatalf("Admin server failed: %v", err)
		}
	}()

	httpsServer := &http.Server{
		Handler:           middleware.Logger(proxyHandler),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		TLSConfig: &tls.Config{
			NextProtos:             []string{"h2", "http/1.1"},
			SessionTicketsDisabled: true,
			GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
				cert := proxyHandler.GetSSLCertificate()
				if cert == nil {
					return nil, fmt.Errorf("SSL not enabled")
				}
				return cert, nil
			},
		},
	}

	httpServer := &http.Server{
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if proxyHandler.GetSSLCertificate() != nil {
				target := "https://" + r.Host + r.URL.String()
				http.Redirect(w, r, target, http.StatusTemporaryRedirect)
				return
			}
			middleware.Logger(proxyHandler).ServeHTTP(w, r)
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
		log.Fatalf("Failed to start proxy stack: %v", err)
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
	proxyStack.Stop()
}
