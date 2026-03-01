package main

import (
	"crypto/tls"
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

func main() {
	adminPort := flag.Int("admin-port", 7996, "Port for the Admin API (binds to 127.0.0.1)")
	proxyPort := flag.Int("proxy-port", 7999, "Port for the Reverse Proxy (binds to 0.0.0.0)")
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
	configPath := filepath.Join(execDir, "config.json")

	cfgManager := config.NewManager(configPath)
	initialCfg, err := cfgManager.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	proxyHandler := proxy.NewHandler(*adminPort, cfgManager, initialCfg)

	currentConfig := proxyHandler.GetAuthConfig()
	proxyHandler.SetAuthConfig(currentConfig)

	adminServer := admin.NewServer(proxyHandler, *adminPort, cfgManager, initialCfg)
	go func() {
		if err := adminServer.Start(); err != nil {
			log.Fatalf("Admin server failed: %v", err)
		}
	}()

	proxyAddr := fmt.Sprintf(":%d", *proxyPort)
	tcpListener, err := net.Listen("tcp", proxyAddr)
	if err != nil {
		log.Fatalf("Failed to listen on proxy port: %v", err)
	}

	proxyListener := &proxyproto.Listener{
		Listener: tcpListener,
		Policy: func(upstream net.Addr) (proxyproto.Policy, error) {
			return proxyproto.REQUIRE, nil
		},
	}

	// 将包装后的 proxyListener 交给 cmux
	m := cmux.New(proxyListener)
	tlsL := m.Match(cmux.TLS())
	httpL := m.Match(cmux.HTTP1Fast(), cmux.HTTP2())

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

	go func() {
		if err := httpsServer.Serve(tls.NewListener(tlsL, httpsServer.TLSConfig)); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTPS server failed: %v", err)
		}
	}()

	go func() {
		if err := httpServer.Serve(httpL); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server failed: %v", err)
		}
	}()

	go func() {
		log.Printf("Reverse Proxy listening on 0.0.0.0:%d", *proxyPort)
		if err := m.Serve(); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			log.Fatalf("cmux server failed: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down...")
}
