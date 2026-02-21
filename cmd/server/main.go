package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"go-reauth-proxy/pkg/admin"
	"go-reauth-proxy/pkg/auth"
	"go-reauth-proxy/pkg/config"
	"go-reauth-proxy/pkg/middleware"
	"go-reauth-proxy/pkg/proxy"
	"log"
	"net"
	"net/http"
	"path/filepath"
	"strings"

	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/soheilhy/cmux"

	_ "go-reauth-proxy/cmd/server/docs"
)

// @title Go-Reauth-Proxy
// @version 1.0
// @description API for managing proxy rules and iptables.
// @license.name MIT
// @license.url https://opensource.org/license/MIT
// @host 127.0.0.1:9091
// @BasePath /

func main() {
	adminPort := flag.Int("admin-port", 9091, "Port for the Admin API (binds to 127.0.0.1)")
	proxyPort := flag.Int("proxy-port", 9090, "Port for the Reverse Proxy (binds to 0.0.0.0)")
	authCacheExpire := flag.Int("auth-cache-expire", 60, "Cache expiration time in seconds for authentication")
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

	authCache := auth.NewCache(time.Duration(*authCacheExpire) * time.Second)
	proxyHandler := proxy.NewHandler(authCache, *adminPort, cfgManager, initialCfg)

	currentConfig := proxyHandler.GetAuthConfig()
	currentConfig.AuthCacheExpire = *authCacheExpire
	proxyHandler.SetAuthConfig(currentConfig)

	adminServer := admin.NewServer(proxyHandler, *adminPort)
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

	m := cmux.New(tcpListener)
	tlsL := m.Match(cmux.TLS())
	httpL := m.Match(cmux.HTTP1Fast(), cmux.HTTP2())

	httpsServer := &http.Server{
		Handler:           middleware.Logger(proxyHandler),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		TLSConfig: &tls.Config{
			NextProtos: []string{"h2", "http/1.1"},
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
