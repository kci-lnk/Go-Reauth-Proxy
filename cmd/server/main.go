package main

import (
	"flag"
	"fmt"
	"go-reauth-proxy/pkg/admin"
	"go-reauth-proxy/pkg/auth"
	"go-reauth-proxy/pkg/middleware"
	"go-reauth-proxy/pkg/proxy"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "go-reauth-proxy/docs" // load Swagger docs
)

// @title Go Reauth Proxy Admin API
// @version 1.0
// @description API for managing proxy rules and iptables.
// @termsOfService http://swagger.io/terms/

// @contact.name API Support
// @contact.url http://www.swagger.io/support
// @contact.email support@swagger.io

// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html

// @host 127.0.0.1:9091
// @BasePath /

func main() {
	adminPort := flag.Int("admin-port", 9091, "Port for the Admin API (binds to 127.0.0.1)")
	proxyPort := flag.Int("proxy-port", 9090, "Port for the Reverse Proxy (binds to 0.0.0.0)")
	flag.Parse()

	log.Printf("Starting Go Reauth Proxy Service...")

	authCache := auth.NewCache(5 * time.Minute)
	proxyHandler := proxy.NewHandler(authCache, *adminPort)

	adminServer := admin.NewServer(proxyHandler, *adminPort)
	go func() {
		if err := adminServer.Start(); err != nil {
			log.Fatalf("Admin server failed: %v", err)
		}
	}()

	proxyAddr := fmt.Sprintf(":%d", *proxyPort)
	proxyServer := &http.Server{
		Addr:    proxyAddr,
		Handler: middleware.Logger(proxyHandler),
	}

	go func() {
		log.Printf("Reverse Proxy listening on 0.0.0.0:%d", *proxyPort)
		if err := proxyServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Proxy server failed: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down...")
}
