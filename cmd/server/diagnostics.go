package main

import (
	"context"
	"crypto/subtle"
	"fmt"
	"go-reauth-proxy/pkg/diagnostics"
	"log"
	"net"
	"net/http"
	"net/http/pprof"
	"strings"
	"time"
)

const diagnosticsAddrEnv = "GO_REPROXY_DIAGNOSTICS_ADDR"

func startDiagnosticsServer(addr string, token string) (func(), string, error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return func() {}, "", nil
	}
	if strings.TrimSpace(token) == "" {
		return nil, "", fmt.Errorf("diagnostics require an internal RPC token")
	}

	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, "", fmt.Errorf("invalid diagnostics address %q: %w", addr, err)
	}
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if !strings.EqualFold(host, "localhost") {
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return nil, "", fmt.Errorf("diagnostics address must use a loopback host")
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	mux.Handle("/debug/metrics", diagnostics.Handler())

	server := &http.Server{
		Handler:           requireDiagnosticsToken(token, mux),
		ReadHeaderTimeout: 2 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, "", err
	}
	diagnostics.SetEnabled(true)
	go func() {
		if serveErr := server.Serve(listener); serveErr != nil && serveErr != http.ErrServerClosed {
			log.Printf("Diagnostics server stopped: %v", serveErr)
		}
	}()

	stop := func() {
		diagnostics.SetEnabled(false)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}
	return stop, listener.Addr().String(), nil
}

func requireDiagnosticsToken(token string, next http.Handler) http.Handler {
	want := []byte(strings.TrimSpace(token))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := strings.TrimSpace(r.Header.Get("x-fn-knock-internal-rpc-token"))
		if got == "" {
			const bearer = "Bearer "
			authorization := r.Header.Get("Authorization")
			if strings.HasPrefix(authorization, bearer) {
				got = strings.TrimSpace(strings.TrimPrefix(authorization, bearer))
			}
		}
		if len(got) != len(want) || subtle.ConstantTimeCompare([]byte(got), want) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
