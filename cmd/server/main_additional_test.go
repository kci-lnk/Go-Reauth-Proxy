package main

import (
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"go-reauth-proxy/pkg/config"
	"go-reauth-proxy/pkg/proxy"
)

func TestEnvPortDefaultUsesFallbackWhenUnset(t *testing.T) {
	t.Setenv("GO_REPROXY_PORT", "")
	if got := envPortDefault("GO_REPROXY_PORT", 7999); got != 7999 {
		t.Fatalf("envPortDefault() = %d", got)
	}
}

func TestEnvPortDefaultUsesValidEnvValue(t *testing.T) {
	t.Setenv("GO_REPROXY_PORT", "8123")
	if got := envPortDefault("GO_REPROXY_PORT", 7999); got != 8123 {
		t.Fatalf("envPortDefault() = %d", got)
	}
}

func TestEnvPortDefaultRejectsNonNumericValue(t *testing.T) {
	t.Setenv("GO_REPROXY_PORT", "abc")
	if got := envPortDefault("GO_REPROXY_PORT", 7999); got != 7999 {
		t.Fatalf("envPortDefault() = %d", got)
	}
}

func TestEnvPortDefaultRejectsOutOfRangeValue(t *testing.T) {
	t.Setenv("GO_REPROXY_PORT", "70000")
	if got := envPortDefault("GO_REPROXY_PORT", 7999); got != 7999 {
		t.Fatalf("envPortDefault() = %d", got)
	}
}

func TestServerIsClosedConnErrRejectsNil(t *testing.T) {
	if isClosedConnErr(nil) {
		t.Fatal("isClosedConnErr(nil) = true")
	}
}

func TestServerIsClosedConnErrAcceptsNetErrClosed(t *testing.T) {
	if !isClosedConnErr(net.ErrClosed) {
		t.Fatal("isClosedConnErr(net.ErrClosed) = false")
	}
}

func TestServerIsClosedConnErrAcceptsLegacyMessage(t *testing.T) {
	if !isClosedConnErr(errors.New("read tcp: use of closed network connection")) {
		t.Fatal("legacy closed connection message was not accepted")
	}
}

func TestProxyStackDesiredHostDefaultsToAllInterfaces(t *testing.T) {
	handler := newServerTestProxyHandler(t)
	stack := newProxyStack(0, handler, &http.Server{}, &http.Server{})
	if got := stack.desiredHost(); got != "0.0.0.0" {
		t.Fatalf("desiredHost() = %q", got)
	}
}

func TestProxyStackDesiredHostUsesLoopbackForProxyProtocol(t *testing.T) {
	handler := newServerTestProxyHandler(t)
	if err := handler.SetProxyProtocolForce(true); err != nil {
		t.Fatalf("SetProxyProtocolForce() returned error: %v", err)
	}
	stack := newProxyStack(0, handler, &http.Server{}, &http.Server{})
	if got := stack.desiredHost(); got != "127.0.0.1" {
		t.Fatalf("desiredHost() = %q", got)
	}
}

func TestStartProxyServersBindsEphemeralLoopbackPort(t *testing.T) {
	handler := newServerTestProxyHandler(t)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})}
	stop, addr, err := startProxyServers("127.0.0.1", 0, handler, server, &http.Server{})
	if err != nil {
		t.Fatalf("startProxyServers() returned error: %v", err)
	}
	defer stop()
	if !strings.Contains(addr, "127.0.0.1:") && !strings.Contains(addr, "[::1]:") {
		t.Fatalf("listen addr = %q", addr)
	}
}

type serverTestCertificateProvider struct {
	cert *tls.Certificate
}

func (p serverTestCertificateProvider) GetCertificate(*tls.ClientHelloInfo) *tls.Certificate {
	return p.cert
}

func TestProxyTLSConfigEnablesSessionResumption(t *testing.T) {
	cfg := newProxyTLSConfig(serverTestCertificateProvider{})
	if cfg.SessionTicketsDisabled {
		t.Fatal("SessionTicketsDisabled = true, want TLS session tickets enabled")
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("MinVersion = %x, want TLS 1.2", cfg.MinVersion)
	}
	if len(cfg.NextProtos) != 2 || cfg.NextProtos[0] != "h2" || cfg.NextProtos[1] != "http/1.1" {
		t.Fatalf("NextProtos = %#v, want h2/http1", cfg.NextProtos)
	}
	if _, err := cfg.GetCertificate(&tls.ClientHelloInfo{}); err == nil {
		t.Fatal("GetCertificate returned nil error for missing certificate")
	}
}

func newServerTestProxyHandler(t *testing.T) *proxy.Handler {
	t.Helper()
	manager := config.NewManager(filepath.Join(t.TempDir(), "config.json"))
	cfg, err := manager.Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	return proxy.NewHandler(7996, 7999, manager, cfg, filepath.Join(t.TempDir(), "logs"), nil)
}
