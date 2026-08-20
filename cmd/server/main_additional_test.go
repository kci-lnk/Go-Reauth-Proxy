package main

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"go-reauth-proxy/pkg/config"
	"go-reauth-proxy/pkg/models"
	"go-reauth-proxy/pkg/proxy"

	"github.com/pires/go-proxyproto"
	"github.com/soheilhy/cmux"
)

// syscall.WSAECONNRESET is only declared on Windows. Keep its stable Winsock
// value here so these cross-platform tests can recognize a reset on every OS.
const windowsConnectionReset syscall.Errno = 10054

func isConnectionResetError(err error) bool {
	return errors.Is(err, syscall.ECONNRESET) || errors.Is(err, windowsConnectionReset)
}

func TestConnectionResetErrorRecognizesWinsockReset(t *testing.T) {
	if !isConnectionResetError(windowsConnectionReset) {
		t.Fatal("Winsock WSAECONNRESET was not recognized as a connection reset")
	}
}

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

func TestResolveAuthBridgeStartupTimeout(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want time.Duration
	}{
		{name: "unset", raw: "", want: 150 * time.Second},
		{name: "DSM default", raw: "180", want: 150 * time.Second},
		{name: "custom DSM budget", raw: "90", want: 60 * time.Second},
		{name: "preserves shutdown margin", raw: "20", want: time.Second},
		{name: "invalid", raw: "invalid", want: 150 * time.Second},
		{name: "zero", raw: "0", want: 150 * time.Second},
		{name: "overflow", raw: "18446744073709551615", want: 150 * time.Second},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("FN_KNOCK_SYNOLOGY_START_TIMEOUT_SECONDS", test.raw)
			if got := resolveAuthBridgeStartupTimeout(); got != test.want {
				t.Fatalf("resolveAuthBridgeStartupTimeout() = %s, want %s", got, test.want)
			}
		})
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
		t.Fatalf("desiredHost() = %q, want 0.0.0.0", got)
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

func TestProxyStackDesiredHostUsesConfiguredListenerScope(t *testing.T) {
	handler := newServerTestProxyHandler(t)
	if err := handler.SetGatewayListenerConfig(models.GatewayListenerConfig{Scope: models.GatewayListenerScopeLoopback}); err != nil {
		t.Fatalf("SetGatewayListenerConfig() returned error: %v", err)
	}
	stack := newProxyStack(0, handler, &http.Server{}, &http.Server{})
	if got := stack.desiredHost(); got != "127.0.0.1" {
		t.Fatalf("desiredHost() = %q, want loopback", got)
	}
	if err := handler.SetGatewayListenerConfig(models.GatewayListenerConfig{Scope: models.GatewayListenerScopeAll}); err != nil {
		t.Fatalf("SetGatewayListenerConfig(all) returned error: %v", err)
	}
	if got := stack.desiredHost(); got != "0.0.0.0" {
		t.Fatalf("desiredHost() = %q, want all interfaces", got)
	}
}

type proxyProtocolReadResult struct {
	remoteAddr   string
	payload      string
	protocolUsed bool
	err          error
}

func readProxyProtocolConnection(t *testing.T, handler *proxy.Handler, writeClient func(net.Conn)) proxyProtocolReadResult {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	wrapped := &proxyproto.Listener{
		Listener:          listener,
		ReadHeaderTimeout: 100 * time.Millisecond,
		ConnPolicy:        proxyProtocolConnPolicy(handler),
	}
	defer wrapped.Close()

	result := make(chan proxyProtocolReadResult, 1)
	go func() {
		connection, acceptErr := wrapped.Accept()
		if acceptErr != nil {
			result <- proxyProtocolReadResult{err: acceptErr}
			return
		}
		defer connection.Close()
		payload := make([]byte, 1)
		_, readErr := io.ReadFull(connection, payload)
		result <- proxyProtocolReadResult{
			remoteAddr:   connection.RemoteAddr().String(),
			payload:      string(payload),
			protocolUsed: proxyProtocolConnectionUsed(connection),
			err:          readErr,
		}
	}()

	client, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	writeClient(client)
	_ = client.Close()
	return <-result
}

func TestProxyProtocolTrustedUpstreamSupportsV1AndV2(t *testing.T) {
	handler := newServerTestProxyHandler(t)
	if err := handler.SetGatewayProxyProtocolConfig(models.GatewayProxyProtocolConfig{
		Enabled:        true,
		TrustedSources: []string{"127.0.0.1"},
	}); err != nil {
		t.Fatal(err)
	}

	for _, version := range []byte{1, 2} {
		t.Run("v"+string(rune('0'+version)), func(t *testing.T) {
			got := readProxyProtocolConnection(t, handler, func(client net.Conn) {
				header := &proxyproto.Header{
					Version:           version,
					Command:           proxyproto.PROXY,
					TransportProtocol: proxyproto.TCPv4,
					SourceAddr:        &net.TCPAddr{IP: net.ParseIP("198.51.100.25"), Port: 4321},
					DestinationAddr:   &net.TCPAddr{IP: net.ParseIP("203.0.113.8"), Port: 7999},
				}
				if _, err := header.WriteTo(client); err != nil {
					t.Errorf("write PROXY v%d header: %v", version, err)
					return
				}
				_, _ = client.Write([]byte("x"))
			})
			if got.err != nil {
				t.Fatalf("read through PROXY v%d listener: %v", version, got.err)
			}
			if got.remoteAddr != "198.51.100.25:4321" || got.payload != "x" || !got.protocolUsed {
				t.Fatalf("PROXY v%d result = %#v", version, got)
			}
		})
	}
}

func TestManagedCloudflareListenerNeverEnablesProxyProtocol(t *testing.T) {
	targets := proxyListenTargets("0.0.0.0", 7999, true)
	if len(targets) != 3 {
		t.Fatalf("proxyListenTargets() returned %d targets", len(targets))
	}
	managedCloudflare := targets[len(targets)-1]
	if managedCloudflare.host != "127.0.0.1" || managedCloudflare.port != proxy.ManagedCloudflareIngressPort {
		t.Fatalf("managed Cloudflare target = %#v", managedCloudflare)
	}
	if managedCloudflare.proxyProtocol {
		t.Fatal("managed Cloudflare listener enabled PROXY protocol")
	}
}

func TestProxyProtocolEnabledStillAcceptsPlainDirectConnections(t *testing.T) {
	handler := newServerTestProxyHandler(t)
	if err := handler.SetGatewayProxyProtocolConfig(models.GatewayProxyProtocolConfig{
		Enabled:        true,
		TrustedSources: []string{"192.0.2.10"},
	}); err != nil {
		t.Fatal(err)
	}
	got := readProxyProtocolConnection(t, handler, func(client net.Conn) {
		_, _ = client.Write([]byte("p"))
	})
	if got.err != nil || got.payload != "p" || got.protocolUsed || !strings.HasPrefix(got.remoteAddr, "127.0.0.1:") {
		t.Fatalf("plain direct result = %#v", got)
	}
}

func TestProxyProtocolRejectsUntrustedAndIncompleteHeaders(t *testing.T) {
	handler := newServerTestProxyHandler(t)
	if err := handler.SetGatewayProxyProtocolConfig(models.GatewayProxyProtocolConfig{
		Enabled:        true,
		TrustedSources: []string{"192.0.2.10"},
	}); err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string]string{
		"untrusted":  "PROXY TCP4 198.51.100.1 203.0.113.8 1234 7999\r\nx",
		"incomplete": "PROXY ",
	} {
		t.Run(name, func(t *testing.T) {
			got := readProxyProtocolConnection(t, handler, func(client net.Conn) {
				_, _ = io.WriteString(client, raw)
			})
			if got.err == nil {
				t.Fatalf("unsafe header entered the application stream: %#v", got)
			}
		})
	}
}

func TestUntrustedProxyHeaderNeverReachesHTTPHandler(t *testing.T) {
	handler := newServerTestProxyHandler(t)
	if err := handler.SetGatewayProxyProtocolConfig(models.GatewayProxyProtocolConfig{
		Enabled:        true,
		TrustedSources: []string{"192.0.2.10"},
	}); err != nil {
		t.Fatal(err)
	}

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	wrapper := &proxyproto.Listener{
		Listener:          listener,
		ReadHeaderTimeout: 100 * time.Millisecond,
		ConnPolicy:        proxyProtocolConnPolicy(handler),
	}
	mux := cmux.New(wrapper)
	httpListener := mux.Match(cmux.HTTP1Fast())
	handled := make(chan struct{}, 1)
	server := &http.Server{Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		handled <- struct{}{}
	})}
	defer server.Close()
	defer wrapper.Close()
	go func() { _ = server.Serve(httpListener) }()
	go func() { _ = mux.Serve() }()

	client, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_, _ = io.WriteString(client, "PROXY TCP4 198.51.100.1 203.0.113.8 1234 7999\r\nGET / HTTP/1.1\r\nHost: app.example\r\n\r\n")
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 1)
	if _, err := client.Read(buffer); err == nil {
		t.Fatal("untrusted PROXY connection remained readable")
	}
	select {
	case <-handled:
		t.Fatal("untrusted PROXY header reached the HTTP handler")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestProxyProtocolTrustedUpstreamRejectsMalformedAndTimedOutHeaders(t *testing.T) {
	handler := newServerTestProxyHandler(t)
	if err := handler.SetGatewayProxyProtocolConfig(models.GatewayProxyProtocolConfig{
		Enabled:        true,
		TrustedSources: []string{"127.0.0.1"},
	}); err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(net.Conn){
		"malformed": func(client net.Conn) {
			_, _ = io.WriteString(client, "PROXY invalid\r\n")
		},
		"timeout": func(client net.Conn) {
			_, _ = io.WriteString(client, "PROXY ")
			time.Sleep(150 * time.Millisecond)
		},
	}
	for name, writeClient := range tests {
		t.Run(name, func(t *testing.T) {
			got := readProxyProtocolConnection(t, handler, writeClient)
			if got.err == nil {
				t.Fatalf("unsafe trusted header entered the application stream: %#v", got)
			}
		})
	}
}

func TestProxyStackDesiredHostForScopeUsesCandidateBeforeItIsPersisted(t *testing.T) {
	handler := newServerTestProxyHandler(t)
	currentScope := handler.GetGatewayListenerConfig().Scope
	candidateScope := models.GatewayListenerScopeLoopback
	if currentScope == candidateScope {
		candidateScope = models.GatewayListenerScopeAll
	}
	stack := newProxyStack(0, handler, &http.Server{}, &http.Server{})
	wantCandidateHost := "0.0.0.0"
	if candidateScope == models.GatewayListenerScopeLoopback {
		wantCandidateHost = "127.0.0.1"
	}
	if got := stack.desiredHostForScope(candidateScope); got != wantCandidateHost {
		t.Fatalf("candidate host = %q, want %q", got, wantCandidateHost)
	}
	wantCurrentHost := "0.0.0.0"
	if currentScope == models.GatewayListenerScopeLoopback {
		wantCurrentHost = "127.0.0.1"
	}
	if got := stack.desiredHost(); got != wantCurrentHost {
		t.Fatalf("current persisted host = %q, want %q", got, wantCurrentHost)
	}
}

func TestProxyStackRebindRestoresPreviousListenerWhenNewBindFails(t *testing.T) {
	targetErr := errors.New("new listener port is occupied")
	previousStopped := false
	restoredStopped := false
	stack := &proxyStack{
		host:       "127.0.0.1",
		listenAddr: "127.0.0.1:7999",
		stop: func() {
			previousStopped = true
		},
	}

	var attempts []string
	err := stack.rebindWithStarter("0.0.0.0", func(host string) (func(), string, error) {
		attempts = append(attempts, host)
		switch host {
		case "0.0.0.0":
			if !previousStopped {
				t.Fatal("previous listener was not stopped before attempting the new bind")
			}
			return nil, "", targetErr
		case "127.0.0.1":
			return func() { restoredStopped = true }, "127.0.0.1:7999", nil
		default:
			t.Fatalf("unexpected bind host %q", host)
			return nil, "", nil
		}
	})
	if !errors.Is(err, targetErr) {
		t.Fatalf("rebind error = %v, want wrapped %v", err, targetErr)
	}
	if got := strings.Join(attempts, ","); got != "0.0.0.0,127.0.0.1" {
		t.Fatalf("bind attempts = %q, want target then previous host", got)
	}
	if !stack.IsServing() {
		t.Fatal("stack is not serving after restoring the previous listener")
	}
	if stack.host != "127.0.0.1" || stack.listenAddr != "127.0.0.1:7999" {
		t.Fatalf("restored stack = host %q addr %q", stack.host, stack.listenAddr)
	}
	stack.stop()
	if !restoredStopped {
		t.Fatal("restored listener stop was not retained")
	}
}

func TestProxyStackRebindReloadsListenerWhenHostIsUnchanged(t *testing.T) {
	previousStopped := false
	reloadedStopped := false
	stack := &proxyStack{
		host:       "0.0.0.0",
		listenAddr: "0.0.0.0:7999",
		stop:       func() { previousStopped = true },
	}
	starts := 0
	err := stack.rebindWithStarter("0.0.0.0", func(host string) (func(), string, error) {
		starts++
		if host != "0.0.0.0" {
			t.Fatalf("reload host = %q", host)
		}
		return func() { reloadedStopped = true }, "0.0.0.0:7999", nil
	})
	if err != nil {
		t.Fatalf("rebindWithStarter() error = %v", err)
	}
	if !previousStopped || starts != 1 {
		t.Fatalf("reload state: previousStopped=%v starts=%d", previousStopped, starts)
	}
	stack.stop()
	if !reloadedStopped {
		t.Fatal("reloaded listener stop function was not retained")
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
	if strings.Count(addr, "127.0.0.1:") < 2 {
		t.Fatalf("listen addr = %q, missing dedicated managed Cloudflare listener", addr)
	}
}

func TestStartProxyServersResetsUnmatchedHTTP1Connection(t *testing.T) {
	handler := newServerTestProxyHandler(t)
	if _, err := handler.SetGatewayUnmatchedRouteConfig(models.GatewayUnmatchedRouteConfig{
		Behavior: models.GatewayUnmatchedRouteBehaviorResetConnection,
	}); err != nil {
		t.Fatalf("SetGatewayUnmatchedRouteConfig() returned error: %v", err)
	}
	server := &http.Server{Handler: handler}
	stop, addr, err := startProxyServers("127.0.0.1", 0, handler, server, &http.Server{})
	if err != nil {
		t.Fatalf("startProxyServers() returned error: %v", err)
	}
	defer stop()

	conn, err := net.DialTimeout("tcp", firstProxyListenAddr(addr), 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	assertHTTP1ConnectionReset(t, conn)
}

func TestStartProxyServersResetsUnmatchedTLSHTTP1Connection(t *testing.T) {
	handler := newServerTestProxyHandler(t)
	if _, err := handler.SetGatewayUnmatchedRouteConfig(models.GatewayUnmatchedRouteConfig{
		Behavior: models.GatewayUnmatchedRouteBehaviorResetConnection,
	}); err != nil {
		t.Fatalf("SetGatewayUnmatchedRouteConfig() returned error: %v", err)
	}
	certificate := newProtocolModeTestCertificate(t)
	serverTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
	}
	httpServer := &http.Server{Handler: handler}
	httpsServer := &http.Server{Handler: handler, TLSConfig: serverTLSConfig}
	stop, addr, err := startProxyServers("127.0.0.1", 0, handler, httpServer, httpsServer)
	if err != nil {
		t.Fatalf("startProxyServers() returned error: %v", err)
	}
	defer stop()

	conn, err := tls.Dial("tcp", firstProxyListenAddr(addr), &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		NextProtos:         []string{"http/1.1"},
	})
	if err != nil {
		t.Fatalf("dial TLS proxy: %v", err)
	}
	defer conn.Close()
	if got := conn.ConnectionState().NegotiatedProtocol; got != "http/1.1" {
		t.Fatalf("negotiated protocol = %q, want http/1.1", got)
	}
	assertHTTP1ConnectionReset(t, conn)
}

func firstProxyListenAddr(value string) string {
	return strings.Split(value, ", ")[0]
}

func assertHTTP1ConnectionReset(t *testing.T, conn net.Conn) {
	t.Helper()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if _, err := conn.Write([]byte("GET /private HTTP/1.1\r\nHost: unknown.example.com\r\nConnection: keep-alive\r\n\r\n")); err != nil {
		t.Fatalf("write request: %v", err)
	}
	buffer := make([]byte, 1)
	if n, err := conn.Read(buffer); n != 0 || !isConnectionResetError(err) {
		t.Fatalf("read = (%d, %v), want (0, connection reset)", n, err)
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
