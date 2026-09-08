package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"github.com/gorilla/websocket"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"go-reauth-proxy/pkg/models"
	"go-reauth-proxy/pkg/proxy"
)

func http3Fixture(t testing.TB, upstream http.Handler) (*http3Runtime, *proxy.Handler, string) {
	t.Helper()
	backend := httptest.NewServer(upstream)
	t.Cleanup(backend.Close)
	h := newServerTestProxyHandler(t)
	t.Cleanup(h.Close)
	certificate := newProtocolModeTestCertificate(t)
	template, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	template.DNSNames = []string{"app.example.test"}
	certificate.Certificate[0], err = x509.CreateCertificate(rand.Reader, template, template, template.PublicKey, certificate.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})
	if err := h.SetSSLCertificatePEM(string(certPEM), string(keyPEM)); err != nil {
		t.Fatal(err)
	}
	if err := h.SetHostRules([]models.HostRule{{Host: "app.example.test", Target: backend.URL, ProtocolMode: models.HostProtocolModeAuto}}); err != nil {
		t.Fatal(err)
	}
	if err := h.SetGatewayListenerConfig(models.GatewayListenerConfig{Scope: models.GatewayListenerScopeLoopback}); err != nil {
		t.Fatal(err)
	}
	m := newHTTP3Runtime(h, 0)
	m.started.Store(true)
	h.SetHTTP3Hooks(m.Apply, m.Status)
	if err := m.ApplyHost(models.GatewayHttp3Config{Enabled: true}, "127.0.0.1", false); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		m.Shutdown(ctx)
	})
	return m, h, m.Status().ListenAddresses[0]
}
func http3TestClient(t testing.TB, addr string) *http.Client {
	t.Helper()
	transport := &http3.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, Dial: func(ctx context.Context, _ string, tlsConfig *tls.Config, config *quic.Config) (*quic.Conn, error) {
		return quic.DialAddr(ctx, addr, tlsConfig, config)
	}}
	t.Cleanup(func() { _ = transport.Close() })
	return &http.Client{Transport: transport, Timeout: 5 * time.Second}
}
func TestHTTP3ProxyStreamsAndProtocolPolicy(t *testing.T) {
	var upstreamProtocol atomic.Value
	m, h, addr := http3Fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamProtocol.Store(r.Proto)
		w.Header().Set("Alt-Svc", `h3=":9999"`)
		if r.URL.Path == "/events" {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "data: ready\n\n")
			w.(http.Flusher).Flush()
			return
		}
		data, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		_, _ = w.Write(data)
	}))
	client := http3TestClient(t, addr)
	payload := bytes.Repeat([]byte("hello HTTP3"), 10000)
	response, err := client.Post("https://app.example.test/upload", "application/octet-stream", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || response.StatusCode != 200 || response.ProtoMajor != 3 || !bytes.Equal(body, payload) {
		t.Fatalf("response %d %s, %d bytes: %v headers=%v body=%q", response.StatusCode, response.Proto, len(body), err, response.Header, body)
	}
	if upstreamProtocol.Load() != "HTTP/1.1" {
		t.Fatalf("unexpected upstream %q", upstreamProtocol.Load())
	}
	if response.Header.Get("Alt-Svc") != `h3=":443"; ma=300` {
		t.Fatalf("upstream Alt-Svc escaped: %v", response.Header)
	}
	response, err = client.Get("https://app.example.test/events")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(response.Body)
	_ = response.Body.Close()
	if !strings.Contains(string(body), "data: ready") {
		t.Fatalf("SSE %q", body)
	}
	rules := h.GetHostRules()
	rules[0].ProtocolMode = models.HostProtocolModeHTTP2
	if err := h.SetHostRules(rules); err != nil {
		t.Fatal(err)
	}
	coalesced, _ := http.NewRequest("GET", "https://app.example.test/", nil)
	coalesced.Header.Set("X-Forwarded-Host", "unrestricted.example.test")
	response, err = client.Do(coalesced)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != 421 {
		t.Fatalf("reused connection bypassed mode: %d", response.StatusCode)
	}
	fresh := http3TestClient(t, addr)
	if response, err = fresh.Get("https://app.example.test/"); err == nil {
		_ = response.Body.Close()
		t.Fatal("HTTP/2-only host accepted HTTP/3 handshake")
	}
	if m.Status().State != "running" {
		t.Fatal(m.Status())
	}
}
func TestHTTP3SettingsDoNotAdvertiseExtendedConnect(t *testing.T) {
	_, _, addr := http3Fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, addr, &tls.Config{InsecureSkipVerify: true, ServerName: "app.example.test", NextProtos: []string{"h3"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "")
	transport := &http3.Transport{}
	defer transport.Close()
	client := transport.NewClientConn(conn)
	select {
	case <-client.ReceivedSettings():
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if client.Settings().EnableExtendedConnect || client.Settings().EnableDatagrams {
		t.Fatalf("unsupported extensions: %+v", client.Settings())
	}
}
func TestHTTP3BindFailureAndDisablePreserveTCP(t *testing.T) {
	m, h, addr := http3Fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	tcp := httptest.NewTLSServer(m.Advertise(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Alt-Svc", "upstream")
		w.WriteHeader(204)
	})))
	defer tcp.Close()
	response, err := tcp.Client().Get(tcp.URL)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if !strings.Contains(response.Header.Get("Alt-Svc"), "ma=300") {
		t.Fatal(response.Header)
	}
	occupied, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	other := newHTTP3Runtime(h, occupied.LocalAddr().(*net.UDPAddr).Port)
	other.started.Store(true)
	if err := other.ApplyHost(models.GatewayHttp3Config{Enabled: true}, "127.0.0.1", false); err == nil {
		t.Fatal("accepted occupied UDP port")
	}
	if other.Status().State != "error" {
		t.Fatal(other.Status())
	}
	if err := m.Apply(models.GatewayHttp3Config{}); err != nil {
		t.Fatal(err)
	}
	response, err = tcp.Client().Get(tcp.URL)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != 204 || response.Header.Get("Alt-Svc") != "clear" {
		t.Fatal(response.Header)
	}
	if m.Status().State != "disabled" || len(m.Status().ListenAddresses) != 0 {
		t.Fatal(m.Status())
	}
	socket, err := net.ListenPacket("udp4", addr)
	if err != nil {
		t.Fatalf("socket leaked: %v", err)
	}
	_ = socket.Close()
}
func TestHTTP3AdvertisedPortAndFlush(t *testing.T) {
	m, _, _ := http3Fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	for _, test := range []struct {
		host string
		port int
		want string
	}{{"app.example.test", 0, `h3=":443"; ma=300`}, {"app.example.test:8443", 0, `h3=":8443"; ma=300`}, {"app.example.test:8443", 443, `h3=":443"; ma=300`}} {
		m.advertised.Store(int64(test.port))
		req := httptest.NewRequest("GET", "https://"+test.host+"/", nil)
		rec := httptest.NewRecorder()
		m.Advertise(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Alt-Svc", "bad")
			w.(http.Flusher).Flush()
			_, _ = w.Write([]byte("hello"))
		})).ServeHTTP(rec, req)
		if rec.Header().Get("Alt-Svc") != test.want || rec.Body.String() != "hello" {
			t.Fatalf("%s: %v", test.host, rec)
		}
	}
}

func TestHTTP3AndTCPWebSocketCoexist(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	m, h, _ := http3Fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		kind, data, err := conn.ReadMessage()
		if err == nil {
			_ = conn.WriteMessage(kind, data)
		}
	}))
	tcp := httptest.NewTLSServer(m.Advertise(h))
	defer tcp.Close()
	dialer := websocket.Dialer{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, NetDialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", tcp.Listener.Addr().String())
	}}
	conn, _, err := dialer.Dial("wss://app.example.test/socket", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if err := conn.WriteMessage(websocket.TextMessage, []byte("echo")); err != nil {
		t.Fatal(err)
	}
	_, data, err := conn.ReadMessage()
	if err != nil || string(data) != "echo" {
		t.Fatalf("websocket %q: %v", data, err)
	}
}
func TestHTTP3CertificateRemovalAndFRPSuspension(t *testing.T) {
	m, h, _ := http3Fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	h.SetProxyProtocolForceChangeHook(m.Refresh)
	// Persist the setting through the real transactional setter.
	if err := h.SetGatewayHttp3Config(models.GatewayHttp3Config{Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := h.SetProxyProtocolForce(true); err != nil {
		t.Fatal(err)
	}
	if m.Status().State != "suspended_frp" || len(m.Status().ListenAddresses) != 0 {
		t.Fatal(m.Status())
	}
	if err := h.SetProxyProtocolForce(false); err != nil {
		t.Fatal(err)
	}
	if m.Status().State != "running" {
		t.Fatal(m.Status())
	}
	h.SetSSLChangeHook(func() {
		if err := m.Refresh(); err != nil {
			t.Error(err)
		}
	})
	if err := h.ClearSSLCertificate(); err != nil {
		t.Fatal(err)
	}
	if m.Status().State != "waiting_certificate" || m.ready.Load() {
		t.Fatal(m.Status())
	}
}
func TestHTTP3RequestCancellationReachesUpstream(t *testing.T) {
	canceled := make(chan struct{})
	_, _, addr := http3Fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("ready\n"))
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		close(canceled)
	}))
	client := http3TestClient(t, addr)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	request, _ := http.NewRequestWithContext(ctx, "GET", "https://app.example.test/events", nil)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 6)
	if _, err := io.ReadFull(response.Body, data); err != nil {
		t.Fatal(err)
	}
	cancel()
	_ = response.Body.Close()
	select {
	case <-canceled:
	case <-time.After(3 * time.Second):
		t.Fatal("upstream request was not canceled")
	}
}

// Loopback smoke benchmark only: it does not model loss, mobile networks or
// low-power ARM CPUs. Both protocols run through the same gateway and upstream.
func BenchmarkGatewayHTTP2HTTP3(b *testing.B) {
	for _, protocol := range []string{"h2", "h3"} {
		b.Run(protocol, func(b *testing.B) {
			payload := bytes.Repeat([]byte("x"), 64<<10)
			_, h, addr := http3Fixture(b, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/octet-stream")
				_, _ = w.Write(payload)
			}))
			client := http3TestClient(b, addr)
			if protocol == "h2" {
				server := httptest.NewUnstartedServer(h)
				server.EnableHTTP2 = true
				server.StartTLS()
				b.Cleanup(server.Close)
				transport := &http.Transport{ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
				}}
				b.Cleanup(transport.CloseIdleConnections)
				client = &http.Client{Transport: transport}
			}
			request := func() {
				response, err := client.Get("https://app.example.test/data")
				if err != nil {
					b.Fatal(err)
				}
				n, err := io.Copy(io.Discard, response.Body)
				_ = response.Body.Close()
				if err != nil || n != int64(len(payload)) || response.StatusCode != 200 {
					b.Fatalf("response %d bytes=%d error=%v", response.StatusCode, n, err)
				}
			}
			request()
			b.ReportAllocs()
			b.SetBytes(int64(len(payload)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				request()
			}
			b.StopTimer()
			b.ReportMetric(float64(runtime.NumGoroutine()), "goroutines")
		})
	}
}

func TestHTTP3AuthenticationCannotBeBypassed(t *testing.T) {
	var reached atomic.Int32
	_, h, addr := http3Fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached.Add(1); w.WriteHeader(204) }))
	rules := h.GetHostRules()
	rules[0].UseAuth = true
	if err := h.SetHostRules(rules); err != nil {
		t.Fatal(err)
	}
	client := http3TestClient(t, addr)
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Get("https://app.example.test/private")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if reached.Load() != 0 || response.StatusCode < 300 {
		t.Fatalf("authentication bypass: upstream=%d status=%d", reached.Load(), response.StatusCode)
	}
}
func TestHTTP3WAFResponseAndConnectionReset(t *testing.T) {
	for _, behavior := range []string{models.WAFBlockBehaviorErrorPage, models.WAFBlockBehaviorResetConnection} {
		t.Run(behavior, func(t *testing.T) {
			var reached atomic.Int32
			_, h, addr := http3Fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached.Add(1); w.WriteHeader(204) }))
			cfg := h.GetWAFConfig()
			cfg.RulesDir = t.TempDir()
			cfg.Enabled = true
			cfg.Mode = "blocking"
			cfg.RequestBodyAccess = true
			cfg.BlockBehavior = behavior
			customDir := filepath.Join(cfg.RulesDir, "custom")
			if err := os.MkdirAll(customDir, 0755); err != nil {
				t.Fatal(err)
			}
			rule := `SecRule ARGS:test "@streq attack" "id:1903991,phase:2,deny,status:403,msg:'HTTP3 test',log"`
			if err := os.WriteFile(filepath.Join(customDir, "http3-test.conf"), []byte(rule+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := h.ReloadWAFBundle(cfg, "", ""); err != nil {
				t.Fatal(err)
			}
			client := http3TestClient(t, addr)
			response, err := client.Get("https://app.example.test/?test=attack")
			if behavior == models.WAFBlockBehaviorResetConnection {
				if err == nil {
					_ = response.Body.Close()
					t.Fatal("WAF did not close QUIC connection")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				_ = response.Body.Close()
				if response.StatusCode != 403 {
					t.Fatalf("WAF status=%d", response.StatusCode)
				}
			}
			if reached.Load() != 0 {
				t.Fatal("blocked request reached upstream")
			}
		})
	}
}

func TestHTTP3ShutdownRejectsLateReenable(t *testing.T) {
	m, _, _ := http3Fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	m.Shutdown(context.Background())
	if err := m.Apply(models.GatewayHttp3Config{Enabled: true}); err == nil {
		t.Fatal("late RPC reopened UDP after shutdown")
	}
	if len(m.Status().ListenAddresses) != 0 {
		t.Fatal(m.Status())
	}
}

func TestHTTP3AdvertisementUsesCommittedResponseState(t *testing.T) {
	m, _, _ := http3Fixture(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	rec := httptest.NewRecorder()
	m.Advertise(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A long-running request began while HTTP/3 was available.
		m.ready.Store(false)
		w.Header().Set("Alt-Svc", `h3=":9999"`)
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(rec, httptest.NewRequest("GET", "https://app.example.test/", nil))
	if got := rec.Result().Header.Get("Alt-Svc"); got != "clear" {
		t.Fatalf("stale advertisement: %q", got)
	}
}

func TestHTTP3FailedHijackStillCommitsResponse(t *testing.T) {
	rec := httptest.NewRecorder()
	writer := &altSvcWriter{ResponseWriter: rec, value: func() string { return "clear" }}
	if _, _, err := writer.Hijack(); err == nil {
		t.Fatal("recorder unexpectedly supports hijack")
	}
	if _, err := writer.Write([]byte("fallback")); err != nil {
		t.Fatal(err)
	}
	if rec.Result().Header.Get("Alt-Svc") != "clear" || rec.Body.String() != "fallback" {
		t.Fatalf("fallback response: %v", rec)
	}
}

func TestHTTP3RetryRecoversFailedListener(t *testing.T) {
	m, _, _ := http3Fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	m.mu.Lock()
	binding := m.bindings[0]
	m.mu.Unlock()
	if err := binding.socket.Close(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for m.Status().State != "error" && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if m.Status().State != "error" {
		t.Fatal("listener failure was not reported")
	}
	if err := m.Apply(models.GatewayHttp3Config{Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if status := m.Status(); status.State != "running" {
		t.Fatalf("retry did not recover: %+v", status)
	}
	client := http3TestClient(t, m.Status().ListenAddresses[0])
	response, err := client.Get("https://app.example.test/")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 204 {
		t.Fatal(response.Status)
	}
}

func TestHTTP3PolicyRefreshWaitsForConfigurationCommit(t *testing.T) {
	m, h, _ := http3Fixture(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	applied, release := make(chan struct{}), make(chan struct{})
	var released atomic.Bool
	unblock := func() {
		if released.CompareAndSwap(false, true) {
			close(release)
		}
	}
	defer unblock()
	h.SetHTTP3Hooks(func(cfg models.GatewayHttp3Config) error {
		if err := m.Apply(cfg); err != nil {
			return err
		}
		close(applied)
		<-release // Runtime changed; persistent configuration has not committed yet.
		return nil
	}, m.Status)
	configured := make(chan error, 1)
	go func() {
		configured <- h.SetGatewayHttp3Config(models.GatewayHttp3Config{Enabled: true, AdvertisedPort: 8443})
	}()
	<-applied
	statusRead := make(chan models.GatewayHttp3Status, 1)
	go func() { statusRead <- h.GetGatewayHttp3Status() }()
	refreshed := make(chan error, 1)
	go func() { refreshed <- m.RefreshPolicy() }()
	select {
	case status := <-statusRead:
		t.Fatalf("status exposed uncommitted transition: %+v", status)
	case err := <-refreshed:
		t.Fatalf("refresh bypassed configuration transaction: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	unblock()
	if err := <-configured; err != nil {
		t.Fatal(err)
	}
	if err := <-refreshed; err != nil {
		t.Fatal(err)
	}
	if status := <-statusRead; !status.Config.Enabled || status.Config.AdvertisedPort != 8443 || status.State != "running" {
		t.Fatalf("inconsistent status: %+v", status)
	}
	if !m.ready.Load() || m.advertised.Load() != 8443 {
		t.Fatalf("refresh restored stale config: %+v", m.Status())
	}
}

func TestHTTP3ShutdownInterruptsExistingDrain(t *testing.T) {
	m, h, addr := http3Fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	if err := h.SetGatewayHttp3Config(models.GatewayHttp3Config{Enabled: true}); err != nil {
		t.Fatal(err)
	}
	response, err := http3TestClient(t, addr).Get("https://app.example.test/events")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	refreshed := make(chan error, 1)
	go func() { refreshed <- m.RefreshPolicy() }()
	deadline := time.Now().Add(time.Second)
	for m.ready.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if m.ready.Load() {
		t.Fatal("refresh did not begin draining")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	m.Shutdown(ctx)
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("shutdown blocked behind configuration drain for %v", elapsed)
	}
	if err := <-refreshed; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("refresh after shutdown: %v", err)
	}
	if status := m.Status(); status.State != "disabled" || len(status.ListenAddresses) != 0 {
		t.Fatalf("listener reopened: %+v", status)
	}
}
