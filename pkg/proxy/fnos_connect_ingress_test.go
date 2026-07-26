package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go-reauth-proxy/pkg/models"
	proxywaf "go-reauth-proxy/pkg/waf"
)

func newFnosConnectTestHandler() *Handler {
	handler := &Handler{
		authCache:      newAuthStateCache(),
		preflightCache: newPreflightStateCache(),
		proxyTransport: &http.Transport{
			Proxy:               nil,
			DisableCompression:  true,
			ForceAttemptHTTP2:   false,
			MaxIdleConnsPerHost: 2,
		},
	}
	handler.publishRequestSnapshotLocked()
	return handler
}

func fnosTestServerPort(t *testing.T, rawURL string) int {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil {
		t.Fatalf("parse test server port: %v", err)
	}
	return port
}

func loopbackClient() *http.Client {
	return &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			Proxy:              nil,
			DisableCompression: true,
		},
	}
}

func TestFnosConnectIngressDualStackForwardsReservedPathsAndTrustedClientIP(t *testing.T) {
	var mu sync.Mutex
	var seenHosts []string
	var seenXFF []string
	var seenForwardedHost []string
	var seenForwardedProto []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seenHosts = append(seenHosts, r.Host)
		seenXFF = append(seenXFF, r.Header.Get("X-Forwarded-For"))
		seenForwardedHost = append(seenForwardedHost, r.Header.Get("X-Forwarded-Host"))
		seenForwardedProto = append(seenForwardedProto, r.Header.Get("X-Forwarded-Proto"))
		mu.Unlock()
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, r.URL.RequestURI())
	}))
	defer upstream.Close()

	ingress := NewFnosConnectIngress(newFnosConnectTestHandler())
	defer ingress.Close()
	status, err := ingress.Apply(true, fnosTestServerPort(t, upstream.URL))
	if err != nil {
		t.Fatalf("enable ingress: %v", err)
	}
	if !status.ListenerActive || !status.IPv4Active || !status.IPv6Active || status.ListenPort == 0 {
		t.Fatalf("unexpected enabled status: %#v", status)
	}

	client := loopbackClient()
	for _, target := range []string{
		"http://127.0.0.1:" + strconv.Itoa(status.ListenPort) + "/__auth__/relay?via=ipv4",
		"http://" + net.JoinHostPort("::1", strconv.Itoa(status.ListenPort)) + "/favicon.ico?via=ipv6",
	} {
		req, err := http.NewRequest(http.MethodGet, target, nil)
		if err != nil {
			t.Fatalf("build request: %v", err)
		}
		req.Host = "nas.example.test"
		req.Header.Set("X-Forwarded-For", "198.51.100.24, 127.0.0.1")
		req.Header.Set("X-Forwarded-Host", "connect.example.test")
		req.Header.Set("X-Real-IP", "203.0.113.9")
		req.Header.Set("X-Forwarded-Proto", "https")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request %s: %v", target, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %s status=%d body=%s", target, resp.StatusCode, body)
		}
		if !strings.Contains(string(body), "via=") {
			t.Fatalf("reserved path was not proxied: %q", body)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if len(seenHosts) != 2 || seenHosts[0] != "nas.example.test" || seenHosts[1] != "nas.example.test" {
		t.Fatalf("upstream hosts = %#v", seenHosts)
	}
	for _, value := range seenXFF {
		if firstForwardedClientIP(value) != "198.51.100.24" {
			t.Fatalf("upstream X-Forwarded-For = %q, want relay client first", value)
		}
	}
	for _, value := range seenForwardedHost {
		if value != "connect.example.test" {
			t.Fatalf("upstream X-Forwarded-Host = %q, want trusted relay host", value)
		}
	}
	for _, value := range seenForwardedProto {
		if value != "https" {
			t.Fatalf("upstream X-Forwarded-Proto = %q, want trusted relay protocol", value)
		}
	}
}

func TestFnosConnectIngressUpdateKeepsListenerAndSwitchesUpstream(t *testing.T) {
	server := func(body string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, body)
		}))
	}
	first := server("first")
	defer first.Close()
	second := server("second")
	defer second.Close()

	ingress := NewFnosConnectIngress(newFnosConnectTestHandler())
	defer ingress.Close()
	before, err := ingress.Apply(true, fnosTestServerPort(t, first.URL))
	if err != nil {
		t.Fatalf("enable ingress: %v", err)
	}
	after, err := ingress.Apply(true, fnosTestServerPort(t, second.URL))
	if err != nil {
		t.Fatalf("update ingress: %v", err)
	}
	if before.ListenPort != after.ListenPort {
		t.Fatalf("listener port changed from %d to %d", before.ListenPort, after.ListenPort)
	}

	resp, err := loopbackClient().Get("http://127.0.0.1:" + strconv.Itoa(after.ListenPort) + "/")
	if err != nil {
		t.Fatalf("request updated ingress: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "second" {
		t.Fatalf("body = %q, want second upstream", body)
	}
}

func TestFnosConnectIngressForwardsWebSocketUpgrade(t *testing.T) {
	var upstreamHit atomic.Bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(r.Header.Get("Connection"), "upgrade") ||
			!strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			http.Error(w, "missing websocket upgrade", http.StatusBadRequest)
			return
		}
		upstreamHit.Store(true)
		w.Header().Set("Connection", "Upgrade")
		w.Header().Set("Upgrade", "websocket")
		w.WriteHeader(http.StatusSwitchingProtocols)
	}))
	defer upstream.Close()

	ingress := NewFnosConnectIngress(newFnosConnectTestHandler())
	defer ingress.Close()
	status, err := ingress.Apply(true, fnosTestServerPort(t, upstream.URL))
	if err != nil {
		t.Fatalf("enable ingress: %v", err)
	}
	req, err := http.NewRequest(
		http.MethodGet,
		"http://127.0.0.1:"+strconv.Itoa(status.ListenPort)+"/socket",
		nil,
	)
	if err != nil {
		t.Fatalf("build websocket request: %v", err)
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	resp, err := loopbackClient().Do(req)
	if err != nil {
		t.Fatalf("websocket upgrade: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("websocket status = %d, want 101", resp.StatusCode)
	}
	if !upstreamHit.Load() {
		t.Fatal("websocket upgrade did not reach fnOS upstream")
	}
}

func TestFnosConnectIngressRejectsInvalidPortAndNonLoopbackPeer(t *testing.T) {
	ingress := NewFnosConnectIngress(newFnosConnectTestHandler())
	if status, err := ingress.Apply(true, 0); err == nil || status.ListenerActive {
		t.Fatalf("invalid port accepted: status=%#v err=%v", status, err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	req.RemoteAddr = "192.0.2.10:40000"
	rec := httptest.NewRecorder()
	ingress.serveHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-loopback status = %d, want 403", rec.Code)
	}
}

func TestFnosConnectIngressAcceptsOnlyVerifiedDirectRedirect(t *testing.T) {
	var seenClientIP string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenClientIP = r.Header.Get("X-Real-IP")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	ingress := NewFnosConnectIngress(newFnosConnectTestHandler())
	defer ingress.Close()
	status, err := ingress.Apply(true, fnosTestServerPort(t, upstream.URL))
	if err != nil {
		t.Fatalf("enable ingress: %v", err)
	}

	request := func(originalPort int, originalErr error) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "http://nas.example.test/", nil)
		req.RemoteAddr = "[2001:db8::25]:4242"
		req.Header.Set("X-Forwarded-For", "198.51.100.99")
		req.Header.Set("X-Real-IP", "198.51.100.98")
		req = req.WithContext(context.WithValue(
			req.Context(),
			fnosConnectConnMetadataKey{},
			fnosConnectConnMetadata{
				originalPort:   originalPort,
				originalDstErr: originalErr,
			},
		))
		recorder := httptest.NewRecorder()
		ingress.serveHTTP(recorder, req)
		return recorder
	}

	if got := request(status.ListenPort, nil).Code; got != http.StatusForbidden {
		t.Fatalf("direct listener-port request status = %d, want 403", got)
	}
	if got := request(status.UpstreamHTTPPort, errors.New("missing conntrack state")).Code; got != http.StatusForbidden {
		t.Fatalf("unverified redirected request status = %d, want 403", got)
	}
	if got := request(status.UpstreamHTTPPort, nil).Code; got != http.StatusNoContent {
		t.Fatalf("verified redirected request status = %d, want 204", got)
	}
	if seenClientIP != "2001:db8::25" {
		t.Fatalf("direct client IP = %q, want socket peer", seenClientIP)
	}
}

func TestFnosConnectIngressBindsWildcardDualStackListeners(t *testing.T) {
	var addresses []string
	listen := func(network, address string) (net.Listener, error) {
		addresses = append(addresses, network+" "+address)
		return net.Listen(network, address)
	}
	ingress := newFnosConnectIngressWithListener(newFnosConnectTestHandler(), listen)
	defer ingress.Close()
	status, err := ingress.Apply(true, 5666)
	if err != nil {
		t.Fatalf("enable ingress: %v", err)
	}
	if len(addresses) != 2 {
		t.Fatalf("listen addresses = %#v", addresses)
	}
	if addresses[0] != "tcp4 0.0.0.0:0" {
		t.Fatalf("IPv4 listen address = %q", addresses[0])
	}
	if addresses[1] != "tcp6 "+net.JoinHostPort("::", strconv.Itoa(status.ListenPort)) {
		t.Fatalf("IPv6 listen address = %q", addresses[1])
	}
}

func TestFnosConnectIngressRollsBackIPv4WhenIPv6BindFails(t *testing.T) {
	var ipv4Address string
	listen := func(network, address string) (net.Listener, error) {
		if network == "tcp6" {
			return nil, errors.New("IPv6 unavailable")
		}
		listener, err := net.Listen(network, address)
		if err == nil {
			ipv4Address = listener.Addr().String()
		}
		return listener, err
	}
	ingress := newFnosConnectIngressWithListener(newFnosConnectTestHandler(), listen)
	status, err := ingress.Apply(true, 5666)
	if err == nil {
		t.Fatal("expected IPv6 bind failure")
	}
	if status.ListenerActive || status.IPv4Active || status.IPv6Active {
		t.Fatalf("partial listener remained active: %#v", status)
	}
	if conn, dialErr := net.DialTimeout("tcp4", ipv4Address, 100*time.Millisecond); dialErr == nil {
		conn.Close()
		t.Fatal("IPv4 listener was not rolled back")
	}
}

func TestFnosConnectIngressRetriesAnIPv6PortCollision(t *testing.T) {
	var ipv6Attempts atomic.Int32
	listen := func(network, address string) (net.Listener, error) {
		if network == "tcp6" && ipv6Attempts.Add(1) == 1 {
			return nil, errors.New("simulated IPv6 port collision")
		}
		return net.Listen(network, address)
	}
	ingress := newFnosConnectIngressWithListener(newFnosConnectTestHandler(), listen)
	defer ingress.Close()
	status, err := ingress.Apply(true, 5666)
	if err != nil {
		t.Fatalf("enable ingress after transient collision: %v", err)
	}
	if !status.IPv4Active || !status.IPv6Active || ipv6Attempts.Load() != 2 {
		t.Fatalf("unexpected retry result: status=%#v attempts=%d", status, ipv6Attempts.Load())
	}
}

func TestFnosConnectIngressDisableClosesBothListeners(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer upstream.Close()
	ingress := NewFnosConnectIngress(newFnosConnectTestHandler())
	status, err := ingress.Apply(true, fnosTestServerPort(t, upstream.URL))
	if err != nil {
		t.Fatalf("enable ingress: %v", err)
	}
	if disabled, err := ingress.Apply(false, 0); err != nil || disabled.ListenerActive || disabled.Enabled {
		t.Fatalf("disable result: status=%#v err=%v", disabled, err)
	}
	for _, address := range []string{
		"127.0.0.1:" + strconv.Itoa(status.ListenPort),
		net.JoinHostPort("::1", strconv.Itoa(status.ListenPort)),
	} {
		if conn, dialErr := net.DialTimeout("tcp", address, 100*time.Millisecond); dialErr == nil {
			conn.Close()
			t.Fatalf("listener %s still accepts connections", address)
		}
	}
}

func TestFnosConnectIngressUsesDedicatedWafRouteContext(t *testing.T) {
	ingressContext := &fnosConnectRequestContext{hostRule: models.HostRule{
		Host:   fnosConnectRouteKey,
		Target: "http://127.0.0.1:19122",
	}}
	req := httptest.NewRequest(http.MethodGet, "http://localhost/__auth__/reserved", nil)
	req = req.WithContext(context.WithValue(req.Context(), fnosConnectRequestContextKey{}, ingressContext))
	routeType, routeKey, upstream := wafRouteContextForRequest(
		req,
		requestSnapshot{},
		true,
		nil,
		nil,
		nil,
	)
	if routeType != "fn_connect" || routeKey != "fn_connect" || upstream != ingressContext.hostRule.Target {
		t.Fatalf("WAF context = %q %q %q", routeType, routeKey, upstream)
	}
}

func TestFnosConnectClientIPHeaderFallbacks(t *testing.T) {
	tests := []struct {
		name string
		xff  string
		real string
		want string
	}{
		{name: "first valid forwarded", xff: "198.51.100.5, 127.0.0.1", real: "203.0.113.5", want: "198.51.100.5"},
		{name: "real ip fallback", xff: "not-an-ip", real: "203.0.113.5", want: "203.0.113.5"},
		{name: "loopback socket fallback", xff: "bad", real: "also-bad", want: "127.0.0.1"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
			req.RemoteAddr = "127.0.0.1:34567"
			req.Header.Set("X-Forwarded-For", test.xff)
			req.Header.Set("X-Real-IP", test.real)
			if got := fnosConnectClientIP(req); got != test.want {
				t.Fatalf("client IP = %q, want %q", got, test.want)
			}
		})
	}
}

func TestFnosConnectClientIPDoesNotTrustDirectPeerHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	req.RemoteAddr = "203.0.113.77:34567"
	req.Header.Set("X-Forwarded-For", "198.51.100.5")
	req.Header.Set("X-Real-IP", "198.51.100.6")
	if got := fnosConnectClientIP(req); got != "203.0.113.77" {
		t.Fatalf("direct client IP = %q, want socket peer", got)
	}
}

func TestFnosConnectForwardedHeadersOnlyTrustHTTPProtocols(t *testing.T) {
	in := httptest.NewRequest(http.MethodGet, "http://listener.internal/", nil)
	in.RemoteAddr = "127.0.0.1:34567"
	in.Host = "nas.example.test"
	in.Header.Set("X-Forwarded-Host", "relay.example.test, ignored.example.test")
	in.Header.Set("X-Forwarded-Proto", "javascript")
	out := in.Clone(in.Context())
	out.Header = in.Header.Clone()

	applyFnosConnectForwardedHeaders(out, in, "198.51.100.7")

	if got := out.Header.Get("X-Real-IP"); got != "198.51.100.7" {
		t.Fatalf("X-Real-IP = %q", got)
	}
	if got := out.Header.Get("X-Forwarded-For"); got != "198.51.100.7" {
		t.Fatalf("X-Forwarded-For = %q", got)
	}
	if got := out.Header.Get("X-Forwarded-Host"); got != "relay.example.test" {
		t.Fatalf("X-Forwarded-Host = %q", got)
	}
	if got := out.Header.Get("X-Forwarded-Proto"); got != "http" {
		t.Fatalf("X-Forwarded-Proto = %q, want listener scheme fallback", got)
	}
}

func TestFnosConnectForwardedHeadersIgnoreDirectPeerOverrides(t *testing.T) {
	in := httptest.NewRequest(http.MethodGet, "http://listener.internal/", nil)
	in.RemoteAddr = "203.0.113.77:34567"
	in.Host = "nas.example.test"
	in.Header.Set("X-Forwarded-Host", "attacker.example.test")
	in.Header.Set("X-Forwarded-Proto", "https")
	in.Header.Set("X-Forwarded-Port", "443")
	in.Header.Set("Forwarded", "for=198.51.100.9;proto=https")
	out := in.Clone(in.Context())
	out.Header = in.Header.Clone()

	applyFnosConnectForwardedHeaders(out, in, "203.0.113.77")

	if got := out.Header.Get("X-Forwarded-Host"); got != "nas.example.test" {
		t.Fatalf("direct forwarded host = %q, want request host", got)
	}
	if got := out.Header.Get("X-Forwarded-Proto"); got != "http" {
		t.Fatalf("direct forwarded protocol = %q, want socket scheme", got)
	}
	if got := out.Header.Get("X-Forwarded-Port"); got != "" {
		t.Fatalf("direct forwarded port override was retained: %q", got)
	}
	if got := out.Header.Get("Forwarded"); got != "" {
		t.Fatalf("direct standardized Forwarded override was retained: %q", got)
	}
}

func TestFnosConnectIngressRunsThroughBlockingWafBeforeUpstream(t *testing.T) {
	var upstreamHit atomic.Bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHit.Store(true)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	rulesDir := t.TempDir()
	customDir := filepath.Join(rulesDir, "custom")
	if err := os.MkdirAll(customDir, 0o755); err != nil {
		t.Fatalf("create custom WAF directory: %v", err)
	}
	rule := `SecRule ARGS:test "@streq attack" "id:1901001,phase:2,deny,status:403,msg:'FN Connect test block',log"`
	if err := os.WriteFile(filepath.Join(customDir, "fn-connect-test.conf"), []byte(rule+"\n"), 0o644); err != nil {
		t.Fatalf("write custom WAF rule: %v", err)
	}
	wafConfig := models.WAFConfig{
		Enabled:           true,
		Mode:              proxywaf.ModeBlocking,
		RulesDir:          rulesDir,
		RequestBodyAccess: true,
	}
	wafRuntime := proxywaf.NewRuntime(wafConfig, rulesDir)
	status, err := wafRuntime.Reload(wafConfig, "", "")
	if err != nil || !status.Loaded {
		t.Fatalf("load WAF: status=%#v err=%v", status, err)
	}

	handler := newFnosConnectTestHandler()
	handler.WAFConfig = wafConfig
	handler.wafRuntime = wafRuntime
	ingress := NewFnosConnectIngress(handler)
	defer ingress.Close()
	ingressStatus, err := ingress.Apply(true, fnosTestServerPort(t, upstream.URL))
	if err != nil {
		t.Fatalf("enable ingress: %v", err)
	}

	resp, err := loopbackClient().Get(
		"http://127.0.0.1:" + strconv.Itoa(ingressStatus.ListenPort) + "/?test=attack",
	)
	if err != nil {
		t.Fatalf("request ingress: %v", err)
	}
	body, readErr := io.ReadAll(resp.Body)
	resp.Body.Close()
	if readErr != nil {
		t.Fatalf("read WAF response: %v", readErr)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("WAF status = %d, want 403", resp.StatusCode)
	}
	if strings.Contains(string(body), "/__assets__/") {
		t.Fatalf("FN Connect WAF response depends on an asset request that would inherit the malicious Referer")
	}
	if !strings.Contains(string(body), "data:image/png;base64,") {
		t.Fatal("FN Connect WAF response does not contain its embedded logo")
	}
	if upstreamHit.Load() {
		t.Fatal("blocked FN Connect request reached upstream")
	}
}
