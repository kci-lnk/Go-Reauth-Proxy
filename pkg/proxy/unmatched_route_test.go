package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/pires/go-proxyproto"
	"github.com/soheilhy/cmux"

	"go-reauth-proxy/pkg/config"
	"go-reauth-proxy/pkg/grpc/pb"
	"go-reauth-proxy/pkg/models"
	"go-reauth-proxy/pkg/response"
)

// syscall.WSAECONNRESET is only declared on Windows. Keep its stable Winsock
// value here so this cross-platform test can recognize a reset on every OS.
const windowsConnectionReset syscall.Errno = 10054

func isConnectionResetError(err error) bool {
	return errors.Is(err, syscall.ECONNRESET) || errors.Is(err, windowsConnectionReset)
}

func TestConnectionResetErrorRecognizesWinsockReset(t *testing.T) {
	if !isConnectionResetError(windowsConnectionReset) {
		t.Fatal("Winsock WSAECONNRESET was not recognized as a connection reset")
	}
}

func TestGatewayUnmatchedRouteConfigPersistsRestartsAndResets(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.json")
	manager := config.NewManager(configPath)
	initial, err := manager.Load()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	handler := NewHandler(7996, 7999, manager, initial, filepath.Join(t.TempDir(), "logs"), nil)
	t.Cleanup(handler.gatewayLogManager.Close)

	if _, err := handler.SetGatewayUnmatchedRouteConfig(models.GatewayUnmatchedRouteConfig{
		Behavior: models.GatewayUnmatchedRouteBehaviorResetConnection,
	}); err != nil {
		t.Fatalf("set unmatched route: %v", err)
	}
	reloaded, err := manager.Load()
	if err != nil {
		t.Fatalf("reload config: %v", err)
	}
	restarted := NewHandler(7996, 7999, manager, reloaded, filepath.Join(t.TempDir(), "restart-logs"), nil)
	t.Cleanup(restarted.gatewayLogManager.Close)
	if got := restarted.GetGatewayUnmatchedRouteConfig().Behavior; got != models.GatewayUnmatchedRouteBehaviorResetConnection {
		t.Fatalf("restarted behavior = %q, want reset_connection", got)
	}
	if got := restarted.GetGatewayUnmatchedRouteConfig().UpstreamErrorDetail; got != models.GatewayUpstreamErrorDetailLess {
		t.Fatalf("restarted upstream error detail = %q, want less", got)
	}

	if err := restarted.ResetAllData(config.DefaultConfig()); err != nil {
		t.Fatalf("ResetAllData: %v", err)
	}
	if got := restarted.GetGatewayUnmatchedRouteConfig().Behavior; got != models.GatewayUnmatchedRouteBehaviorErrorPage {
		t.Fatalf("reset behavior = %q, want error_page", got)
	}
	if got := restarted.GetGatewayUnmatchedRouteConfig().UpstreamErrorDetail; got != models.GatewayUpstreamErrorDetailLess {
		t.Fatalf("reset upstream error detail = %q, want less", got)
	}
}

func TestGatewayUnmatchedRouteConfigRollsBackOnSaveFailure(t *testing.T) {
	tempDir := t.TempDir()
	initial := config.DefaultConfig()
	blocker := filepath.Join(tempDir, "not-a-directory")
	if err := os.WriteFile(blocker, []byte("block"), 0o644); err != nil {
		t.Fatalf("write blocker: %v", err)
	}
	manager := config.NewManager(filepath.Join(blocker, "config.json"))
	handler := NewHandler(7996, 7999, manager, initial, filepath.Join(tempDir, "logs"), nil)
	t.Cleanup(handler.gatewayLogManager.Close)

	if _, err := handler.SetGatewayUnmatchedRouteConfig(models.GatewayUnmatchedRouteConfig{
		Behavior: models.GatewayUnmatchedRouteBehaviorResetConnection,
	}); err == nil {
		t.Fatal("SetGatewayUnmatchedRouteConfig returned nil error")
	}
	if got := handler.GetGatewayUnmatchedRouteConfig().Behavior; got != models.GatewayUnmatchedRouteBehaviorErrorPage {
		t.Fatalf("runtime behavior after save failure = %q, want error_page", got)
	}
	if got := handler.snapshotForRequest().unmatchedRoute.Behavior; got != models.GatewayUnmatchedRouteBehaviorErrorPage {
		t.Fatalf("snapshot behavior after save failure = %q, want error_page", got)
	}
}

func TestResetConnectionDisablesAndRestoresDefaultHostRedirect(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "default-host-ok")
	}))
	defer upstream.Close()

	cfg := config.DefaultConfig()
	cfg.HostRules = []models.HostRule{{
		Host:      "app.example.com",
		Target:    upstream.URL,
		IsDefault: true,
	}}
	cfg.UnmatchedRoute.Behavior = models.GatewayUnmatchedRouteBehaviorResetConnection
	handler := NewHandler(7996, 7999, nil, cfg, filepath.Join(t.TempDir(), "logs"), nil)
	t.Cleanup(handler.gatewayLogManager.Close)

	blocked := httptest.NewRequest(http.MethodGet, "http://unknown.example.com/private", nil)
	blockedRec := newHijackableResponseRecorder()
	defer blockedRec.Close()
	handler.ServeHTTP(blockedRec, blocked)
	if blockedRec.client == nil {
		t.Fatal("unmatched request was not aborted")
	}
	if rules := handler.GetHostRules(); len(rules) != 1 || !rules[0].IsDefault {
		t.Fatalf("default host configuration was changed: %#v", rules)
	}
	defaultHostRequest := httptest.NewRequest(http.MethodGet, "http://app.example.com/private", nil)
	defaultHostResponse := httptest.NewRecorder()
	handler.ServeHTTP(defaultHostResponse, defaultHostRequest)
	if defaultHostResponse.Code != http.StatusOK || defaultHostResponse.Body.String() != "default-host-ok" {
		t.Fatalf("default host response = %d %q", defaultHostResponse.Code, defaultHostResponse.Body.String())
	}

	if _, err := handler.SetGatewayUnmatchedRouteConfig(models.GatewayUnmatchedRouteConfig{
		Behavior: models.GatewayUnmatchedRouteBehaviorErrorPage,
	}); err != nil {
		t.Fatalf("restore error_page behavior: %v", err)
	}
	restored := httptest.NewRequest(http.MethodGet, "http://unknown.example.com/private", nil)
	restoredRec := httptest.NewRecorder()
	handler.ServeHTTP(restoredRec, restored)
	if restoredRec.Code != http.StatusFound {
		t.Fatalf("restored redirect status = %d, want 302", restoredRec.Code)
	}
	if got := restoredRec.Header().Get("Location"); got != "http://app.example.com/private" {
		t.Fatalf("restored redirect location = %q", got)
	}
}

func TestResetConnectionPreservesDefaultPathRule(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "default-route-ok")
	}))
	defer upstream.Close()

	cfg := config.DefaultConfig()
	cfg.Rules = []models.Rule{{Path: "/fallback", Target: upstream.URL, UseAuth: false}}
	cfg.DefaultRoute = "/fallback"
	cfg.UnmatchedRoute.Behavior = models.GatewayUnmatchedRouteBehaviorResetConnection
	handler := NewHandler(7996, 7999, nil, cfg, filepath.Join(t.TempDir(), "logs"), nil)
	t.Cleanup(handler.gatewayLogManager.Close)

	req := httptest.NewRequest(http.MethodGet, "http://unknown.example.com/no-explicit-match", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "default-route-ok" {
		t.Fatalf("default path response = %d %q", rec.Code, rec.Body.String())
	}
}

func TestResetConnectionPreservesExplicitAndBuiltInRoutes(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.Host+" "+r.URL.Path)
	}))
	defer upstream.Close()

	cfg := config.DefaultConfig()
	cfg.AuthConfig.AuthURL = ""
	cfg.AuthConfig.AuthPort = 0
	cfg.Rules = []models.Rule{{Path: "/app/", Target: upstream.URL, UseAuth: false}}
	cfg.HostRules = []models.HostRule{{Host: "host.example.com", Target: upstream.URL}}
	cfg.CrawlerBlocker.Enabled = true
	cfg.UnmatchedRoute.Behavior = models.GatewayUnmatchedRouteBehaviorResetConnection
	handler := NewHandler(7996, 7999, nil, cfg, filepath.Join(t.TempDir(), "logs"), nil)
	t.Cleanup(handler.gatewayLogManager.Close)

	tests := []struct {
		name       string
		target     string
		wantStatus int
	}{
		{name: "host rule", target: "http://host.example.com/private", wantStatus: http.StatusOK},
		{name: "path rule", target: "http://unknown.example.com/app/private", wantStatus: http.StatusOK},
		{name: "slash redirect", target: "http://unknown.example.com/app", wantStatus: http.StatusMovedPermanently},
		{name: "favicon", target: "http://unknown.example.com/__assets__/favicon/favicon-16x16.png", wantStatus: http.StatusOK},
		{name: "toolbar asset", target: "http://unknown.example.com" + response.ToolbarAssetPath(), wantStatus: http.StatusOK},
		{name: "select page requires auth", target: "http://unknown.example.com/__select__", wantStatus: http.StatusInternalServerError},
		{name: "auth entry", target: "http://unknown.example.com/__auth__/status", wantStatus: http.StatusInternalServerError},
		{name: "crawler robots", target: "http://unknown.example.com/robots.txt", wantStatus: http.StatusOK},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.target, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body=%q", rec.Code, tc.wantStatus, rec.Body.String())
			}
		})
	}
}

func TestRouteNotFoundNavigationRequiresAuthenticatedIdentity(t *testing.T) {
	tests := []struct {
		name           string
		cookie         *http.Cookie
		wantNavigation bool
		wantVerifyHits int
	}{
		{name: "anonymous"},
		{
			name: "temporary grant is not a login",
			cookie: &http.Cookie{
				Name:  advancedAuthGrantCookieName,
				Value: "temporary-grant",
			},
		},
		{
			name: "authenticated session",
			cookie: &http.Cookie{
				Name:  authSessionCookieName,
				Value: "ok",
			},
			wantNavigation: true,
			wantVerifyHits: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			verifyHits := 0
			handler := &Handler{
				Rules: []models.Rule{{
					Path:   "/private-app",
					Target: "http://127.0.0.1:8080",
				}},
				AuthConfig: models.AuthConfig{
					AuthURL:      "/api/auth/verify",
					PreflightURL: "/api/auth/preflight",
				},
				authBridge: testAuthBridge{
					verify: func(context.Context, *pb.VerifyAuthRequest) (*pb.VerifyAuthResponse, error) {
						verifyHits++
						return &pb.VerifyAuthResponse{Success: true, Status: http.StatusOK}, nil
					},
				},
				authCache:      newAuthStateCache(),
				preflightCache: newPreflightStateCache(),
			}
			handler.publishRequestSnapshotLocked()

			req := httptest.NewRequest(http.MethodGet, "http://gateway.example.com/missing", nil)
			if test.cookie != nil {
				req.AddCookie(test.cookie)
			}
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusNotFound {
				t.Fatalf("status = %d, want 404; body = %s", rec.Code, rec.Body.String())
			}
			if verifyHits != test.wantVerifyHits {
				t.Fatalf("verify hits = %d, want %d", verifyHits, test.wantVerifyHits)
			}
			if cacheControl := rec.Header().Get("Cache-Control"); !strings.Contains(cacheControl, "no-store") {
				t.Fatalf("Cache-Control = %q, want no-store", cacheControl)
			}

			body := rec.Body.String()
			hasNavigation := strings.Contains(body, "/__select__") ||
				strings.Contains(body, "/private-app") ||
				strings.Contains(body, "reauth-proxy-toolbar")
			if hasNavigation != test.wantNavigation {
				t.Fatalf("protected navigation presence = %v, want %v; body = %s", hasNavigation, test.wantNavigation, body)
			}
		})
	}
}

func TestResetConnectionWritesLoopbackRequestLog(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Logging = models.LoggingConfig{Enabled: true, MaxDays: 1}
	cfg.UnmatchedRoute.Behavior = models.GatewayUnmatchedRouteBehaviorResetConnection
	handler := NewHandler(7996, 7999, nil, cfg, filepath.Join(t.TempDir(), "logs"), nil)
	t.Cleanup(handler.gatewayLogManager.Close)

	req := httptest.NewRequest(http.MethodGet, "http://MiXeD.Example.COM:7999/private", nil)
	req.RemoteAddr = "127.0.0.1:4567"
	rec := newHijackableResponseRecorder()
	defer rec.Close()
	handler.ServeHTTP(rec, req)

	result, err := handler.QueryLogEntries("", 1, 20, "unmatched_route_blocked", "", "", "", "", "page")
	if err != nil {
		t.Fatalf("QueryLogEntries: %v", err)
	}
	if len(result.Items) != 1 {
		t.Fatalf("logged items = %d, want 1", len(result.Items))
	}
	entry := result.Items[0]
	if entry.Status != 499 || entry.RouteType != "unmatched_route_blocked" ||
		entry.AuthDecision != "connection_reset" || entry.Matched ||
		entry.RouteKey != "mixed.example.com" {
		t.Fatalf("unexpected unmatched-route log: %#v", entry)
	}
}

func TestResetConnectionHTTP1ClosesWithoutHTTPResponse(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.UnmatchedRoute.Behavior = models.GatewayUnmatchedRouteBehaviorResetConnection
	handler := NewHandler(7996, 7999, nil, cfg, filepath.Join(t.TempDir(), "logs"), nil)
	t.Cleanup(handler.gatewayLogManager.Close)
	server := httptest.NewServer(handler)
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}
	conn, err := net.DialTimeout("tcp", serverURL.Host, 2*time.Second)
	if err != nil {
		t.Fatalf("dial test server: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.WriteString(conn, "GET /private HTTP/1.1\r\nHost: unknown.example.com\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatalf("write request: %v", err)
	}
	data, readErr := bufio.NewReader(conn).ReadBytes('\n')
	if len(data) != 0 {
		t.Fatalf("received an HTTP response before reset: %q", data)
	}
	if !isConnectionResetError(readErr) {
		t.Fatalf("read error = %v, want connection reset", readErr)
	}
}

func TestUnwrapTCPConnHandlesProductionWrappers(t *testing.T) {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("listen TCP: %v", err)
	}
	defer listener.Close()

	accepted := make(chan *net.TCPConn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.AcceptTCP()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()

	client, err := net.DialTCP("tcp", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatalf("dial TCP: %v", err)
	}
	defer client.Close()

	var serverTCP *net.TCPConn
	select {
	case serverTCP = <-accepted:
	case err := <-acceptErr:
		t.Fatalf("accept TCP: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out accepting TCP connection")
	}
	defer serverTCP.Close()

	proxyConn := proxyproto.NewConn(serverTCP)
	muxConn := &cmux.MuxConn{Conn: proxyConn}
	tlsConn := tls.Server(muxConn, &tls.Config{})
	if got := unwrapTCPConn(tlsConn); got != serverTCP {
		t.Fatalf("unwrapped TCP connection = %p, want %p", got, serverTCP)
	}
}

func TestResetConnectionHTTP2AbortsOnlyCurrentStream(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.UnmatchedRoute.Behavior = models.GatewayUnmatchedRouteBehaviorResetConnection
	handler := NewHandler(7996, 7999, nil, cfg, filepath.Join(t.TempDir(), "logs"), nil)
	t.Cleanup(handler.gatewayLogManager.Close)

	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	client := server.Client()

	blocked, err := http.NewRequest(http.MethodGet, server.URL+"/private", nil)
	if err != nil {
		t.Fatalf("build blocked request: %v", err)
	}
	blocked.Host = "unknown.example.com"
	if response, err := client.Do(blocked); err == nil {
		response.Body.Close()
		t.Fatal("HTTP/2 unmatched stream unexpectedly returned a response")
	}

	var gotConnInfo httptrace.GotConnInfo
	matched, err := http.NewRequest(http.MethodGet, server.URL+"/__assets__/favicon/favicon-16x16.png", nil)
	if err != nil {
		t.Fatalf("build matched request: %v", err)
	}
	matched = matched.WithContext(httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			gotConnInfo = info
		},
	}))
	response, err := client.Do(matched)
	if err != nil {
		t.Fatalf("matched HTTP/2 stream failed after reset: %v", err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, response.Body)
	if response.ProtoMajor != 2 {
		t.Fatalf("matched request protocol = %s, want HTTP/2", response.Proto)
	}
	if !gotConnInfo.Reused {
		t.Fatal("HTTP/2 connection was not reused after resetting one stream")
	}
}

func TestResetConnectionHTTP2FallbackPanicsWithAbortHandler(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.UnmatchedRoute.Behavior = models.GatewayUnmatchedRouteBehaviorResetConnection
	handler := NewHandler(7996, 7999, nil, cfg, filepath.Join(t.TempDir(), "logs"), nil)
	t.Cleanup(handler.gatewayLogManager.Close)
	req := httptest.NewRequest(http.MethodGet, "https://unknown.example.com/private", nil)
	req.ProtoMajor = 2
	req.ProtoMinor = 0
	req.Proto = "HTTP/2.0"

	defer func() {
		if recovered := recover(); recovered != http.ErrAbortHandler {
			t.Fatalf("panic = %#v, want http.ErrAbortHandler", recovered)
		}
	}()
	handler.ServeHTTP(httptest.NewRecorder(), req)
}

func TestGatewayUnmatchedRouteErrorPageRemainsDefault(t *testing.T) {
	cfg := config.DefaultConfig()
	handler := NewHandler(7996, 7999, nil, cfg, filepath.Join(t.TempDir(), "logs"), nil)
	t.Cleanup(handler.gatewayLogManager.Close)
	if got := handler.GetGatewayUnmatchedRouteConfig().Behavior; got != models.GatewayUnmatchedRouteBehaviorErrorPage {
		t.Fatalf("default behavior = %q, want error_page", got)
	}

	req := httptest.NewRequest(http.MethodGet, "http://unknown.example.com/", strings.NewReader(""))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code == 0 {
		t.Fatal("legacy unmatched route did not return an HTTP response")
	}
}

func TestUpstreamUnavailableMessageHidesDetailsByDefault(t *testing.T) {
	err := errors.New("dial tcp 127.0.0.1:16601: connect: connection refused")
	if got := upstreamUnavailableMessage(models.GatewayUnmatchedRouteConfig{}, err); got != "Upstream unavailable" {
		t.Fatalf("message = %q, want redacted message", got)
	}
}

func TestUpstreamUnavailableMessageCanShowMoreForTroubleshooting(t *testing.T) {
	err := errors.New("dial tcp 127.0.0.1:16601: connect: connection refused")
	cfg := models.GatewayUnmatchedRouteConfig{
		UpstreamErrorDetail: models.GatewayUpstreamErrorDetailMore,
	}
	got := upstreamUnavailableMessage(cfg, err)
	if !strings.Contains(got, "127.0.0.1:16601") || !strings.Contains(got, "connection refused") {
		t.Fatalf("message = %q, want detailed upstream error", got)
	}
}

func TestUpstreamUnavailableCanResetConnection(t *testing.T) {
	handler := &Handler{}
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/", nil)
	req.ProtoMajor = 2
	req.ProtoMinor = 0
	req.Proto = "HTTP/2.0"
	cfg := models.GatewayUnmatchedRouteConfig{
		UpstreamErrorDetail: models.GatewayUpstreamErrorDetailResetConnection,
	}

	defer func() {
		if recovered := recover(); recovered != http.ErrAbortHandler {
			t.Fatalf("panic = %#v, want http.ErrAbortHandler", recovered)
		}
	}()
	handler.handleUpstreamUnavailable(
		httptest.NewRecorder(),
		req,
		cfg,
		nil,
		false,
		errors.New("dial tcp: connection refused"),
	)
}

func TestUpstreamUnavailableResetRecords499BeforeClosing(t *testing.T) {
	handler := &Handler{}
	recorder := newHijackableResponseRecorder()
	defer recorder.Close()
	trafficWriter := &trafficResponseWriter{
		ResponseWriter: recorder,
		handler:        handler,
	}
	trafficWriter.metrics.statusCode = http.StatusOK
	writer := newProxyResponseCoalescer(trafficWriter)
	cfg := models.GatewayUnmatchedRouteConfig{
		UpstreamErrorDetail: models.GatewayUpstreamErrorDetailResetConnection,
	}

	handler.handleUpstreamUnavailable(
		writer,
		httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil),
		cfg,
		nil,
		false,
		errors.New("dial tcp: connection refused"),
	)

	if trafficWriter.metrics.statusCode != 499 {
		t.Fatalf("status = %d, want 499", trafficWriter.metrics.statusCode)
	}
}

func TestUpstreamUnavailableResetWrites499AccessLog(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	target := upstream.URL
	upstream.Close()

	cfg := config.DefaultConfig()
	cfg.Logging = models.LoggingConfig{
		Enabled:         true,
		RecordLocalhost: true,
		MaxDays:         1,
	}
	cfg.HostRules = []models.HostRule{{
		Host:   "app.example.com",
		Target: target,
	}}
	cfg.UnmatchedRoute.UpstreamErrorDetail =
		models.GatewayUpstreamErrorDetailResetConnection
	handler := NewHandler(7996, 7999, nil, cfg, filepath.Join(t.TempDir(), "logs"), nil)
	t.Cleanup(handler.gatewayLogManager.Close)

	req := httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil)
	req.RemoteAddr = "127.0.0.1:4567"
	recorder := newHijackableResponseRecorder()
	defer recorder.Close()
	handler.ServeHTTP(recorder, req)

	result, err := handler.QueryLogEntries("", 1, 20, "host_rule", "", "", "", "", "page")
	if err != nil {
		t.Fatalf("QueryLogEntries: %v", err)
	}
	if len(result.Items) != 1 {
		t.Fatalf("logged items = %d, want 1", len(result.Items))
	}
	if entry := result.Items[0]; entry.Status != 499 || entry.RouteType != "host_rule" {
		t.Fatalf("unexpected upstream reset log: %#v", entry)
	}
}

func TestUpstreamUnavailableResetCoversEveryReverseProxyRoute(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	target := upstream.URL
	upstream.Close()

	tests := []struct {
		name  string
		rules []models.Rule
		hosts []models.HostRule
		url   string
		host  string
	}{
		{
			name: "path rule",
			rules: []models.Rule{{
				Path:   "/app",
				Target: target,
			}},
			url:  "https://gateway.example.com/app/resource",
			host: "gateway.example.com",
		},
		{
			name: "host rule",
			hosts: []models.HostRule{{
				Host:   "app.example.com",
				Target: target,
			}},
			url:  "https://app.example.com/",
			host: "app.example.com",
		},
		{
			name: "host location",
			hosts: []models.HostRule{{
				Host:   "app.example.com",
				Target: "http://127.0.0.1:1",
				Locations: []models.HostLocation{{
					Path:   "/api",
					Match:  models.HostLocationMatchPrefix,
					Action: models.HostLocationActionProxy,
					Target: target,
				}},
			}},
			url:  "https://app.example.com/api/resource",
			host: "app.example.com",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.DefaultConfig()
			cfg.Rules = tc.rules
			cfg.HostRules = tc.hosts
			cfg.UnmatchedRoute.UpstreamErrorDetail =
				models.GatewayUpstreamErrorDetailResetConnection
			handler := NewHandler(
				7996,
				7999,
				nil,
				cfg,
				filepath.Join(t.TempDir(), "logs"),
				nil,
			)
			t.Cleanup(handler.gatewayLogManager.Close)
			req := httptest.NewRequest(http.MethodGet, tc.url, nil)
			req.Host = tc.host
			req.ProtoMajor = 2
			req.ProtoMinor = 0
			req.Proto = "HTTP/2.0"

			defer func() {
				if recovered := recover(); recovered != http.ErrAbortHandler {
					t.Fatalf("panic = %#v, want http.ErrAbortHandler", recovered)
				}
			}()
			handler.ServeHTTP(httptest.NewRecorder(), req)
		})
	}
}
