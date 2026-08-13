package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"go-reauth-proxy/pkg/config"
	"go-reauth-proxy/pkg/gatewaylog"
	"go-reauth-proxy/pkg/grpc/pb"
	"go-reauth-proxy/pkg/models"
	proxywaf "go-reauth-proxy/pkg/waf"
)

const (
	handlerBenchmarkAuthOff  = "AuthOff"
	handlerBenchmarkAuthMiss = "CombinedMiss"
	handlerBenchmarkAuthHit  = "CombinedCacheHit"
)

var (
	handlerBenchmarkStatusSink int
	handlerBenchmarkBytesSink  int
)

type handlerEndToEndBenchmarkScenario struct {
	name          string
	routeKind     string
	authMode      string
	portalEnabled bool
	logging       bool
	responseBytes int
	htmlResponse  bool
	unknownLength bool
	wafEnabled    bool
}

type handlerEndToEndBenchmarkFixture struct {
	handler      *Handler
	target       *httptest.Server
	logManager   *gatewaylog.Manager
	authorizeRPC *atomic.Int64
	connections  *atomic.Int64
	requestURL   string
	authCookie   bool
}

type handlerBenchmarkResponseWriter struct {
	header http.Header
	status int
	bytes  int
}

func newHandlerBenchmarkResponseWriter() *handlerBenchmarkResponseWriter {
	return &handlerBenchmarkResponseWriter{header: make(http.Header)}
}

func (w *handlerBenchmarkResponseWriter) Header() http.Header { return w.header }

func (w *handlerBenchmarkResponseWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}

func (w *handlerBenchmarkResponseWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	w.bytes += len(p)
	return len(p), nil
}

func (w *handlerBenchmarkResponseWriter) Flush() {}

type handlerBenchmarkRoundTripper struct {
	payload       []byte
	contentType   string
	unknownLength bool
}

func (rt handlerBenchmarkRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	var reader io.Reader = bytes.NewReader(rt.payload)
	contentLength := int64(len(rt.payload))
	header := http.Header{"Content-Type": []string{rt.contentType}}
	if rt.unknownLength {
		reader = &coalescingTestChunkReader{reader: bytes.NewReader(rt.payload), size: 8 << 10}
		contentLength = -1
	} else {
		header.Set("Content-Length", strconv.Itoa(len(rt.payload)))
	}
	return &http.Response{
		StatusCode:    http.StatusOK,
		Header:        header,
		Body:          io.NopCloser(reader),
		ContentLength: contentLength,
		Request:       request,
	}, nil
}

func BenchmarkHandlerEndToEnd(b *testing.B) {
	scenarios := []handlerEndToEndBenchmarkScenario{
		{
			name:          "Path/AuthOff/PortalOff/LoggingOff/1KiB",
			routeKind:     "path",
			authMode:      handlerBenchmarkAuthOff,
			responseBytes: 1 << 10,
		},
		{
			name:          "Host/AuthOff/PortalOff/LoggingOff/1KiB",
			routeKind:     "host",
			authMode:      handlerBenchmarkAuthOff,
			responseBytes: 1 << 10,
		},
		{
			name:          "Path/CombinedMiss/PortalOff/LoggingOff/1KiB",
			routeKind:     "path",
			authMode:      handlerBenchmarkAuthMiss,
			responseBytes: 1 << 10,
		},
		{
			name:          "Host/CombinedCacheHit/PortalOff/LoggingOff/1KiB",
			routeKind:     "host",
			authMode:      handlerBenchmarkAuthHit,
			responseBytes: 1 << 10,
		},
		{
			name:          "Host/CombinedCacheHit/PortalOn/LoggingOff/64KiB",
			routeKind:     "host",
			authMode:      handlerBenchmarkAuthHit,
			portalEnabled: true,
			responseBytes: 64 << 10,
			htmlResponse:  true,
		},
		{
			name:          "Path/AuthOff/PortalOff/LoggingOn/1KiB",
			routeKind:     "path",
			authMode:      handlerBenchmarkAuthOff,
			logging:       true,
			responseBytes: 1 << 10,
		},
		{
			name:          "Path/AuthOff/PortalOff/LoggingOff/64KiB",
			routeKind:     "path",
			authMode:      handlerBenchmarkAuthOff,
			responseBytes: 64 << 10,
		},
		{
			name:          "Path/AuthOff/PortalOff/LoggingOff/2MiB",
			routeKind:     "path",
			authMode:      handlerBenchmarkAuthOff,
			responseBytes: 2 << 20,
		},
		{
			name:          "Path/AuthOff/PortalOff/LoggingOff/WAFEnabled/1KiB",
			routeKind:     "path",
			authMode:      handlerBenchmarkAuthOff,
			responseBytes: 1 << 10,
			wafEnabled:    true,
		},
	}

	for _, scenario := range scenarios {
		b.Run(scenario.name, func(b *testing.B) {
			benchmarkHandlerEndToEndScenario(b, scenario, false)
		})
	}
}

func BenchmarkHandlerEndToEndParallelAuthOff1KiB(b *testing.B) {
	benchmarkHandlerEndToEndScenario(b, handlerEndToEndBenchmarkScenario{
		name:          "Path/AuthOff/PortalOff/LoggingOff/1KiB",
		routeKind:     "path",
		authMode:      handlerBenchmarkAuthOff,
		responseBytes: 1 << 10,
	}, true)
}

func BenchmarkHandlerEndToEndParallelCombinedCacheHit1KiB(b *testing.B) {
	benchmarkHandlerEndToEndScenario(b, handlerEndToEndBenchmarkScenario{
		name:          "Host/CombinedCacheHit/PortalOff/LoggingOff/1KiB",
		routeKind:     "host",
		authMode:      handlerBenchmarkAuthHit,
		responseBytes: 1 << 10,
	}, true)
}

func BenchmarkHandlerEndToEndParallelAuthOff2MiB(b *testing.B) {
	benchmarkHandlerEndToEndScenario(b, handlerEndToEndBenchmarkScenario{
		name:          "Path/AuthOff/PortalOff/LoggingOff/2MiB",
		routeKind:     "path",
		authMode:      handlerBenchmarkAuthOff,
		responseBytes: 2 << 20,
	}, true)
}

func BenchmarkHandlerEndToEndParallelUnknownLength2MiB(b *testing.B) {
	benchmarkHandlerEndToEndScenario(b, handlerEndToEndBenchmarkScenario{
		name:          "Path/AuthOff/PortalOff/LoggingOff/UnknownLength/2MiB",
		routeKind:     "path",
		authMode:      handlerBenchmarkAuthOff,
		responseBytes: 2 << 20,
		unknownLength: true,
	}, true)
}

func BenchmarkHandlerIsolated(b *testing.B) {
	scenarios := []handlerEndToEndBenchmarkScenario{
		{name: "Path/AuthOff/1KiB", routeKind: "path", authMode: handlerBenchmarkAuthOff, responseBytes: 1 << 10},
		{name: "Host/CombinedCacheHit/1KiB", routeKind: "host", authMode: handlerBenchmarkAuthHit, responseBytes: 1 << 10},
		{name: "Path/AuthOff/WAFEnabled/1KiB", routeKind: "path", authMode: handlerBenchmarkAuthOff, responseBytes: 1 << 10, wafEnabled: true},
		{name: "Path/AuthOff/KnownLength/2MiB", routeKind: "path", authMode: handlerBenchmarkAuthOff, responseBytes: 2 << 20},
		{name: "Path/AuthOff/UnknownLength/2MiB", routeKind: "path", authMode: handlerBenchmarkAuthOff, responseBytes: 2 << 20, unknownLength: true},
	}
	for _, scenario := range scenarios {
		b.Run(scenario.name, func(b *testing.B) {
			benchmarkHandlerScenario(b, scenario, false, true)
		})
	}
}

func benchmarkHandlerEndToEndScenario(b *testing.B, scenario handlerEndToEndBenchmarkScenario, parallel bool) {
	benchmarkHandlerScenario(b, scenario, parallel, false)
}

func benchmarkHandlerScenario(b *testing.B, scenario handlerEndToEndBenchmarkScenario, parallel bool, isolated bool) {
	b.StopTimer()
	fixture := newHandlerEndToEndBenchmarkFixture(b, scenario, isolated)
	defer func() {
		b.StopTimer()
		fixture.logManager.Flush()
		fixture.handler.proxyTransport.CloseIdleConnections()
		fixture.handler.Close()
		if fixture.target != nil {
			fixture.target.Close()
		}
	}()

	warmRecorder := httptest.NewRecorder()
	fixture.handler.ServeHTTP(warmRecorder, fixture.newRequest())
	if warmRecorder.Code != http.StatusOK {
		b.Fatalf("warm-up status = %d; body=%s", warmRecorder.Code, warmRecorder.Body.String())
	}
	if scenario.portalEnabled && !bytes.Contains(warmRecorder.Body.Bytes(), []byte("reauth-proxy-toolbar-loader")) {
		b.Fatal("portal-enabled warm-up response did not include the toolbar loader")
	}
	reuseRecorder := httptest.NewRecorder()
	fixture.handler.ServeHTTP(reuseRecorder, fixture.newRequest())
	if reuseRecorder.Code != http.StatusOK {
		b.Fatalf("connection-reuse probe status = %d; body=%s", reuseRecorder.Code, reuseRecorder.Body.String())
	}
	if !isolated && fixture.connections.Load() != 1 {
		connections := fixture.connections.Load()
		b.Fatalf("warm-up opened %d upstream connections, want one reused connection", connections)
	}
	authorizeCallsBefore := fixture.authorizeRPC.Load()

	b.SetBytes(int64(scenario.responseBytes))
	b.ReportAllocs()
	b.ResetTimer()
	b.StartTimer()
	if parallel {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				writer := newHandlerBenchmarkResponseWriter()
				fixture.handler.ServeHTTP(writer, fixture.newRequest())
				if writer.status != http.StatusOK {
					b.Errorf("status = %d, want 200", writer.status)
					continue
				}
			}
		})
	} else {
		for b.Loop() {
			writer := newHandlerBenchmarkResponseWriter()
			fixture.handler.ServeHTTP(writer, fixture.newRequest())
			if writer.status != http.StatusOK {
				b.Fatalf("status = %d, want 200", writer.status)
			}
			handlerBenchmarkStatusSink = writer.status
			handlerBenchmarkBytesSink = writer.bytes
		}
	}
	b.StopTimer()

	authorizeCallsAfter := fixture.authorizeRPC.Load()
	switch scenario.authMode {
	case handlerBenchmarkAuthHit:
		if authorizeCallsBefore != 1 || authorizeCallsAfter != authorizeCallsBefore {
			b.Fatalf("cached auth RPC calls before=%d after=%d, want one warm-up call only", authorizeCallsBefore, authorizeCallsAfter)
		}
	case handlerBenchmarkAuthMiss:
		if authorizeCallsAfter <= authorizeCallsBefore {
			b.Fatalf("auth miss RPC calls before=%d after=%d, want timed misses", authorizeCallsBefore, authorizeCallsAfter)
		}
	case handlerBenchmarkAuthOff:
		if authorizeCallsAfter != 0 {
			b.Fatalf("auth-off RPC calls = %d, want 0", authorizeCallsAfter)
		}
	}
	fixture.logManager.Flush()
	if dropped := fixture.logManager.DroppedLogEntries(); dropped != 0 {
		b.Fatalf("dropped log entries = %d", dropped)
	}
}

func newHandlerEndToEndBenchmarkFixture(b *testing.B, scenario handlerEndToEndBenchmarkScenario, isolated bool) *handlerEndToEndBenchmarkFixture {
	b.Helper()
	payload := handlerBenchmarkResponseBody(scenario.responseBytes, scenario.htmlResponse)
	contentLength := strconv.Itoa(len(payload))
	contentType := "text/plain; charset=utf-8"
	if scenario.unknownLength {
		contentType = "application/octet-stream"
	} else if scenario.htmlResponse {
		contentType = "text/html; charset=utf-8"
	}
	connections := new(atomic.Int64)
	var target *httptest.Server
	targetURL := "http://benchmark-upstream.invalid"
	if !isolated {
		target = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", contentType)
			if !scenario.unknownLength {
				w.Header().Set("Content-Length", contentLength)
				_, _ = w.Write(payload)
				return
			}
			for remaining := payload; len(remaining) > 0; {
				chunkSize := min(len(remaining), 8<<10)
				_, _ = w.Write(remaining[:chunkSize])
				remaining = remaining[chunkSize:]
				if flusher, ok := w.(http.Flusher); ok {
					flusher.Flush()
				}
			}
		}))
		target.Config.ConnState = func(_ net.Conn, state http.ConnState) {
			if state == http.StateNew {
				connections.Add(1)
			}
		}
		target.Start()
		targetURL = target.URL
	}

	loggingConfig := models.LoggingConfig{Enabled: scenario.logging}
	fixture := &handlerEndToEndBenchmarkFixture{
		target:       target,
		authorizeRPC: new(atomic.Int64),
		connections:  connections,
	}
	initialConfig := config.DefaultConfig()
	initialConfig.Logging = loggingConfig
	initialConfig.Portal = benchmarkGatewayPortalConfig(b, scenario.portalEnabled)
	initialConfig.ReverseProxyThrottle.Enabled = false

	if scenario.routeKind == "host" {
		initialConfig.HostRules = []models.HostRule{{
			Host:       "bench.example.test",
			Target:     targetURL,
			UseAuth:    scenario.authMode != handlerBenchmarkAuthOff,
			AccessMode: "login_first",
		}}
		fixture.requestURL = "http://bench.example.test/benchmark"
	} else {
		initialConfig.Rules = []models.Rule{{
			Path:    "/benchmark",
			Target:  targetURL,
			UseAuth: scenario.authMode != handlerBenchmarkAuthOff,
		}}
		fixture.requestURL = "http://gateway.example.test/benchmark/resource"
	}

	if scenario.authMode != handlerBenchmarkAuthOff {
		fixture.authCookie = true
		cacheTTL := 0
		if scenario.authMode == handlerBenchmarkAuthHit {
			cacheTTL = 3600
		}
		initialConfig.AuthConfig.AuthCacheTTL = cacheTTL
	}

	if scenario.wafEnabled {
		initialConfig.WAF = models.WAFConfig{Enabled: true, Mode: proxywaf.ModeBlocking}
	}

	runtimeDir := b.TempDir()
	manager := config.NewManager(filepath.Join(runtimeDir, "config.json"))
	handler := NewHandler(7996, 7999, manager, initialConfig, filepath.Join(runtimeDir, "logs"), nil)
	fixture.handler = handler
	fixture.logManager = handler.gatewayLogManager
	if isolated {
		handler.proxyRoundTripper = handlerBenchmarkRoundTripper{
			payload:       payload,
			contentType:   contentType,
			unknownLength: scenario.unknownLength,
		}
	}

	if scenario.authMode != handlerBenchmarkAuthOff {
		preflightScope := pb.AuthCacheScope_AUTH_CACHE_SCOPE_NONE
		verifyScope := pb.AuthCacheScope_AUTH_CACHE_SCOPE_NONE
		if scenario.authMode == handlerBenchmarkAuthHit {
			preflightScope = pb.AuthCacheScope_AUTH_CACHE_SCOPE_EXACT_REQUEST
			verifyScope = pb.AuthCacheScope_AUTH_CACHE_SCOPE_HOST
		}
		handler.authBridge = testAuthBridge{
			supports: true,
			authorize: func(_ context.Context, request *pb.AuthorizeHttpRequest) (*pb.AuthorizeHttpResponse, error) {
				fixture.authorizeRPC.Add(1)
				return handlerBenchmarkCombinedAuthResponse(request.GetMode(), preflightScope, verifyScope), nil
			},
		}
	}

	if scenario.wafEnabled {
		if status := handler.wafRuntime.Status(); !status.Loaded {
			handler.Close()
			if target != nil {
				target.Close()
			}
			b.Fatal("benchmark WAF runtime was not loaded")
		}
		// Reload schedules a memory release after 500ms. Keep that maintenance
		// work outside the measured WAF request loop.
		time.Sleep(600 * time.Millisecond)
	}

	return fixture
}

func (f *handlerEndToEndBenchmarkFixture) newRequest() *http.Request {
	request := httptest.NewRequest(http.MethodGet, f.requestURL, nil)
	if f.authCookie {
		request.AddCookie(&http.Cookie{Name: authSessionCookieName, Value: "benchmark-session"})
	}
	return request
}

func handlerBenchmarkResponseBody(size int, htmlResponse bool) []byte {
	if size <= 0 {
		return nil
	}
	if !htmlResponse {
		return bytes.Repeat([]byte("x"), size)
	}
	prefix := []byte("<!doctype html><html><body><main>")
	suffix := []byte("</main></body></html>")
	if size < len(prefix)+len(suffix) {
		return append(append([]byte(nil), prefix...), suffix...)
	}
	body := make([]byte, 0, size)
	body = append(body, prefix...)
	body = append(body, bytes.Repeat([]byte("x"), size-len(prefix)-len(suffix))...)
	body = append(body, suffix...)
	return body
}

func benchmarkGatewayPortalConfig(b *testing.B, enabled bool) models.GatewayPortalConfig {
	b.Helper()
	value := []byte(`{"enabled":false}`)
	if enabled {
		value = []byte(`{"enabled":true}`)
	}
	var config models.GatewayPortalConfig
	if err := json.Unmarshal(value, &config); err != nil {
		b.Fatalf("unmarshal gateway portal config: %v", err)
	}
	return config
}

func handlerBenchmarkCombinedAuthResponse(mode pb.HttpAuthMode, preflightScope pb.AuthCacheScope, verifyScope pb.AuthCacheScope) *pb.AuthorizeHttpResponse {
	response := &pb.AuthorizeHttpResponse{
		PreflightCacheScope: preflightScope,
		VerifyCacheScope:    verifyScope,
	}
	if mode != pb.HttpAuthMode_HTTP_AUTH_MODE_VERIFY_ONLY {
		response.Preflight = &pb.PreflightAuthResponse{}
	}
	if mode != pb.HttpAuthMode_HTTP_AUTH_MODE_PREFLIGHT_ONLY {
		response.Verify = &pb.VerifyAuthResponse{Success: true, Status: http.StatusOK}
	}
	return response
}
