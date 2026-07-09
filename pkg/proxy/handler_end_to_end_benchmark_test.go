package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

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
	wafEnabled    bool
}

type handlerEndToEndBenchmarkFixture struct {
	handler      *Handler
	target       *httptest.Server
	logManager   *gatewaylog.Manager
	authorizeRPC *atomic.Int64
	requestURL   string
	authCookie   bool
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

func benchmarkHandlerEndToEndScenario(b *testing.B, scenario handlerEndToEndBenchmarkScenario, parallel bool) {
	b.StopTimer()
	fixture := newHandlerEndToEndBenchmarkFixture(b, scenario)
	defer func() {
		b.StopTimer()
		fixture.logManager.Flush()
		fixture.logManager.Close()
		fixture.target.Close()
	}()

	warmRecorder := httptest.NewRecorder()
	fixture.handler.ServeHTTP(warmRecorder, fixture.newRequest())
	if warmRecorder.Code != http.StatusOK {
		b.Fatalf("warm-up status = %d; body=%s", warmRecorder.Code, warmRecorder.Body.String())
	}
	if scenario.portalEnabled && !bytes.Contains(warmRecorder.Body.Bytes(), []byte("reauth-proxy-toolbar-loader")) {
		b.Fatal("portal-enabled warm-up response did not include the toolbar loader")
	}
	authorizeCallsBefore := fixture.authorizeRPC.Load()

	b.SetBytes(int64(scenario.responseBytes))
	b.ReportAllocs()
	b.ResetTimer()
	b.StartTimer()
	if parallel {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				recorder := httptest.NewRecorder()
				fixture.handler.ServeHTTP(recorder, fixture.newRequest())
				if recorder.Code != http.StatusOK {
					b.Errorf("status = %d, want 200", recorder.Code)
					continue
				}
			}
		})
	} else {
		for b.Loop() {
			recorder := httptest.NewRecorder()
			fixture.handler.ServeHTTP(recorder, fixture.newRequest())
			if recorder.Code != http.StatusOK {
				b.Fatalf("status = %d, want 200; body=%s", recorder.Code, recorder.Body.String())
			}
			handlerBenchmarkStatusSink = recorder.Code
			handlerBenchmarkBytesSink = recorder.Body.Len()
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

func newHandlerEndToEndBenchmarkFixture(b *testing.B, scenario handlerEndToEndBenchmarkScenario) *handlerEndToEndBenchmarkFixture {
	b.Helper()
	payload := handlerBenchmarkResponseBody(scenario.responseBytes, scenario.htmlResponse)
	contentLength := strconv.Itoa(len(payload))
	contentType := "text/plain; charset=utf-8"
	if scenario.htmlResponse {
		contentType = "text/html; charset=utf-8"
	}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Content-Length", contentLength)
		_, _ = w.Write(payload)
	}))

	loggingConfig := models.LoggingConfig{Enabled: scenario.logging}
	logManager := gatewaylog.NewManager(b.TempDir(), loggingConfig)
	fixture := &handlerEndToEndBenchmarkFixture{
		target:       target,
		logManager:   logManager,
		authorizeRPC: new(atomic.Int64),
	}
	handler := &Handler{
		LoggingConfig:     loggingConfig,
		GatewayPortal:     benchmarkGatewayPortalConfig(b, scenario.portalEnabled),
		gatewayLogManager: logManager,
		authCache:         newAuthStateCache(),
		preflightCache:    newPreflightStateCache(),
	}

	if scenario.routeKind == "host" {
		handler.HostRules = []models.HostRule{{
			Host:       "bench.example.test",
			Target:     target.URL,
			UseAuth:    scenario.authMode != handlerBenchmarkAuthOff,
			AccessMode: "login_first",
		}}
		fixture.requestURL = "http://bench.example.test/benchmark"
	} else {
		handler.Rules = []models.Rule{{
			Path:    "/benchmark",
			Target:  target.URL,
			UseAuth: scenario.authMode != handlerBenchmarkAuthOff,
		}}
		fixture.requestURL = "http://gateway.example.test/benchmark/resource"
	}

	if scenario.authMode != handlerBenchmarkAuthOff {
		fixture.authCookie = true
		cacheTTL := 0
		preflightScope := pb.AuthCacheScope_AUTH_CACHE_SCOPE_NONE
		verifyScope := pb.AuthCacheScope_AUTH_CACHE_SCOPE_NONE
		if scenario.authMode == handlerBenchmarkAuthHit {
			cacheTTL = 3600
			preflightScope = pb.AuthCacheScope_AUTH_CACHE_SCOPE_EXACT_REQUEST
			verifyScope = pb.AuthCacheScope_AUTH_CACHE_SCOPE_HOST
		}
		handler.AuthConfig = models.AuthConfig{
			AuthURL:      "/api/auth/verify",
			PreflightURL: "/api/auth/preflight",
			AuthCacheTTL: cacheTTL,
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
		wafConfig := models.WAFConfig{Enabled: true, Mode: proxywaf.ModeBlocking}
		wafRuntime := proxywaf.NewRuntime(wafConfig, b.TempDir())
		status, err := wafRuntime.Reload(wafConfig, "", "")
		if err != nil {
			logManager.Close()
			target.Close()
			b.Fatalf("load benchmark WAF runtime: %v", err)
		}
		if !status.Loaded {
			logManager.Close()
			target.Close()
			b.Fatal("benchmark WAF runtime was not loaded")
		}
		handler.WAFConfig = wafConfig
		handler.wafRuntime = wafRuntime
		// Reload schedules a memory release after 500ms. Keep that maintenance
		// work outside the measured WAF request loop.
		time.Sleep(600 * time.Millisecond)
	}

	handler.publishRequestSnapshotLocked()
	fixture.handler = handler
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
