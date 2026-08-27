package proxy

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go-reauth-proxy/pkg/grpc/pb"
	"go-reauth-proxy/pkg/models"
)

const combinedAuthTestCookieValue = "combined-session"

func TestCombinedAuthCapabilityUsesOneRequestForProtectedPathAndHost(t *testing.T) {
	for _, routeKind := range []string{"path", "host"} {
		t.Run(routeKind, func(t *testing.T) {
			var authorizeCalls atomic.Int32
			var preflightCalls atomic.Int32
			var verifyCalls atomic.Int32
			var expectedRoutedUpstream string
			var expectedRoutedUpstreamHost string
			bridge := testAuthBridge{
				supports: true,
				authorize: func(_ context.Context, request *pb.AuthorizeHttpRequest) (*pb.AuthorizeHttpResponse, error) {
					authorizeCalls.Add(1)
					if request.GetMode() != pb.HttpAuthMode_HTTP_AUTH_MODE_PREFLIGHT_AND_VERIFY {
						t.Errorf("AuthorizeHTTP mode = %s, want PREFLIGHT_AND_VERIFY", request.GetMode())
					}
					if request.GetContext().RoutedUpstream == nil {
						t.Error("AuthorizeHTTP routed_upstream presence = false, want true")
					} else if got := request.GetContext().GetRoutedUpstream(); got != expectedRoutedUpstream {
						t.Errorf("AuthorizeHTTP routed_upstream = %q, want %q", got, expectedRoutedUpstream)
					}
					if request.GetContext().RoutedUpstreamHost == nil {
						t.Error("AuthorizeHTTP routed_upstream_host presence = false, want true")
					} else if got := request.GetContext().GetRoutedUpstreamHost(); got != expectedRoutedUpstreamHost {
						t.Errorf("AuthorizeHTTP routed_upstream_host = %q, want %q", got, expectedRoutedUpstreamHost)
					}
					if request.GetContext().RoutedUpstreamRouteId == nil ||
						request.GetContext().GetRoutedUpstreamRouteId() == "" {
						t.Error("AuthorizeHTTP routed_upstream_route_id must be present and non-empty")
					}
					return successfulCombinedAuthResponse(request.GetMode(), pb.AuthCacheScope_AUTH_CACHE_SCOPE_NONE, pb.AuthCacheScope_AUTH_CACHE_SCOPE_NONE, nil), nil
				},
				preflight: func(context.Context, *pb.PreflightAuthRequest) (*pb.PreflightAuthResponse, error) {
					preflightCalls.Add(1)
					return &pb.PreflightAuthResponse{}, nil
				},
				verify: func(context.Context, *pb.VerifyAuthRequest) (*pb.VerifyAuthResponse, error) {
					verifyCalls.Add(1)
					return successfulVerifyAuthResponse(nil), nil
				},
			}

			target := newCombinedAuthTestTarget(t, nil)
			defer target.Close()
			expectedRoutedUpstream = target.URL
			handler := newCombinedAuthTestHandler(target.URL, bridge, routeKind, 0)
			request := newCombinedAuthTestRequest(routeKind, "/protected/resource")
			expectedRoutedUpstreamHost = request.Host
			if routeKind == "host" {
				expectedRoutedUpstreamHost = target.Listener.Addr().String()
			}
			recorder, recovered := serveCombinedAuthTestRequest(handler, request)

			if recovered != nil {
				t.Fatalf("ServeHTTP panic = %v", recovered)
			}
			if recorder.Code != http.StatusOK || recorder.Body.String() != "upstream-ok" {
				t.Fatalf("response = status %d body %q", recorder.Code, recorder.Body.String())
			}
			if got := authorizeCalls.Load(); got != 1 {
				t.Fatalf("AuthorizeHTTP calls = %d, want 1", got)
			}
			if got := preflightCalls.Load(); got != 0 {
				t.Fatalf("legacy PreflightAuth calls = %d, want 0", got)
			}
			if got := verifyCalls.Load(); got != 0 {
				t.Fatalf("legacy VerifyAuth calls = %d, want 0", got)
			}
		})
	}
}

func TestCombinedAuthCapabilityFallbackUsesLegacyPreflightAndVerify(t *testing.T) {
	var authorizeCalls atomic.Int32
	var preflightCalls atomic.Int32
	var verifyCalls atomic.Int32
	var expectedRoutedUpstream string
	var expectedRoutedUpstreamHost string
	assertRoutedUpstream := func(context *pb.AuthContext) {
		t.Helper()
		if context.RoutedUpstream == nil {
			t.Error("legacy AuthContext routed_upstream presence = false, want true")
		} else if got := context.GetRoutedUpstream(); got != expectedRoutedUpstream {
			t.Errorf("legacy AuthContext routed_upstream = %q, want %q", got, expectedRoutedUpstream)
		}
		if context.RoutedUpstreamHost == nil {
			t.Error("legacy AuthContext routed_upstream_host presence = false, want true")
		} else if got := context.GetRoutedUpstreamHost(); got != expectedRoutedUpstreamHost {
			t.Errorf("legacy AuthContext routed_upstream_host = %q, want %q", got, expectedRoutedUpstreamHost)
		}
		if context.RoutedUpstreamRouteId == nil || context.GetRoutedUpstreamRouteId() == "" {
			t.Error("legacy AuthContext routed_upstream_route_id must be present and non-empty")
		}
	}
	bridge := testAuthBridge{
		supports: false,
		authorize: func(context.Context, *pb.AuthorizeHttpRequest) (*pb.AuthorizeHttpResponse, error) {
			authorizeCalls.Add(1)
			return nil, errors.New("combined authorization must not be called")
		},
		preflight: func(_ context.Context, request *pb.PreflightAuthRequest) (*pb.PreflightAuthResponse, error) {
			preflightCalls.Add(1)
			assertRoutedUpstream(request.GetContext())
			return &pb.PreflightAuthResponse{}, nil
		},
		verify: func(_ context.Context, request *pb.VerifyAuthRequest) (*pb.VerifyAuthResponse, error) {
			verifyCalls.Add(1)
			assertRoutedUpstream(request.GetContext())
			return successfulVerifyAuthResponse(nil), nil
		},
	}

	target := newCombinedAuthTestTarget(t, nil)
	defer target.Close()
	expectedRoutedUpstream = target.URL
	handler := newCombinedAuthTestHandler(target.URL, bridge, "path", 0)
	request := newCombinedAuthTestRequest("path", "/protected/legacy")
	expectedRoutedUpstreamHost = request.Host
	recorder, recovered := serveCombinedAuthTestRequest(handler, request)

	if recovered != nil {
		t.Fatalf("ServeHTTP panic = %v", recovered)
	}
	if recorder.Code != http.StatusOK || recorder.Body.String() != "upstream-ok" {
		t.Fatalf("response = status %d body %q", recorder.Code, recorder.Body.String())
	}
	if got := authorizeCalls.Load(); got != 0 {
		t.Fatalf("AuthorizeHTTP calls = %d, want 0", got)
	}
	if got := preflightCalls.Load(); got != 1 {
		t.Fatalf("legacy PreflightAuth calls = %d, want 1", got)
	}
	if got := verifyCalls.Load(); got != 1 {
		t.Fatalf("legacy VerifyAuth calls = %d, want 1", got)
	}
}

func TestCombinedAuthPreflightStopDoesNotRequireVerifyResponse(t *testing.T) {
	tests := []struct {
		name       string
		preflight  *pb.PreflightAuthResponse
		wantStatus int
		wantPanic  bool
		location   string
	}{
		{
			name:      "deny",
			preflight: &pb.PreflightAuthResponse{Deny: true},
			wantPanic: true,
		},
		{
			name:       "redirect",
			preflight:  &pb.PreflightAuthResponse{RedirectLocation: "/login"},
			wantStatus: http.StatusFound,
			location:   "/login",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var authorizeCalls atomic.Int32
			var legacyVerifyCalls atomic.Int32
			var targetCalls atomic.Int32
			bridge := testAuthBridge{
				supports: true,
				authorize: func(_ context.Context, request *pb.AuthorizeHttpRequest) (*pb.AuthorizeHttpResponse, error) {
					authorizeCalls.Add(1)
					return &pb.AuthorizeHttpResponse{
						Preflight:           test.preflight,
						PreflightCacheScope: pb.AuthCacheScope_AUTH_CACHE_SCOPE_NONE,
					}, nil
				},
				verify: func(context.Context, *pb.VerifyAuthRequest) (*pb.VerifyAuthResponse, error) {
					legacyVerifyCalls.Add(1)
					return successfulVerifyAuthResponse(nil), nil
				},
			}

			target := newCombinedAuthTestTarget(t, &targetCalls)
			defer target.Close()
			handler := newCombinedAuthTestHandler(target.URL, bridge, "path", 0)
			recorder, recovered := serveCombinedAuthTestRequest(handler, newCombinedAuthTestRequest("path", "/protected/stopped"))

			if test.wantPanic {
				recoveredErr, ok := recovered.(error)
				if !ok || !errors.Is(recoveredErr, http.ErrAbortHandler) {
					t.Fatalf("ServeHTTP panic = %v, want http.ErrAbortHandler", recovered)
				}
			} else {
				if recovered != nil {
					t.Fatalf("ServeHTTP panic = %v", recovered)
				}
				if recorder.Code != test.wantStatus {
					t.Fatalf("status = %d, want %d", recorder.Code, test.wantStatus)
				}
				if got := recorder.Header().Get("Location"); got != test.location {
					t.Fatalf("Location = %q, want %q", got, test.location)
				}
				assertAuthResponseNoStore(t, recorder.Header())
			}
			if got := authorizeCalls.Load(); got != 1 {
				t.Fatalf("AuthorizeHTTP calls = %d, want 1", got)
			}
			if got := legacyVerifyCalls.Load(); got != 0 {
				t.Fatalf("legacy VerifyAuth calls = %d, want 0", got)
			}
			if got := targetCalls.Load(); got != 0 {
				t.Fatalf("upstream calls = %d, want 0", got)
			}
		})
	}
}

func TestCombinedAuthServiceUnavailablePreflightReturns503WithoutAborting(t *testing.T) {
	var upstreamCalls atomic.Int32
	bridge := testAuthBridge{
		supports: true,
		authorize: func(_ context.Context, _ *pb.AuthorizeHttpRequest) (*pb.AuthorizeHttpResponse, error) {
			return &pb.AuthorizeHttpResponse{
				Preflight: &pb.PreflightAuthResponse{
					Deny:               true,
					AccessDeniedReason: reauthServiceUnavailableReason,
					ResponseHeaders: []*pb.Header{{
						Name:   "Retry-After",
						Values: []string{"1"},
					}},
				},
				Verify: &pb.VerifyAuthResponse{
					Status:   http.StatusServiceUnavailable,
					Decision: "auth_unavailable",
				},
			}, nil
		},
	}
	target := newCombinedAuthTestTarget(t, &upstreamCalls)
	defer target.Close()
	handler := newCombinedAuthTestHandler(target.URL, bridge, "path", 0)
	recorder, recovered := serveCombinedAuthTestRequest(
		handler,
		newCombinedAuthTestRequest("path", "/protected/app.js"),
	)

	if recovered != nil {
		t.Fatalf("ServeHTTP panic = %v", recovered)
	}
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%s", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get("Retry-After"); got != "1" {
		t.Fatalf("Retry-After = %q, want 1", got)
	}
	assertAuthResponseNoStore(t, recorder.Header())
	if got := upstreamCalls.Load(); got != 0 {
		t.Fatalf("upstream calls = %d, want 0", got)
	}
}

func TestCombinedAuthContextUsesDedicatedAccessTokenFields(t *testing.T) {
	var authorizeCalls atomic.Int32
	bridge := testAuthBridge{
		supports: true,
		authorize: func(_ context.Context, request *pb.AuthorizeHttpRequest) (*pb.AuthorizeHttpResponse, error) {
			authorizeCalls.Add(1)
			authContext := request.GetContext()
			if got := len(authContext.GetExtraHeaders()); got != 0 {
				t.Errorf("combined AuthContext ExtraHeaders length = %d, want 0", got)
			}
			if got := authContext.GetAccessToken(); got != "compact-token" {
				t.Errorf("AuthContext access_token = %q", got)
			}
			if got := authContext.GetAccessTokenHyphenated(); got != "hyphenated-token" {
				t.Errorf("AuthContext access_token_hyphenated = %q", got)
			}
			return successfulCombinedAuthResponse(request.GetMode(), pb.AuthCacheScope_AUTH_CACHE_SCOPE_NONE, pb.AuthCacheScope_AUTH_CACHE_SCOPE_NONE, nil), nil
		},
	}

	target := newCombinedAuthTestTarget(t, nil)
	defer target.Close()
	handler := newCombinedAuthTestHandler(target.URL, bridge, "path", 0)
	request := newCombinedAuthTestRequest("path", "/protected/context")
	request.Header.Set("AccessToken", "compact-token")
	request.Header.Set("Access-Token", "hyphenated-token")
	request.Header.Set("X-Unrelated-Legacy-Header", "must-not-be-copied")
	recorder, recovered := serveCombinedAuthTestRequest(handler, request)

	if recovered != nil {
		t.Fatalf("ServeHTTP panic = %v", recovered)
	}
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", recorder.Code, recorder.Body.String())
	}
	if got := authorizeCalls.Load(); got != 1 {
		t.Fatalf("AuthorizeHTTP calls = %d, want 1", got)
	}
}

func TestCombinedAuthCacheDoesNotCrossDedicatedAccessTokenIdentities(t *testing.T) {
	var authorizeCalls atomic.Int32
	bridge := testAuthBridge{
		supports: true,
		authorize: func(_ context.Context, request *pb.AuthorizeHttpRequest) (*pb.AuthorizeHttpResponse, error) {
			authorizeCalls.Add(1)
			return successfulCombinedAuthResponse(request.GetMode(), pb.AuthCacheScope_AUTH_CACHE_SCOPE_EXACT_REQUEST, pb.AuthCacheScope_AUTH_CACHE_SCOPE_EXACT_REQUEST, nil), nil
		},
	}
	target := newCombinedAuthTestTarget(t, nil)
	defer target.Close()
	handler := newCombinedAuthTestHandler(target.URL, bridge, "path", 60)

	for _, token := range []string{"token-a", "token-b", ""} {
		request := newCombinedAuthTestRequest("path", "/protected/media")
		request.Header.Set("User-Agent", "com.trim.media")
		if token != "" {
			request.Header.Set("AccessToken", token)
		}
		recorder, recovered := serveCombinedAuthTestRequest(handler, request)
		if recovered != nil || recorder.Code != http.StatusOK {
			t.Fatalf("token %q: status=%d panic=%v body=%s", token, recorder.Code, recovered, recorder.Body.String())
		}
	}
	if got := authorizeCalls.Load(); got != 3 {
		t.Fatalf("AuthorizeHTTP calls = %d, want 3 distinct credential identities", got)
	}
}

func TestCombinedAuthCacheScopeHostReusesVerifyAcrossPaths(t *testing.T) {
	var modesMu sync.Mutex
	var modes []pb.HttpAuthMode
	var verifyComputations atomic.Int32
	bridge := testAuthBridge{
		supports: true,
		authorize: func(_ context.Context, request *pb.AuthorizeHttpRequest) (*pb.AuthorizeHttpResponse, error) {
			modesMu.Lock()
			modes = append(modes, request.GetMode())
			modesMu.Unlock()
			if request.GetMode() != pb.HttpAuthMode_HTTP_AUTH_MODE_PREFLIGHT_ONLY {
				verifyComputations.Add(1)
			}
			return successfulCombinedAuthResponse(request.GetMode(), pb.AuthCacheScope_AUTH_CACHE_SCOPE_EXACT_REQUEST, pb.AuthCacheScope_AUTH_CACHE_SCOPE_HOST, nil), nil
		},
	}

	target := newCombinedAuthTestTarget(t, nil)
	defer target.Close()
	handler := newCombinedAuthTestHandler(target.URL, bridge, "host", 60)
	for _, requestPath := range []string{"/first", "/second"} {
		recorder, recovered := serveCombinedAuthTestRequest(handler, newCombinedAuthTestRequest("host", requestPath))
		if recovered != nil {
			t.Fatalf("request %s panic = %v", requestPath, recovered)
		}
		if recorder.Code != http.StatusOK {
			t.Fatalf("request %s status = %d; body=%s", requestPath, recorder.Code, recorder.Body.String())
		}
	}

	modesMu.Lock()
	gotModes := append([]pb.HttpAuthMode(nil), modes...)
	modesMu.Unlock()
	wantModes := []pb.HttpAuthMode{
		pb.HttpAuthMode_HTTP_AUTH_MODE_PREFLIGHT_AND_VERIFY,
		pb.HttpAuthMode_HTTP_AUTH_MODE_PREFLIGHT_ONLY,
	}
	if !slices.Equal(gotModes, wantModes) {
		t.Fatalf("AuthorizeHTTP modes = %v, want %v", gotModes, wantModes)
	}
	if got := verifyComputations.Load(); got != 1 {
		t.Fatalf("verify computations = %d, want 1", got)
	}
}

func TestCombinedAuthSetCookieAndNoneScopeDoNotCacheVerify(t *testing.T) {
	tests := []struct {
		name        string
		verifyScope pb.AuthCacheScope
		setCookies  []string
		wantModes   []pb.HttpAuthMode
	}{
		{
			name:        "set cookie",
			verifyScope: pb.AuthCacheScope_AUTH_CACHE_SCOPE_HOST,
			setCookies:  []string{authSessionCookieName + "=rotated; Path=/; HttpOnly"},
			wantModes: []pb.HttpAuthMode{
				pb.HttpAuthMode_HTTP_AUTH_MODE_PREFLIGHT_AND_VERIFY,
				pb.HttpAuthMode_HTTP_AUTH_MODE_PREFLIGHT_AND_VERIFY,
			},
		},
		{
			name:        "none scope",
			verifyScope: pb.AuthCacheScope_AUTH_CACHE_SCOPE_NONE,
			wantModes: []pb.HttpAuthMode{
				pb.HttpAuthMode_HTTP_AUTH_MODE_PREFLIGHT_AND_VERIFY,
				pb.HttpAuthMode_HTTP_AUTH_MODE_VERIFY_ONLY,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var modesMu sync.Mutex
			var modes []pb.HttpAuthMode
			bridge := testAuthBridge{
				supports: true,
				authorize: func(_ context.Context, request *pb.AuthorizeHttpRequest) (*pb.AuthorizeHttpResponse, error) {
					modesMu.Lock()
					modes = append(modes, request.GetMode())
					modesMu.Unlock()
					return successfulCombinedAuthResponse(request.GetMode(), pb.AuthCacheScope_AUTH_CACHE_SCOPE_EXACT_REQUEST, test.verifyScope, test.setCookies), nil
				},
			}

			target := newCombinedAuthTestTarget(t, nil)
			defer target.Close()
			handler := newCombinedAuthTestHandler(target.URL, bridge, "host", 60)
			for i := 0; i < 2; i++ {
				recorder, recovered := serveCombinedAuthTestRequest(handler, newCombinedAuthTestRequest("host", "/same"))
				if recovered != nil {
					t.Fatalf("request %d panic = %v", i+1, recovered)
				}
				if recorder.Code != http.StatusOK {
					t.Fatalf("request %d status = %d; body=%s", i+1, recorder.Code, recorder.Body.String())
				}
				if len(test.setCookies) > 0 {
					if got := recorder.Header().Values("Set-Cookie"); !slices.Equal(got, test.setCookies) {
						t.Fatalf("request %d Set-Cookie = %#v, want %#v", i+1, got, test.setCookies)
					}
					assertAuthResponseNoStore(t, recorder.Header())
				}
			}

			modesMu.Lock()
			gotModes := append([]pb.HttpAuthMode(nil), modes...)
			modesMu.Unlock()
			if !slices.Equal(gotModes, test.wantModes) {
				t.Fatalf("AuthorizeHTTP modes = %v, want %v", gotModes, test.wantModes)
			}
		})
	}
}

func TestCombinedAuthCanceledRequestReturnsWithoutWaitingForSharedCall(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	returned := make(chan struct{})
	var startOnce sync.Once
	var releaseOnce sync.Once
	bridge := testAuthBridge{
		supports: true,
		authorize: func(context.Context, *pb.AuthorizeHttpRequest) (*pb.AuthorizeHttpResponse, error) {
			startOnce.Do(func() { close(started) })
			<-release
			close(returned)
			return successfulCombinedAuthResponse(pb.HttpAuthMode_HTTP_AUTH_MODE_PREFLIGHT_AND_VERIFY, pb.AuthCacheScope_AUTH_CACHE_SCOPE_EXACT_REQUEST, pb.AuthCacheScope_AUTH_CACHE_SCOPE_EXACT_REQUEST, nil), nil
		},
	}
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })

	target := newCombinedAuthTestTarget(t, nil)
	defer target.Close()
	handler := newCombinedAuthTestHandler(target.URL, bridge, "path", 60)
	baseRequest := newCombinedAuthTestRequest("path", "/protected/cancel")
	ctx, cancel := context.WithCancel(baseRequest.Context())
	request := baseRequest.WithContext(ctx)
	recorder := httptest.NewRecorder()
	serveDone := make(chan any, 1)
	go func() {
		var recovered any
		defer func() { serveDone <- recovered }()
		func() {
			defer func() { recovered = recover() }()
			handler.ServeHTTP(recorder, request)
		}()
	}()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("AuthorizeHTTP did not start")
	}
	cancel()
	select {
	case recovered := <-serveDone:
		if recovered != nil {
			t.Fatalf("ServeHTTP panic = %v", recovered)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("canceled request remained blocked on shared AuthorizeHTTP call")
	}

	releaseOnce.Do(func() { close(release) })
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("shared AuthorizeHTTP call did not finish after release")
	}
}

func newCombinedAuthTestTarget(t *testing.T, calls *atomic.Int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls != nil {
			calls.Add(1)
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "upstream-ok")
	}))
}

func newCombinedAuthTestHandler(targetURL string, bridge authBridgeClient, routeKind string, cacheTTL int) *Handler {
	handler := &Handler{
		AuthConfig: models.AuthConfig{
			AuthURL:      "/api/auth/verify",
			PreflightURL: "/api/auth/preflight",
			AuthCacheTTL: cacheTTL,
		},
		authBridge:     bridge,
		authCache:      newAuthStateCache(),
		preflightCache: newPreflightStateCache(),
	}
	if routeKind == "host" {
		handler.HostRules = []models.HostRule{{
			Host:       "protected.example.test",
			Target:     targetURL,
			UseAuth:    true,
			AccessMode: "login_first",
		}}
	} else {
		handler.Rules = []models.Rule{{
			Path:    "/protected",
			Target:  targetURL,
			UseAuth: true,
		}}
	}
	handler.publishRequestSnapshotLocked()
	return handler
}

func newCombinedAuthTestRequest(routeKind string, requestPath string) *http.Request {
	host := "gateway.example.test"
	if routeKind == "host" {
		host = "protected.example.test"
	}
	request := httptest.NewRequest(http.MethodGet, "http://"+host+requestPath, nil)
	request.AddCookie(&http.Cookie{Name: authSessionCookieName, Value: combinedAuthTestCookieValue})
	return request
}

func serveCombinedAuthTestRequest(handler *Handler, request *http.Request) (recorder *httptest.ResponseRecorder, recovered any) {
	recorder = httptest.NewRecorder()
	func() {
		defer func() { recovered = recover() }()
		handler.ServeHTTP(recorder, request)
	}()
	return recorder, recovered
}

func successfulCombinedAuthResponse(mode pb.HttpAuthMode, preflightScope pb.AuthCacheScope, verifyScope pb.AuthCacheScope, setCookies []string) *pb.AuthorizeHttpResponse {
	response := &pb.AuthorizeHttpResponse{
		PreflightCacheScope: preflightScope,
		VerifyCacheScope:    verifyScope,
	}
	switch mode {
	case pb.HttpAuthMode_HTTP_AUTH_MODE_PREFLIGHT_ONLY:
		response.Preflight = &pb.PreflightAuthResponse{}
	case pb.HttpAuthMode_HTTP_AUTH_MODE_VERIFY_ONLY:
		response.Verify = successfulVerifyAuthResponse(setCookies)
	default:
		response.Preflight = &pb.PreflightAuthResponse{}
		response.Verify = successfulVerifyAuthResponse(setCookies)
	}
	return response
}

func successfulVerifyAuthResponse(setCookies []string) *pb.VerifyAuthResponse {
	return &pb.VerifyAuthResponse{
		Success:            true,
		Status:             http.StatusOK,
		SetCookies:         append([]string(nil), setCookies...),
		LoginAuthenticated: true,
	}
}
