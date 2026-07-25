package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go-reauth-proxy/pkg/grpc/pb"
	"go-reauth-proxy/pkg/models"
)

func TestAuthLogoutRouteTakesPrecedenceOverHostRule(t *testing.T) {
	var targetHits int32
	var logoutHits int32

	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead && r.URL.Path == "/api/auth/preflight" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodGet || r.URL.Path != "/api/auth/logout" {
			t.Fatalf("unexpected auth request %s %s", r.Method, r.URL.Path)
		}
		atomic.AddInt32(&logoutHits, 1)
		if !strings.Contains(r.Header.Get("Cookie"), authSessionCookieName+"=ok") {
			t.Fatalf("auth logout Cookie = %q, want %s=ok", r.Header.Get("Cookie"), authSessionCookieName)
		}
		_, _ = io.WriteString(w, "logged-out")
	}))
	defer authServer.Close()

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&targetHits, 1)
		http.Error(w, "host target should not be reached", http.StatusTeapot)
	}))
	defer target.Close()

	handler := &Handler{
		HostRules: []models.HostRule{
			{
				Host:       "fnknock.example.com",
				Target:     target.URL,
				UseAuth:    true,
				AccessMode: "login_first",
			},
		},
		AuthConfig: models.AuthConfig{
			AuthPort:  testServerPort(t, authServer.URL),
			AuthURL:   "/api/auth/verify",
			LogoutURL: "/api/auth/logout",
		},
		authCache:      newAuthStateCache(),
		preflightCache: newPreflightStateCache(),
	}
	handler.publishRequestSnapshotLocked()

	req := httptest.NewRequest(http.MethodGet, "http://fnknock.example.com/__auth__/logout", nil)
	req.AddCookie(&http.Cookie{Name: authSessionCookieName, Value: "ok"})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); body != "logged-out" {
		t.Fatalf("body = %q, want logged-out", body)
	}
	if got := atomic.LoadInt32(&logoutHits); got != 1 {
		t.Fatalf("logout hits = %d, want 1", got)
	}
	if got := atomic.LoadInt32(&targetHits); got != 0 {
		t.Fatalf("target hits = %d, want 0", got)
	}
}

func TestInternalAuthRouteBypassesRedirectingPreflight(t *testing.T) {
	var preflightHits int32
	var logoutHits int32

	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/auth/logout":
			atomic.AddInt32(&logoutHits, 1)
			_, _ = io.WriteString(w, "logged-out")
		default:
			t.Fatalf("unexpected auth request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer authServer.Close()
	bridge := testAuthBridge{
		preflight: func(_ context.Context, _ *pb.PreflightAuthRequest) (*pb.PreflightAuthResponse, error) {
			atomic.AddInt32(&preflightHits, 1)
			return &pb.PreflightAuthResponse{RedirectLocation: "/__auth__/login"}, nil
		},
	}

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "host target should not be reached", http.StatusTeapot)
	}))
	defer target.Close()

	handler := &Handler{
		HostRules: []models.HostRule{
			{
				Host:       "fnknock.example.com",
				Target:     target.URL,
				UseAuth:    true,
				AccessMode: "login_first",
			},
		},
		AuthConfig: models.AuthConfig{
			AuthPort:  testServerPort(t, authServer.URL),
			AuthURL:   "/api/auth/verify",
			LogoutURL: "/api/auth/logout",
		},
		authBridge:     bridge,
		authCache:      newAuthStateCache(),
		preflightCache: newPreflightStateCache(),
	}
	handler.publishRequestSnapshotLocked()

	req := httptest.NewRequest(http.MethodGet, "http://fnknock.example.com/__auth__/api/auth/logout", nil)
	req.AddCookie(&http.Cookie{Name: authSessionCookieName, Value: "ok"})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); body != "logged-out" {
		t.Fatalf("body = %q, want logged-out", body)
	}
	assertAuthResponseNoStore(t, rec.Header())
	if got := atomic.LoadInt32(&preflightHits); got != 0 {
		t.Fatalf("preflight hits = %d, want 0 for internal auth recovery route", got)
	}
	if got := atomic.LoadInt32(&logoutHits); got != 1 {
		t.Fatalf("logout hits = %d, want 1", got)
	}
}

func TestInternalAuthLoginCanonicalRedirectIsNoStore(t *testing.T) {
	handler := &Handler{
		AuthConfig: models.AuthConfig{
			AuthPort: 7997,
			LoginURL: "/#/login",
		},
		authCache:      newAuthStateCache(),
		preflightCache: newPreflightStateCache(),
	}
	handler.publishRequestSnapshotLocked()

	request := httptest.NewRequest(http.MethodGet, "https://app.example.com/__auth__/login?redirect_uri=%2Fprivate", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", recorder.Code)
	}
	if got := recorder.Header().Get("Location"); got != "/__auth__/?redirect_uri=%2Fprivate#/login" {
		t.Fatalf("Location = %q, want canonical internal auth view redirect", got)
	}
	assertAuthResponseNoStore(t, recorder.Header())
}

func TestHostRuleAuthVerifyReceivesSessionCookie(t *testing.T) {
	var verifyHits int32
	var targetHits int32

	bridge := testAuthBridge{
		verify: func(_ context.Context, in *pb.VerifyAuthRequest) (*pb.VerifyAuthResponse, error) {
			atomic.AddInt32(&verifyHits, 1)
			if !strings.Contains(in.GetContext().GetCookie(), authSessionCookieName+"=ok") {
				t.Fatalf("auth verify Cookie = %q, want %s=ok", in.GetContext().GetCookie(), authSessionCookieName)
			}
			return &pb.VerifyAuthResponse{Success: true, Status: http.StatusOK}, nil
		},
	}

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&targetHits, 1)
		if !strings.Contains(r.Header.Get("Cookie"), authSessionCookieName+"=ok") {
			t.Fatalf("target Cookie = %q, want %s=ok", r.Header.Get("Cookie"), authSessionCookieName)
		}
		_, _ = io.WriteString(w, "panel")
	}))
	defer target.Close()

	handler := &Handler{
		HostRules: []models.HostRule{
			{
				Host:       "fnknock.example.com",
				Target:     target.URL,
				UseAuth:    true,
				AccessMode: "login_first",
			},
		},
		AuthConfig: models.AuthConfig{
			AuthURL:      "/api/auth/verify",
			PreflightURL: "/api/auth/preflight",
		},
		authBridge:     bridge,
		authCache:      newAuthStateCache(),
		preflightCache: newPreflightStateCache(),
	}
	handler.publishRequestSnapshotLocked()

	req := httptest.NewRequest(http.MethodGet, "http://fnknock.example.com/", nil)
	req.AddCookie(&http.Cookie{Name: authSessionCookieName, Value: "ok"})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); body != "panel" {
		t.Fatalf("body = %q, want panel", body)
	}
	if got := atomic.LoadInt32(&verifyHits); got != 1 {
		t.Fatalf("verify hits = %d, want 1", got)
	}
	if got := atomic.LoadInt32(&targetHits); got != 1 {
		t.Fatalf("target hits = %d, want 1", got)
	}
}

func TestHostRulePreflightScopeDeniedReturnsAccessDeniedPage(t *testing.T) {
	var targetHits int32
	var verifyHits int32

	bridge := testAuthBridge{
		preflight: func(context.Context, *pb.PreflightAuthRequest) (*pb.PreflightAuthResponse, error) {
			return &pb.PreflightAuthResponse{AccessDeniedReason: reauthScopeDeniedReason}, nil
		},
		verify: func(context.Context, *pb.VerifyAuthRequest) (*pb.VerifyAuthResponse, error) {
			atomic.AddInt32(&verifyHits, 1)
			return &pb.VerifyAuthResponse{Success: true, Status: http.StatusTeapot}, nil
		},
	}

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&targetHits, 1)
		http.Error(w, "target should not be reached", http.StatusTeapot)
	}))
	defer target.Close()

	handler := &Handler{
		HostRules: []models.HostRule{
			{
				Host:       "fnknock.example.com",
				Target:     target.URL,
				UseAuth:    true,
				AccessMode: "login_first",
			},
		},
		AuthConfig: models.AuthConfig{
			AuthURL:      "/api/auth/verify",
			PreflightURL: "/api/auth/preflight",
		},
		authBridge:     bridge,
		authCache:      newAuthStateCache(),
		preflightCache: newPreflightStateCache(),
	}
	handler.publishRequestSnapshotLocked()

	req := httptest.NewRequest(http.MethodGet, "http://fnknock.example.com/private", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body = %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("X-Fn-Knock-Access-Denied") != reauthScopeDeniedReason {
		t.Fatalf("missing access denied response header")
	}
	if body := rec.Body.String(); !strings.Contains(body, "权限不足") {
		t.Fatalf("body did not include access denied page: %s", body)
	}
	if got := atomic.LoadInt32(&verifyHits); got != 0 {
		t.Fatalf("verify hits = %d, want 0", got)
	}
	if got := atomic.LoadInt32(&targetHits); got != 0 {
		t.Fatalf("target hits = %d, want 0", got)
	}
}

func TestHostRuleWithoutAuthSkipsPreflight(t *testing.T) {
	var preflightHits int32
	var targetHits int32

	bridge := testAuthBridge{
		preflight: func(context.Context, *pb.PreflightAuthRequest) (*pb.PreflightAuthResponse, error) {
			atomic.AddInt32(&preflightHits, 1)
			return &pb.PreflightAuthResponse{AccessDeniedReason: reauthScopeDeniedReason}, nil
		},
	}

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&targetHits, 1)
		_, _ = io.WriteString(w, "public")
	}))
	defer target.Close()

	handler := &Handler{
		HostRules: []models.HostRule{
			{
				Host:       "public.example.com",
				Target:     target.URL,
				UseAuth:    false,
				AccessMode: "login_first",
			},
		},
		AuthConfig: models.AuthConfig{
			AuthURL:      "/api/auth/verify",
			PreflightURL: "/api/auth/preflight",
		},
		authBridge:     bridge,
		authCache:      newAuthStateCache(),
		preflightCache: newPreflightStateCache(),
	}
	handler.publishRequestSnapshotLocked()

	req := httptest.NewRequest(http.MethodGet, "http://public.example.com/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); body != "public" {
		t.Fatalf("body = %q, want public", body)
	}
	if got := atomic.LoadInt32(&preflightHits); got != 0 {
		t.Fatalf("preflight hits = %d, want 0", got)
	}
	if got := atomic.LoadInt32(&targetHits); got != 1 {
		t.Fatalf("target hits = %d, want 1", got)
	}
}

func TestSelectRouteRequiresConfiguredAuthentication(t *testing.T) {
	handler := &Handler{}
	handler.publishRequestSnapshotLocked()

	req := httptest.NewRequest(http.MethodGet, "http://gateway.example.com/__select__", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body = %s", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); strings.Contains(body, `class="select-page"`) {
		t.Fatalf("select page was rendered without configured authentication: %s", body)
	}
}

func TestSelectRouteRedirectsWithoutLoginState(t *testing.T) {
	tests := []struct {
		name       string
		verify     *pb.VerifyAuthResponse
		grantValue string
	}{
		{
			name:   "anonymous",
			verify: &pb.VerifyAuthResponse{Success: false, Status: http.StatusUnauthorized},
		},
		{
			name: "temporary grant is not a login",
			verify: &pb.VerifyAuthResponse{
				Success:            true,
				Status:             http.StatusOK,
				GrantKind:          pb.AuthGrantKind_AUTH_GRANT_KIND_SUBDOMAIN_RULE,
				LoginAuthenticated: false,
			},
			grantValue: "temporary-grant",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			bridge := testAuthBridge{
				verify: func(context.Context, *pb.VerifyAuthRequest) (*pb.VerifyAuthResponse, error) {
					return test.verify, nil
				},
			}
			handler := &Handler{
				AuthConfig: models.AuthConfig{
					AuthURL:      "/api/auth/verify",
					LoginURL:     "/login",
					PreflightURL: "/api/auth/preflight",
				},
				authBridge:     bridge,
				authCache:      newAuthStateCache(),
				preflightCache: newPreflightStateCache(),
			}
			handler.publishRequestSnapshotLocked()

			req := httptest.NewRequest(http.MethodGet, "http://gateway.example.com/__select__", nil)
			if test.grantValue != "" {
				req.AddCookie(&http.Cookie{Name: advancedAuthGrantCookieName, Value: test.grantValue})
			}
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusFound {
				t.Fatalf("status = %d, want 302; body = %s", rec.Code, rec.Body.String())
			}
			location := rec.Header().Get("Location")
			if !strings.HasPrefix(location, "/__auth__/login?") ||
				!strings.Contains(location, "redirect_uri=http%3A%2F%2Fgateway.example.com%2F__select__") {
				t.Fatalf("Location = %q, want login redirect back to /__select__", location)
			}
			if body := rec.Body.String(); strings.Contains(body, `class="select-page"`) {
				t.Fatalf("select page was rendered without login state: %s", body)
			}
		})
	}
}

func TestSelectRouteFiltersHostRulesByCredentialScope(t *testing.T) {
	var verifyHits int32

	bridge := testAuthBridge{
		verify: func(_ context.Context, in *pb.VerifyAuthRequest) (*pb.VerifyAuthResponse, error) {
			atomic.AddInt32(&verifyHits, 1)
			if got := in.GetContext().GetForwardedPath(); got != "/__select__" {
				t.Fatalf("X-Forwarded-Path = %q, want /__select__", got)
			}
			return &pb.VerifyAuthResponse{
				Success: true,
				Message: "ok",
				Status:  http.StatusOK,
				ResponseHeaders: headersToProto(http.Header{
					reauthSubdomainAccessHeader:       []string{reauthSubdomainAccessCustom},
					reauthAllowedSubdomainHostsHeader: []string{"app.example.com"},
				}),
			}, nil
		},
	}

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "target")
	}))
	defer target.Close()

	handler := &Handler{
		HostRules: []models.HostRule{
			{
				Host:    "app.example.com",
				Target:  target.URL,
				UseAuth: true,
				Title:   "Allowed App",
			},
			{
				Host:    "admin.example.com",
				Target:  target.URL,
				UseAuth: true,
				Title:   "Hidden Admin",
			},
		},
		AuthConfig: models.AuthConfig{
			AuthURL:      "/api/auth/verify",
			PreflightURL: "/api/auth/preflight",
		},
		authBridge:     bridge,
		authCache:      newAuthStateCache(),
		preflightCache: newPreflightStateCache(),
	}
	handler.publishRequestSnapshotLocked()

	req := httptest.NewRequest(http.MethodGet, "http://gateway.example.com/__select__", nil)
	req.AddCookie(&http.Cookie{Name: authSessionCookieName, Value: "ok"})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	if cacheControl := rec.Header().Get("Cache-Control"); !strings.Contains(cacheControl, "no-store") {
		t.Fatalf("Cache-Control = %q, want authenticated select page to be non-cacheable", cacheControl)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "app.example.com") {
		t.Fatalf("body did not include allowed host rule: %s", body)
	}
	if strings.Contains(body, "admin.example.com") {
		t.Fatalf("body included disallowed host rule: %s", body)
	}
	if got := atomic.LoadInt32(&verifyHits); got != 1 {
		t.Fatalf("verify hits = %d, want 1", got)
	}
}

func TestSelectRouteCachedCredentialScopeStillFiltersHostRules(t *testing.T) {
	var verifyHits int32

	bridge := testAuthBridge{
		verify: func(context.Context, *pb.VerifyAuthRequest) (*pb.VerifyAuthResponse, error) {
			atomic.AddInt32(&verifyHits, 1)
			return &pb.VerifyAuthResponse{
				Success: true,
				Message: "ok",
				Status:  http.StatusOK,
				ResponseHeaders: headersToProto(http.Header{
					reauthSubdomainAccessHeader:       []string{reauthSubdomainAccessCustom},
					reauthAllowedSubdomainHostsHeader: []string{"app.example.com"},
				}),
			}, nil
		},
	}

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "target")
	}))
	defer target.Close()

	handler := &Handler{
		HostRules: []models.HostRule{
			{Host: "app.example.com", Target: target.URL, UseAuth: true, Title: "Allowed App"},
			{Host: "admin.example.com", Target: target.URL, UseAuth: true, Title: "Hidden Admin"},
		},
		AuthConfig: models.AuthConfig{
			AuthURL:      "/api/auth/verify",
			PreflightURL: "/api/auth/preflight",
			AuthCacheTTL: 60,
		},
		authBridge:     bridge,
		authCache:      newAuthStateCache(),
		preflightCache: newPreflightStateCache(),
	}
	handler.publishRequestSnapshotLocked()

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "http://gateway.example.com/__select__", nil)
		req.AddCookie(&http.Cookie{Name: authSessionCookieName, Value: "ok"})
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("request %d status = %d, want 200; body = %s", i, rec.Code, rec.Body.String())
		}
		body := rec.Body.String()
		if !strings.Contains(body, "app.example.com") || strings.Contains(body, "admin.example.com") {
			t.Fatalf("request %d body did not respect cached scope filter: %s", i, body)
		}
	}

	if got := atomic.LoadInt32(&verifyHits); got != 1 {
		t.Fatalf("verify hits = %d, want cached second request", got)
	}
}

func TestHostRuleVerifyScopeDeniedReturnsJSONWithoutRedirect(t *testing.T) {
	var verifyHits int32
	var targetHits int32

	bridge := testAuthBridge{
		verify: func(context.Context, *pb.VerifyAuthRequest) (*pb.VerifyAuthResponse, error) {
			atomic.AddInt32(&verifyHits, 1)
			return &pb.VerifyAuthResponse{
				Success:            false,
				Message:            "scope denied",
				Status:             http.StatusForbidden,
				AccessDeniedReason: reauthScopeDeniedReason,
			}, nil
		},
	}

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&targetHits, 1)
		http.Error(w, "target should not be reached", http.StatusTeapot)
	}))
	defer target.Close()

	handler := &Handler{
		HostRules: []models.HostRule{
			{
				Host:       "fnknock.example.com",
				Target:     target.URL,
				UseAuth:    true,
				AccessMode: "login_first",
			},
		},
		AuthConfig: models.AuthConfig{
			AuthURL:      "/api/auth/verify",
			PreflightURL: "/api/auth/preflight",
		},
		authBridge:     bridge,
		authCache:      newAuthStateCache(),
		preflightCache: newPreflightStateCache(),
	}
	handler.publishRequestSnapshotLocked()

	req := httptest.NewRequest(http.MethodGet, "http://fnknock.example.com/private", nil)
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body = %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Location") != "" {
		t.Fatalf("Location = %q, want empty", rec.Header().Get("Location"))
	}
	if body := rec.Body.String(); !strings.Contains(body, `"code":"ACCESS_DENIED"`) {
		t.Fatalf("body did not include access denied JSON: %s", body)
	}
	if got := atomic.LoadInt32(&verifyHits); got != 1 {
		t.Fatalf("verify hits = %d, want 1", got)
	}
	if got := atomic.LoadInt32(&targetHits); got != 0 {
		t.Fatalf("target hits = %d, want 0", got)
	}
}

func TestHostRuleVerifyScopeDeniedCacheServesAccessDenied(t *testing.T) {
	var verifyHits int32

	bridge := testAuthBridge{
		verify: func(context.Context, *pb.VerifyAuthRequest) (*pb.VerifyAuthResponse, error) {
			atomic.AddInt32(&verifyHits, 1)
			return &pb.VerifyAuthResponse{
				Success:            false,
				Message:            "scope denied",
				Status:             http.StatusForbidden,
				AccessDeniedReason: reauthScopeDeniedReason,
			}, nil
		},
	}

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "target should not be reached", http.StatusTeapot)
	}))
	defer target.Close()

	handler := &Handler{
		HostRules: []models.HostRule{
			{
				Host:       "fnknock.example.com",
				Target:     target.URL,
				UseAuth:    true,
				AccessMode: "login_first",
			},
		},
		AuthConfig: models.AuthConfig{
			AuthURL:          "/api/auth/verify",
			PreflightURL:     "/api/auth/preflight",
			AuthCacheFailTTL: 60,
		},
		authBridge:     bridge,
		authCache:      newAuthStateCache(),
		preflightCache: newPreflightStateCache(),
	}
	handler.publishRequestSnapshotLocked()

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "http://fnknock.example.com/private", nil)
		req.Header.Set("Accept", "application/json")
		req.AddCookie(&http.Cookie{Name: authSessionCookieName, Value: "ok"})
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("request %d status = %d, want 403; body = %s", i+1, rec.Code, rec.Body.String())
		}
		if body := rec.Body.String(); !strings.Contains(body, `"code":"ACCESS_DENIED"`) {
			t.Fatalf("request %d body did not include access denied JSON: %s", i+1, body)
		}
	}

	if got := atomic.LoadInt32(&verifyHits); got != 1 {
		t.Fatalf("verify hits = %d, want 1 cached access_denied decision", got)
	}
}

func TestExpiredSessionClearCookieRedirectsAndInvalidatesAuthCaches(t *testing.T) {
	const (
		clientIP      = "198.51.100.40"
		expiredCookie = "expired-session"
		clearCookie   = authSessionCookieName + "=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"
		loginRedirect = "https://auth.example.com/login?redirect_uri=https%3A%2F%2Fapp.example.com%2Fprivate"
	)

	var verifyHits atomic.Int32
	var targetHits atomic.Int32
	bridge := testAuthBridge{
		verify: func(_ context.Context, request *pb.VerifyAuthRequest) (*pb.VerifyAuthResponse, error) {
			verifyHits.Add(1)
			if got := request.GetContext().GetCookie(); !strings.Contains(got, authSessionCookieName+"="+expiredCookie) {
				t.Fatalf("verify Cookie = %q, want expired session", got)
			}
			return &pb.VerifyAuthResponse{
				Success:          false,
				Status:           http.StatusUnauthorized,
				Message:          "session expired",
				SetCookies:       []string{clearCookie},
				RedirectLocation: loginRedirect,
			}, nil
		},
	}

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetHits.Add(1)
		http.Error(w, "target should not be reached", http.StatusTeapot)
	}))
	defer target.Close()

	handler := &Handler{
		HostRules: []models.HostRule{{
			Host:       "app.example.com",
			Target:     target.URL,
			UseAuth:    true,
			AccessMode: "login_first",
		}},
		AuthConfig: models.AuthConfig{
			AuthURL:          "/api/auth/verify",
			PreflightURL:     "/api/auth/preflight",
			AuthCacheTTL:     60,
			AuthCacheFailTTL: 60,
		},
		authBridge:     bridge,
		authCache:      newAuthStateCache(),
		preflightCache: newPreflightStateCache(),
	}
	handler.publishRequestSnapshotLocked()

	newRequest := func(requestPath string) *http.Request {
		request := httptest.NewRequest(http.MethodGet, "https://app.example.com"+requestPath, nil)
		request.RemoteAddr = clientIP + ":43210"
		request.AddCookie(&http.Cookie{Name: authSessionCookieName, Value: expiredCookie})
		return request
	}

	// Seed another request for the same session to prove that the clear-cookie
	// mutation invalidates both verify and preflight decisions by identity.
	staleRequest := newRequest("/previous")
	staleAuthLookup, ok := buildAuthCacheLookup(staleRequest, clientIP, "login_first")
	if !ok {
		t.Fatal("stale auth cache lookup was not buildable")
	}
	stalePreflightLookup, ok := buildPreflightCacheLookup(staleRequest, clientIP, "login_first", true)
	if !ok {
		t.Fatal("stale preflight cache lookup was not buildable")
	}
	now := time.Now()
	handler.authCacheStore(staleAuthLookup.cacheKey, authCacheEntry{
		result:      authCheckResult{allowed: true, authenticated: true, decision: "passed"},
		expiresAt:   now.Add(time.Minute),
		identityKey: staleAuthLookup.identityKey,
	}, now)
	handler.preflightCacheStore(stalePreflightLookup.cacheKey, preflightCacheEntry{
		decision:    preflightDecision{},
		expiresAt:   now.Add(time.Minute),
		identityKey: stalePreflightLookup.identityKey,
	}, now)

	request := newRequest("/private")
	currentPreflightLookup, ok := buildPreflightCacheLookup(request, clientIP, "login_first", true)
	if !ok {
		t.Fatal("current preflight cache lookup was not buildable")
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302; body = %s", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get("Location"); got != loginRedirect {
		t.Fatalf("Location = %q, want %q", got, loginRedirect)
	}
	if got := recorder.Header().Values("Set-Cookie"); len(got) != 1 || got[0] != clearCookie {
		t.Fatalf("Set-Cookie = %#v, want clear cookie %q", got, clearCookie)
	}
	assertAuthResponseNoStore(t, recorder.Header())
	if got := verifyHits.Load(); got != 1 {
		t.Fatalf("verify hits = %d, want 1", got)
	}
	if got := targetHits.Load(); got != 0 {
		t.Fatalf("target hits = %d, want 0", got)
	}
	if _, ok := handler.authCacheGet(staleAuthLookup.cacheKey, time.Now()); ok {
		t.Fatal("stale verify cache survived the expired-session clear cookie")
	}
	if _, ok := handler.preflightCacheGet(stalePreflightLookup.cacheKey, time.Now()); ok {
		t.Fatal("stale preflight cache survived the expired-session clear cookie")
	}
	if _, ok := handler.preflightCacheGet(currentPreflightLookup.cacheKey, time.Now()); ok {
		t.Fatal("current preflight decision was cached after the session clear cookie")
	}
}

func TestCachedAuthRedirectRemainsNoStore(t *testing.T) {
	var verifyHits atomic.Int32
	bridge := testAuthBridge{
		verify: func(context.Context, *pb.VerifyAuthRequest) (*pb.VerifyAuthResponse, error) {
			verifyHits.Add(1)
			return &pb.VerifyAuthResponse{
				Status:           http.StatusUnauthorized,
				RedirectLocation: "/login",
			}, nil
		},
	}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "target should not be reached", http.StatusTeapot)
	}))
	defer target.Close()

	handler := &Handler{
		HostRules: []models.HostRule{{
			Host:       "app.example.com",
			Target:     target.URL,
			UseAuth:    true,
			AccessMode: "login_first",
		}},
		AuthConfig: models.AuthConfig{
			AuthURL:          "/api/auth/verify",
			PreflightURL:     "/api/auth/preflight",
			AuthCacheFailTTL: 60,
		},
		authBridge:     bridge,
		authCache:      newAuthStateCache(),
		preflightCache: newPreflightStateCache(),
	}
	handler.publishRequestSnapshotLocked()

	for requestNumber := 1; requestNumber <= 2; requestNumber++ {
		request := httptest.NewRequest(http.MethodGet, "https://app.example.com/private", nil)
		request.AddCookie(&http.Cookie{Name: authSessionCookieName, Value: "invalid-session"})
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)

		if recorder.Code != http.StatusFound || recorder.Header().Get("Location") != "/login" {
			t.Fatalf("request %d response = status %d Location %q, want 302 /login", requestNumber, recorder.Code, recorder.Header().Get("Location"))
		}
		assertAuthResponseNoStore(t, recorder.Header())
	}
	if got := verifyHits.Load(); got != 1 {
		t.Fatalf("verify hits = %d, want 1 with cached second redirect", got)
	}
}

func TestAuthHostSensitiveResponsesAreNoStore(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=3600")
		if r.URL.Path == "/assets/session-reset" {
			w.Header().Add("Set-Cookie", authSessionCookieName+"=; Path=/; Max-Age=0")
		}
		_, _ = io.WriteString(w, r.URL.Path)
	}))
	defer authServer.Close()

	handler := &Handler{
		HostRules: []models.HostRule{{
			Host:            "auth.example.com",
			Target:          authServer.URL,
			SuppressToolbar: true,
		}},
		AuthConfig: models.AuthConfig{
			AuthHost: "auth.example.com",
			AuthPort: testServerPort(t, authServer.URL),
		},
		authCache:      newAuthStateCache(),
		preflightCache: newPreflightStateCache(),
	}
	handler.publishRequestSnapshotLocked()

	for _, requestPath := range []string{
		"/",
		"/login",
		"/oidc/bind",
		"/api/auth/logout",
		"/api/auth/oidc/callback/provider-1",
		"/auth/login",
		"/auth/api/auth/logout",
		"/__auth__/api/auth/oidc/callback/provider-1",
	} {
		t.Run(requestPath, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "https://auth.example.com"+requestPath, nil)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)

			if recorder.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body = %s", recorder.Code, recorder.Body.String())
			}
			assertAuthResponseNoStore(t, recorder.Header())
		})
	}

	for _, requestPath := range []string{
		"/assets/auth-view-deadbeef.js",
		"/auth/assets/auth-view-deadbeef.js",
		"/__auth__/assets/auth-view-deadbeef.js",
	} {
		request := httptest.NewRequest(http.MethodGet, "https://auth.example.com"+requestPath, nil)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if got := recorder.Header().Get("Cache-Control"); got != "public, max-age=3600" {
			t.Fatalf("static asset %q Cache-Control = %q, want upstream cache policy", requestPath, got)
		}
	}

	request := httptest.NewRequest(http.MethodGet, "https://auth.example.com/assets/session-reset", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if got := recorder.Header().Values("Set-Cookie"); len(got) != 1 {
		t.Fatalf("session reset Set-Cookie = %#v, want one forwarded cookie", got)
	}
	assertAuthResponseNoStore(t, recorder.Header())
}

func assertAuthResponseNoStore(t *testing.T, headers http.Header) {
	t.Helper()
	want := map[string]string{
		"Cache-Control":     "private, no-store, no-cache, max-age=0, must-revalidate",
		"Pragma":            "no-cache",
		"Expires":           "0",
		"CDN-Cache-Control": "private, no-store",
		"Surrogate-Control": "no-store",
	}
	for name, value := range want {
		if got := headers.Get(name); got != value {
			t.Fatalf("%s = %q, want %q", name, got, value)
		}
	}
}
