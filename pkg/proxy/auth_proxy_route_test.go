package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

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

func TestAuthLogoutRouteIgnoresScopeDeniedPreflight(t *testing.T) {
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
		preflight: func(_ context.Context, in *pb.PreflightAuthRequest) (*pb.PreflightAuthResponse, error) {
			atomic.AddInt32(&preflightHits, 1)
			if got := in.GetContext().GetForwardedPath(); got != "/__auth__/api/auth/logout" {
				t.Fatalf("X-Forwarded-Path = %q, want /__auth__/api/auth/logout", got)
			}
			return &pb.PreflightAuthResponse{AccessDeniedReason: reauthScopeDeniedReason}, nil
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
	if got := atomic.LoadInt32(&preflightHits); got != 1 {
		t.Fatalf("preflight hits = %d, want 1", got)
	}
	if got := atomic.LoadInt32(&logoutHits); got != 1 {
		t.Fatalf("logout hits = %d, want 1", got)
	}
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
