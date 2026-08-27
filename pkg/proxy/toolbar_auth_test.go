package proxy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"go-reauth-proxy/pkg/grpc/pb"
	"go-reauth-proxy/pkg/models"
)

func disabledGatewayPortalConfigForProxyTest(t *testing.T) models.GatewayPortalConfig {
	t.Helper()

	var cfg models.GatewayPortalConfig
	if err := json.Unmarshal([]byte(`{"enabled":false}`), &cfg); err != nil {
		t.Fatalf("unmarshal disabled gateway portal config: %v", err)
	}
	return cfg
}

func newToolbarHTMLTarget(t *testing.T) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, "<!doctype html><html><body><main>public app</main></body></html>")
	}))
}

func newPublicHostToolbarHandler(targetURL string, bridge authBridgeClient) *Handler {
	h := &Handler{
		HostRules: []models.HostRule{
			{
				Host:    "public.example.com",
				Target:  targetURL,
				UseAuth: false,
			},
		},
		AuthConfig: models.AuthConfig{
			AuthURL: "/api/auth/verify",
		},
		authBridge:     bridge,
		authCache:      newAuthStateCache(),
		preflightCache: newPreflightStateCache(),
	}
	h.publishRequestSnapshotLocked()
	return h
}

func TestPublicHostRuleInjectsToolbarWhenAuthCookieIsAuthenticated(t *testing.T) {
	var verifyCalls int32
	bridge := testAuthBridge{
		verify: func(_ context.Context, in *pb.VerifyAuthRequest) (*pb.VerifyAuthResponse, error) {
			t.Helper()

			ctx := in.GetContext()
			atomic.AddInt32(&verifyCalls, 1)
			if !strings.Contains(ctx.GetCookie(), authSessionCookieName+"=ok") {
				t.Fatalf("auth request Cookie = %q, want %s=ok", ctx.GetCookie(), authSessionCookieName)
			}
			return &pb.VerifyAuthResponse{Success: true, Status: http.StatusOK, LoginAuthenticated: true}, nil
		},
	}

	target := newToolbarHTMLTarget(t)
	defer target.Close()

	handler := newPublicHostToolbarHandler(target.URL, bridge)
	req := httptest.NewRequest(http.MethodGet, "http://public.example.com/", nil)
	req.AddCookie(&http.Cookie{Name: authSessionCookieName, Value: "ok"})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	if got := atomic.LoadInt32(&verifyCalls); got != 1 {
		t.Fatalf("verify calls = %d, want 1", got)
	}
	if body := rec.Body.String(); !strings.Contains(body, "reauth-proxy-toolbar") {
		t.Fatalf("response body did not include toolbar: %s", body)
	}
}

func TestPublicHostRuleDoesNotProbeOrInjectToolbarForWebSocketTarget(t *testing.T) {
	var verifyCalls int32
	bridge := testAuthBridge{
		verify: func(context.Context, *pb.VerifyAuthRequest) (*pb.VerifyAuthResponse, error) {
			atomic.AddInt32(&verifyCalls, 1)
			return &pb.VerifyAuthResponse{Success: true, Status: http.StatusOK}, nil
		},
	}

	target := newToolbarHTMLTarget(t)
	defer target.Close()

	webSocketTargetURL := strings.Replace(target.URL, "http://", "ws://", 1)
	handler := newPublicHostToolbarHandler(webSocketTargetURL, bridge)
	req := httptest.NewRequest(http.MethodGet, "http://public.example.com/", nil)
	req.AddCookie(&http.Cookie{Name: authSessionCookieName, Value: "ok"})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	if got := atomic.LoadInt32(&verifyCalls); got != 0 {
		t.Fatalf("verify calls = %d, want 0 for WebSocket target toolbar probe", got)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "public app") {
		t.Fatalf("response body did not include upstream HTML: %s", body)
	}
	if strings.Contains(body, "reauth-proxy-toolbar") {
		t.Fatalf("response body included toolbar for WebSocket target: %s", body)
	}
}

func TestPublicHostRuleDoesNotProbeOrInjectToolbarWhenPortalDisabled(t *testing.T) {
	var verifyCalls int32
	bridge := testAuthBridge{
		verify: func(context.Context, *pb.VerifyAuthRequest) (*pb.VerifyAuthResponse, error) {
			atomic.AddInt32(&verifyCalls, 1)
			return &pb.VerifyAuthResponse{Success: true, Status: http.StatusOK}, nil
		},
	}

	target := newToolbarHTMLTarget(t)
	defer target.Close()

	handler := newPublicHostToolbarHandler(target.URL, bridge)
	handler.mu.Lock()
	handler.GatewayPortal = disabledGatewayPortalConfigForProxyTest(t)
	handler.publishRequestSnapshotLocked()
	handler.mu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "http://public.example.com/", nil)
	req.AddCookie(&http.Cookie{Name: authSessionCookieName, Value: "ok"})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	if got := atomic.LoadInt32(&verifyCalls); got != 0 {
		t.Fatalf("verify calls = %d, want 0 when portal is disabled", got)
	}
	if body := rec.Body.String(); strings.Contains(body, "reauth-proxy-toolbar") {
		t.Fatalf("response body included toolbar while portal disabled: %s", body)
	}
}

func TestPublicHostRuleDoesNotInjectToolbarWithoutAuthIdentity(t *testing.T) {
	var verifyCalls int32
	bridge := testAuthBridge{
		verify: func(context.Context, *pb.VerifyAuthRequest) (*pb.VerifyAuthResponse, error) {
			atomic.AddInt32(&verifyCalls, 1)
			return &pb.VerifyAuthResponse{Success: true, Status: http.StatusOK}, nil
		},
	}

	target := newToolbarHTMLTarget(t)
	defer target.Close()

	handler := newPublicHostToolbarHandler(target.URL, bridge)
	req := httptest.NewRequest(http.MethodGet, "http://public.example.com/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	if got := atomic.LoadInt32(&verifyCalls); got != 0 {
		t.Fatalf("verify calls = %d, want 0", got)
	}
	if body := rec.Body.String(); strings.Contains(body, "reauth-proxy-toolbar") {
		t.Fatalf("response body included toolbar for anonymous public request: %s", body)
	}
}

func TestPublicHostRuleDoesNotProbeToolbarAuthForOrdinaryCookie(t *testing.T) {
	var verifyCalls int32
	bridge := testAuthBridge{
		verify: func(context.Context, *pb.VerifyAuthRequest) (*pb.VerifyAuthResponse, error) {
			atomic.AddInt32(&verifyCalls, 1)
			return &pb.VerifyAuthResponse{Success: true, Status: http.StatusOK}, nil
		},
	}

	target := newToolbarHTMLTarget(t)
	defer target.Close()

	handler := newPublicHostToolbarHandler(target.URL, bridge)
	req := httptest.NewRequest(http.MethodGet, "http://public.example.com/", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: "business-app"})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	if got := atomic.LoadInt32(&verifyCalls); got != 0 {
		t.Fatalf("verify calls = %d, want 0", got)
	}
	if body := rec.Body.String(); strings.Contains(body, "reauth-proxy-toolbar") {
		t.Fatalf("response body included toolbar for ordinary public cookie: %s", body)
	}
}

func TestPublicHostRuleDoesNotInjectToolbarWhenAuthCookieIsRejected(t *testing.T) {
	bridge := testAuthBridge{
		verify: func(context.Context, *pb.VerifyAuthRequest) (*pb.VerifyAuthResponse, error) {
			return &pb.VerifyAuthResponse{Success: false, Message: "expired", Status: http.StatusOK}, nil
		},
	}

	target := newToolbarHTMLTarget(t)
	defer target.Close()

	handler := newPublicHostToolbarHandler(target.URL, bridge)
	req := httptest.NewRequest(http.MethodGet, "http://public.example.com/", nil)
	req.AddCookie(&http.Cookie{Name: authSessionCookieName, Value: "expired"})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want public upstream response; body = %s", rec.Code, rec.Body.String())
	}
	if location := rec.Header().Get("Location"); location != "" {
		t.Fatalf("Location = %q, want no redirect for public route", location)
	}
	if body := rec.Body.String(); strings.Contains(body, "reauth-proxy-toolbar") {
		t.Fatalf("response body included toolbar for rejected auth cookie: %s", body)
	}
}

func TestUnavailablePublicHostHidesSelectLinkWithoutAuthenticatedIdentity(t *testing.T) {
	target := newToolbarHTMLTarget(t)
	targetURL := target.URL
	target.Close()

	handler := newPublicHostToolbarHandler(targetURL, testAuthBridge{})
	req := httptest.NewRequest(http.MethodGet, "http://public.example.com/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body = %s", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); strings.Contains(body, "/__select__") {
		t.Fatalf("anonymous upstream error included select link: %s", body)
	}
	targetAddress := strings.TrimPrefix(targetURL, "http://")
	// The target address is a stable, sensitive detail across platforms. Do not
	// couple this privacy check to OS-generated connection error wording.
	if body := rec.Body.String(); strings.Contains(body, targetAddress) {
		t.Fatalf("default upstream error exposed connection details: %s", body)
	}
}

func TestUnavailablePublicHostCanShowConnectionDetailsForTroubleshooting(t *testing.T) {
	target := newToolbarHTMLTarget(t)
	targetURL := target.URL
	target.Close()

	handler := newPublicHostToolbarHandler(targetURL, testAuthBridge{})
	handler.GatewayUnmatchedRoute.UpstreamErrorDetail = models.GatewayUpstreamErrorDetailMore
	handler.publishRequestSnapshotLocked()
	req := httptest.NewRequest(http.MethodGet, "http://public.example.com/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body = %s", rec.Code, rec.Body.String())
	}
	targetAddress := strings.TrimPrefix(targetURL, "http://")
	// Go preserves the target address in net.OpError on every supported OS, but
	// the accompanying text is platform-specific (for example, Winsock says
	// "actively refused it" instead of Unix's "connection refused").
	if body := rec.Body.String(); !strings.Contains(body, targetAddress) {
		t.Fatalf("detailed upstream error omitted connection details: %s", body)
	}
}

func TestUnavailablePublicHostShowsSelectLinkForAuthenticatedIdentity(t *testing.T) {
	target := newToolbarHTMLTarget(t)
	targetURL := target.URL
	target.Close()

	bridge := testAuthBridge{
		verify: func(context.Context, *pb.VerifyAuthRequest) (*pb.VerifyAuthResponse, error) {
			return &pb.VerifyAuthResponse{Success: true, Status: http.StatusOK, LoginAuthenticated: true}, nil
		},
	}
	handler := newPublicHostToolbarHandler(targetURL, bridge)
	req := httptest.NewRequest(http.MethodGet, "http://public.example.com/", nil)
	req.AddCookie(&http.Cookie{Name: authSessionCookieName, Value: "ok"})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body = %s", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); !strings.Contains(body, "/__select__") {
		t.Fatalf("authenticated upstream error did not include select link: %s", body)
	}
}
