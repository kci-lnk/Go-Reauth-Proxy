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
	"go-reauth-proxy/pkg/response"
)

type toolbarDataEnvelope struct {
	RuntimeURL string `json:"runtime_url"`
	Data       struct {
		Rules []struct {
			Path string `json:"path"`
		} `json:"rules"`
		HostRules []struct {
			Host string `json:"host"`
		} `json:"host_rules"`
		CurrentPath string `json:"current_path"`
		CurrentHost string `json:"current_host"`
	} `json:"data"`
}

func authenticatedToolbarDataRequest(method string, host string, pagePath string) *http.Request {
	req := httptest.NewRequest(method, "http://"+host+response.ToolbarDataPath()+"?page_path="+pagePath, nil)
	req.AddCookie(&http.Cookie{Name: authSessionCookieName, Value: "ok"})
	return req
}

func decodeToolbarDataEnvelope(t *testing.T, rec *httptest.ResponseRecorder) toolbarDataEnvelope {
	t.Helper()
	var payload toolbarDataEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode toolbar data: %v\n%s", err, rec.Body.String())
	}
	return payload
}

func TestToolbarDataRouteUsesOriginalPageContextAndLatestSnapshot(t *testing.T) {
	var verifyCalls int32
	bridge := testAuthBridge{
		verify: func(_ context.Context, in *pb.VerifyAuthRequest) (*pb.VerifyAuthResponse, error) {
			atomic.AddInt32(&verifyCalls, 1)
			if got := in.GetContext().GetPath(); got != "/dashboard" {
				t.Fatalf("auth context path = %q, want /dashboard", got)
			}
			if got := in.GetContext().GetRawQuery(); got != "tab=recent" {
				t.Fatalf("auth context query = %q, want tab=recent", got)
			}
			return &pb.VerifyAuthResponse{Success: true, Status: http.StatusOK, LoginAuthenticated: true}, nil
		},
	}
	target := newToolbarHTMLTarget(t)
	defer target.Close()
	handler := newPublicHostToolbarHandler(target.URL, bridge)

	first := httptest.NewRecorder()
	firstRequest := authenticatedToolbarDataRequest(http.MethodGet, "public.example.com", "/dashboard")
	firstRequest.Header.Set(toolbarPageQueryHeader, "tab=recent")
	handler.ServeHTTP(first, firstRequest)
	if first.Code != http.StatusOK {
		t.Fatalf("first status = %d, body = %s", first.Code, first.Body.String())
	}
	if cacheControl := first.Header().Get("Cache-Control"); !strings.Contains(cacheControl, "no-store") {
		t.Fatalf("Cache-Control = %q, want no-store", cacheControl)
	}
	firstPayload := decodeToolbarDataEnvelope(t, first)
	if firstPayload.Data.CurrentPath != "/dashboard" || firstPayload.Data.CurrentHost != "public.example.com" {
		t.Fatalf("unexpected first context: %#v", firstPayload.Data)
	}
	if firstPayload.RuntimeURL != response.ToolbarAssetPath() {
		t.Fatalf("first runtime_url = %q", firstPayload.RuntimeURL)
	}

	handler.mu.Lock()
	handler.HostRules = append(handler.HostRules, models.HostRule{
		Host:   "second.example.com",
		Target: target.URL,
	})
	handler.GatewayPortal.Version = models.GatewayPortalVersionV2
	handler.publishRequestSnapshotLocked()
	handler.mu.Unlock()

	second := httptest.NewRecorder()
	secondRequest := authenticatedToolbarDataRequest(http.MethodGet, "public.example.com", "/dashboard")
	secondRequest.Header.Set(toolbarPageQueryHeader, "tab=recent")
	handler.ServeHTTP(second, secondRequest)
	if second.Code != http.StatusOK {
		t.Fatalf("second status = %d, body = %s", second.Code, second.Body.String())
	}
	secondPayload := decodeToolbarDataEnvelope(t, second)
	if secondPayload.RuntimeURL != response.ToolbarAssetPathForVersion(models.GatewayPortalVersionV2) {
		t.Fatalf("second runtime_url = %q", secondPayload.RuntimeURL)
	}
	foundSecondHost := false
	for _, rule := range secondPayload.Data.HostRules {
		if rule.Host == "second.example.com" {
			foundSecondHost = true
			break
		}
	}
	if !foundSecondHost {
		t.Fatalf("updated host rules missing from second response: %#v", secondPayload.Data.HostRules)
	}
	if got := atomic.LoadInt32(&verifyCalls); got < 1 {
		t.Fatalf("verify calls = %d, want at least 1", got)
	}
}

func TestToolbarDataRouteRevalidatesAuthenticationAfterLogout(t *testing.T) {
	const clearSessionCookie = authSessionCookieName + "=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"
	var verifyCalls atomic.Int32
	var loggedOut atomic.Bool
	bridge := testAuthBridge{
		verify: func(context.Context, *pb.VerifyAuthRequest) (*pb.VerifyAuthResponse, error) {
			verifyCalls.Add(1)
			if loggedOut.Load() {
				return &pb.VerifyAuthResponse{
					Success:    false,
					Status:     http.StatusUnauthorized,
					Message:    "session revoked",
					SetCookies: []string{clearSessionCookie},
				}, nil
			}
			return &pb.VerifyAuthResponse{Success: true, Status: http.StatusOK, LoginAuthenticated: true}, nil
		},
	}
	target := newToolbarHTMLTarget(t)
	defer target.Close()
	handler := newPublicHostToolbarHandler(target.URL, bridge)
	handler.mu.Lock()
	handler.AuthConfig.AuthCacheTTL = 60
	handler.publishRequestSnapshotLocked()
	handler.mu.Unlock()

	// A normal page request populates the shared proxy-auth cache for this
	// session and page context before the user logs out.
	pageRequest := httptest.NewRequest(http.MethodGet, "http://public.example.com/", nil)
	pageRequest.AddCookie(&http.Cookie{Name: authSessionCookieName, Value: "ok"})
	pageResponse := httptest.NewRecorder()
	handler.ServeHTTP(pageResponse, pageRequest)
	if pageResponse.Code != http.StatusOK {
		t.Fatalf("authenticated page response = %d %q", pageResponse.Code, pageResponse.Body.String())
	}
	handler.authCache.mu.RLock()
	cachedEntries := len(handler.authCache.entries)
	handler.authCache.mu.RUnlock()
	if cachedEntries == 0 {
		t.Fatal("authenticated page request did not seed the proxy-auth cache")
	}

	// Keep the same browser cookie to model a logout/revocation racing cookie
	// removal. The data endpoint must bypass that positive cache entry and
	// treat the authentication service as authoritative.
	loggedOut.Store(true)
	second := httptest.NewRecorder()
	handler.ServeHTTP(second, authenticatedToolbarDataRequest(http.MethodGet, "public.example.com", "/"))
	if second.Code != http.StatusNoContent || second.Body.Len() != 0 {
		t.Fatalf("logged-out response = %d %q", second.Code, second.Body.String())
	}
	if got := second.Header().Values("Set-Cookie"); len(got) != 1 || got[0] != clearSessionCookie {
		t.Fatalf("logged-out Set-Cookie = %#v, want clear cookie", got)
	}
	if got := verifyCalls.Load(); got != 2 {
		t.Fatalf("verify calls = %d, want 2 fresh checks", got)
	}
	handler.authCache.mu.RLock()
	remainingCachedEntries := len(handler.authCache.entries)
	handler.authCache.mu.RUnlock()
	if remainingCachedEntries != 0 {
		t.Fatalf("stale proxy-auth cache entries after revocation = %d", remainingCachedEntries)
	}
}

func TestToolbarDataRouteDoesNotTreatRouteAccessAsLogin(t *testing.T) {
	const clearSessionCookie = authSessionCookieName + "=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"
	tests := []struct {
		name       string
		credential func(*http.Request)
		setCookies []string
	}{
		{
			name: "forged session cookie",
			credential: func(r *http.Request) {
				r.AddCookie(&http.Cookie{Name: authSessionCookieName, Value: "forged"})
			},
			setCookies: []string{clearSessionCookie},
		},
		{
			name: "forged share cookie",
			credential: func(r *http.Request) {
				r.AddCookie(&http.Cookie{Name: authShareSessionCookieName, Value: "forged"})
			},
		},
		{
			name: "forged authorization header",
			credential: func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer forged")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var verifyCalls atomic.Int32
			bridge := testAuthBridge{
				verify: func(context.Context, *pb.VerifyAuthRequest) (*pb.VerifyAuthResponse, error) {
					verifyCalls.Add(1)
					return &pb.VerifyAuthResponse{
						Success:            true,
						Status:             http.StatusOK,
						LoginAuthenticated: false,
						SetCookies:         test.setCookies,
					}, nil
				},
			}
			target := newToolbarHTMLTarget(t)
			defer target.Close()
			handler := newPublicHostToolbarHandler(target.URL, bridge)
			req := httptest.NewRequest(http.MethodGet, "http://public.example.com"+response.ToolbarDataPath()+"?page_path=/", nil)
			test.credential(req)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusNoContent || rec.Body.Len() != 0 {
				t.Fatalf("route-authorized anonymous response = %d %q", rec.Code, rec.Body.String())
			}
			if got := verifyCalls.Load(); got != 1 {
				t.Fatalf("verify calls = %d, want 1", got)
			}
			if got := rec.Header().Get("Cache-Control"); !strings.Contains(got, "no-store") {
				t.Fatalf("Cache-Control = %q, want no-store", got)
			}
		})
	}
}

func TestToolbarDataRoutePreservesAccessModeAndAdvancedPolicyCacheDimension(t *testing.T) {
	var verifyCalls int32
	bridge := testAuthBridge{
		verify: func(_ context.Context, in *pb.VerifyAuthRequest) (*pb.VerifyAuthResponse, error) {
			atomic.AddInt32(&verifyCalls, 1)
			if got := in.GetContext().GetAccessMode(); got != "strict_whitelist" {
				t.Fatalf("auth context access_mode = %q", got)
			}
			return &pb.VerifyAuthResponse{
				Success:            true,
				Status:             http.StatusOK,
				LoginAuthenticated: true,
				CacheMaxAgeSeconds: 60,
			}, nil
		},
	}
	target := newToolbarHTMLTarget(t)
	defer target.Close()
	handler := newPublicHostToolbarHandler(target.URL, bridge)
	handler.mu.Lock()
	handler.HostRules[0].UseAuth = true
	handler.HostRules[0].AccessMode = "strict_whitelist"
	handler.HostRules[0].AdvancedAuth.PolicyVersion = "policy-a"
	handler.AuthConfig.AuthCacheTTL = 60
	handler.publishRequestSnapshotLocked()
	handler.mu.Unlock()

	first := httptest.NewRecorder()
	handler.ServeHTTP(first, authenticatedToolbarDataRequest(http.MethodGet, "public.example.com", "/"))
	if first.Code != http.StatusOK {
		t.Fatalf("first status = %d, body = %s", first.Code, first.Body.String())
	}

	handler.mu.Lock()
	handler.HostRules[0].AdvancedAuth.PolicyVersion = "policy-b"
	handler.publishRequestSnapshotLocked()
	handler.mu.Unlock()
	second := httptest.NewRecorder()
	handler.ServeHTTP(second, authenticatedToolbarDataRequest(http.MethodGet, "public.example.com", "/"))
	if second.Code != http.StatusOK {
		t.Fatalf("second status = %d, body = %s", second.Code, second.Body.String())
	}
	if got := atomic.LoadInt32(&verifyCalls); got != 2 {
		t.Fatalf("verify calls = %d, want 2 after advanced policy rotation", got)
	}
}

func TestToolbarDataRouteFailsClosed(t *testing.T) {
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

	unauthenticated := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://public.example.com"+response.ToolbarDataPath()+"?page_path=/", nil)
	handler.ServeHTTP(unauthenticated, req)
	if unauthenticated.Code != http.StatusNoContent || unauthenticated.Body.Len() != 0 {
		t.Fatalf("unauthenticated response = %d %q", unauthenticated.Code, unauthenticated.Body.String())
	}
	if got := atomic.LoadInt32(&verifyCalls); got != 0 {
		t.Fatalf("unauthenticated request made %d verify calls", got)
	}

	handler.mu.Lock()
	handler.HostRules[0].SuppressToolbar = true
	handler.publishRequestSnapshotLocked()
	handler.mu.Unlock()
	suppressed := httptest.NewRecorder()
	handler.ServeHTTP(suppressed, authenticatedToolbarDataRequest(http.MethodGet, "public.example.com", "/"))
	if suppressed.Code != http.StatusNoContent || suppressed.Body.Len() != 0 {
		t.Fatalf("suppressed response = %d %q", suppressed.Code, suppressed.Body.String())
	}
	if got := atomic.LoadInt32(&verifyCalls); got != 0 {
		t.Fatalf("suppressed request made %d verify calls", got)
	}

	handler.mu.Lock()
	handler.HostRules[0].SuppressToolbar = false
	handler.HostRules[0].Disabled = true
	handler.publishRequestSnapshotLocked()
	handler.mu.Unlock()
	unavailable := httptest.NewRecorder()
	handler.ServeHTTP(unavailable, authenticatedToolbarDataRequest(http.MethodGet, "public.example.com", "/"))
	if unavailable.Code != http.StatusNoContent || unavailable.Body.Len() != 0 {
		t.Fatalf("unavailable response = %d %q", unavailable.Code, unavailable.Body.String())
	}
	if got := atomic.LoadInt32(&verifyCalls); got != 0 {
		t.Fatalf("unavailable request made %d verify calls", got)
	}

	handler.mu.Lock()
	handler.HostRules[0].Disabled = false
	handler.GatewayPortal = disabledGatewayPortalConfigForProxyTest(t)
	handler.publishRequestSnapshotLocked()
	handler.mu.Unlock()
	disabledPortal := httptest.NewRecorder()
	handler.ServeHTTP(disabledPortal, authenticatedToolbarDataRequest(http.MethodGet, "public.example.com", "/"))
	if disabledPortal.Code != http.StatusNoContent || disabledPortal.Body.Len() != 0 {
		t.Fatalf("disabled portal response = %d %q", disabledPortal.Code, disabledPortal.Body.String())
	}
	if got := atomic.LoadInt32(&verifyCalls); got != 0 {
		t.Fatalf("disabled portal request made %d verify calls", got)
	}

	invalid := httptest.NewRecorder()
	handler.ServeHTTP(invalid, httptest.NewRequest(http.MethodGet, "http://public.example.com"+response.ToolbarDataPath(), nil))
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("missing page_path status = %d", invalid.Code)
	}
	invalidQuery := httptest.NewRecorder()
	invalidQueryRequest := authenticatedToolbarDataRequest(http.MethodGet, "public.example.com", "/")
	invalidQueryRequest.Header.Set(toolbarPageQueryHeader, "tab=recent#fragment")
	handler.ServeHTTP(invalidQuery, invalidQueryRequest)
	if invalidQuery.Code != http.StatusBadRequest {
		t.Fatalf("invalid page query status = %d", invalidQuery.Code)
	}
	invalidUTF8 := httptest.NewRecorder()
	handler.ServeHTTP(invalidUTF8, httptest.NewRequest(http.MethodGet, "http://public.example.com"+response.ToolbarDataPath()+"?page_path=%2F%FF", nil))
	if invalidUTF8.Code != http.StatusBadRequest {
		t.Fatalf("invalid UTF-8 page_path status = %d", invalidUTF8.Code)
	}
	duplicatePath := httptest.NewRecorder()
	handler.ServeHTTP(duplicatePath, httptest.NewRequest(http.MethodGet, "http://public.example.com"+response.ToolbarDataPath()+"?page_path=%2F&page_path=%2Fadmin", nil))
	if duplicatePath.Code != http.StatusBadRequest {
		t.Fatalf("duplicate page_path status = %d", duplicatePath.Code)
	}
	unknownParameter := httptest.NewRecorder()
	handler.ServeHTTP(unknownParameter, httptest.NewRequest(http.MethodGet, "http://public.example.com"+response.ToolbarDataPath()+"?page_path=%2F&extra=value", nil))
	if unknownParameter.Code != http.StatusBadRequest {
		t.Fatalf("unknown toolbar data parameter status = %d", unknownParameter.Code)
	}
	invalidEncodedQuery := httptest.NewRecorder()
	invalidEncodedQueryRequest := authenticatedToolbarDataRequest(http.MethodGet, "public.example.com", "/")
	invalidEncodedQueryRequest.Header.Set(toolbarPageQueryHeader, "tab=%FF")
	handler.ServeHTTP(invalidEncodedQuery, invalidEncodedQueryRequest)
	if invalidEncodedQuery.Code != http.StatusBadRequest {
		t.Fatalf("invalid encoded page query status = %d", invalidEncodedQuery.Code)
	}

	methodNotAllowed := httptest.NewRecorder()
	handler.ServeHTTP(methodNotAllowed, authenticatedToolbarDataRequest(http.MethodPost, "public.example.com", "/"))
	if methodNotAllowed.Code != http.StatusMethodNotAllowed || methodNotAllowed.Header().Get("Allow") != "GET, HEAD" {
		t.Fatalf("POST response = %d Allow=%q", methodNotAllowed.Code, methodNotAllowed.Header().Get("Allow"))
	}
}

func TestToolbarDataRouteHonorsAuthToolbarSuppression(t *testing.T) {
	bridge := testAuthBridge{
		verify: func(context.Context, *pb.VerifyAuthRequest) (*pb.VerifyAuthResponse, error) {
			return &pb.VerifyAuthResponse{
				Success:         true,
				Status:          http.StatusOK,
				SuppressToolbar: true,
			}, nil
		},
	}
	target := newToolbarHTMLTarget(t)
	defer target.Close()
	handler := newPublicHostToolbarHandler(target.URL, bridge)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, authenticatedToolbarDataRequest(http.MethodGet, "public.example.com", "/"))
	if rec.Code != http.StatusNoContent || rec.Body.Len() != 0 {
		t.Fatalf("auth-suppressed response = %d %q", rec.Code, rec.Body.String())
	}
}

func TestToolbarDataRouteHeadReturnsMetadataWithoutBody(t *testing.T) {
	target := newToolbarHTMLTarget(t)
	defer target.Close()
	handler := newPublicHostToolbarHandler(target.URL, testAuthBridge{})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, authenticatedToolbarDataRequest(http.MethodHead, "public.example.com", "/"))
	if rec.Code != http.StatusOK || rec.Body.Len() != 0 {
		t.Fatalf("HEAD response = %d %q", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Content-Type") != "application/json; charset=utf-8" || rec.Header().Get("Content-Length") == "" {
		t.Fatalf("HEAD metadata headers = %#v", rec.Header())
	}
}

func TestToolbarProxyRefreshesHTMLWithoutChangingUpstreamCachePolicy(t *testing.T) {
	var htmlConditionalSeen atomic.Bool
	var staticConditionalSeen atomic.Bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/app.js" {
			w.Header().Set("Content-Type", "text/javascript")
			w.Header().Set("Cache-Control", "public, max-age=86400")
			w.Header().Set("ETag", `"static"`)
			if r.Header.Get("If-None-Match") == `"static"` {
				staticConditionalSeen.Store(true)
				w.WriteHeader(http.StatusNotModified)
				return
			}
			_, _ = io.WriteString(w, "window.app = true;")
			return
		}

		if r.Header.Get("If-None-Match") != "" || r.Header.Get("If-Modified-Since") != "" {
			htmlConditionalSeen.Store(true)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.Header().Set("ETag", `"upstream-html"`)
		w.Header().Set("Last-Modified", "Wed, 21 Oct 2015 07:28:00 GMT")
		w.Header().Set("Content-MD5", "stale-digest")
		w.Header().Set("Content-Digest", "sha-256=:stale:")
		w.Header().Set("Accept-Ranges", "bytes")
		_, _ = io.WriteString(w, "<!doctype html><html><body><main>app</main></body></html>")
	}))
	defer upstream.Close()

	handler := newPublicHostToolbarHandler(upstream.URL, testAuthBridge{})
	htmlReq := httptest.NewRequest(http.MethodGet, "http://public.example.com/", nil)
	htmlReq.AddCookie(&http.Cookie{Name: authSessionCookieName, Value: "ok"})
	htmlReq.Header.Set("Sec-Fetch-Dest", "document")
	htmlReq.Header.Set("If-None-Match", `"old-toolbar-page"`)
	htmlReq.Header.Set("If-Modified-Since", "Wed, 21 Oct 2015 07:28:00 GMT")
	htmlRec := httptest.NewRecorder()
	handler.ServeHTTP(htmlRec, htmlReq)

	if htmlRec.Code != http.StatusOK {
		t.Fatalf("HTML status = %d, body = %s", htmlRec.Code, htmlRec.Body.String())
	}
	if htmlConditionalSeen.Load() {
		t.Fatal("HTML validators reached upstream")
	}
	if got := htmlRec.Header().Get("Cache-Control"); got != "public, max-age=3600" {
		t.Fatalf("HTML Cache-Control = %q", got)
	}
	for _, name := range []string{"ETag", "Last-Modified", "Content-MD5", "Content-Digest", "Accept-Ranges"} {
		if got := htmlRec.Header().Get(name); got != "" {
			t.Fatalf("mutated HTML retained %s: %q", name, got)
		}
	}
	body := htmlRec.Body.String()
	if !strings.Contains(body, response.ToolbarBootstrapAssetPath()) || strings.Contains(body, "data-toolbar") {
		t.Fatalf("HTML did not contain data-free bootstrap: %s", body)
	}

	staticReq := httptest.NewRequest(http.MethodGet, "http://public.example.com/app.js", nil)
	staticReq.AddCookie(&http.Cookie{Name: authSessionCookieName, Value: "ok"})
	staticReq.Header.Set("Sec-Fetch-Dest", "script")
	staticReq.Header.Set("If-None-Match", `"static"`)
	staticRec := httptest.NewRecorder()
	handler.ServeHTTP(staticRec, staticReq)
	if staticRec.Code != http.StatusNotModified || !staticConditionalSeen.Load() {
		t.Fatalf("static response = %d, validator seen=%v", staticRec.Code, staticConditionalSeen.Load())
	}
	if got := staticRec.Header().Get("ETag"); got != `"static"` {
		t.Fatalf("static ETag = %q", got)
	}
}

func TestPrepareToolbarProxyRequestPreservesClearStaticRequests(t *testing.T) {
	document := httptest.NewRequest(http.MethodGet, "http://example.com/app", nil)
	document.Header.Set("Sec-Fetch-Dest", "document")
	document.Header.Set("Accept-Encoding", "gzip")
	document.Header.Set("If-None-Match", `"document"`)
	prepareToolbarProxyRequest(document)
	if document.Header.Get("Accept-Encoding") != "" || document.Header.Get("If-None-Match") != "" {
		t.Fatalf("document conditionals were not removed: %#v", document.Header)
	}

	static := httptest.NewRequest(http.MethodGet, "http://example.com/app.css", nil)
	static.Header.Set("Sec-Fetch-Dest", "style")
	static.Header.Set("Accept-Encoding", "gzip")
	static.Header.Set("If-None-Match", `"static"`)
	prepareToolbarProxyRequest(static)
	if static.Header.Get("Accept-Encoding") != "gzip" || static.Header.Get("If-None-Match") != `"static"` {
		t.Fatalf("static request headers changed: %#v", static.Header)
	}
}
