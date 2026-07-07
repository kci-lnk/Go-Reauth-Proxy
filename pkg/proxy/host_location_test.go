package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go-reauth-proxy/pkg/grpc/pb"
	"go-reauth-proxy/pkg/models"
)

func newHostLocationTestHandler(rule models.HostRule) *Handler {
	handler := &Handler{
		HostRules:      []models.HostRule{rule},
		authCache:      newAuthStateCache(),
		preflightCache: newPreflightStateCache(),
	}
	handler.publishRequestSnapshotLocked()
	return handler
}

func TestSetHostRulesRejectsRootHostLocation(t *testing.T) {
	handler := &Handler{}
	err := handler.SetHostRules([]models.HostRule{
		{
			Host:   "app.example.com",
			Target: "http://127.0.0.1:8080",
			Locations: []models.HostLocation{
				{
					Path:   "/",
					Match:  models.HostLocationMatchPrefix,
					Action: models.HostLocationActionResponse,
					Response: models.HostLocationResponse{
						Body: "root",
					},
				},
			},
		},
	})
	if err == nil {
		t.Fatal("SetHostRules returned nil error, want root location validation error")
	}
}

func TestSetHostRulesRejectsProxyConnectionResponseHeader(t *testing.T) {
	handler := &Handler{}
	err := handler.SetHostRules([]models.HostRule{
		{
			Host:   "app.example.com",
			Target: "http://127.0.0.1:8080",
			Locations: []models.HostLocation{
				{
					Path:   "/healthz",
					Match:  models.HostLocationMatchExact,
					Action: models.HostLocationActionResponse,
					Response: models.HostLocationResponse{
						Headers: map[string]string{
							"Proxy-Connection": "keep-alive",
						},
					},
				},
			},
		},
	})
	if err == nil {
		t.Fatal("SetHostRules returned nil error, want proxy-connection header validation error")
	}
}

func TestMatchHostLocationExactWinsOverPrefix(t *testing.T) {
	hostRule := &models.HostRule{
		Host: "app.example.com",
		Locations: []models.HostLocation{
			{Path: "/api", Match: models.HostLocationMatchPrefix, Action: models.HostLocationActionResponse, Response: models.HostLocationResponse{Body: "prefix"}},
			{Path: "/api", Match: models.HostLocationMatchExact, Action: models.HostLocationActionResponse, Response: models.HostLocationResponse{Body: "exact"}},
		},
	}
	req := httptest.NewRequest(http.MethodGet, "http://app.example.com/api", nil)

	location := matchHostLocation(req, hostRule)
	if location == nil {
		t.Fatal("expected location match")
	}
	if got := location.Match; got != models.HostLocationMatchExact {
		t.Fatalf("match = %q, want exact", got)
	}
	if got := location.Response.Body; got != "exact" {
		t.Fatalf("body = %q, want exact", got)
	}
}

func TestMatchHostLocationUsesLongestPrefix(t *testing.T) {
	hostRule := &models.HostRule{
		Host: "app.example.com",
		Locations: []models.HostLocation{
			{Path: "/api", Match: models.HostLocationMatchPrefix, Action: models.HostLocationActionResponse, Response: models.HostLocationResponse{Body: "api"}},
			{Path: "/api/admin", Match: models.HostLocationMatchPrefix, Action: models.HostLocationActionResponse, Response: models.HostLocationResponse{Body: "admin"}},
		},
	}
	req := httptest.NewRequest(http.MethodGet, "http://app.example.com/api/admin/users", nil)

	location := matchHostLocation(req, hostRule)
	if location == nil {
		t.Fatal("expected location match")
	}
	if got := location.Path; got != "/api/admin" {
		t.Fatalf("path = %q, want /api/admin", got)
	}
}

func TestMatchHostLocationPrefixRequiresPathBoundary(t *testing.T) {
	hostRule := &models.HostRule{
		Host: "app.example.com",
		Locations: []models.HostLocation{
			{Path: "/api", Match: models.HostLocationMatchPrefix, Action: models.HostLocationActionResponse, Response: models.HostLocationResponse{Body: "api"}},
		},
	}

	tests := []struct {
		path      string
		wantMatch bool
	}{
		{path: "/api", wantMatch: true},
		{path: "/api/users", wantMatch: true},
		{path: "/apiary", wantMatch: false},
		{path: "/api-v2", wantMatch: false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://app.example.com"+tt.path, nil)
			location := matchHostLocation(req, hostRule)
			if gotMatch := location != nil; gotMatch != tt.wantMatch {
				t.Fatalf("match = %v, want %v", gotMatch, tt.wantMatch)
			}
		})
	}
}

func TestHostLocationFixedResponseWritesCustomHeaders(t *testing.T) {
	handler := newHostLocationTestHandler(models.HostRule{
		Host:   "app.example.com",
		Target: "http://127.0.0.1:8080",
		Locations: []models.HostLocation{
			{
				Path:   "/healthz",
				Match:  models.HostLocationMatchExact,
				Action: models.HostLocationActionResponse,
				Response: models.HostLocationResponse{
					Status:      http.StatusAccepted,
					ContentType: "application/json",
					Headers: map[string]string{
						"X-Location": "health",
					},
					Body: `{"ok":true}`,
				},
			},
		},
	})
	req := httptest.NewRequest(http.MethodGet, "http://app.example.com/healthz", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body = %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", got)
	}
	if got := rec.Header().Get("X-Location"); got != "health" {
		t.Fatalf("X-Location = %q, want health", got)
	}
	if got := rec.Body.String(); got != `{"ok":true}` {
		t.Fatalf("body = %q, want fixed JSON body", got)
	}
}

func TestHostLocationFixedResponseRequiresHostAuth(t *testing.T) {
	var verifyCalled bool
	bridge := testAuthBridge{
		verify: func(context.Context, *pb.VerifyAuthRequest) (*pb.VerifyAuthResponse, error) {
			verifyCalled = true
			return &pb.VerifyAuthResponse{
				Success: false,
				Message: "login required",
				Status:  http.StatusOK,
			}, nil
		},
	}

	handler := newHostLocationTestHandler(models.HostRule{
		Host:       "app.example.com",
		Target:     "http://127.0.0.1:8080",
		UseAuth:    true,
		AccessMode: "login_first",
		Locations: []models.HostLocation{
			{
				Path:   "/private",
				Match:  models.HostLocationMatchExact,
				Action: models.HostLocationActionResponse,
				Response: models.HostLocationResponse{
					Status: http.StatusOK,
					Body:   "secret",
				},
			},
		},
	})
	handler.AuthConfig = models.AuthConfig{
		AuthURL: "/api/auth/verify",
	}
	setTestAuthBridge(t, handler, bridge)
	handler.publishRequestSnapshotLocked()

	req := httptest.NewRequest(http.MethodGet, "http://app.example.com/private", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !verifyCalled {
		t.Fatal("auth verify endpoint was not called")
	}
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302; body = %s", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); strings.Contains(body, "secret") {
		t.Fatalf("fixed response body leaked before auth: %s", body)
	}
}

func TestHostLocationProxyStripsPathAndRewritesHTML(t *testing.T) {
	var gotPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, `<html><body><a href="/login">login</a></body></html>`)
	}))
	defer upstream.Close()

	handler := newHostLocationTestHandler(models.HostRule{
		Host:   "app.example.com",
		Target: "http://127.0.0.1:8080",
		Locations: []models.HostLocation{
			{
				Path:        "/admin",
				Match:       models.HostLocationMatchPrefix,
				Action:      models.HostLocationActionProxy,
				Target:      upstream.URL,
				StripPath:   true,
				RewriteHTML: true,
			},
		},
	})
	req := httptest.NewRequest(http.MethodGet, "http://app.example.com/admin/users", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	if gotPath != "/users" {
		t.Fatalf("upstream path = %q, want /users", gotPath)
	}
	if body := rec.Body.String(); !strings.Contains(body, `href="/admin/login"`) {
		t.Fatalf("response body did not rewrite absolute path: %s", body)
	}
}

func TestHostLocationRouteContextMarksWAFAndThrottleAsHostLocation(t *testing.T) {
	hostRule := &models.HostRule{
		Host:   "app.example.com",
		Target: "http://127.0.0.1:8080",
	}
	location := &models.HostLocation{
		Path:   "/healthz",
		Match:  models.HostLocationMatchExact,
		Action: models.HostLocationActionResponse,
	}
	req := httptest.NewRequest(http.MethodGet, "http://app.example.com/healthz", nil)

	if got := classifyReverseProxyRouteType(req.URL.Path, false, hostRule, location, nil); got != "host_location" {
		t.Fatalf("route type = %q, want host_location", got)
	}

	routeType, routeKey, upstream := wafRouteContext(req, requestSnapshot{}, false, hostRule, location, nil)
	if routeType != "host_location" {
		t.Fatalf("WAF route type = %q, want host_location", routeType)
	}
	if routeKey != "app.example.com /healthz" {
		t.Fatalf("WAF route key = %q, want host/path key", routeKey)
	}
	if upstream != "" {
		t.Fatalf("WAF upstream = %q, want empty for fixed response", upstream)
	}
}

func TestRequestSnapshotDeepCopiesHostLocations(t *testing.T) {
	handler := &Handler{
		HostRules: []models.HostRule{
			{
				Host:   "app.example.com",
				Target: "http://127.0.0.1:8080",
				Locations: []models.HostLocation{
					{
						Path:   "/healthz",
						Match:  models.HostLocationMatchExact,
						Action: models.HostLocationActionResponse,
						Response: models.HostLocationResponse{
							Headers: map[string]string{"X-Test": "original"},
						},
					},
				},
			},
		},
	}
	handler.publishRequestSnapshotLocked()

	handler.HostRules[0].Locations[0].Path = "/mutated"
	handler.HostRules[0].Locations[0].Response.Headers["X-Test"] = "mutated"

	snapshot := handler.snapshotForRequest()
	if got := snapshot.hostRules[0].Locations[0].Path; got != "/healthz" {
		t.Fatalf("snapshot location path = %q, want /healthz", got)
	}
	if got := snapshot.hostRules[0].Locations[0].Response.Headers["X-Test"]; got != "original" {
		t.Fatalf("snapshot location header = %q, want original", got)
	}
}
