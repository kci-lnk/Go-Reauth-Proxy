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

func TestShareNamespaceRejectsRouteOverrides(t *testing.T) {
	handler := &Handler{}
	for _, routePath := range []string{"/s", "/s/download", "/s/abc123abc123abc123"} {
		t.Run("path_rule_"+strings.ReplaceAll(routePath, "/", "_"), func(t *testing.T) {
			err := handler.validateRule(models.Rule{
				Path:   routePath,
				Target: "http://127.0.0.1:8080",
			})
			if err == nil {
				t.Fatalf("validateRule(%q) returned nil, want reserved share namespace error", routePath)
			}
		})
		t.Run("host_location_"+strings.ReplaceAll(routePath, "/", "_"), func(t *testing.T) {
			_, err := handler.normalizeHostLocation(models.HostLocation{
				Path:      routePath,
				Match:     models.HostLocationMatchPrefix,
				Action:    models.HostLocationActionProxy,
				Target:    "http://127.0.0.1:8080",
				StripPath: true,
			})
			if err == nil {
				t.Fatalf("normalizeHostLocation(%q) returned nil, want reserved share namespace error", routePath)
			}
		})
	}
}

func TestShareNamespaceUsesBaseOrDefaultRoute(t *testing.T) {
	hostRule := &models.HostRule{
		Host:   "nas.example.test",
		Target: "http://127.0.0.1:5666",
	}
	location := &models.HostLocation{
		Path:      "/s/download",
		Match:     models.HostLocationMatchPrefix,
		Action:    models.HostLocationActionProxy,
		Target:    hostRule.Target,
		StripPath: true,
	}
	overrideRule := &models.Rule{
		Path:      "/s/download",
		Target:    hostRule.Target,
		StripPath: true,
	}
	defaultRule := &models.Rule{
		Path:   "/fnos",
		Target: hostRule.Target,
	}
	snapshot := requestSnapshot{defaultRule: defaultRule}

	gotLocation, gotRule, gotRedirect := enforceReservedFnosShareRoute(
		"/s/download/file",
		snapshot,
		hostRule,
		location,
		overrideRule,
		"/s/download/",
	)
	if gotLocation != nil || gotRule != nil || gotRedirect != "" {
		t.Fatalf(
			"host share route = location:%#v rule:%#v redirect:%q, want base host route",
			gotLocation,
			gotRule,
			gotRedirect,
		)
	}

	gotLocation, gotRule, gotRedirect = enforceReservedFnosShareRoute(
		"/s/download/file",
		snapshot,
		nil,
		nil,
		overrideRule,
		"/s/download/",
	)
	if gotLocation != nil || gotRule != defaultRule || gotRedirect != "" {
		t.Fatalf(
			"path share route = location:%#v rule:%#v redirect:%q, want default route",
			gotLocation,
			gotRule,
			gotRedirect,
		)
	}
}

func TestShareNamespaceHostRoutePreservesPathAndIgnoresLegacyLocation(t *testing.T) {
	var basePath string
	var baseQuery string
	baseUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		basePath = r.URL.Path
		baseQuery = r.URL.RawQuery
		_, _ = io.WriteString(w, "base")
	}))
	defer baseUpstream.Close()

	var overrideCalls int
	overrideUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		overrideCalls++
		_, _ = io.WriteString(w, "override")
	}))
	defer overrideUpstream.Close()

	// Construct the handler directly to emulate a legacy persisted location
	// that predates the reserved /s namespace validation.
	handler := newHostLocationTestHandler(models.HostRule{
		Host:   "nas.example.test",
		Target: baseUpstream.URL,
		Locations: []models.HostLocation{
			{
				Path:      "/s/download",
				Match:     models.HostLocationMatchPrefix,
				Action:    models.HostLocationActionProxy,
				Target:    overrideUpstream.URL,
				StripPath: true,
			},
		},
	})
	request := httptest.NewRequest(
		http.MethodGet,
		"http://nas.example.test/s/download/file.bin?token=abc",
		nil,
	)
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK || recorder.Body.String() != "base" {
		t.Fatalf("response = %d %q, want base upstream", recorder.Code, recorder.Body.String())
	}
	if overrideCalls != 0 {
		t.Fatalf("legacy /s location calls = %d, want 0", overrideCalls)
	}
	if basePath != "/s/download/file.bin" || baseQuery != "token=abc" {
		t.Fatalf("base upstream request = %q?%s, want original share path and query", basePath, baseQuery)
	}
}

func TestShareNamespacePathModePreservesPathAndIgnoresLegacyRule(t *testing.T) {
	var defaultPath string
	var defaultQuery string
	defaultUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defaultPath = r.URL.Path
		defaultQuery = r.URL.RawQuery
		_, _ = io.WriteString(w, "default")
	}))
	defer defaultUpstream.Close()

	var overrideCalls int
	overrideUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		overrideCalls++
		_, _ = io.WriteString(w, "override")
	}))
	defer overrideUpstream.Close()

	// Construct the handler directly to emulate a legacy persisted path rule
	// that predates the reserved /s namespace validation.
	handler := &Handler{
		Rules: []models.Rule{
			{
				Path:      "/s/download",
				Target:    overrideUpstream.URL,
				StripPath: true,
			},
			{
				Path:      "/fnos",
				Target:    defaultUpstream.URL,
				StripPath: true,
			},
		},
		DefaultRoute:   "/fnos",
		authCache:      newAuthStateCache(),
		preflightCache: newPreflightStateCache(),
	}
	handler.publishRequestSnapshotLocked()
	request := httptest.NewRequest(
		http.MethodGet,
		"http://gateway.example.test/s/download/file.bin?token=abc",
		nil,
	)
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK || recorder.Body.String() != "default" {
		t.Fatalf("response = %d %q, want default upstream", recorder.Code, recorder.Body.String())
	}
	if overrideCalls != 0 {
		t.Fatalf("legacy /s path-rule calls = %d, want 0", overrideCalls)
	}
	if defaultPath != "/s/download/file.bin" || defaultQuery != "token=abc" {
		t.Fatalf("default upstream request = %q?%s, want original share path and query", defaultPath, defaultQuery)
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
