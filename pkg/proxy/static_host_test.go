package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"go-reauth-proxy/pkg/grpc/pb"
	"go-reauth-proxy/pkg/models"
	proxywaf "go-reauth-proxy/pkg/waf"
)

func TestSetHostRulesNormalizesStaticDiscriminatedUnion(t *testing.T) {
	handler, manager := newAdditionalProxyTestHandler(t)
	staticRoot := t.TempDir()
	rule := models.HostRule{
		Host:            "static.example.test",
		Target:          "not-a-proxy-url",
		TargetType:      models.HostRuleTargetTypeDirectory,
		TargetPathMode:  models.HostTargetPathModePrefix,
		SuppressToolbar: false,
		PreserveHost:    true,
		BasicAuth:       models.BasicAuthConfig{Enabled: true},
		Locations: []models.HostLocation{{
			Path:   "not-an-absolute-path",
			Target: "not-a-proxy-url",
		}},
		StaticServe: &models.StaticServeConfig{
			Path:       staticRoot,
			IndexFiles: []string{"index.html"},
		},
	}
	if err := handler.SetHostRules([]models.HostRule{rule}); err != nil {
		t.Fatalf("SetHostRules() returned error: %v", err)
	}
	got := handler.GetHostRules()
	if len(got) != 1 {
		t.Fatalf("rules = %#v", got)
	}
	normalized := got[0]
	if normalized.TargetType != models.HostRuleTargetTypeDirectory || normalized.Target != "" || normalized.TargetPathMode != models.HostTargetPathModeEntry {
		t.Fatalf("static target fields = %#v", normalized)
	}
	if !normalized.SuppressToolbar || normalized.PreserveHost || normalized.BasicAuth.Enabled || len(normalized.Locations) != 0 {
		t.Fatalf("proxy-only fields survived normalization: %#v", normalized)
	}
	if normalized.StaticServe == nil || normalized.StaticServe.Path != filepath.Clean(staticRoot) || len(normalized.StaticServe.IndexFiles) != 1 {
		t.Fatalf("static config = %#v", normalized.StaticServe)
	}
	if targets := handler.snapshotForRequest().targets; len(targets) != 0 {
		t.Fatalf("static rule compiled reverse-proxy targets: %#v", targets)
	}
	persisted, err := manager.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(persisted.HostRules) != 1 || persisted.HostRules[0].TargetType != models.HostRuleTargetTypeDirectory || persisted.HostRules[0].Target != "" {
		t.Fatalf("persisted static rule = %#v", persisted.HostRules)
	}
}

func TestStaticHostRuleDispatchesAfterRoutingPolicies(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	staticRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(staticRoot, "hello.txt"), []byte("hello static"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := handler.SetHostRules([]models.HostRule{{
		Host:       "static.example.test",
		TargetType: models.HostRuleTargetTypeDirectory,
		StaticServe: &models.StaticServeConfig{
			Path: staticRoot,
		},
	}}); err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, "http://static.example.test/hello.txt", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Body.String() != "hello static" {
		t.Fatalf("static dispatch = %d %q", recorder.Code, recorder.Body.String())
	}
	if recorder.Header().Get("Cache-Control") != "public, max-age=0, must-revalidate" {
		t.Fatalf("static cache = %q", recorder.Header().Get("Cache-Control"))
	}

	snapshot := handler.snapshotForRequest()
	matched := matchHostRule(request, snapshot)
	if matched == nil {
		t.Fatal("static host rule did not match")
	}
	routeType, routeKey, upstream := wafRouteContext(request, snapshot, false, matched, nil, nil)
	if routeType != "static_directory" || routeKey != "static.example.test" || upstream != "" {
		t.Fatalf("WAF route context = %q %q %q", routeType, routeKey, upstream)
	}
	backend := handler.routedBackendForRequest(request, snapshot, matched, nil, nil)
	if !backend.matched || backend.target != "" || backend.host != "" || backend.routeID == "" {
		t.Fatalf("static routed backend = %#v", backend)
	}
}

func TestStaticHostRuleRejectsNonCanonicalPathsBeforeInternalRouting(t *testing.T) {
	staticRoot := t.TempDir()
	var authHits atomic.Int32
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHits.Add(1)
		if r.URL.Path != "/api/auth/logout" {
			t.Errorf("unexpected auth path %q", r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer authServer.Close()

	handler := &Handler{
		HostRules: []models.HostRule{{
			Host:       "static.example.test",
			TargetType: models.HostRuleTargetTypeDirectory,
			StaticServe: &models.StaticServeConfig{
				Path: staticRoot,
			},
		}},
		AuthConfig: models.AuthConfig{
			AuthPort:  testServerPort(t, authServer.URL),
			LogoutURL: "/api/auth/logout",
		},
		authCache:      newAuthStateCache(),
		preflightCache: newPreflightStateCache(),
	}
	handler.publishRequestSnapshotLocked()

	for _, target := range []string{
		"http://static.example.test/public/../__auth__/api/auth/logout",
		"http://static.example.test/public/%2e%2e/__auth__/api/auth/logout",
		"http://static.example.test/__auth__%2fapi%2fauth%2flogout",
		"http://static.example.test/safe%5c..%5c__auth__%5capi%5cauth%5clogout",
	} {
		request := httptest.NewRequest(http.MethodGet, target, nil)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusNotFound {
			t.Errorf("GET %q = %d %q, want 404", target, recorder.Code, recorder.Body.String())
		}
	}
	if got := authHits.Load(); got != 0 {
		t.Fatalf("non-canonical static paths reached auth service %d times", got)
	}

	canonicalAuth := httptest.NewRequest(http.MethodGet, "http://static.example.test/__auth__/api/auth/logout", nil)
	canonicalResponse := httptest.NewRecorder()
	handler.ServeHTTP(canonicalResponse, canonicalAuth)
	if canonicalResponse.Code != http.StatusNoContent || authHits.Load() != 1 {
		t.Fatalf("canonical internal route = %d, auth hits=%d", canonicalResponse.Code, authHits.Load())
	}
}

func TestStaticHostRuleNonCanonicalPathsStillTraverseRoutingPolicies(t *testing.T) {
	t.Run("availability", func(t *testing.T) {
		handler, _ := newAdditionalProxyTestHandler(t)
		if err := handler.SetHostRules([]models.HostRule{{
			Host:       "static.example.test",
			TargetType: models.HostRuleTargetTypeDirectory,
			Disabled:   true,
			StaticServe: &models.StaticServeConfig{
				Path: t.TempDir(),
			},
		}}); err != nil {
			t.Fatal(err)
		}

		request := httptest.NewRequest(http.MethodGet, "http://static.example.test/safe/../missing.txt", nil)
		request.Header.Set("Accept", "application/json")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), `"reason":"disabled"`) {
			t.Fatalf("availability response = %d %q", response.Code, response.Body.String())
		}
	})

	t.Run("visibility", func(t *testing.T) {
		handler, _ := newAdditionalProxyTestHandler(t)
		if err := handler.SetGatewayVisibility(models.GatewayVisibilityConfig{
			Enabled: true,
			CIDRs:   []string{"8.8.8.0/24"},
		}); err != nil {
			t.Fatal(err)
		}
		if err := handler.SetHostRules([]models.HostRule{{
			Host:       "static.example.test",
			TargetType: models.HostRuleTargetTypeDirectory,
			Visibility: models.HostRuleVisibility{
				Mode:  models.HostVisibilityModeCustom,
				CIDRs: []string{"1.1.1.0/24"},
			},
			StaticServe: &models.StaticServeConfig{Path: t.TempDir()},
		}}); err != nil {
			t.Fatal(err)
		}

		request := httptest.NewRequest(http.MethodGet, "http://static.example.test/safe/../missing.txt", nil)
		request.RemoteAddr = "8.8.8.8:4567"
		response := newHijackableResponseRecorder()
		defer response.Close()
		handler.ServeHTTP(response, request)
		if response.client == nil {
			t.Fatal("non-canonical static request bypassed visibility connection reset")
		}
	})

	t.Run("throttle", func(t *testing.T) {
		handler, _ := newAdditionalProxyTestHandler(t)
		if err := handler.SetHostRules([]models.HostRule{{
			Host:        "static.example.test",
			TargetType:  models.HostRuleTargetTypeDirectory,
			StaticServe: &models.StaticServeConfig{Path: t.TempDir()},
		}}); err != nil {
			t.Fatal(err)
		}
		if err := handler.SetReverseProxyThrottle(models.ReverseProxyThrottleConfig{
			Enabled:           true,
			RequestsPerSecond: 1,
			Burst:             1,
			BlockSeconds:      30,
		}); err != nil {
			t.Fatal(err)
		}

		request := func(port string) *http.Request {
			r := httptest.NewRequest(http.MethodGet, "http://static.example.test/safe/../missing.txt", nil)
			r.RemoteAddr = "198.51.100.20:" + port
			return r
		}
		first := httptest.NewRecorder()
		handler.ServeHTTP(first, request("4567"))
		if first.Code != http.StatusNotFound {
			t.Fatalf("first response = %d %q", first.Code, first.Body.String())
		}
		second := newHijackableResponseRecorder()
		defer second.Close()
		handler.ServeHTTP(second, request("4568"))
		if second.client == nil {
			t.Fatal("non-canonical static request bypassed reverse-proxy throttle")
		}
	})
}

func TestStaticHostRuleIsBlockedByWAFBeforeFilesystemDispatch(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	if _, err := handler.SetLoggingConfig(models.LoggingConfig{Enabled: true, RecordLocalhost: true, MaxDays: 1}); err != nil {
		t.Fatal(err)
	}
	staticRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(staticRoot, "index.html"), []byte("must not be served"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := handler.SetHostRules([]models.HostRule{{
		Host:       "static.example.test",
		TargetType: models.HostRuleTargetTypeDirectory,
		StaticServe: &models.StaticServeConfig{
			Path:       staticRoot,
			IndexFiles: []string{"index.html"},
		},
	}}); err != nil {
		t.Fatal(err)
	}

	rulesDir := t.TempDir()
	customDir := filepath.Join(rulesDir, "custom")
	if err := os.MkdirAll(customDir, 0o755); err != nil {
		t.Fatal(err)
	}
	rule := `SecRule ARGS:test "@streq attack" "id:1904001,phase:2,deny,status:403,msg:'static WAF test',log"`
	if err := os.WriteFile(filepath.Join(customDir, "static-test.conf"), []byte(rule+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	wafConfig := models.WAFConfig{
		Enabled:           true,
		Mode:              proxywaf.ModeBlocking,
		RulesDir:          rulesDir,
		RequestBodyAccess: true,
	}
	wafRuntime := proxywaf.NewRuntime(wafConfig, rulesDir)
	status, err := wafRuntime.Reload(wafConfig, "", "")
	if err != nil || !status.Loaded {
		t.Fatalf("load WAF: status=%#v err=%v", status, err)
	}
	handler.WAFConfig = wafRuntime.Config()
	handler.wafRuntime = wafRuntime

	request := httptest.NewRequest(http.MethodGet, "http://static.example.test/safe/../?test=attack", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden || recorder.Header().Get("X-Fn-Knock-WAF-Blocked") != "1" || recorder.Body.String() == "must not be served" {
		t.Fatalf("WAF response = %d headers=%v body=%q", recorder.Code, recorder.Header(), recorder.Body.String())
	}
	events := handler.DrainWAFEvents(10).Events
	if len(events) != 1 || events[0].RouteType != "static_directory" || events[0].RouteKey != "static.example.test" || events[0].Upstream != "" {
		t.Fatalf("static WAF event = %#v", events)
	}
	handler.gatewayLogManager.Flush()
	logs, err := handler.QueryLogEntries("", 1, 20, "waf_blocked", "", "", "", "", "page")
	if err != nil {
		t.Fatal(err)
	}
	if len(logs.Items) != 1 {
		t.Fatalf("static WAF access logs = %#v", logs.Items)
	}
	entry := logs.Items[0]
	if !entry.WAFBlocked || entry.RouteType != "static_directory" || entry.RouteKey != "static.example.test" || entry.Upstream != "" || strings.Contains(entry.RequestURI, staticRoot) {
		t.Fatalf("static WAF access log = %#v", entry)
	}
}

func TestStaticHostRuleAuthenticatesBeforeFilesystemDispatch(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	staticRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(staticRoot, "asset.txt"), []byte("private static"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := handler.SetHostRules([]models.HostRule{{
		Host:       "static.example.test",
		TargetType: models.HostRuleTargetTypeDirectory,
		UseAuth:    true,
		StaticServe: &models.StaticServeConfig{
			Path: staticRoot,
		},
	}}); err != nil {
		t.Fatal(err)
	}
	authorizeCalls := 0
	setTestAuthBridge(t, handler, testAuthBridge{
		supports: true,
		authorize: func(_ context.Context, request *pb.AuthorizeHttpRequest) (*pb.AuthorizeHttpResponse, error) {
			authorizeCalls++
			authContext := request.GetContext()
			if authContext.RoutedUpstream == nil || authContext.GetRoutedUpstream() != "" ||
				authContext.RoutedUpstreamHost == nil || authContext.GetRoutedUpstreamHost() != "" ||
				authContext.RoutedUpstreamRouteId == nil || authContext.GetRoutedUpstreamRouteId() == "" {
				t.Errorf("static auth context leaked/missed route identity: %#v", authContext)
			}
			return successfulCombinedAuthResponse(
				request.GetMode(),
				pb.AuthCacheScope_AUTH_CACHE_SCOPE_NONE,
				pb.AuthCacheScope_AUTH_CACHE_SCOPE_NONE,
				nil,
			), nil
		},
	})

	request := httptest.NewRequest(http.MethodGet, "http://static.example.test/asset.txt", nil)
	request.AddCookie(&http.Cookie{Name: authSessionCookieName, Value: combinedAuthTestCookieValue})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if authorizeCalls != 1 || recorder.Code != http.StatusOK || recorder.Body.String() != "private static" {
		t.Fatalf("auth/static response calls=%d status=%d body=%q", authorizeCalls, recorder.Code, recorder.Body.String())
	}
	if recorder.Header().Get("Cache-Control") != "private, no-store" {
		t.Fatalf("authenticated static cache = %q", recorder.Header().Get("Cache-Control"))
	}

	invalidRequest := httptest.NewRequest(http.MethodGet, "http://static.example.test/safe/../asset.txt", nil)
	invalidRequest.AddCookie(&http.Cookie{Name: authSessionCookieName, Value: combinedAuthTestCookieValue})
	invalidResponse := httptest.NewRecorder()
	handler.ServeHTTP(invalidResponse, invalidRequest)
	if authorizeCalls != 2 || invalidResponse.Code != http.StatusNotFound || invalidResponse.Body.String() == "private static" {
		t.Fatalf("auth/non-canonical response calls=%d status=%d body=%q", authorizeCalls, invalidResponse.Code, invalidResponse.Body.String())
	}
}

func TestStaticHostRuleRejectsProtectedRuntimeDirectory(t *testing.T) {
	handler, manager := newAdditionalProxyTestHandler(t)
	protected := filepath.Join(manager.RuntimeDir(), "public")
	err := handler.SetHostRules([]models.HostRule{{
		Host:       "static.example.test",
		TargetType: models.HostRuleTargetTypeDirectory,
		StaticServe: &models.StaticServeConfig{
			Path: protected,
		},
	}})
	if err == nil {
		t.Fatal("SetHostRules() accepted a directory beneath the config runtime")
	}
}

func TestStaticRouteIncarnationChangesWithStaticConfig(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	staticRoot := t.TempDir()
	rule := models.HostRule{
		Host:       "static.example.test",
		TargetType: models.HostRuleTargetTypeDirectory,
		StaticServe: &models.StaticServeConfig{
			Path: staticRoot,
			DirectoryListing: models.StaticDirectoryListingConfig{
				Enabled: true,
			},
		},
	}
	if err := handler.SetHostRules([]models.HostRule{rule}); err != nil {
		t.Fatal(err)
	}
	firstRule := handler.snapshotForRequest().hostRulesByHost["static.example.test"]
	firstID := handler.snapshotForRequest().routeIDs[hostRouteIncarnationKey(firstRule)]
	rule.StaticServe.DirectoryListing.RenderReadme = true
	if err := handler.SetHostRules([]models.HostRule{rule}); err != nil {
		t.Fatal(err)
	}
	secondSnapshot := handler.snapshotForRequest()
	secondRule := secondSnapshot.hostRulesByHost["static.example.test"]
	secondID := secondSnapshot.routeIDs[hostRouteIncarnationKey(secondRule)]
	if firstID == "" || secondID == "" || firstID == secondID {
		t.Fatalf("route IDs = %q then %q", firstID, secondID)
	}
}
