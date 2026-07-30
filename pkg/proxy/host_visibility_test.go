package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strconv"
	"testing"
	"time"

	"go-reauth-proxy/pkg/events"
	compiledipset "go-reauth-proxy/pkg/ipset"
	"go-reauth-proxy/pkg/models"
)

func TestSetHostRulesNormalizesAndDeepCopiesVisibility(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	rules := []models.HostRule{{
		Host:   "app.example.test",
		Target: "http://127.0.0.1:8080",
		Visibility: models.HostRuleVisibility{
			Mode:  " CUSTOM ",
			CIDRs: []string{"1.1.1.7/24", "1.1.1.0/24"},
		},
	}}
	if err := handler.SetHostRules(rules); err != nil {
		t.Fatalf("SetHostRules() returned error: %v", err)
	}
	rules[0].Visibility.CIDRs[0] = "8.8.8.0/24"

	want := models.HostRuleVisibility{
		Mode:  models.HostVisibilityModeCustom,
		CIDRs: []string{"1.1.1.0/24"},
	}
	got := handler.GetHostRules()
	if got[0].Visibility.PolicyID == "" {
		t.Fatal("custom visibility was not compiled into a shared policy")
	}
	want.PolicyID = got[0].Visibility.PolicyID
	if !reflect.DeepEqual(got[0].Visibility, want) {
		t.Fatalf("visibility = %#v, want %#v", got[0].Visibility, want)
	}
	got[0].Visibility.CIDRs[0] = "9.9.9.0/24"
	if current := handler.GetHostRules()[0].Visibility; !reflect.DeepEqual(current, want) {
		t.Fatalf("GetHostRules() did not return a defensive visibility copy: %#v", current)
	}
}

func TestSixHostsAndGlobalVisibilityShareOneCompiledPolicyPointer(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	policy, err := compiledipset.Compile([]string{
		"203.0.113.0/25",
		"203.0.113.128/25",
	})
	if err != nil {
		t.Fatal(err)
	}
	rules := make([]models.HostRule, 0, 6)
	for index := range 6 {
		rules = append(rules, models.HostRule{
			Host:   "app-" + strconv.Itoa(index) + ".example.test",
			Target: "http://127.0.0.1:8080",
			Visibility: models.HostRuleVisibility{
				Mode:     models.HostVisibilityModeCustom,
				PolicyID: policy.ID,
			},
		})
	}
	if err := handler.SetHostRulesBundle(
		rules,
		map[string]models.CompiledIPSet{policy.ID: policy},
	); err != nil {
		t.Fatal(err)
	}
	snapshot := handler.snapshotForRequest()
	first := snapshot.hostVisibility["app-0.example.test"]
	if first == nil {
		t.Fatal("first host did not resolve a compiled visibility set")
	}
	for index := range 6 {
		host := "app-" + strconv.Itoa(index) + ".example.test"
		if snapshot.hostVisibility[host] != first {
			t.Fatalf("host %s did not share the immutable compiled set pointer", host)
		}
	}
	if len(handler.VisibilityPolicies) != 1 {
		t.Fatalf("policy count = %d, want 1", len(handler.VisibilityPolicies))
	}

	globalPolicy := policy
	if err := handler.SetGatewayVisibility(models.GatewayVisibilityConfig{
		Enabled:  true,
		PolicyID: policy.ID,
		Policy:   &globalPolicy,
	}); err != nil {
		t.Fatal(err)
	}
	snapshot = handler.snapshotForRequest()
	handler.gatewayVisibility.mu.RLock()
	globalSet := handler.gatewayVisibility.set
	handler.gatewayVisibility.mu.RUnlock()
	if globalSet == nil || snapshot.hostVisibility["app-0.example.test"] != globalSet {
		t.Fatal("global and host visibility did not share the compiled set pointer")
	}
	if err := handler.FlushHostRules(); err != nil {
		t.Fatal(err)
	}
	if len(handler.VisibilityPolicies) != 1 {
		t.Fatalf("global reference did not retain shared policy: %d", len(handler.VisibilityPolicies))
	}
	if err := handler.SetGatewayVisibility(models.GatewayVisibilityConfig{Enabled: false}); err != nil {
		t.Fatal(err)
	}
	if len(handler.VisibilityPolicies) != 0 {
		t.Fatalf("unreferenced policy count = %d, want 0", len(handler.VisibilityPolicies))
	}
}

func TestSetHostRulesPreservesDisabledVisibility(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	if err := handler.SetHostRules([]models.HostRule{{
		Host:       "app.example.test",
		Target:     "http://127.0.0.1:8080",
		Visibility: models.HostRuleVisibility{Mode: " DISABLED "},
	}}); err != nil {
		t.Fatalf("SetHostRules() returned error: %v", err)
	}
	if got := handler.GetHostRules()[0].Visibility.Mode; got != models.HostVisibilityModeDisabled {
		t.Fatalf("visibility mode = %q, want %q", got, models.HostVisibilityModeDisabled)
	}
}

func TestSetHostRulesRejectsInvalidCustomVisibility(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	for name, visibility := range map[string]models.HostRuleVisibility{
		"empty":   {Mode: models.HostVisibilityModeCustom},
		"invalid": {Mode: models.HostVisibilityModeCustom, CIDRs: []string{"not-a-cidr"}},
	} {
		t.Run(name, func(t *testing.T) {
			err := handler.SetHostRules([]models.HostRule{{
				Host:       "app.example.test",
				Target:     "http://127.0.0.1:8080",
				Visibility: visibility,
			}})
			if err == nil {
				t.Fatal("SetHostRules() returned nil error")
			}
		})
	}
}

func TestSetHostRulesPreservesVisibilityWhenLegacyUpdateOmitsIt(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	if err := handler.SetHostRules([]models.HostRule{{
		Host:       "app.example.test",
		Target:     "http://127.0.0.1:8080",
		Visibility: models.HostRuleVisibility{Mode: models.HostVisibilityModeCustom, CIDRs: []string{"1.1.1.0/24"}},
	}}); err != nil {
		t.Fatalf("initial SetHostRules() returned error: %v", err)
	}
	if err := handler.SetHostRules([]models.HostRule{{
		Host:   "app.example.test",
		Target: "http://127.0.0.1:8081",
	}}); err != nil {
		t.Fatalf("legacy SetHostRules() returned error: %v", err)
	}

	want := models.HostRuleVisibility{
		Mode:     models.HostVisibilityModeCustom,
		CIDRs:    []string{"1.1.1.0/24"},
		PolicyID: handler.GetHostRules()[0].Visibility.PolicyID,
	}
	if got := handler.GetHostRules()[0].Visibility; !reflect.DeepEqual(got, want) {
		t.Fatalf("visibility = %#v, want preserved %#v", got, want)
	}
}

func TestHostVisibilityCustomRulesReplaceGlobalRules(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	if err := handler.SetGatewayVisibility(models.GatewayVisibilityConfig{
		Enabled: true,
		CIDRs:   []string{"8.8.8.0/24"},
	}); err != nil {
		t.Fatalf("SetGatewayVisibility() returned error: %v", err)
	}
	if err := handler.SetHostRules([]models.HostRule{
		{
			Host:       "custom.example.test",
			Target:     "http://127.0.0.1:8080",
			Visibility: models.HostRuleVisibility{Mode: models.HostVisibilityModeCustom, CIDRs: []string{"1.1.1.0/24"}},
		},
		{
			Host:       "inherit.example.test",
			Target:     "http://127.0.0.1:8081",
			Visibility: models.HostRuleVisibility{Mode: models.HostVisibilityModeInherit},
		},
	}); err != nil {
		t.Fatalf("SetHostRules() returned error: %v", err)
	}

	snapshot := handler.snapshotForRequest()
	customRequest := httptest.NewRequest("GET", "http://custom.example.test/", nil)
	customRule := matchHostRule(customRequest, snapshot)
	if !handler.IsClientIPVisibleForHost("1.1.1.7", customRule, snapshot) {
		t.Fatal("custom host denied an IP in its own CIDR")
	}
	if handler.IsClientIPVisibleForHost("8.8.8.7", customRule, snapshot) {
		t.Fatal("custom host incorrectly merged the global CIDR")
	}
	if !handler.IsClientIPVisibleForHost("127.0.0.1", customRule, snapshot) {
		t.Fatal("custom host did not preserve the loopback exemption")
	}

	inheritRequest := httptest.NewRequest("GET", "http://inherit.example.test/", nil)
	inheritRule := matchHostRule(inheritRequest, snapshot)
	if !handler.IsClientIPVisibleForHost("8.8.8.7", inheritRule, snapshot) {
		t.Fatal("inherited host denied an IP in the global CIDR")
	}
	if handler.IsClientIPVisibleForHost("1.1.1.7", inheritRule, snapshot) {
		t.Fatal("inherited host incorrectly used another host's custom CIDR")
	}

	unmatchedRequest := httptest.NewRequest("GET", "http://missing.example.test/", nil)
	if rule := matchHostRule(unmatchedRequest, snapshot); rule != nil {
		t.Fatalf("unmatched request unexpectedly matched %#v", rule)
	}
	if !handler.IsClientIPVisibleForHost("8.8.8.7", nil, snapshot) {
		t.Fatal("unmatched host did not inherit global visibility")
	}
	if handler.IsClientIPVisibleForHost("1.1.1.7", nil, snapshot) {
		t.Fatal("unmatched host incorrectly used custom visibility")
	}

	if err := handler.SetGatewayVisibility(models.GatewayVisibilityConfig{Enabled: false}); err != nil {
		t.Fatalf("disabling gateway visibility returned error: %v", err)
	}
	if !handler.IsClientIPVisibleForHost("9.9.9.9", customRule, snapshot) {
		t.Fatal("disabled global switch did not pause custom host visibility")
	}
}

func TestEmptyEnabledGlobalVisibilityAllowsOnlyCustomHostRules(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	if err := handler.SetGatewayVisibility(models.GatewayVisibilityConfig{Enabled: true}); err != nil {
		t.Fatalf("SetGatewayVisibility() returned error: %v", err)
	}
	if err := handler.SetHostRules([]models.HostRule{
		{
			Host:       "custom.example.test",
			Target:     "http://127.0.0.1:8080",
			Visibility: models.HostRuleVisibility{Mode: models.HostVisibilityModeCustom, CIDRs: []string{"1.1.1.0/24"}},
		},
		{
			Host:       "inherit.example.test",
			Target:     "http://127.0.0.1:8081",
			Visibility: models.HostRuleVisibility{Mode: models.HostVisibilityModeInherit},
		},
	}); err != nil {
		t.Fatalf("SetHostRules() returned error: %v", err)
	}

	snapshot := handler.snapshotForRequest()
	customRule := matchHostRule(
		httptest.NewRequest("GET", "http://custom.example.test/", nil),
		snapshot,
	)
	if !handler.IsClientIPVisibleForHost("1.1.1.7", customRule, snapshot) {
		t.Fatal("custom host denied an IP in its own CIDR when global rules were empty")
	}

	inheritRule := matchHostRule(
		httptest.NewRequest("GET", "http://inherit.example.test/", nil),
		snapshot,
	)
	if handler.IsClientIPVisibleForHost("1.1.1.7", inheritRule, snapshot) {
		t.Fatal("inherited host allowed a public IP while global rules were empty")
	}
	if handler.IsClientIPVisibleForHost("1.1.1.7", nil, snapshot) {
		t.Fatal("unmatched host allowed a public IP while global rules were empty")
	}
	if !handler.IsClientIPVisibleForHost("127.0.0.1", inheritRule, snapshot) {
		t.Fatal("empty global rules did not preserve the loopback exemption")
	}
}

func TestDisabledHostVisibilityOverridesGlobalRules(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	if err := handler.SetGatewayVisibility(models.GatewayVisibilityConfig{
		Enabled: true,
		CIDRs:   []string{"8.8.8.0/24"},
	}); err != nil {
		t.Fatalf("SetGatewayVisibility() returned error: %v", err)
	}
	if err := handler.SetHostRules([]models.HostRule{{
		Host:       "disabled.example.test",
		Target:     "http://127.0.0.1:8080",
		Visibility: models.HostRuleVisibility{Mode: models.HostVisibilityModeDisabled},
	}}); err != nil {
		t.Fatalf("SetHostRules() returned error: %v", err)
	}

	snapshot := handler.snapshotForRequest()
	rule := matchHostRule(
		httptest.NewRequest("GET", "http://disabled.example.test/", nil),
		snapshot,
	)
	if !handler.IsClientIPVisibleForHost("1.1.1.7", rule, snapshot) {
		t.Fatal("disabled host visibility did not override the global deny rule")
	}
	if handler.IsClientIPVisibleForHost("1.1.1.7", nil, snapshot) {
		t.Fatal("disabled host visibility leaked into unmatched hosts")
	}
}

func TestDisabledHostVisibilityAllowsRequestDeniedByGlobalRules(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	handler, _ := newAdditionalProxyTestHandler(t)
	if err := handler.SetGatewayVisibility(models.GatewayVisibilityConfig{
		Enabled: true,
		CIDRs:   []string{"8.8.8.0/24"},
	}); err != nil {
		t.Fatalf("SetGatewayVisibility() returned error: %v", err)
	}
	if err := handler.SetHostRules([]models.HostRule{{
		Host:       "disabled.example.test",
		Target:     upstream.URL,
		Visibility: models.HostRuleVisibility{Mode: models.HostVisibilityModeDisabled},
	}}); err != nil {
		t.Fatalf("SetHostRules() returned error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://disabled.example.test/", nil)
	req.RemoteAddr = "1.1.1.7:4567"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("response status = %d, want %d", rec.Code, http.StatusNoContent)
	}
}

func TestAuthHostAlwaysUsesGlobalVisibility(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	if err := handler.SetGatewayVisibility(models.GatewayVisibilityConfig{
		Enabled: true,
		CIDRs:   []string{"8.8.8.0/24"},
	}); err != nil {
		t.Fatalf("SetGatewayVisibility() returned error: %v", err)
	}
	if err := handler.SetAuthConfig(models.AuthConfig{AuthHost: "auth.example.test"}); err != nil {
		t.Fatalf("SetAuthConfig() returned error: %v", err)
	}
	if err := handler.SetHostRules([]models.HostRule{{
		Host:       "auth.example.test",
		Target:     "http://127.0.0.1:7997",
		Visibility: models.HostRuleVisibility{Mode: models.HostVisibilityModeCustom, CIDRs: []string{"1.1.1.0/24"}},
	}}); err != nil {
		t.Fatalf("SetHostRules() returned error: %v", err)
	}

	snapshot := handler.snapshotForRequest()
	rule := matchHostRule(httptest.NewRequest("GET", "http://auth.example.test/", nil), snapshot)
	if !handler.IsClientIPVisibleForHost("8.8.8.7", rule, snapshot) {
		t.Fatal("auth host denied an IP allowed by global visibility")
	}
	if handler.IsClientIPVisibleForHost("1.1.1.7", rule, snapshot) {
		t.Fatal("auth host incorrectly used custom visibility")
	}

	if err := handler.SetHostRules([]models.HostRule{{
		Host:       "auth.example.test",
		Target:     "http://127.0.0.1:7997",
		Visibility: models.HostRuleVisibility{Mode: models.HostVisibilityModeDisabled},
	}}); err != nil {
		t.Fatalf("SetHostRules() with disabled auth visibility returned error: %v", err)
	}
	snapshot = handler.snapshotForRequest()
	rule = matchHostRule(httptest.NewRequest("GET", "http://auth.example.test/", nil), snapshot)
	if handler.IsClientIPVisibleForHost("1.1.1.7", rule, snapshot) {
		t.Fatal("auth host incorrectly disabled global visibility")
	}
}

func TestCustomHostVisibilityDenialKeeps499AndAccessLogBehavior(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	if _, err := handler.SetLoggingConfig(models.LoggingConfig{Enabled: true, MaxDays: 1}); err != nil {
		t.Fatalf("SetLoggingConfig() returned error: %v", err)
	}
	if err := handler.SetGatewayVisibility(models.GatewayVisibilityConfig{
		Enabled: true,
		CIDRs:   []string{"8.8.8.0/24"},
	}); err != nil {
		t.Fatalf("SetGatewayVisibility() returned error: %v", err)
	}
	if err := handler.SetHostRules([]models.HostRule{{
		Host:       "custom.example.test",
		Target:     "http://127.0.0.1:8080",
		Visibility: models.HostRuleVisibility{Mode: models.HostVisibilityModeCustom, CIDRs: []string{"1.1.1.0/24"}},
	}}); err != nil {
		t.Fatalf("SetHostRules() returned error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://custom.example.test/private", nil)
	req.RemoteAddr = "8.8.8.8:4567"
	rec := newHijackableResponseRecorder()
	defer rec.Close()
	handler.ServeHTTP(rec, req)

	result, err := handler.QueryLogEntries("", 1, 20, "visibility_denied", "", "", "", "", "page")
	if err != nil {
		t.Fatalf("QueryLogEntries() returned error: %v", err)
	}
	if len(result.Items) != 1 {
		t.Fatalf("visibility log count = %d, want 1", len(result.Items))
	}
	entry := result.Items[0]
	if entry.Status != 499 || entry.RouteType != "visibility" || entry.AuthDecision != "visibility_denied" {
		t.Fatalf("visibility access log = %#v", entry)
	}
}

func TestGatewayVisibilityPolicyContextUsesEffectivePolicy(t *testing.T) {
	snapshot := requestSnapshot{
		authConfig: models.AuthConfig{AuthHost: "auth.example.test"},
	}
	cases := []struct {
		name      string
		rule      *models.HostRule
		wantScope string
		wantMode  string
	}{
		{name: "unmatched", wantScope: "gateway", wantMode: models.HostVisibilityModeInherit},
		{
			name:      "inherited host",
			rule:      &models.HostRule{Host: "app.example.test", Visibility: models.HostRuleVisibility{Mode: models.HostVisibilityModeInherit}},
			wantScope: "gateway",
			wantMode:  models.HostVisibilityModeInherit,
		},
		{
			name:      "custom host",
			rule:      &models.HostRule{Host: "app.example.test", Visibility: models.HostRuleVisibility{Mode: models.HostVisibilityModeCustom}},
			wantScope: "host",
			wantMode:  models.HostVisibilityModeCustom,
		},
		{
			name:      "auth host ignores custom mode",
			rule:      &models.HostRule{Host: "AUTH.EXAMPLE.TEST", Visibility: models.HostRuleVisibility{Mode: models.HostVisibilityModeCustom}},
			wantScope: "gateway",
			wantMode:  models.HostVisibilityModeInherit,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scope, mode := gatewayVisibilityPolicyContext(tc.rule, snapshot)
			if scope != tc.wantScope || mode != tc.wantMode {
				t.Fatalf("policy context = (%q, %q), want (%q, %q)", scope, mode, tc.wantScope, tc.wantMode)
			}
		})
	}
}

func TestGatewayVisibilityRouteContextCoversGatewayEntrypoints(t *testing.T) {
	hostRule := &models.HostRule{Host: "app.example.test"}
	cases := []struct {
		name      string
		request   *http.Request
		snapshot  requestSnapshot
		rule      *models.HostRule
		fnConnect bool
		wantType  string
		wantKey   string
	}{
		{
			name:     "host rule",
			request:  httptest.NewRequest(http.MethodGet, "https://app.example.test/private", nil),
			rule:     hostRule,
			wantType: "host_rule",
			wantKey:  "app.example.test",
		},
		{
			name:    "host location",
			request: httptest.NewRequest(http.MethodGet, "https://app.example.test/api/private", nil),
			rule: &models.HostRule{
				Host: "app.example.test",
				Locations: []models.HostLocation{{
					Path:  "/api",
					Match: models.HostLocationMatchPrefix,
				}},
			},
			wantType: "host_location",
			wantKey:  "app.example.test /api",
		},
		{
			name:     "path rule",
			request:  httptest.NewRequest(http.MethodGet, "https://gateway.example.test/apps/private", nil),
			snapshot: requestSnapshot{rules: []models.Rule{{Path: "/apps", Target: "http://127.0.0.1:8080"}}},
			wantType: "path_rule",
			wantKey:  "/apps",
		},
		{
			name:     "path rule slash redirect",
			request:  httptest.NewRequest(http.MethodGet, "https://gateway.example.test/apps", nil),
			snapshot: requestSnapshot{rules: []models.Rule{{Path: "/apps", Target: "http://127.0.0.1:8080"}}},
			wantType: "slash_redirect",
			wantKey:  "/apps/",
		},
		{
			name:     "default path rule",
			request:  httptest.NewRequest(http.MethodGet, "https://gateway.example.test/private", nil),
			snapshot: requestSnapshot{defaultRule: &models.Rule{Path: "/", Target: "http://127.0.0.1:8080"}},
			wantType: "path_rule",
			wantKey:  "/",
		},
		{
			name:    "default host redirect",
			request: httptest.NewRequest(http.MethodGet, "https://missing.example.test/private", nil),
			snapshot: requestSnapshot{
				defaultHostRule: &models.HostRule{Host: "default.example.test", Target: "http://127.0.0.1:8080"},
			},
			wantType: "default_host_redirect",
			wantKey:  "default.example.test",
		},
		{
			name:    "reset unmatched route",
			request: httptest.NewRequest(http.MethodGet, "https://missing.example.test/private", nil),
			snapshot: requestSnapshot{
				unmatchedRoute: models.GatewayUnmatchedRouteConfig{
					Behavior: models.GatewayUnmatchedRouteBehaviorResetConnection,
				},
			},
			wantType: "unmatched_route_blocked",
			wantKey:  "missing.example.test",
		},
		{
			name:     "auth route",
			request:  httptest.NewRequest(http.MethodGet, "https://auth.example.test/__auth__/login", nil),
			rule:     &models.HostRule{Host: "auth.example.test"},
			wantType: "auth_proxy",
			wantKey:  "/__auth__/login",
		},
		{
			name:      "fn connect",
			request:   httptest.NewRequest(http.MethodGet, "http://127.0.0.1/private", nil),
			rule:      &models.HostRule{Host: fnosConnectRouteKey},
			fnConnect: true,
			wantType:  fnosConnectRouteKey,
			wantKey:   fnosConnectRouteKey,
		},
		{
			name:     "unmatched",
			request:  httptest.NewRequest(http.MethodGet, "https://missing.example.test/private", nil),
			wantType: "not_found",
			wantKey:  "missing.example.test",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			routeType, routeKey := gatewayVisibilityRouteContext(tc.request, tc.snapshot, tc.rule, tc.fnConnect)
			if routeType != tc.wantType || routeKey != tc.wantKey {
				t.Fatalf("route context = (%q, %q), want (%q, %q)", routeType, routeKey, tc.wantType, tc.wantKey)
			}
		})
	}
}

func TestVisibilityDenialsEnqueueEffectivePolicyAndRouteContext(t *testing.T) {
	cases := []struct {
		name          string
		requestURL    string
		globalCIDRs   []string
		hostRules     []models.HostRule
		pathRules     []models.Rule
		authHost      string
		fnConnect     bool
		wantScope     string
		wantMode      string
		wantRouteType string
		wantRouteKey  string
	}{
		{
			name:          "global",
			requestURL:    "https://missing.example.test/private",
			globalCIDRs:   []string{"8.8.8.0/24"},
			wantScope:     "gateway",
			wantMode:      models.HostVisibilityModeInherit,
			wantRouteType: "not_found",
			wantRouteKey:  "missing.example.test",
		},
		{
			name:        "inherited host",
			requestURL:  "https://inherit.example.test/private",
			globalCIDRs: []string{"8.8.8.0/24"},
			hostRules: []models.HostRule{{
				Host:       "inherit.example.test",
				Target:     "http://127.0.0.1:8080",
				Visibility: models.HostRuleVisibility{Mode: models.HostVisibilityModeInherit},
			}},
			wantScope:     "gateway",
			wantMode:      models.HostVisibilityModeInherit,
			wantRouteType: "host_rule",
			wantRouteKey:  "inherit.example.test",
		},
		{
			name:        "custom host",
			requestURL:  "https://custom.example.test/private",
			globalCIDRs: []string{"1.1.1.0/24"},
			hostRules: []models.HostRule{{
				Host:       "custom.example.test",
				Target:     "http://127.0.0.1:8080",
				Visibility: models.HostRuleVisibility{Mode: models.HostVisibilityModeCustom, CIDRs: []string{"8.8.8.0/24"}},
			}},
			wantScope:     "host",
			wantMode:      models.HostVisibilityModeCustom,
			wantRouteType: "host_rule",
			wantRouteKey:  "custom.example.test",
		},
		{
			name:        "host location",
			requestURL:  "https://location.example.test/api/private",
			globalCIDRs: []string{"8.8.8.0/24"},
			hostRules: []models.HostRule{{
				Host:   "location.example.test",
				Target: "http://127.0.0.1:8080",
				Locations: []models.HostLocation{{
					Path:   "/api",
					Match:  models.HostLocationMatchPrefix,
					Action: models.HostLocationActionProxy,
					Target: "http://127.0.0.1:8081",
				}},
			}},
			wantScope:     "gateway",
			wantMode:      models.HostVisibilityModeInherit,
			wantRouteType: "host_location",
			wantRouteKey:  "location.example.test /api",
		},
		{
			name:        "path rule",
			requestURL:  "https://gateway.example.test/apps/private",
			globalCIDRs: []string{"8.8.8.0/24"},
			pathRules: []models.Rule{{
				Path:   "/apps",
				Target: "http://127.0.0.1:8080",
			}},
			wantScope:     "gateway",
			wantMode:      models.HostVisibilityModeInherit,
			wantRouteType: "path_rule",
			wantRouteKey:  "/apps",
		},
		{
			name:        "auth host",
			requestURL:  "https://auth.example.test/__auth__/login",
			globalCIDRs: []string{"8.8.8.0/24"},
			authHost:    "auth.example.test",
			hostRules: []models.HostRule{{
				Host:       "auth.example.test",
				Target:     "http://127.0.0.1:8080",
				Visibility: models.HostRuleVisibility{Mode: models.HostVisibilityModeCustom, CIDRs: []string{"1.1.1.0/24"}},
			}},
			wantScope:     "gateway",
			wantMode:      models.HostVisibilityModeInherit,
			wantRouteType: "auth_proxy",
			wantRouteKey:  "/__auth__/login",
		},
		{
			name:          "fn connect",
			requestURL:    "http://localhost/private",
			globalCIDRs:   []string{"8.8.8.0/24"},
			fnConnect:     true,
			wantScope:     "gateway",
			wantMode:      models.HostVisibilityModeInherit,
			wantRouteType: fnosConnectRouteKey,
			wantRouteKey:  fnosConnectRouteKey,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			handler, _ := newAdditionalProxyTestHandler(t)
			if err := handler.SetGatewayVisibility(models.GatewayVisibilityConfig{
				Enabled: true,
				CIDRs:   tc.globalCIDRs,
			}); err != nil {
				t.Fatalf("SetGatewayVisibility() returned error: %v", err)
			}
			if tc.authHost != "" {
				if err := handler.SetAuthConfig(models.AuthConfig{AuthHost: tc.authHost}); err != nil {
					t.Fatalf("SetAuthConfig() returned error: %v", err)
				}
			}
			if len(tc.hostRules) > 0 {
				if err := handler.SetHostRules(tc.hostRules); err != nil {
					t.Fatalf("SetHostRules() returned error: %v", err)
				}
			}
			if len(tc.pathRules) > 0 {
				if err := handler.SetRules(tc.pathRules); err != nil {
					t.Fatalf("SetRules() returned error: %v", err)
				}
			}
			handler.systemEventClient = events.NewClient(nil)
			handler.visibilityEventQueue = make(chan gatewayVisibilityBlockedEvent, 1)

			req := httptest.NewRequest(http.MethodGet, tc.requestURL, nil)
			if tc.fnConnect {
				req.RemoteAddr = "127.0.0.1:4567"
				req.Header.Set("X-Forwarded-For", "1.1.1.7")
				ingress := &fnosConnectRequestContext{hostRule: models.HostRule{
					Host:   fnosConnectRouteKey,
					Target: "http://127.0.0.1:5666",
				}}
				req = req.WithContext(context.WithValue(req.Context(), fnosConnectRequestContextKey{}, ingress))
			} else {
				req.RemoteAddr = "1.1.1.7:4567"
			}
			rec := newHijackableResponseRecorder()
			defer rec.Close()
			handler.ServeHTTP(rec, req)

			select {
			case event := <-handler.visibilityEventQueue:
				if event.ClientIP != "1.1.1.7" ||
					event.VisibilityScope != tc.wantScope ||
					event.VisibilityMode != tc.wantMode ||
					event.RouteType != tc.wantRouteType ||
					event.RouteKey != tc.wantRouteKey {
					t.Fatalf("visibility event = %#v", event)
				}
			default:
				t.Fatal("visibility denial did not enqueue an audit event")
			}
		})
	}
}

func TestGatewayVisibilityEventQueueFullDoesNotBlock(t *testing.T) {
	handler := &Handler{
		systemEventClient:    events.NewClient(nil),
		visibilityEventQueue: make(chan gatewayVisibilityBlockedEvent, 1),
	}
	handler.visibilityEventQueue <- gatewayVisibilityBlockedEvent{ClientIP: "203.0.113.1"}

	done := make(chan struct{})
	go func() {
		handler.enqueueGatewayVisibilityBlockedEvent(gatewayVisibilityBlockedEvent{ClientIP: "203.0.113.2"})
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("full visibility event queue blocked the request path")
	}
	if dropped := handler.visibilityDropped.Load(); dropped != 1 {
		t.Fatalf("dropped visibility events = %d, want 1", dropped)
	}
	firstWarn := handler.visibilityDropWarnNano.Load()
	if firstWarn == 0 {
		t.Fatal("queue overflow did not record the first warning timestamp")
	}
	_, shouldLog := handler.recordDroppedGatewayVisibilityEvent(time.Unix(0, firstWarn).Add(time.Second))
	if shouldLog {
		t.Fatal("queue overflow warning was not rate limited")
	}
}

func TestUnavailableSystemEventEndpointDoesNotBlockVisibilityDenial(t *testing.T) {
	publishStarted := make(chan struct{}, 1)
	releasePublish := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		select {
		case publishStarted <- struct{}{}:
		default:
		}
		<-releasePublish
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	defer close(releasePublish)

	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}
	port, err := strconv.Atoi(serverURL.Port())
	if err != nil {
		t.Fatalf("parse server port: %v", err)
	}
	t.Setenv("BACKEND_PORT", strconv.Itoa(port))

	handler, _ := newAdditionalProxyTestHandler(t)
	if err := handler.SetGatewayVisibility(models.GatewayVisibilityConfig{
		Enabled: true,
		CIDRs:   []string{"8.8.8.0/24"},
	}); err != nil {
		t.Fatalf("SetGatewayVisibility() returned error: %v", err)
	}
	handler.systemEventClient = events.NewClient(server.Client())
	handler.visibilityEventQueue = make(chan gatewayVisibilityBlockedEvent, gatewayVisibilityEventQueueSize)
	handler.startGatewayVisibilityEventWorker()
	handler.enqueueGatewayVisibilityBlockedEvent(gatewayVisibilityBlockedEvent{
		ClientIP:  "203.0.113.1",
		BlockedAt: time.Now(),
	})

	select {
	case <-publishStarted:
	case <-time.After(time.Second):
		t.Fatal("visibility event worker did not reach the stalled endpoint")
	}
	for i := 0; i < cap(handler.visibilityEventQueue); i++ {
		handler.visibilityEventQueue <- gatewayVisibilityBlockedEvent{
			ClientIP:  "203.0.113.2",
			BlockedAt: time.Now(),
		}
	}

	req := httptest.NewRequest(http.MethodGet, "https://missing.example.test/private", nil)
	req.RemoteAddr = "203.0.113.3:4567"
	rec := newHijackableResponseRecorder()
	defer rec.Close()
	startedAt := time.Now()
	handler.ServeHTTP(rec, req)
	if elapsed := time.Since(startedAt); elapsed >= 500*time.Millisecond {
		t.Fatalf("visibility denial waited for the stalled event endpoint: %v", elapsed)
	}
	if dropped := handler.visibilityDropped.Load(); dropped != 1 {
		t.Fatalf("dropped visibility events = %d, want 1", dropped)
	}
}

func TestVisibilityDenialEnqueuesAuditEventWithoutChangingResponse(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	if _, err := handler.SetLoggingConfig(models.LoggingConfig{Enabled: true, MaxDays: 1}); err != nil {
		t.Fatalf("SetLoggingConfig() returned error: %v", err)
	}
	if err := handler.SetGatewayVisibility(models.GatewayVisibilityConfig{
		Enabled: true,
		CIDRs:   []string{"8.8.8.0/24"},
	}); err != nil {
		t.Fatalf("SetGatewayVisibility() returned error: %v", err)
	}
	if err := handler.SetHostRules([]models.HostRule{{
		Host:       "custom.example.test",
		Target:     "http://127.0.0.1:8080",
		Visibility: models.HostRuleVisibility{Mode: models.HostVisibilityModeCustom, CIDRs: []string{"1.1.1.0/24"}},
	}}); err != nil {
		t.Fatalf("SetHostRules() returned error: %v", err)
	}
	handler.systemEventClient = events.NewClient(nil)
	handler.visibilityEventQueue = make(chan gatewayVisibilityBlockedEvent, 1)

	req := httptest.NewRequest(http.MethodPost, "https://custom.example.test/private?token=secret", nil)
	req.RemoteAddr = "8.8.8.8:4567"
	rec := newHijackableResponseRecorder()
	defer rec.Close()
	handler.ServeHTTP(rec, req)

	select {
	case event := <-handler.visibilityEventQueue:
		if event.ClientIP != "8.8.8.8" ||
			event.Method != http.MethodPost ||
			event.Scheme != "https" ||
			event.Host != "custom.example.test" ||
			event.Path != "/private" ||
			event.RouteType != "host_rule" ||
			event.RouteKey != "custom.example.test" ||
			event.VisibilityScope != "host" ||
			event.VisibilityMode != models.HostVisibilityModeCustom {
			t.Fatalf("visibility event = %#v", event)
		}
	default:
		t.Fatal("visibility denial did not enqueue an audit event")
	}

	result, err := handler.QueryLogEntries("", 1, 20, "visibility_denied", "", "", "", "", "page")
	if err != nil {
		t.Fatalf("QueryLogEntries() returned error: %v", err)
	}
	if len(result.Items) != 1 || result.Items[0].Status != 499 {
		t.Fatalf("visibility access log = %#v", result.Items)
	}
}

func TestAllowedVisibilityRequestDoesNotEnqueueAuditEvent(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	handler, _ := newAdditionalProxyTestHandler(t)
	if err := handler.SetGatewayVisibility(models.GatewayVisibilityConfig{
		Enabled: true,
		CIDRs:   []string{"8.8.8.0/24"},
	}); err != nil {
		t.Fatalf("SetGatewayVisibility() returned error: %v", err)
	}
	if err := handler.SetHostRules([]models.HostRule{{
		Host:   "visible.example.test",
		Target: upstream.URL,
	}}); err != nil {
		t.Fatalf("SetHostRules() returned error: %v", err)
	}
	handler.systemEventClient = events.NewClient(nil)
	handler.visibilityEventQueue = make(chan gatewayVisibilityBlockedEvent, 1)

	req := httptest.NewRequest(http.MethodGet, "http://visible.example.test/", nil)
	req.RemoteAddr = "8.8.8.8:4567"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("response status = %d, want %d", rec.Code, http.StatusNoContent)
	}
	select {
	case event := <-handler.visibilityEventQueue:
		t.Fatalf("allowed request enqueued visibility event %#v", event)
	default:
	}
}

func TestEmitGatewayVisibilityBlockedEventPublishesSafePayload(t *testing.T) {
	published := make(chan events.SystemEventPublishInput, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/internal/system-events" {
			t.Errorf("request path = %q", r.URL.Path)
		}
		var input events.SystemEventPublishInput
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			t.Errorf("decode event: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		published <- input
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}
	port, err := strconv.Atoi(serverURL.Port())
	if err != nil {
		t.Fatalf("parse server port: %v", err)
	}
	t.Setenv("BACKEND_PORT", strconv.Itoa(port))

	handler := &Handler{systemEventClient: events.NewClient(server.Client())}
	blockedAt := time.Date(2026, 7, 27, 10, 11, 12, 0, time.UTC)
	handler.emitGatewayVisibilityBlockedEvent(gatewayVisibilityBlockedEvent{
		ClientIP:        "203.0.113.8:54321",
		BlockedAt:       blockedAt,
		Method:          http.MethodGet,
		Scheme:          "https",
		Host:            "app.example.test",
		Path:            "/private",
		RouteType:       "host_rule",
		RouteKey:        "app.example.test",
		VisibilityScope: "gateway",
		VisibilityMode:  models.HostVisibilityModeInherit,
	})

	select {
	case input := <-published:
		if input.Type != events.FnEventGatewayVisibilityBlocked ||
			input.Source != events.SystemEventSourceGoReauthProxy ||
			input.Level != events.FnEventLevelWarn ||
			input.DedupeKey != gatewayVisibilityEventDedupeKey ||
			input.DedupeTTLSeconds != gatewayVisibilityEventDedupeTTLSeconds {
			t.Fatalf("event envelope = %#v", input)
		}
		if !reflect.DeepEqual(input.Tags, []string{"gateway", "visibility", "security"}) {
			t.Fatalf("event tags = %#v", input.Tags)
		}
		payload, ok := input.Payload.(map[string]any)
		if !ok {
			t.Fatalf("payload type = %T", input.Payload)
		}
		if payload["ip"] != "203.0.113.8" ||
			payload["host"] != "app.example.test" ||
			payload["path"] != "/private" ||
			payload["visibility_scope"] != "gateway" ||
			payload["visibility_mode"] != models.HostVisibilityModeInherit ||
			payload["status"] != float64(499) {
			t.Fatalf("event payload = %#v", payload)
		}
		if _, exists := payload["request_uri"]; exists {
			t.Fatalf("event payload leaked request URI: %#v", payload)
		}
	case <-time.After(time.Second):
		t.Fatal("visibility event was not published")
	}
}
