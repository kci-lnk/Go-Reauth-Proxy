package proxy

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"go-reauth-proxy/pkg/grpc/pb"
	compiledipset "go-reauth-proxy/pkg/ipset"
	"go-reauth-proxy/pkg/models"
)

func testAdvancedAuthPolicy(t *testing.T, groups []models.AdvancedAuthGroup) *compiledAdvancedAuthPolicy {
	t.Helper()
	policy, err := compileAdvancedAuthPolicy(models.AdvancedAuthConfig{
		Enabled:            true,
		PolicyVersion:      "v1",
		IdleTTLSeconds:     advancedAuthDefaultIdleSeconds,
		MaxLifetimeSeconds: advancedAuthDefaultMaxSeconds,
		Groups:             groups,
	})
	if err != nil {
		t.Fatalf("compileAdvancedAuthPolicy() error = %v", err)
	}
	return policy
}

func TestAdvancedAuthPolicyUsesORGroupsAndANDConditions(t *testing.T) {
	policy := testAdvancedAuthPolicy(t, []models.AdvancedAuthGroup{
		{ID: "ip-and-header", Conditions: []models.AdvancedAuthCondition{
			{ID: "ip", Target: "source_ip", Operator: "equals", Values: []string{"192.0.2.10"}},
			{ID: "header", Target: "request_header", Operator: "equals", Name: "X-Deploy", Values: []string{"green"}},
		}},
		{ID: "path", Conditions: []models.AdvancedAuthCondition{
			{ID: "path", Target: "url_path", Operator: "prefix", Values: []string{"/public"}},
		}},
	})

	request := httptest.NewRequest(http.MethodGet, "https://app.example/public/index.html", nil)
	if got := policy.evaluate(request, "198.51.100.4"); got == nil || got.groupID != "path" {
		t.Fatalf("path OR group match = %#v, want path group", got)
	}
	request = httptest.NewRequest(http.MethodGet, "https://app.example/private", nil)
	request.Header.Set("X-Deploy", "green")
	if got := policy.evaluate(request, "192.0.2.10"); got == nil || got.groupID != "ip-and-header" {
		t.Fatalf("AND group match = %#v, want ip-and-header group", got)
	}
	if got := policy.evaluate(request, "192.0.2.11"); got != nil {
		t.Fatalf("partial AND match = %#v, want no match", got)
	}
}

func TestAdvancedAuthNegativeMultiValuesRequireAllValuesNotToMatch(t *testing.T) {
	policy := testAdvancedAuthPolicy(t, []models.AdvancedAuthGroup{{ID: "negative", Conditions: []models.AdvancedAuthCondition{
		{ID: "h", Target: "request_header", Operator: "not_contains", Name: "X-Role", Values: []string{"blocked"}},
		{ID: "q", Target: "query_parameter", Operator: "not_equals", Name: "mode", Values: []string{"deny"}},
	}}})

	for name, tc := range map[string]struct {
		header string
		query  string
		want   bool
	}{
		"all-negative":       {header: "ok; safe", query: "mode=allow&mode=preview", want: true},
		"one-header-matches": {header: "ok; blocked", query: "mode=allow", want: false},
		"one-query-matches":  {header: "ok", query: "mode=allow&mode=deny", want: false},
		"missing-header":     {header: "", query: "mode=allow", want: false},
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "https://app.example/private?"+tc.query, nil)
			if tc.header != "" {
				request.Header["x-role"] = []string{tc.header}
			}
			got := policy.evaluate(request, "192.0.2.1") != nil
			if got != tc.want {
				t.Fatalf("evaluate() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAdvancedAuthLegacyCIDRsUseSharedIPSetForIPv4IPv6AndRegion(t *testing.T) {
	policy := testAdvancedAuthPolicy(t, []models.AdvancedAuthGroup{
		{ID: "source-networks", Conditions: []models.AdvancedAuthCondition{{
			ID:       "ip",
			Target:   "source_ip",
			Operator: "in_cidr",
			CIDRs:    []string{"192.0.2.0/24", "2001:db8:1::/48"},
		}}},
		{ID: "region", Conditions: []models.AdvancedAuthCondition{{ID: "region", Target: "source_region", Operator: "in", CIDRs: []string{"2001:db8::/32", "198.51.100.0/24"}}}},
	})
	request := httptest.NewRequest(http.MethodGet, "https://app.example/", nil)
	if policy.evaluate(request, "192.0.2.1") == nil {
		t.Fatal("IPv4 source should satisfy the IPv4 CIDR")
	}
	if got := policy.evaluate(request, "2001:db8:1::1234"); got == nil || got.groupID != "source-networks" {
		t.Fatalf("IPv6 source match = %#v, want source-networks group", got)
	}
	if policy.evaluate(request, "2001:db8::1234") == nil {
		t.Fatal("IPv6 source should satisfy the region CIDR")
	}
	negative := testAdvancedAuthPolicy(t, []models.AdvancedAuthGroup{{ID: "negative", Conditions: []models.AdvancedAuthCondition{{
		ID: "ip", Target: "source_ip", Operator: "not_in_cidr", CIDRs: []string{"192.0.2.0/24"},
	}}}})
	if negative.evaluate(request, "not-an-ip") != nil {
		t.Fatal("invalid source IP must not satisfy a negative CIDR condition")
	}
}

func TestAdvancedAuthUsesSharedCompiledIPSetPolicy(t *testing.T) {
	transport, err := compiledipset.Compile([]string{
		"192.0.2.0/25",
		"192.0.2.128/25",
		"2001:db8::/32",
	})
	if err != nil {
		t.Fatal(err)
	}
	set, err := compiledipset.Decode(transport)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := compileAdvancedAuthPolicyWithSets(models.AdvancedAuthConfig{
		Enabled:            true,
		PolicyVersion:      "compiled",
		IdleTTLSeconds:     advancedAuthDefaultIdleSeconds,
		MaxLifetimeSeconds: advancedAuthDefaultMaxSeconds,
		Groups: []models.AdvancedAuthGroup{{ID: "compiled", Conditions: []models.AdvancedAuthCondition{{
			ID:       "source",
			Target:   "source_region",
			Operator: "in",
			PolicyID: transport.ID,
		}}}},
	}, map[string]*compiledipset.Set{transport.ID: set})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "https://app.example/", nil)
	if policy.evaluate(request, "192.0.2.255") == nil {
		t.Fatal("compiled IPv4 range did not match")
	}
	if policy.evaluate(request, "2001:db8::1") == nil {
		t.Fatal("compiled IPv6 range did not match")
	}
	if policy.evaluate(request, "198.51.100.1") != nil {
		t.Fatal("address outside the compiled policy matched")
	}
}

func TestAdvancedAuthExactSourceIPSupportsMultipleIPv4AndIPv6Addresses(t *testing.T) {
	policy := testAdvancedAuthPolicy(t, []models.AdvancedAuthGroup{{ID: "exact", Conditions: []models.AdvancedAuthCondition{{
		ID:       "ip",
		Target:   "source_ip",
		Operator: "equals",
		// Legacy control snapshots encoded exact addresses as host prefixes.
		// Keep that migration shape accepted alongside compiled policies.
		CIDRs: []string{
			"192.0.2.10/32",
			"2001:0db8::10/128",
			"2001:db8::10/128",
		},
	}}}})
	request := httptest.NewRequest(http.MethodGet, "https://app.example/", nil)
	for _, address := range []string{"192.0.2.10", "2001:db8::10"} {
		if got := policy.evaluate(request, address); got == nil || got.groupID != "exact" {
			t.Fatalf("exact source %q match = %#v, want exact group", address, got)
		}
	}
	if got := policy.evaluate(request, "2001:db8::11"); got != nil {
		t.Fatalf("unlisted IPv6 source match = %#v, want nil", got)
	}
}

func TestAdvancedAuthSourceNetworkModesRejectAmbiguousInput(t *testing.T) {
	for _, condition := range []models.AdvancedAuthCondition{
		{ID: "bare-cidr", Target: "source_ip", Operator: "in_cidr", Values: []string{"192.0.2.10"}},
		{ID: "network-as-ip", Target: "source_ip", Operator: "equals", Values: []string{"2001:db8::/32"}},
	} {
		if _, err := compileAdvancedAuthPolicy(models.AdvancedAuthConfig{
			Enabled:       true,
			PolicyVersion: "v1",
			Groups: []models.AdvancedAuthGroup{{
				ID: "g", Conditions: []models.AdvancedAuthCondition{condition},
			}},
		}); err == nil {
			t.Fatalf("ambiguous source network condition %#v unexpectedly compiled", condition)
		}
	}
}

func TestAdvancedAuthMethodConditionsAndUpgradeAuthorization(t *testing.T) {
	postPolicy := testAdvancedAuthPolicy(t, []models.AdvancedAuthGroup{{ID: "post", Conditions: []models.AdvancedAuthCondition{
		{ID: "method", Target: "http_method", Operator: "in", Values: []string{"POST"}},
	}}})
	for method, want := range map[string]bool{http.MethodPost: true, http.MethodGet: false, http.MethodDelete: false} {
		request := httptest.NewRequest(method, "https://app.example/", nil)
		if got := postPolicy.evaluate(request, "192.0.2.1") != nil; got != want {
			t.Fatalf("method %s evaluate() = %v, want %v", method, got, want)
		}
	}
	allMethodsPolicy := testAdvancedAuthPolicy(t, []models.AdvancedAuthGroup{{ID: "path", Conditions: []models.AdvancedAuthCondition{
		{ID: "path", Target: "url_path", Operator: "prefix", Values: []string{"/"}},
	}}})
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		request := httptest.NewRequest(method, "https://app.example/", nil)
		if got := allMethodsPolicy.evaluate(request, "192.0.2.1"); got == nil {
			t.Fatalf("method %s without an HTTP method condition = nil, want path group", method)
		}
	}
	for _, upgrade := range []string{"h2c, websocket", "h2c"} {
		upgraded := httptest.NewRequest(http.MethodGet, "https://app.example/", nil)
		upgraded.Header.Set("Upgrade", upgrade)
		upgraded.Header.Set("Connection", "keep-alive, Upgrade")
		if got := allMethodsPolicy.evaluate(upgraded, "192.0.2.1"); got == nil {
			t.Fatalf("Upgrade %q authorization match = nil, want path group", upgrade)
		}
	}
}

func TestCombinedRequestAuthContextCarriesOnlyUpgradeSignal(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "https://app.example/websocket", nil)
	request.Header.Set("Upgrade", "websocket")
	request.Header.Set("Connection", "Upgrade")
	request.Header.Set("X-Unrelated", "must-not-be-forwarded")

	context := newRequestAuthContext(request, "192.0.2.1", "login_first", routedBackend{}).proto(false)
	if got := len(context.GetExtraHeaders()); got != 1 {
		t.Fatalf("combined ExtraHeaders length = %d, want 1", got)
	}
	header := context.GetExtraHeaders()[0]
	if header.GetName() != "Upgrade" || len(header.GetValues()) != 1 || header.GetValues()[0] != "websocket" {
		t.Fatalf("combined Upgrade header = %#v", header)
	}
}

func TestCombinedRequestAuthContextRejectsIncompleteUpgradeSignal(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "https://app.example/websocket", nil)
	request.Header.Set("Upgrade", "websocket")

	context := newRequestAuthContext(request, "192.0.2.1", "login_first", routedBackend{}).proto(false)
	if got := len(context.GetExtraHeaders()); got != 0 {
		t.Fatalf("incomplete Upgrade ExtraHeaders length = %d, want 0", got)
	}
}

func TestAdvancedAuthUserAgentRuleMatchesTrimAppWebSocket(t *testing.T) {
	policy := testAdvancedAuthPolicy(t, []models.AdvancedAuthGroup{{
		ID: "trim-app",
		Conditions: []models.AdvancedAuthCondition{{
			ID:       "user-agent",
			Target:   "request_header",
			Operator: "contains",
			Name:     "User-Agent",
			Values:   []string{"com.trim.app.ios"},
		}},
	}})
	request := httptest.NewRequest(http.MethodGet, "https://fn.example/websocket", nil)
	request.Header.Set("User-Agent", "Dart/3.10 (dart:io), 1.32.3 (com.trim.app.ios; build:1323019; iOS 26.5.2) Flutter/3.10.9")
	request.Header.Set("Upgrade", "websocket")
	request.Header.Set("Connection", "Upgrade")

	match := policy.evaluate(request, "2001:db8::1")
	if match == nil || match.groupID != "trim-app" {
		t.Fatalf("Trim App WebSocket match = %#v, want trim-app group", match)
	}
}

func TestAdvancedAuthUserAgentRuleMatchesTrimAppMutationMethods(t *testing.T) {
	policy := testAdvancedAuthPolicy(t, []models.AdvancedAuthGroup{{
		ID: "trim-app",
		Conditions: []models.AdvancedAuthCondition{{
			ID:       "user-agent",
			Target:   "request_header",
			Operator: "contains",
			Name:     "User-Agent",
			Values:   []string{"com.trim.app.ios"},
		}},
	}})
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		request := httptest.NewRequest(method, "https://fn.example/v/api/v1/item", nil)
		request.Header.Set("User-Agent", "1.32.3 (com.trim.app.ios; build:1323019; iOS 26.5.2) Flutter/3.10.9")
		match := policy.evaluate(request, "2001:db8::1")
		if match == nil || match.groupID != "trim-app" {
			t.Fatalf("Trim App %s match = %#v, want trim-app group", method, match)
		}
	}
}

func TestAdvancedAuthRejectsProtectedHeadersAndInvalidRegex(t *testing.T) {
	for _, condition := range []models.AdvancedAuthCondition{
		{ID: "cookie", Target: "request_header", Operator: "exists", Name: "Cookie"},
		{ID: "host", Target: "request_header", Operator: "exists", Name: "Host"},
		{ID: "regex", Target: "url_path", Operator: "regex", Values: []string{"["}},
		{ID: "empty", Target: "url_path", Operator: "prefix", Values: []string{"/admin", ""}},
	} {
		if _, err := compileAdvancedAuthPolicy(models.AdvancedAuthConfig{
			Enabled: true, PolicyVersion: "v1", Groups: []models.AdvancedAuthGroup{{ID: "g", Conditions: []models.AdvancedAuthCondition{condition}}},
		}); err == nil {
			t.Fatalf("condition %#v unexpectedly compiled", condition)
		}
	}
}

func TestRequestAuthContextUsesTheEffectiveRoutingHost(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "https://origin.internal/private", nil)
	request.Host = "origin.internal:8443"
	request.Header.Set("X-Forwarded-Host", "APP.EXAMPLE.COM.:443")

	context := newRequestAuthContext(
		request,
		"192.0.2.1",
		"login_first",
		newRoutedBackendWithRouteID(
			"http://10.0.0.8:5666",
			"app.example.com",
			"route-generation-a",
		),
	).proto(false)
	if got, want := context.GetForwardedHost(), requestHostForRouting(request); got != want {
		t.Fatalf("ForwardedHost = %q, want effective routing host %q", got, want)
	}
	if got, want := context.GetHost(), requestHostForRouting(request); got != want {
		t.Fatalf("Host = %q, want effective routing host %q", got, want)
	}
	if got := context.GetRoutedUpstream(); got != "http://10.0.0.8:5666" {
		t.Fatalf("RoutedUpstream = %q", got)
	}
	if context.RoutedUpstream == nil {
		t.Fatal("RoutedUpstream presence = false, want true")
	}
	if got := context.GetRoutedUpstreamHost(); got != "app.example.com" {
		t.Fatalf("RoutedUpstreamHost = %q", got)
	}
	if context.RoutedUpstreamHost == nil {
		t.Fatal("RoutedUpstreamHost presence = false, want true")
	}
	if got := context.GetRoutedUpstreamRouteId(); got != "route-generation-a" {
		t.Fatalf("RoutedUpstreamRouteId = %q", got)
	}
	if context.RoutedUpstreamRouteId == nil {
		t.Fatal("RoutedUpstreamRouteId presence = false, want true")
	}
}

func TestRequestAuthContextPreservesOptionalRoutedBackendFields(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "https://app.example/private", nil)
	rule := &models.Rule{Path: "/", Target: "http://[invalid"}
	backend := (&Handler{}).routedBackendForRequest(request, requestSnapshot{
		routeGeneration: "route-a",
	}, nil, nil, rule)
	if !backend.matched || backend.hostSet {
		t.Fatalf("invalid-target backend = %#v, want matched route without resolved host", backend)
	}

	context := newRequestAuthContext(request, "192.0.2.1", "login_first", backend).proto(false)
	if context.RoutedUpstream == nil || context.GetRoutedUpstream() != backend.target {
		t.Fatalf("RoutedUpstream = %#v, want present target %q", context.RoutedUpstream, backend.target)
	}
	if context.RoutedUpstreamHost != nil {
		t.Fatalf("RoutedUpstreamHost = %#v, want absent", context.RoutedUpstreamHost)
	}
	if context.RoutedUpstreamRouteId == nil || context.GetRoutedUpstreamRouteId() != backend.routeID {
		t.Fatalf("RoutedUpstreamRouteId = %#v, want present route %q", context.RoutedUpstreamRouteId, backend.routeID)
	}
}

func TestRoutedUpstreamFollowsTheSelectedGatewayRoute(t *testing.T) {
	handler := &Handler{preserveHost: newPreserveHostConfig(models.PreserveHostConfig{})}
	request := httptest.NewRequest(http.MethodGet, "https://app.example.com/s/share", nil)
	hostRule := &models.HostRule{
		Host:         "app.example.com",
		Target:       " http://10.0.0.8:5666/fnos ",
		PreserveHost: true,
	}
	nonPreservingHostRule := &models.HostRule{
		Host:   "plain.example.com",
		Target: "http://10.0.0.11:5666",
	}
	pathRule := &models.Rule{Path: "/app", Target: "http://10.0.0.9:8000"}
	proxyLocation := &models.HostLocation{
		Path:   "/api",
		Match:  models.HostLocationMatchPrefix,
		Action: models.HostLocationActionProxy,
		Target: "http://10.0.0.10:9000",
	}
	responseLocation := &models.HostLocation{
		Path:   "/health",
		Match:  models.HostLocationMatchExact,
		Action: models.HostLocationActionResponse,
	}
	snapshot := requestSnapshot{
		routeGeneration: "route-generation-fallback",
		routeIDs: map[string]string{
			hostRouteIncarnationKey(hostRule):                           "route-host",
			hostRouteIncarnationKey(nonPreservingHostRule):              "route-host-plain",
			hostLocationRouteIncarnationKey(hostRule, proxyLocation):    "route-location-proxy",
			hostLocationRouteIncarnationKey(hostRule, responseLocation): "route-location-response",
			pathRouteIncarnationKey(pathRule):                           "route-path",
		},
	}

	tests := []struct {
		name     string
		hostRule *models.HostRule
		location *models.HostLocation
		rule     *models.Rule
		want     routedBackend
	}{
		{name: "host", hostRule: hostRule, want: newRoutedBackendWithRouteID("http://10.0.0.8:5666/fnos", "app.example.com", "route-host")},
		{name: "host without preserve host", hostRule: nonPreservingHostRule, want: newRoutedBackendWithRouteID("http://10.0.0.11:5666", "10.0.0.11:5666", "route-host-plain")},
		{name: "host location", hostRule: hostRule, location: proxyLocation, want: newRoutedBackendWithRouteID("http://10.0.0.10:9000", "app.example.com", "route-location-proxy")},
		{name: "static response", hostRule: hostRule, location: responseLocation, want: newRoutedBackendWithRouteID("", "", "route-location-response")},
		{name: "path", rule: pathRule, want: newRoutedBackendWithRouteID("http://10.0.0.9:8000", "app.example.com", "route-path")},
		{name: "unmatched", want: routedBackend{}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := handler.routedBackendForRequest(request, snapshot, test.hostRule, test.location, test.rule); !reflect.DeepEqual(got, test.want) {
				t.Fatalf("routedBackendForRequest() = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestAdvancedAuthRejectsOversizedValueAndRegexSets(t *testing.T) {
	tooManyValues := make([]string, advancedAuthMaxValues+1)
	for index := range tooManyValues {
		tooManyValues[index] = fmt.Sprintf("value-%d", index)
	}
	for _, condition := range []models.AdvancedAuthCondition{
		{ID: "values", Target: "url_path", Operator: "equals", Values: tooManyValues},
		{ID: "regexes", Target: "url_path", Operator: "regex", Values: tooManyValues},
		{ID: "networks", Target: "source_ip", Operator: "in_cidr", CIDRs: tooManyValues},
	} {
		if _, err := compileAdvancedAuthPolicy(models.AdvancedAuthConfig{
			Enabled: true, PolicyVersion: "v1", Groups: []models.AdvancedAuthGroup{{
				ID: "g", Conditions: []models.AdvancedAuthCondition{condition},
			}},
		}); err == nil {
			t.Fatalf("oversized condition %#v unexpectedly compiled", condition)
		}
	}
}

func TestStripAdvancedAuthGrantCookiePreservesOtherCookies(t *testing.T) {
	headers := http.Header{}
	headers.Add("Cookie", "sid=one; "+advancedAuthGrantCookieName+"=secret; theme=dark")
	headers.Add("Cookie", advancedAuthGrantCookieName+"=second")
	stripAdvancedAuthGrantCookie(headers)
	if got, want := headers.Values("Cookie"), []string{"sid=one; theme=dark"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Cookie headers = %#v, want %#v", got, want)
	}
	lowercase := http.Header{"cookie": {"sid=one; " + advancedAuthGrantCookieName + "=secret"}}
	stripAdvancedAuthGrantCookie(lowercase)
	if got, exists := advancedAuthHeaderValues(lowercase, "Cookie"); !exists || len(got) != 1 || got[0] != "sid=one" {
		t.Fatalf("lowercase Cookie headers = %#v, want sid-only", got)
	}
}

func TestStripAdvancedAuthGrantSetCookiesPreservesMalformedUnrelatedHeaders(t *testing.T) {
	headers := http.Header{}
	headers.Add("Set-Cookie", advancedAuthGrantCookieName+"=secret; Path=/")
	headers.Add("Set-Cookie", "session=ok; Path=/")
	headers.Add("Set-Cookie", advancedAuthGrantCookieName+"=malformed")
	stripAdvancedAuthGrantSetCookies(headers)
	values := headers.Values("Set-Cookie")
	if len(values) != 1 || !strings.HasPrefix(values[0], "session=ok") {
		t.Fatalf("Set-Cookie headers = %#v, want only session cookie", values)
	}
}

func TestSetHostRulesPreservesAdvancedAuthForLegacyEditors(t *testing.T) {
	handler := &Handler{HostRules: []models.HostRule{{
		Host:    "app.example.com",
		Target:  "http://127.0.0.1:8080",
		UseAuth: true,
		AdvancedAuth: models.AdvancedAuthConfig{
			Enabled:       true,
			PolicyVersion: "v1",
			Groups: []models.AdvancedAuthGroup{{ID: "g", Conditions: []models.AdvancedAuthCondition{{
				ID: "path", Target: "url_path", Operator: "prefix", Values: []string{"/public"},
			}}}},
		},
	}}}
	if err := handler.SetHostRules([]models.HostRule{{
		Host: "app.example.com", Target: "http://127.0.0.1:8080", UseAuth: true,
	}}); err != nil {
		t.Fatalf("SetHostRules() error = %v", err)
	}
	got := handler.GetHostRules()
	if len(got) != 1 || !got[0].AdvancedAuth.Enabled || got[0].AdvancedAuth.PolicyVersion != "v1" {
		t.Fatalf("advanced auth after legacy update = %#v, want existing policy preserved", got)
	}
}

func TestDisabledAdvancedAuthMissingPolicyDoesNotBlockHostRuleUpdate(t *testing.T) {
	rule := models.HostRule{
		Host:    "app.example.com",
		Target:  "http://127.0.0.1:8080",
		UseAuth: true,
		AdvancedAuth: models.AdvancedAuthConfig{
			Enabled:       false,
			PolicyVersion: "draft-v1",
			Groups: []models.AdvancedAuthGroup{{
				ID: "group-1",
				Conditions: []models.AdvancedAuthCondition{{
					ID:       "condition-1",
					Target:   "source_region",
					Operator: "in",
					PolicyID: "ipset-v2:missing",
				}},
			}},
		},
	}

	handler := &Handler{}
	if err := handler.SetHostRulesBundle([]models.HostRule{rule}, nil); err != nil {
		t.Fatalf("disabled draft blocked unrelated Host update: %v", err)
	}
	rule.AdvancedAuth.Enabled = true
	if err := handler.SetHostRulesBundle([]models.HostRule{rule}, nil); err == nil ||
		!strings.Contains(err.Error(), "references missing IP set") {
		t.Fatalf("enabled rule did not fail closed for a missing policy: %v", err)
	}
}

func TestExplicitDisabledAdvancedAuthClearsUnusablePersistedDraft(t *testing.T) {
	handler := &Handler{HostRules: []models.HostRule{{
		Host:    "app.example.com",
		Target:  "http://127.0.0.1:8080",
		UseAuth: true,
		AdvancedAuth: models.AdvancedAuthConfig{
			Enabled:       false,
			PolicyVersion: "draft-v1",
			Groups: []models.AdvancedAuthGroup{{
				ID: "group-1",
				Conditions: []models.AdvancedAuthCondition{{
					ID:       "condition-1",
					Target:   "source_region",
					Operator: "in",
				}},
			}},
		},
	}}}

	err := handler.SetHostRulesBundle([]models.HostRule{{
		Host:            "app.example.com",
		Target:          "http://127.0.0.1:8080",
		UseAuth:         true,
		AdvancedAuthSet: true,
	}}, nil)
	if err != nil {
		t.Fatalf("explicit disabled advanced auth did not clear unusable draft: %v", err)
	}
	got := handler.GetHostRules()
	if len(got) != 1 || !isEmptyAdvancedAuthConfig(got[0].AdvancedAuth) {
		t.Fatalf("advanced auth after explicit disable = %#v, want empty", got)
	}
}

func TestAdvancedAuthPolicyVersionPartitionsAuthCache(t *testing.T) {
	first := httptest.NewRequest(http.MethodGet, "https://app.example/public", nil)
	first.AddCookie(&http.Cookie{Name: advancedAuthGrantCookieName, Value: "opaque"})
	withAdvancedAuthPolicyVersion(first, "v1")
	second := first.Clone(first.Context())
	withAdvancedAuthPolicyVersion(second, "v2")
	firstLookup, firstOK := buildAuthCacheLookup(first, "192.0.2.1", "login_first")
	secondLookup, secondOK := buildAuthCacheLookup(second, "192.0.2.1", "login_first")
	if !firstOK || !secondOK || firstLookup.cacheKey == secondLookup.cacheKey || firstLookup.hostCacheKey == secondLookup.hostCacheKey {
		t.Fatalf("policy versions did not partition auth cache: %#v vs %#v", firstLookup, secondLookup)
	}
}

func TestAdvancedAuthGrantCacheTTLHonorsSuccessCacheSetting(t *testing.T) {
	result := authCheckResult{
		allowed:            true,
		cacheMaxAgeSeconds: 120,
	}
	tests := []struct {
		name string
		ttl  int
		want time.Duration
	}{
		{name: "disabled", ttl: 0, want: 0},
		{name: "configured cap", ttl: 15, want: 15 * time.Second},
		{name: "bridge cap", ttl: 120, want: 60 * time.Second},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := models.AuthConfig{
				AuthCacheTTL:     test.ttl,
				AuthCacheFailTTL: 60,
			}
			if got := authCacheTTL(config, result); got != test.want {
				t.Fatalf("authCacheTTL() = %s, want %s", got, test.want)
			}
		})
	}
}

func TestSubdomainRuleGrantDoesNotMarkSystemLoginActive(t *testing.T) {
	handler := &Handler{}
	request := httptest.NewRequest(http.MethodGet, "https://app.example/public", nil)
	result := handler.applyAuthCheckPlan(httptest.NewRecorder(), request, authCheckPlan{result: authCheckResult{
		allowed:       true,
		authenticated: false,
		decision:      "subdomain_rule_allowed",
	}}, "192.0.2.1", "")
	if !result.allowed || result.authenticated {
		t.Fatalf("grant result = %#v, want allowed with authenticated=false", result)
	}
	if got := handler.loggedInActiveCount.Load(); got != 0 {
		t.Fatalf("loggedInActiveCount = %d, want 0 for temporary grant", got)
	}
}

func TestAuthRateLimitResponsePreserves429AndRetryAfter(t *testing.T) {
	handler := &Handler{}
	request := httptest.NewRequest(http.MethodGet, "https://app.example/public", nil)
	plan := handler.authCheckPlanFromResponse(request, models.AuthConfig{}, "", "", time.Now(), &pb.VerifyAuthResponse{
		Status: 429,
		ResponseHeaders: []*pb.Header{{
			Name:   "Retry-After",
			Values: []string{"7"},
		}},
	})
	recorder := httptest.NewRecorder()
	result := handler.applyAuthCheckPlan(recorder, request, plan, "192.0.2.1", "")
	if result.decision != "rate_limited" || result.statusCode != http.StatusTooManyRequests {
		t.Fatalf("rate-limited result = %#v", result)
	}
	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", recorder.Code)
	}
	if got := recorder.Header().Get("Retry-After"); got != "7" {
		t.Fatalf("Retry-After = %q, want 7", got)
	}
}
