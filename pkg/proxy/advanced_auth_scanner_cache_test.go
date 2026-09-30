package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go-reauth-proxy/pkg/grpc/pb"
	"go-reauth-proxy/pkg/models"
)

func TestAdvancedAuthGrantCookieTransportAndCacheIsolation(t *testing.T) {
	for _, preflightOnly := range []bool{false, true} {
		t.Run(httpAuthCacheTestName(preflightOnly, ""), func(t *testing.T) {
			h := &Handler{authCache: newAuthStateCache(), preflightCache: newPreflightStateCache()}
			h.authBridge = testAuthBridge{supports: true, authorize: func(_ context.Context, req *pb.AuthorizeHttpRequest) (*pb.AuthorizeHttpResponse, error) {
				forwarded := &http.Request{Header: http.Header{"Cookie": {req.GetContext().GetCookie()}}}
				cookie, err := forwarded.Cookie(advancedAuthGrantCookieName)
				if err != nil || cookie.Value != "valid" {
					return &pb.AuthorizeHttpResponse{
						Preflight:           &pb.PreflightAuthResponse{Deny: true},
						PreflightCacheScope: pb.AuthCacheScope_AUTH_CACHE_SCOPE_EXACT_REQUEST,
					}, nil
				}
				resp := successfulCombinedAuthResponse(req.Mode, pb.AuthCacheScope_AUTH_CACHE_SCOPE_EXACT_REQUEST, pb.AuthCacheScope_AUTH_CACHE_SCOPE_EXACT_REQUEST, nil)
				if resp.Verify != nil {
					resp.Verify.GrantKind = pb.AuthGrantKind_AUTH_GRANT_KIND_SUBDOMAIN_RULE
					resp.Verify.AuthGrantState = "reused"
					resp.Verify.CacheMaxAgeSeconds = 60
					resp.Verify.LoginAuthenticated = false
				}
				return resp, nil
			}}
			cfg := models.AuthConfig{AuthURL: "/verify", AuthCacheTTL: 60, AuthCacheFailTTL: 60}
			valid := advancedAuthGrantCookieName + "=valid"
			forged := advancedAuthGrantCookieName + "=forged"
			empty := advancedAuthGrantCookieName + "="
			for _, tc := range []struct {
				name    string
				cookies []string
				deny    bool
			}{
				{"later header", []string{"theme=dark", valid}, false},
				{"joined header", []string{"theme=dark; " + valid}, false},
				{"first duplicate valid", []string{valid, forged}, false},
				{"first duplicate forged", []string{forged, valid}, true},
				{"first duplicate empty", []string{empty, valid}, true},
				{"single valid", []string{valid}, false},
			} {
				r := httptest.NewRequest(http.MethodGet, "https://app.example/uncommon", nil)
				r.Header["Cookie"] = tc.cookies
				withAdvancedAuthPolicyVersion(r, "v1")
				auth := newRequestAuthContext(r, "203.0.113.20", "login_first", routedBackend{})
				var decision preflightDecision
				if preflightOnly {
					decision = h.runPreflight(r, cfg, "203.0.113.20", true, "login_first", "", auth)
				} else {
					result, handled := h.executeCombinedHTTPAuth(r, cfg, "203.0.113.20", "login_first", true, "", auth)
					if !handled {
						t.Fatal("combined auth was not handled")
					}
					decision = result.preflight
				}
				if decision.deny != tc.deny {
					t.Errorf("%s: deny=%v, want %v", tc.name, decision.deny, tc.deny)
				}
			}
		})
	}
}

func TestRequestAuthContextPreservesAllCookieHeaders(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		r := httptest.NewRequest(http.MethodGet, "https://app.example/uncommon", nil)
		values := []string{"theme=dark", advancedAuthGrantCookieName + "=valid"}
		r.Header["Cookie"] = values
		got := newRequestAuthContext(r, "203.0.113.20", "login_first", routedBackend{}).proto(legacy)
		if got.Cookie != strings.Join(values, "; ") {
			t.Fatalf("legacy=%v: Cookie=%q", legacy, got.Cookie)
		}
	}
}

func TestAdvancedAuthRuleMatchPartitionsAllCacheKeys(t *testing.T) {
	seen := map[[3]authCacheKey]bool{}
	for _, match := range []*advancedAuthRuleMatch{
		nil,
		{host: "app.example", policyVersion: "v1", groupID: "group-1"},
		{host: "app.example", policyVersion: "v1", groupID: "group-2"},
		{host: "app.example", policyVersion: "v2", groupID: "group-1"},
		{host: "other.example", policyVersion: "v1", groupID: "group-1"},
	} {
		r := httptest.NewRequest(http.MethodGet, "https://app.example/uncommon", nil)
		withAdvancedAuthPolicyVersion(r, "v1")
		withAdvancedAuthRuleMatch(r, match)
		dimensions, ok := buildAuthCacheDimensions(r, "203.0.113.20", "login_first")
		if !ok {
			t.Fatal("missing cache dimensions")
		}
		auth := dimensions.authLookup()
		keys := [3]authCacheKey{auth.cacheKey, auth.hostCacheKey, dimensions.preflightLookup(true).cacheKey}
		for prior := range seen {
			for index := range keys {
				if prior[index] == keys[index] {
					t.Fatalf("cache key %d did not distinguish rule match %#v", index, match)
				}
			}
		}
		seen[keys] = true
	}
}

func TestAdvancedAuthRuleMatchPartitionsCachedAuthorization(t *testing.T) {
	for _, preflightOnly := range []bool{false, true} {
		for _, first := range []string{"", "group-1"} {
			t.Run(httpAuthCacheTestName(preflightOnly, first), func(t *testing.T) {
				calls := map[string]int{}
				h := &Handler{authCache: newAuthStateCache(), preflightCache: newPreflightStateCache()}
				h.authBridge = testAuthBridge{supports: true, authorize: func(_ context.Context, req *pb.AuthorizeHttpRequest) (*pb.AuthorizeHttpResponse, error) {
					group := req.GetSubdomainRuleMatch().GetGroupId()
					calls[group]++
					if group == "" {
						return &pb.AuthorizeHttpResponse{
							Preflight:           &pb.PreflightAuthResponse{Deny: true},
							PreflightCacheScope: pb.AuthCacheScope_AUTH_CACHE_SCOPE_EXACT_REQUEST,
						}, nil
					}
					resp := successfulCombinedAuthResponse(req.Mode, pb.AuthCacheScope_AUTH_CACHE_SCOPE_EXACT_REQUEST, pb.AuthCacheScope_AUTH_CACHE_SCOPE_HOST, nil)
					if resp.Verify != nil {
						resp.Verify.AuthRuleGroupId = group
					}
					return resp, nil
				}}
				cfg := models.AuthConfig{AuthURL: "/verify", AuthCacheTTL: 60, AuthCacheFailTTL: 60}
				// Same IP, cookies, URL and policy; only the evaluated rule changes.
				for _, group := range []string{first, "", "group-1", "group-2", "", "group-2", "group-1"} {
					r := httptest.NewRequest(http.MethodGet, "https://app.example/uncommon", nil)
					withAdvancedAuthPolicyVersion(r, "v1")
					if group != "" {
						withAdvancedAuthRuleMatch(r, &advancedAuthRuleMatch{host: "app.example", policyVersion: "v1", groupID: group})
					}
					auth := newRequestAuthContext(r, "203.0.113.20", "login_first", routedBackend{})
					if preflightOnly {
						result := h.runPreflight(r, cfg, "203.0.113.20", true, "login_first", "", auth)
						if result.deny != (group == "") {
							t.Fatalf("group=%q deny=%v", group, result.deny)
						}
					} else {
						result, handled := h.executeCombinedHTTPAuth(r, cfg, "203.0.113.20", "login_first", true, "", auth)
						if !handled || result.preflight.deny != (group == "") {
							t.Fatalf("group=%q handled=%v deny=%v", group, handled, result.preflight.deny)
						}
						if group != "" && (result.auth.entry == nil || result.auth.entry.result.authRuleGroupID != group) {
							t.Fatalf("cached authorization crossed rule groups: want %q, got %#v", group, result.auth)
						}
					}
				}
				for _, group := range []string{"", "group-1", "group-2"} {
					if calls[group] != 1 {
						t.Fatalf("group=%q calls=%d, want one cached fill", group, calls[group])
					}
				}
			})
		}
	}
}

func httpAuthCacheTestName(preflightOnly bool, first string) string {
	mode := "combined"
	if preflightOnly {
		mode = "preflight"
	}
	if first == "" {
		return mode + "/denial-first"
	}
	return mode + "/grant-first"
}
