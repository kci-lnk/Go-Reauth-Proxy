package proxy

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"go-reauth-proxy/pkg/grpc/pb"
	"go-reauth-proxy/pkg/models"
	"go-reauth-proxy/pkg/rpcbridge"
)

type grantSecurityTestBridge struct {
	testAuthBridge
	inspectSupported bool
}

func (b grantSecurityTestBridge) SupportsCapability(capability string) bool {
	return (capability == rpcbridge.CapabilityInspectSubdomainGrantV1 && b.inspectSupported) ||
		b.testAuthBridge.SupportsCapability(capability)
}

func TestSubdomainGrantWAFExemption(t *testing.T) {
	for _, tc := range []struct {
		name, cookie                          string
		valid, bridgeError, oldPeer, disabled bool
		wantInspections                       int
		wantStatus                            int
	}{
		{name: "valid grant", cookie: "opaque", valid: true, wantInspections: 1, wantStatus: 200},
		{name: "valid probe", cookie: "p1.signed", valid: true, wantInspections: 1, wantStatus: 200},
		{name: "first rule match", wantStatus: 403},
		{name: "invalid grant", cookie: "forged", wantInspections: 1, wantStatus: 403},
		{name: "bridge failure", cookie: "opaque", bridgeError: true, wantInspections: 1, wantStatus: 403},
		{name: "old peer", cookie: "opaque", oldPeer: true, wantStatus: 403},
		{name: "disabled policy", cookie: "opaque", valid: true, disabled: true, wantStatus: 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstreamCalls := 0
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				upstreamCalls++
				if _, err := r.Cookie(advancedAuthGrantCookieName); err == nil {
					t.Error("grant leaked upstream")
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer upstream.Close()
			inspections, verifies := 0, 0
			bridge := grantSecurityTestBridge{
				inspectSupported: !tc.oldPeer,
				testAuthBridge: testAuthBridge{supports: true, authorize: func(_ context.Context, req *pb.AuthorizeHttpRequest) (*pb.AuthorizeHttpResponse, error) {
					if req.Mode == pb.HttpAuthMode_HTTP_AUTH_MODE_INSPECT_SUBDOMAIN_GRANT {
						inspections++
						if req.SubdomainRuleMatch != nil {
							t.Error("inspection must not submit a first-time match")
						}
						if req.Context.ForwardedHost != "protected.example.test" {
							t.Errorf("wrong host: %q", req.Context.ForwardedHost)
						}
						if tc.bridgeError {
							return nil, errors.New("inspection unavailable")
						}
						return &pb.AuthorizeHttpResponse{SubdomainGrantSecurityExempt: tc.valid}, nil
					}
					verifies++
					return &pb.AuthorizeHttpResponse{
						Preflight: &pb.PreflightAuthResponse{},
						Verify:    &pb.VerifyAuthResponse{Success: true, Status: 200, GrantKind: pb.AuthGrantKind_AUTH_GRANT_KIND_SUBDOMAIN_RULE, SuppressToolbar: true, AuthGrantState: "session"},
					}, nil
				}},
			}
			handler := newCombinedAuthTestHandler(upstream.URL, bridge, "host", 0)
			handler.HostRules[0].AdvancedAuth = models.AdvancedAuthConfig{
				Enabled: !tc.disabled, PolicyVersion: "v1",
				Groups: []models.AdvancedAuthGroup{{ID: "g1", Conditions: []models.AdvancedAuthCondition{
					{ID: "path", Target: "url_path", Operator: "prefix", Values: []string{"/"}},
				}}},
			}
			configureWAFBlockBehaviorTest(t, handler, models.WAFBlockBehaviorErrorPage, upstream.URL)
			handler.publishRequestSnapshotLocked()
			for i := 0; i < 2; i++ {
				req := httptest.NewRequest("GET", "http://protected.example.test/private?test=attack", nil)
				req.RemoteAddr = "203.0.113.20:12345"
				if tc.cookie != "" {
					req.AddCookie(&http.Cookie{Name: advancedAuthGrantCookieName, Value: tc.cookie})
				}
				rec, recovered := serveCombinedAuthTestRequest(handler, req)
				if recovered != nil {
					t.Fatalf("request panicked: %v", recovered)
				}
				if rec.Code != tc.wantStatus {
					t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
				}
			}
			if inspections != 2*tc.wantInspections {
				t.Fatalf("inspections=%d", inspections)
			}
			if tc.wantStatus == 200 {
				if upstreamCalls != 2 || verifies != 2 {
					t.Fatalf("upstream=%d verifies=%d", upstreamCalls, verifies)
				}
				if events := handler.DrainWAFEvents(10); len(events.Events) != 0 {
					t.Fatalf("exempt requests generated WAF events: %#v", events)
				}
			} else if upstreamCalls != 0 || verifies != 0 {
				t.Fatalf("blocked request reached upstream/auth: %d/%d", upstreamCalls, verifies)
			}
		})
	}
}
