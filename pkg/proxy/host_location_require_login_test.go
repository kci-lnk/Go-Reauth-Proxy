package proxy

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go-reauth-proxy/pkg/grpc/pb"
	"go-reauth-proxy/pkg/models"
	"go-reauth-proxy/pkg/rpcbridge"
)

func TestHostLocationAuthMatrix(t *testing.T) {
	for _, hostAuth := range []bool{false, true} {
		for _, mode := range []string{"inherit", "public", "require_login"} {
			for _, match := range []string{"exact", "prefix"} {
				for _, action := range []string{"response", "proxy"} {
					t.Run(fmt.Sprintf("host=%t/%s/%s/%s", hostAuth, mode, match, action), func(t *testing.T) {
						upstreamCalls, verifyCalls := 0, 0
						upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
							upstreamCalls++
							fmt.Fprint(w, "secret")
						}))
						defer upstream.Close()
						path := "/private"
						if match == "prefix" {
							path += "/nested"
						}
						handler := newHostLocationTestHandler(models.HostRule{
							Host: "app.example.com", Target: upstream.URL, UseAuth: hostAuth,
							AccessMode: "login_first", SuppressToolbar: true,
							Locations: []models.HostLocation{{
								Path: "/private", Match: match, Action: action, Target: upstream.URL, AuthMode: mode,
								Response: models.HostLocationResponse{Status: 200, Body: "secret"},
							}},
						})
						handler.AuthConfig = models.AuthConfig{AuthURL: "/api/auth/verify"}
						loggedIn := false
						setTestAuthBridge(t, handler, testAuthBridge{
							verify: func(_ context.Context, request *pb.VerifyAuthRequest) (*pb.VerifyAuthResponse, error) {
								verifyCalls++
								if request.GetContext().GetAccessMode() != "login_first" {
									t.Fatal("Host access policy was not inherited")
								}
								return &pb.VerifyAuthResponse{Success: loggedIn, Status: http.StatusOK, LoginAuthenticated: loggedIn}, nil
							},
						})
						handler.publishRequestSnapshotLocked()
						required := mode == "require_login" || (mode == "inherit" && hostAuth)
						for _, login := range []bool{false, true} {
							loggedIn = login
							recorder := httptest.NewRecorder()
							handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://app.example.com"+path, nil))
							wantStatus := http.StatusOK
							if required && !login {
								wantStatus = http.StatusFound
							}
							if recorder.Code != wantStatus {
								t.Fatalf("login=%t: status=%d, body=%s", login, recorder.Code, recorder.Body.String())
							}
							if required && !login && (strings.Contains(recorder.Body.String(), "secret") || upstreamCalls != 0) {
								t.Fatal("protected response leaked before authentication")
							}
						}
						if required && verifyCalls != 2 {
							t.Fatalf("verify calls=%d, want 2", verifyCalls)
						}
						if !required && verifyCalls != 0 {
							t.Fatalf("public route called verify %d times", verifyCalls)
						}
					})
				}
			}
		}
	}
}

func TestRequiredLoginFailsClosed(t *testing.T) {
	for _, action := range []string{"response", "proxy"} {
		for _, failure := range []string{"missing", "unavailable", "verify_unavailable", "combined_unavailable", "whitelist"} {
			t.Run(action+"/"+failure, func(t *testing.T) {
				upstreamCalls := 0
				upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					upstreamCalls++
					fmt.Fprint(w, "secret")
				}))
				defer upstream.Close()
				handler := newHostLocationTestHandler(models.HostRule{
					Host: "app.example.com", Target: upstream.URL, AccessMode: "strict_whitelist", SuppressToolbar: true,
					Locations: []models.HostLocation{{Path: "/private", Match: "exact", Action: action, Target: upstream.URL,
						AuthMode: models.HostLocationAuthModeRequireLogin, Response: models.HostLocationResponse{Status: 200, Body: "secret"}}},
				})
				wantStatus := http.StatusServiceUnavailable
				if failure != "missing" {
					handler.AuthConfig = models.AuthConfig{AuthURL: "/api/auth/verify"}
					setTestAuthBridge(t, handler, testAuthBridge{
						supports: failure == "combined_unavailable",
						authorize: func(context.Context, *pb.AuthorizeHttpRequest) (*pb.AuthorizeHttpResponse, error) {
							return nil, rpcbridge.ErrAuthBridgeUnavailable
						},
						verify: func(context.Context, *pb.VerifyAuthRequest) (*pb.VerifyAuthResponse, error) {
							if failure == "verify_unavailable" {
								return nil, rpcbridge.ErrAuthBridgeUnavailable
							}
							return &pb.VerifyAuthResponse{Success: true, Status: 200}, nil
						},
						preflight: func(_ context.Context, request *pb.PreflightAuthRequest) (*pb.PreflightAuthResponse, error) {
							if failure == "unavailable" {
								return nil, rpcbridge.ErrAuthBridgeUnavailable
							}
							if request.GetContext().GetAccessMode() != "strict_whitelist" {
								t.Fatal("missing whitelist policy")
							}
							if failure == "whitelist" {
								return &pb.PreflightAuthResponse{AccessDeniedReason: reauthScopeDeniedReason}, nil
							}
							return &pb.PreflightAuthResponse{}, nil
						}})
					if failure == "whitelist" {
						wantStatus = http.StatusForbidden
					}
				}
				handler.publishRequestSnapshotLocked()
				for attempt := 0; attempt < 2; attempt++ {
					recorder := httptest.NewRecorder()
					handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://app.example.com/private", nil))
					if recorder.Code != wantStatus {
						t.Fatalf("status=%d, want %d; %s", recorder.Code, wantStatus, recorder.Body.String())
					}
					if upstreamCalls != 0 || strings.Contains(recorder.Body.String(), "secret") {
						t.Fatal("protected content leaked")
					}
				}
			})
		}
	}
}

func TestRequiredLoginInheritsAdvancedPolicyAndHotUpdates(t *testing.T) {
	handler := newHostLocationTestHandler(models.HostRule{
		Host: "app.example.com", Target: "http://127.0.0.1:8080", AccessMode: "login_first", SuppressToolbar: true,
		AdvancedAuth: models.AdvancedAuthConfig{Enabled: true, PolicyVersion: "v1", Groups: []models.AdvancedAuthGroup{{
			ID: "path-group", Conditions: []models.AdvancedAuthCondition{{ID: "path", Target: "url_path", Operator: "prefix", Values: []string{"/private"}}},
		}}},
		Locations: []models.HostLocation{{Path: "/private", Match: "prefix", Action: "response", AuthMode: "public", Response: models.HostLocationResponse{Status: 200, Body: "secret"}}},
	})
	handler.AuthConfig = models.AuthConfig{AuthURL: "/api/auth/verify", AuthCacheTTL: 60, AuthCacheFailTTL: 60}
	calls := 0
	allow := true
	setTestAuthBridge(t, handler, testAuthBridge{supports: true, authorize: func(_ context.Context, request *pb.AuthorizeHttpRequest) (*pb.AuthorizeHttpResponse, error) {
		calls++
		if request.GetSubdomainRuleMatch().GetGroupId() != "path-group" {
			t.Fatalf("missing advanced policy: %v", request.GetSubdomainRuleMatch())
		}
		response := successfulCombinedAuthResponse(request.GetMode(), pb.AuthCacheScope_AUTH_CACHE_SCOPE_EXACT_REQUEST, pb.AuthCacheScope_AUTH_CACHE_SCOPE_HOST, nil)
		response.Verify.Success = allow
		response.Verify.LoginAuthenticated = allow
		return response, nil
	}})
	handler.publishRequestSnapshotLocked()
	request := func(want int) {
		t.Helper()
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://app.example.com/private/nested", nil))
		if recorder.Code != want {
			t.Fatalf("status=%d, want %d: %s", recorder.Code, want, recorder.Body.String())
		}
	}
	update := func(mode string) {
		t.Helper()
		rules := handler.GetHostRules()
		rules[0].Locations[0].AuthMode = mode
		if err := handler.SetHostRules(rules); err != nil {
			t.Fatal(err)
		}
	}
	request(200)
	if calls != 0 {
		t.Fatal("public route evaluated auth")
	}
	update("require_login")
	request(200)
	if calls != 1 {
		t.Fatal("required route did not evaluate auth")
	}
	request(200)
	if calls != 1 {
		t.Fatal("successful auth was not cached")
	}
	update("public")
	request(200)
	allow = false
	update("require_login")
	request(302)
	if calls != 2 {
		t.Fatal("auth cache survived route auth mode changes")
	}
}

func TestRequiredLoginDoesNotProtectReservedAuthNamespace(t *testing.T) {
	if shouldRunPreflightForRoute(false, true, &models.HostRule{UseAuth: false}, &models.HostLocation{AuthMode: "require_login"}, nil) {
		t.Fatal("login service ingress must remain reachable")
	}
}

func TestRequiredLoginCannotSkipPreflightWithClientHeader(t *testing.T) {
	for _, supportsCombined := range []bool{false, true} {
		t.Run(fmt.Sprintf("combined=%t", supportsCombined), func(t *testing.T) {
			handler := newHostLocationTestHandler(models.HostRule{
				Host: "app.example.com", Target: "http://127.0.0.1:8080", SuppressToolbar: true,
				Locations: []models.HostLocation{{Path: "/private", Match: "exact", Action: "response", AuthMode: "require_login", Response: models.HostLocationResponse{Status: 200, Body: "secret"}}},
			})
			handler.AuthConfig = models.AuthConfig{AuthURL: "/api/auth/verify", AuthCacheTTL: 60}
			calls := 0
			setTestAuthBridge(t, handler, testAuthBridge{
				supports: supportsCombined,
				preflight: func(context.Context, *pb.PreflightAuthRequest) (*pb.PreflightAuthResponse, error) {
					calls++
					return &pb.PreflightAuthResponse{AccessDeniedReason: reauthScopeDeniedReason}, nil
				},
				authorize: func(context.Context, *pb.AuthorizeHttpRequest) (*pb.AuthorizeHttpResponse, error) {
					calls++
					return &pb.AuthorizeHttpResponse{Preflight: &pb.PreflightAuthResponse{AccessDeniedReason: reauthScopeDeniedReason}, Verify: &pb.VerifyAuthResponse{Success: true, Status: 200}}, nil
				},
			})
			handler.publishRequestSnapshotLocked()
			request := httptest.NewRequest(http.MethodGet, "http://app.example.com/private", nil)
			request.Header.Set("X-Reauth-Internal-Preflight", "1")
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if calls != 1 || recorder.Code != http.StatusForbidden || strings.Contains(recorder.Body.String(), "secret") {
				t.Fatalf("client bypassed permissions: calls=%d, status=%d, body=%s", calls, recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestRequiredLoginRejectsMissingLegacyPreflightResponse(t *testing.T) {
	handler := newHostLocationTestHandler(models.HostRule{
		Host: "app.example.com", Target: "http://127.0.0.1:8080", SuppressToolbar: true,
		Locations: []models.HostLocation{{Path: "/private", Match: "exact", Action: "response", AuthMode: "require_login", Response: models.HostLocationResponse{Status: 200, Body: "secret"}}},
	})
	handler.AuthConfig = models.AuthConfig{AuthURL: "/api/auth/verify"}
	setTestAuthBridge(t, handler, testAuthBridge{preflight: func(context.Context, *pb.PreflightAuthRequest) (*pb.PreflightAuthResponse, error) { return nil, nil }})
	handler.publishRequestSnapshotLocked()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://app.example.com/private", nil))
	if recorder.Code != http.StatusServiceUnavailable || strings.Contains(recorder.Body.String(), "secret") {
		t.Fatalf("empty preflight response failed open: status=%d, body=%s", recorder.Code, recorder.Body.String())
	}
}
