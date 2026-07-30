package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"go-reauth-proxy/pkg/grpc/pb"
	compiledipset "go-reauth-proxy/pkg/ipset"
	"go-reauth-proxy/pkg/models"
	proxywaf "go-reauth-proxy/pkg/waf"
)

func TestGatewayTrustedClientIPsRuntimeNormalizesMatchesAndClears(t *testing.T) {
	runtime := newGatewayTrustedClientIPsRuntime(models.GatewayTrustedClientIPsRuntime{
		IPs:       []string{" 192.168.1.8 ", "::ffff:203.0.113.9", "192.168.1.8", "::1", "not-an-ip"},
		CIDRs:     []string{"100.64.0.7/10", "2001:db8::8/32", "::1/128", "bad-cidr"},
		UpdatedAt: "2026-07-31T01:00:00Z",
	})

	for _, clientIP := range []string{
		"192.168.1.8",
		"203.0.113.9",
		"100.127.255.254",
		"2001:db8::99",
		"127.0.0.1",
		"::1",
	} {
		if !runtime.contains(clientIP) {
			t.Fatalf("trusted runtime did not match %q", clientIP)
		}
	}
	if runtime.contains("198.51.100.1") {
		t.Fatal("trusted runtime matched an unrelated IP")
	}

	got := runtime.getConfig()
	if len(got.IPs) != 3 || got.IPs[0] != "192.168.1.8" || got.IPs[1] != "203.0.113.9" || got.IPs[2] != "127.0.0.1" {
		t.Fatalf("normalized IPs = %#v, want private, mapped IPv4 and canonical loopback addresses", got.IPs)
	}
	if len(got.CIDRs) != 0 || got.Policy == nil || got.PolicyID == "" {
		t.Fatalf("trusted CIDRs were not compacted into a policy: %#v", got)
	}
	if rangeCount := runtime.cidrSet.RangeCount(); rangeCount != 3 {
		t.Fatalf("compiled CIDR range count = %d, want 3", rangeCount)
	}

	if updated, err := runtime.updateConfig(models.GatewayTrustedClientIPsRuntime{
		UpdatedAt: "2026-07-31T00:59:59Z",
	}); err != nil || !updated {
		t.Fatal("authoritative trusted runtime update was rejected because its wall clock moved backwards")
	}
	if runtime.contains("192.168.1.8") {
		t.Fatal("authoritative empty update did not revoke the trusted runtime")
	}

	if updated, err := runtime.updateConfig(models.GatewayTrustedClientIPsRuntime{
		IPs:       []string{},
		CIDRs:     []string{},
		UpdatedAt: "2026-07-31T01:00:01Z",
	}); err != nil || !updated {
		t.Fatal("newer empty trusted runtime update was ignored")
	}
	if runtime.contains("192.168.1.8") || runtime.contains("100.64.0.1") {
		t.Fatal("empty trusted runtime did not clear exact IPs and CIDRs")
	}
}

func TestReverseProxyThrottleExemptSnapshotAcceptsClockRollbackRevocation(t *testing.T) {
	runtime := newReverseProxyThrottleExemptIPsRuntime(
		models.ReverseProxyThrottleExemptIPsRuntime{
			Enabled:   true,
			IPs:       []string{"203.0.113.8"},
			UpdatedAt: "2026-07-31T01:00:00Z",
		},
	)
	if !runtime.shouldBypass("203.0.113.8") {
		t.Fatal("initial throttle exemption was not active")
	}

	updated, err := runtime.updateConfig(models.ReverseProxyThrottleExemptIPsRuntime{
		Enabled:   false,
		UpdatedAt: "2026-07-31T00:59:59Z",
	})
	if err != nil || !updated {
		t.Fatalf("authoritative throttle revocation was rejected after clock rollback: updated=%v err=%v", updated, err)
	}
	if runtime.shouldBypass("203.0.113.8") {
		t.Fatal("clock rollback preserved a revoked throttle exemption")
	}
}

func TestGatewayTrustedClientIPsRuntimeAcceptsCompiledPolicyWithoutCIDRExpansion(t *testing.T) {
	policy, err := compiledipset.Compile([]string{
		"203.0.113.0/25",
		"203.0.113.128/25",
		"2001:db8::/32",
	})
	if err != nil {
		t.Fatal(err)
	}
	runtime := newGatewayTrustedClientIPsRuntime(models.GatewayTrustedClientIPsRuntime{
		PolicyID: policy.ID,
		Policy:   &policy,
	})
	if !runtime.contains("203.0.113.200") || !runtime.contains("2001:db8::1") {
		t.Fatal("compiled trusted policy did not match its ranges")
	}
	got := runtime.getConfig()
	if got.PolicyID != policy.ID || got.Policy == nil || len(got.CIDRs) != 0 {
		t.Fatalf("compiled trusted policy was not retained compactly: %#v", got)
	}

	corrupt := policy
	corrupt.ID = "ipset-v2:wrong"
	if _, err := runtime.updateConfig(models.GatewayTrustedClientIPsRuntime{
		PolicyID: corrupt.ID,
		Policy:   &corrupt,
	}); err == nil {
		t.Fatal("corrupt compiled trusted policy was accepted")
	}
}

func TestGatewayTrustedClientIPBypassesAllGatewaySecurityFilters(t *testing.T) {
	const clientIP = "203.0.113.77"

	trustCases := []struct {
		name string
		cfg  models.GatewayTrustedClientIPsRuntime
	}{
		{
			name: "exact IP",
			cfg: models.GatewayTrustedClientIPsRuntime{
				IPs: []string{clientIP},
			},
		},
		{
			name: "CIDR",
			cfg: models.GatewayTrustedClientIPsRuntime{
				CIDRs: []string{"203.0.113.0/24"},
			},
		},
	}
	filterCases := []struct {
		name  string
		setup func(*testing.T, *Handler)
	}{
		{
			name: "crawler blocker",
			setup: func(t *testing.T, handler *Handler) {
				t.Helper()
				handler.CrawlerBlocker = models.CrawlerBlockerConfig{Enabled: true}
			},
		},
		{
			name: "general blacklist conflict",
			setup: func(t *testing.T, handler *Handler) {
				t.Helper()
				handler.generalBlacklist = newGeneralBlacklistRuntime(models.GeneralBlacklistConfig{
					Items: []models.GeneralBlacklistRecord{{
						IP:     clientIP,
						Source: models.GeneralBlacklistSourceManual,
					}},
				})
			},
		},
		{
			name: "gateway visibility",
			setup: func(t *testing.T, handler *Handler) {
				t.Helper()
				if err := handler.SetGatewayVisibility(models.GatewayVisibilityConfig{
					Enabled: true,
					CIDRs:   []string{"198.51.100.0/24"},
				}); err != nil {
					t.Fatalf("set gateway visibility: %v", err)
				}
			},
		},
		{
			name: "reverse proxy throttle",
			setup: func(t *testing.T, handler *Handler) {
				t.Helper()
				handler.reverseProxyThrottle = newReverseProxyThrottle(models.ReverseProxyThrottleConfig{
					Enabled:           true,
					RequestsPerSecond: 1,
					Burst:             1,
					BlockSeconds:      3600,
				})
				now := time.Now()
				_ = handler.reverseProxyThrottle.evaluate(clientIP, now)
				if decision := handler.reverseProxyThrottle.evaluate(clientIP, now); decision.Allowed {
					t.Fatal("test setup did not throttle the client IP")
				}
			},
		},
		{
			name: "WAF",
			setup: func(t *testing.T, handler *Handler) {
				t.Helper()
				rulesDir := t.TempDir()
				customDir := filepath.Join(rulesDir, "custom")
				if err := os.MkdirAll(customDir, 0o755); err != nil {
					t.Fatalf("create custom WAF directory: %v", err)
				}
				rule := `SecRule ARGS:test "@streq attack" "id:1902001,phase:2,deny,status:403,msg:'trusted IP bypass test',log"`
				if err := os.WriteFile(filepath.Join(customDir, "trusted-ip-test.conf"), []byte(rule+"\n"), 0o644); err != nil {
					t.Fatalf("write custom WAF rule: %v", err)
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
				handler.WAFConfig = wafConfig
				handler.wafRuntime = wafRuntime
			},
		},
	}

	for _, trustCase := range trustCases {
		for _, filterCase := range filterCases {
			t.Run(trustCase.name+"/"+filterCase.name, func(t *testing.T) {
				var upstreamHits atomic.Int32
				upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					upstreamHits.Add(1)
					w.WriteHeader(http.StatusNoContent)
				}))
				defer upstream.Close()

				handler, _ := newAdditionalProxyTestHandler(t)
				if err := handler.SetRules([]models.Rule{{
					Path:    "/app",
					Target:  upstream.URL,
					UseAuth: false,
				}}); err != nil {
					t.Fatalf("set path rule: %v", err)
				}
				filterCase.setup(t, handler)
				trustedConfig := trustCase.cfg
				trustedConfig.UpdatedAt = "2026-07-31T01:00:00Z"
				handler.SetGatewayTrustedClientIPs(trustedConfig)

				request := httptest.NewRequest(http.MethodGet, "http://gateway.example.com/app/?test=attack", nil)
				request.RemoteAddr = clientIP + ":43210"
				request.Header.Set("User-Agent", "GPTBot")
				recorder := httptest.NewRecorder()

				handler.ServeHTTP(recorder, request)

				if recorder.Code != http.StatusNoContent {
					t.Fatalf("status = %d, want 204; body=%s", recorder.Code, recorder.Body.String())
				}
				if got := upstreamHits.Load(); got != 1 {
					t.Fatalf("upstream hits = %d, want 1", got)
				}
			})
		}
	}
}

func TestGatewayTrustedClientIPRemovalAppliesToNextRequest(t *testing.T) {
	const clientIP = "203.0.113.88"
	var upstreamHits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	handler, _ := newAdditionalProxyTestHandler(t)
	if err := handler.SetRules([]models.Rule{{
		Path:    "/app",
		Target:  upstream.URL,
		UseAuth: false,
	}}); err != nil {
		t.Fatalf("set path rule: %v", err)
	}
	handler.CrawlerBlocker = models.CrawlerBlockerConfig{Enabled: true}
	handler.SetGatewayTrustedClientIPs(models.GatewayTrustedClientIPsRuntime{
		IPs:       []string{clientIP},
		UpdatedAt: "2026-07-31T01:00:00Z",
	})

	request := func() *http.Request {
		req := httptest.NewRequest(http.MethodGet, "http://gateway.example.com/app/private", nil)
		req.RemoteAddr = clientIP + ":43210"
		req.Header.Set("User-Agent", "GPTBot")
		return req
	}
	trustedRecorder := httptest.NewRecorder()
	handler.ServeHTTP(trustedRecorder, request())
	if trustedRecorder.Code != http.StatusNoContent {
		t.Fatalf("trusted status = %d, want 204", trustedRecorder.Code)
	}

	handler.SetGatewayTrustedClientIPs(models.GatewayTrustedClientIPsRuntime{
		IPs:       []string{},
		CIDRs:     []string{},
		UpdatedAt: "2026-07-31T01:00:01Z",
	})
	untrustedRecorder := httptest.NewRecorder()
	handler.ServeHTTP(untrustedRecorder, request())
	if untrustedRecorder.Code != http.StatusForbidden {
		t.Fatalf("status after removal = %d, want 403", untrustedRecorder.Code)
	}
	if got := upstreamHits.Load(); got != 1 {
		t.Fatalf("upstream hits after removal = %d, want 1", got)
	}
}

func TestGatewayTrustedClientIPStillRequiresRouteAuthentication(t *testing.T) {
	const clientIP = "203.0.113.99"
	var upstreamHits atomic.Int32
	var verifyHits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	handler := &Handler{
		HostRules: []models.HostRule{{
			Host:       "app.example.com",
			Target:     upstream.URL,
			UseAuth:    true,
			AccessMode: "login_first",
		}},
		AuthConfig: models.AuthConfig{
			AuthURL:      "/api/auth/verify",
			PreflightURL: "/api/auth/preflight",
		},
		CrawlerBlocker: models.CrawlerBlockerConfig{Enabled: true},
		authBridge: testAuthBridge{
			verify: func(context.Context, *pb.VerifyAuthRequest) (*pb.VerifyAuthResponse, error) {
				verifyHits.Add(1)
				return &pb.VerifyAuthResponse{
					Success:          false,
					Status:           http.StatusUnauthorized,
					RedirectLocation: "/__auth__/login",
				}, nil
			},
		},
		authCache:      newAuthStateCache(),
		preflightCache: newPreflightStateCache(),
		trustedClientIPs: newGatewayTrustedClientIPsRuntime(models.GatewayTrustedClientIPsRuntime{
			IPs: []string{clientIP},
		}),
	}
	handler.publishRequestSnapshotLocked()

	request := httptest.NewRequest(http.MethodGet, "http://app.example.com/private", nil)
	request.RemoteAddr = clientIP + ":43210"
	request.Header.Set("User-Agent", "GPTBot")
	request.AddCookie(&http.Cookie{Name: authSessionCookieName, Value: "invalid-session"})
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusFound || recorder.Header().Get("Location") != "/__auth__/login" {
		t.Fatalf("response = status %d Location %q, want 302 /__auth__/login", recorder.Code, recorder.Header().Get("Location"))
	}
	if got := verifyHits.Load(); got != 1 {
		t.Fatalf("verify hits = %d, want 1", got)
	}
	if got := upstreamHits.Load(); got != 0 {
		t.Fatalf("upstream hits = %d, want 0", got)
	}
}

func TestGatewayTrustedClientIPBypassesHostVisibilityWithoutAuditEvent(t *testing.T) {
	const clientIP = "203.0.113.100"
	var upstreamHits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	handler, _ := newAdditionalProxyTestHandler(t)
	if err := handler.SetHostRules([]models.HostRule{{
		Host:   "private.example.test",
		Target: upstream.URL,
		Visibility: models.HostRuleVisibility{
			Mode:  models.HostVisibilityModeCustom,
			CIDRs: []string{"198.51.100.0/24"},
		},
	}}); err != nil {
		t.Fatalf("set host visibility: %v", err)
	}
	handler.visibilityEventQueue = make(chan gatewayVisibilityBlockedEvent, 1)
	handler.SetGatewayTrustedClientIPs(models.GatewayTrustedClientIPsRuntime{
		IPs:       []string{clientIP},
		UpdatedAt: "2026-07-31T01:00:00Z",
	})

	request := httptest.NewRequest(http.MethodGet, "http://private.example.test/private", nil)
	request.RemoteAddr = clientIP + ":43210"
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body=%s", recorder.Code, recorder.Body.String())
	}
	if got := upstreamHits.Load(); got != 1 {
		t.Fatalf("upstream hits = %d, want 1", got)
	}
	select {
	case event := <-handler.visibilityEventQueue:
		t.Fatalf("trusted request enqueued a visibility block event: %#v", event)
	default:
	}
}

func TestGatewayTrustedClientIPStillEnforcesStrictWhitelistAndSubdomainScope(t *testing.T) {
	const clientIP = "203.0.113.101"

	tests := []struct {
		name               string
		accessMode         string
		verify             *pb.VerifyAuthResponse
		wantStatus         int
		wantConnectionDrop bool
	}{
		{
			name:       "strict whitelist",
			accessMode: "strict_whitelist",
			verify: &pb.VerifyAuthResponse{
				Success: false,
				Status:  http.StatusUnauthorized,
				Message: "IP is not in the strict whitelist",
			},
			wantConnectionDrop: true,
		},
		{
			name:       "subdomain scope",
			accessMode: "login_first",
			verify: &pb.VerifyAuthResponse{
				Success:            false,
				Status:             http.StatusForbidden,
				Message:            "credential cannot access this subdomain",
				AccessDeniedReason: reauthScopeDeniedReason,
			},
			wantStatus: http.StatusForbidden,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var upstreamHits atomic.Int32
			var verifyHits atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				upstreamHits.Add(1)
				w.WriteHeader(http.StatusNoContent)
			}))
			defer upstream.Close()

			handler := &Handler{
				HostRules: []models.HostRule{{
					Host:       "restricted.example.test",
					Target:     upstream.URL,
					UseAuth:    true,
					AccessMode: test.accessMode,
				}},
				AuthConfig: models.AuthConfig{
					AuthURL:      "/api/auth/verify",
					PreflightURL: "/api/auth/preflight",
				},
				CrawlerBlocker: models.CrawlerBlockerConfig{Enabled: true},
				authBridge: testAuthBridge{
					verify: func(context.Context, *pb.VerifyAuthRequest) (*pb.VerifyAuthResponse, error) {
						verifyHits.Add(1)
						return test.verify, nil
					},
				},
				authCache:      newAuthStateCache(),
				preflightCache: newPreflightStateCache(),
				trustedClientIPs: newGatewayTrustedClientIPsRuntime(models.GatewayTrustedClientIPsRuntime{
					IPs: []string{clientIP},
				}),
			}
			handler.publishRequestSnapshotLocked()

			request := httptest.NewRequest(http.MethodGet, "http://restricted.example.test/private", nil)
			request.RemoteAddr = clientIP + ":43210"
			request.Header.Set("User-Agent", "GPTBot")
			request.Header.Set("Accept", "application/json")
			request.AddCookie(&http.Cookie{Name: authSessionCookieName, Value: "valid-but-restricted"})

			if test.wantConnectionDrop {
				recorder := newHijackableResponseRecorder()
				defer recorder.Close()
				handler.ServeHTTP(recorder, request)
				if recorder.client == nil {
					t.Fatal("strict-whitelist denial did not terminate the connection")
				}
			} else {
				recorder := httptest.NewRecorder()
				handler.ServeHTTP(recorder, request)
				if recorder.Code != test.wantStatus {
					t.Fatalf("status = %d, want %d; body=%s", recorder.Code, test.wantStatus, recorder.Body.String())
				}
			}
			if got := verifyHits.Load(); got != 1 {
				t.Fatalf("verify hits = %d, want 1", got)
			}
			if got := upstreamHits.Load(); got != 0 {
				t.Fatalf("upstream hits = %d, want 0", got)
			}
		})
	}
}

func TestGatewayTrustedClientIPStillEnforcesProtocolAndAvailability(t *testing.T) {
	const clientIP = "203.0.113.102"

	tests := []struct {
		name       string
		rule       models.HostRule
		wantStatus int
	}{
		{
			name: "protocol",
			rule: models.HostRule{
				Host:         "protocol.example.test",
				ProtocolMode: models.HostProtocolModeHTTP2,
			},
			wantStatus: http.StatusMisdirectedRequest,
		},
		{
			name: "availability",
			rule: models.HostRule{
				Host:     "unavailable.example.test",
				Disabled: true,
			},
			wantStatus: http.StatusServiceUnavailable,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var upstreamHits atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				upstreamHits.Add(1)
				w.WriteHeader(http.StatusNoContent)
			}))
			defer upstream.Close()

			handler, _ := newAdditionalProxyTestHandler(t)
			test.rule.Target = upstream.URL
			if err := handler.SetHostRules([]models.HostRule{test.rule}); err != nil {
				t.Fatalf("set host rule: %v", err)
			}
			handler.CrawlerBlocker = models.CrawlerBlockerConfig{Enabled: true}
			handler.SetGatewayTrustedClientIPs(models.GatewayTrustedClientIPsRuntime{
				IPs:       []string{clientIP},
				UpdatedAt: "2026-07-31T01:00:00Z",
			})

			request := httptest.NewRequest(http.MethodGet, "https://"+test.rule.Host+"/private", nil)
			request.RemoteAddr = clientIP + ":43210"
			request.Header.Set("User-Agent", "GPTBot")
			request.Header.Set("Accept", "application/json")
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)

			if recorder.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", recorder.Code, test.wantStatus, recorder.Body.String())
			}
			if got := upstreamHits.Load(); got != 0 {
				t.Fatalf("upstream hits = %d, want 0", got)
			}
		})
	}
}
