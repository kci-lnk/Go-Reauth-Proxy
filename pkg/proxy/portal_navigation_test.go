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

func TestPortalNavigationModes(t *testing.T) {
	for _, mode := range []string{"internet", "lan"} {
		portal := models.GatewayPortalConfig{NavigationMode: mode}
		for _, client := range []string{"192.168.1.4", "8.8.8.8", "invalid"} {
			if got := gatewayPortalForNavigation(portal, client); got.NavigationMode != mode {
				t.Fatalf("fixed %s for %s became %s", mode, client, got.NavigationMode)
			}
		}
	}
	for client, want := range map[string]string{
		"10.2.3.4": "lan", "172.16.0.1": "lan", "192.168.2.4": "lan",
		"fd00::1": "lan", "fc00::1": "lan", "100.64.0.1": "lan",
		"100.127.255.254": "lan", "::ffff:192.168.1.4": "lan",
		"8.8.8.8": "internet", "2001:4860:4860::8888": "internet",
		"100.128.0.1": "internet", "172.32.0.1": "internet",
		"127.0.0.1": "internet", "::1": "internet", "::ffff:127.0.0.1": "internet",
		"fe80::1": "internet", "invalid": "internet", "": "internet",
	} {
		t.Run(client, func(t *testing.T) {
			portal := models.GatewayPortalConfig{NavigationMode: "lan", SmartLANDetection: true}
			if got := gatewayPortalForNavigation(portal, client); got.NavigationMode != want {
				t.Fatalf("%s: got %s, want %s", client, got.NavigationMode, want)
			}
			if portal.NavigationMode != "lan" {
				t.Fatal("request resolution modified the configured fixed mode")
			}
		})
	}
}

func TestPortalNavigationUsesResolvedClientIPForSelectAndToolbar(t *testing.T) {
	bridge := testAuthBridge{verify: func(context.Context, *pb.VerifyAuthRequest) (*pb.VerifyAuthResponse, error) {
		return &pb.VerifyAuthResponse{Success: true, Status: http.StatusOK, LoginAuthenticated: true}, nil
	}}
	target := newToolbarHTMLTarget(t)
	defer target.Close()
	handler := newPublicHostToolbarHandler(target.URL, bridge)
	handler.mu.Lock()
	handler.HostRules = append(handler.HostRules, models.HostRule{
		Host: "lan.example.com", Target: "http://192.168.1.5:9000/base?tab=1",
	})
	handler.GatewayPortal.SmartLANDetection = true
	handler.publishRequestSnapshotLocked()
	handler.mu.Unlock()

	for _, version := range []string{"v1", "v2"} {
		handler.mu.Lock()
		handler.GatewayPortal.Version = version
		handler.publishRequestSnapshotLocked()
		handler.mu.Unlock()
		for _, endpoint := range []string{"/__select__", "/__assets__/toolbar/data?page_path=/"} {
			for _, client := range []string{"192.168.1.3:54321", "8.8.8.8:54321", "127.0.0.1:54321"} {
				t.Run(version+endpoint+client, func(t *testing.T) {
					req := httptest.NewRequest(http.MethodGet, "http://public.example.com"+endpoint, nil)
					req.RemoteAddr = client
					req.AddCookie(&http.Cookie{Name: authSessionCookieName, Value: "ok"})
					// Direct requests must not accept a forged private forwarded IP.
					req.Header.Set("X-Forwarded-For", "10.0.0.1")
					rec := httptest.NewRecorder()
					handler.ServeHTTP(rec, req)
					if rec.Code != http.StatusOK {
						t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
					}
					body := rec.Body.String()
					got := strings.Contains(body, `"href":"http://192.168.1.5:9000/base?tab=1"`) ||
						strings.Contains(body, `href="http://192.168.1.5:9000/base?tab=1"`)
					if want := strings.HasPrefix(client, "192.168."); got != want {
						t.Fatalf("direct href = %v, want %v: %s", got, want, body)
					}
				})
			}
		}
	}
}

func TestPortalLANNavigationPreservesAccountScope(t *testing.T) {
	bridge := testAuthBridge{verify: func(context.Context, *pb.VerifyAuthRequest) (*pb.VerifyAuthResponse, error) {
		return &pb.VerifyAuthResponse{
			Success: true, Status: http.StatusOK, LoginAuthenticated: true,
			ResponseHeaders: headersToProto(http.Header{
				reauthSubdomainAccessHeader:       {reauthSubdomainAccessCustom},
				reauthAllowedSubdomainHostsHeader: {"allowed.example.com"},
			}),
		}, nil
	}}
	target := newToolbarHTMLTarget(t)
	defer target.Close()
	handler := newPublicHostToolbarHandler(target.URL, bridge)
	handler.mu.Lock()
	handler.HostRules = append(handler.HostRules,
		models.HostRule{Host: "allowed.example.com", Target: "http://192.168.1.5:9000"},
		models.HostRule{Host: "forbidden.example.com", Target: "http://192.168.1.6:9001"},
	)
	handler.GatewayPortal.NavigationMode = "lan"
	handler.publishRequestSnapshotLocked()
	handler.mu.Unlock()
	for _, endpoint := range []string{"/__select__", "/__assets__/toolbar/data?page_path=/"} {
		req := httptest.NewRequest(http.MethodGet, "http://public.example.com"+endpoint, nil)
		req.AddCookie(&http.Cookie{Name: authSessionCookieName, Value: "ok"})
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		body := rec.Body.String()
		if rec.Code != http.StatusOK || !strings.Contains(body, "192.168.1.5:9000") ||
			strings.Contains(body, "192.168.1.6:9001") || strings.Contains(body, "forbidden.example.com") {
			t.Fatalf("LAN navigation ignored account scope: %d %s", rec.Code, body)
		}
	}
}
