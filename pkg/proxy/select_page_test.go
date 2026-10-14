package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go-reauth-proxy/pkg/config"
	"go-reauth-proxy/pkg/grpc/pb"
	"go-reauth-proxy/pkg/models"
)

func TestDisabledSelectPageCannotReachAuthOrMappings(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("disabled select page reached upstream") }))
	defer upstream.Close()
	for _, behavior := range []string{"error_page", "reset_connection"} {
		for _, mapping := range []string{"none", "host", "path", "default-host", "default-path"} {
			for _, loggedIn := range []bool{false, true} {
				t.Run(behavior+"/"+mapping+"/loggedIn="+map[bool]string{true: "true", false: "false"}[loggedIn], func(t *testing.T) {
					cfg := config.DefaultConfig()
					cfg.Portal.SetSelectPageEnabled(false)
					cfg.UnmatchedRoute.Behavior = behavior
					switch mapping {
					case "host":
						cfg.HostRules = []models.HostRule{{Host: "gateway.example.com", Target: upstream.URL, UseAuth: true}}
					case "path":
						cfg.Rules = []models.Rule{{Path: "/", Target: upstream.URL, UseAuth: true}}
					case "default-host":
						cfg.HostRules = []models.HostRule{{Host: "default.example.com", Target: upstream.URL, IsDefault: true}}
					case "default-path":
						cfg.Rules = []models.Rule{{Path: "/app/", Target: upstream.URL}}
						cfg.DefaultRoute = "/app/"
					}
					h := NewHandler(7996, 7999, nil, cfg, filepath.Join(t.TempDir(), "logs"), nil)
					t.Cleanup(h.gatewayLogManager.Close)
					h.authBridge = testAuthBridge{verify: func(context.Context, *pb.VerifyAuthRequest) (*pb.VerifyAuthResponse, error) {
						t.Error("disabled select page reached auth")
						return &pb.VerifyAuthResponse{Success: true, Status: 200, LoginAuthenticated: true}, nil
					}}
					req := httptest.NewRequest("GET", "http://gateway.example.com/__select__?test=1", nil)
					if loggedIn {
						req.AddCookie(&http.Cookie{Name: authSessionCookieName, Value: "ok"})
					}
					rec := newHijackableResponseRecorder()
					defer rec.Close()
					h.ServeHTTP(rec, req)
					if rec.Header().Get("Location") != "" {
						t.Fatal("disabled page redirected")
					}
					if behavior == "reset_connection" {
						if rec.client == nil || rec.body.Len() != 0 {
							t.Fatal("expected connection close without response body")
						}
						if _, err := rec.client.Read(make([]byte, 1)); err != io.EOF {
							t.Fatalf("connection remains open: %v", err)
						}
					} else if rec.code != http.StatusNotFound || strings.Contains(rec.body.String(), `href="/__select__"`) || strings.Contains(rec.body.String(), upstream.URL) {
						t.Fatalf("unexpected disabled page: %d %s", rec.code, rec.body.String())
					}
				})
			}
		}
	}
}

func TestSelectPageRootFallbackAndExistingRoutes(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "mapped") }))
	defer upstream.Close()
	for _, tc := range []struct {
		name         string
		enabled      bool
		rules        bool
		defaultRoute bool
		host         bool
		want         int
		location     string
	}{
		{name: "legacy fallback", enabled: true, rules: true, want: 302, location: "/__select__"},
		{name: "disabled fallback", rules: true, want: 404},
		{name: "empty welcome", want: 200},
		{name: "custom default route", rules: true, defaultRoute: true, want: 200},
		{name: "default host", host: true, want: 302, location: "http://app.example.com/"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.DefaultConfig()
			cfg.AuthConfig.AuthURL = ""
			cfg.Portal.SetSelectPageEnabled(tc.enabled)
			if tc.rules {
				cfg.Rules = []models.Rule{{Path: "/app/", Target: upstream.URL}}
			}
			if tc.defaultRoute {
				cfg.DefaultRoute = "/app/"
			}
			if tc.host {
				cfg.HostRules = []models.HostRule{{Host: "app.example.com", Target: upstream.URL, IsDefault: true}}
			}
			h := NewHandler(7996, 7999, nil, cfg, filepath.Join(t.TempDir(), "logs"), nil)
			t.Cleanup(h.gatewayLogManager.Close)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest("GET", "http://gateway.example.com/", nil))
			if rec.Code != tc.want || rec.Header().Get("Location") != tc.location {
				t.Fatalf("got %d %q", rec.Code, rec.Header().Get("Location"))
			}
			if !tc.enabled && strings.Contains(rec.Body.String(), `href="/__select__"`) {
				t.Fatal("disabled link rendered")
			}
		})
	}
}

func TestSelectPageTogglePersistsAndUpdatesSnapshot(t *testing.T) {
	manager := config.NewManager(filepath.Join(t.TempDir(), "config.json"))
	cfg, err := manager.Load()
	if err != nil {
		t.Fatal(err)
	}
	h := NewHandler(7996, 7999, manager, cfg, filepath.Join(t.TempDir(), "logs"), nil)
	t.Cleanup(h.gatewayLogManager.Close)
	for _, enabled := range []bool{false, true, false} {
		portal := h.GetGatewayPortalConfig()
		portal.SetSelectPageEnabled(enabled)
		if _, err := h.SetGatewayPortalConfig(portal); err != nil {
			t.Fatal(err)
		}
		if h.snapshotForRequest().gatewayPortal.IsSelectPageEnabled() != enabled {
			t.Fatal("snapshot did not update")
		}
		loaded, err := manager.Load()
		if err != nil {
			t.Fatal(err)
		}
		if loaded.Portal.IsSelectPageEnabled() != enabled {
			t.Fatal("setting did not persist")
		}
		restarted := NewHandler(7996, 7999, nil, loaded, filepath.Join(t.TempDir(), "restart"), nil)
		t.Cleanup(restarted.gatewayLogManager.Close)
		if restarted.snapshotForRequest().gatewayPortal.IsSelectPageEnabled() != enabled {
			t.Fatal("restart lost setting")
		}
	}
}

func TestSelectPageToggleRollsBackOnSaveFailure(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("block"), 0600); err != nil {
		t.Fatal(err)
	}
	h := NewHandler(7996, 7999, config.NewManager(filepath.Join(blocker, "config.json")), config.DefaultConfig(), filepath.Join(t.TempDir(), "logs"), nil)
	t.Cleanup(h.gatewayLogManager.Close)
	portal := h.GetGatewayPortalConfig()
	portal.SetSelectPageEnabled(false)
	if _, err := h.SetGatewayPortalConfig(portal); err == nil {
		t.Fatal("expected save failure")
	}
	if !h.GetGatewayPortalConfig().IsSelectPageEnabled() || !h.snapshotForRequest().gatewayPortal.IsSelectPageEnabled() {
		t.Fatal("failed update changed runtime")
	}
}

func TestDisabledSelectPageKeepsToolbarAndHidesBuiltinLinks(t *testing.T) {
	bridge := testAuthBridge{verify: func(context.Context, *pb.VerifyAuthRequest) (*pb.VerifyAuthResponse, error) {
		return &pb.VerifyAuthResponse{Success: true, Status: 200, LoginAuthenticated: true}, nil
	}}
	target := newToolbarHTMLTarget(t)
	defer target.Close()
	h := newPublicHostToolbarHandler(target.URL, bridge)
	h.GatewayPortal.SetSelectPageEnabled(false)
	h.GatewayPortal.ShowWOL = true
	h.Rules = []models.Rule{{Path: "/private-app/", Target: target.URL}}
	h.publishRequestSnapshotLocked()
	for _, endpoint := range []string{"/", "/__assets__/toolbar/data?page_path=/", "/__wol__"} {
		req := httptest.NewRequest("GET", "http://public.example.com"+endpoint, nil)
		req.AddCookie(&http.Cookie{Name: authSessionCookieName, Value: "ok"})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Fatalf("%s: %d", endpoint, rec.Code)
		}
		if endpoint == "/" && !strings.Contains(rec.Body.String(), "reauth-proxy-toolbar") {
			t.Fatal("toolbar no longer injected")
		}
		if strings.Contains(rec.Body.String(), `href="/__select__"`) {
			t.Fatalf("%s has disabled select link", endpoint)
		}
	}
	req := httptest.NewRequest("GET", "http://unknown.example.com/missing", nil)
	req.AddCookie(&http.Cookie{Name: authSessionCookieName, Value: "ok"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 404 || strings.Contains(rec.Body.String(), "/private-app/") || strings.Contains(rec.Body.String(), `href="/__select__"`) {
		t.Fatal("not-found page exposed navigation")
	}
}

func TestDisabledSelectPageRootFallbackResetsConnection(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Portal.SetSelectPageEnabled(false)
	cfg.Rules = []models.Rule{{Path: "/app/", Target: "http://127.0.0.1:1"}}
	cfg.UnmatchedRoute.Behavior = models.GatewayUnmatchedRouteBehaviorResetConnection
	h := NewHandler(7996, 7999, nil, cfg, filepath.Join(t.TempDir(), "logs"), nil)
	t.Cleanup(h.gatewayLogManager.Close)
	rec := newHijackableResponseRecorder()
	defer rec.Close()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "http://gateway.example.com/", nil))
	if rec.client == nil || rec.body.Len() != 0 || rec.Header().Get("Location") != "" {
		t.Fatal("root fallback did not reset without redirect")
	}
}

func TestSelectPageLiveToggleKeepsToolbarPreference(t *testing.T) {
	bridge := testAuthBridge{verify: func(context.Context, *pb.VerifyAuthRequest) (*pb.VerifyAuthResponse, error) {
		return &pb.VerifyAuthResponse{Success: true, Status: 200, LoginAuthenticated: true}, nil
	}}
	h := newPublicHostToolbarHandler("http://127.0.0.1:1", bridge)
	for _, enabled := range []bool{false, true, false} {
		portal := models.NewGatewayPortalConfig(false, "title", true, "corners", "v1", false)
		portal.SetSelectPageEnabled(enabled)
		if _, err := h.SetGatewayPortalConfig(portal); err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest("GET", "http://public.example.com/__select__", nil)
		req.AddCookie(&http.Cookie{Name: authSessionCookieName, Value: "ok"})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		want := http.StatusNotFound
		if enabled {
			want = http.StatusOK
		}
		if rec.Code != want {
			t.Fatalf("enabled=%v: got %d, want %d", enabled, rec.Code, want)
		}
		if h.GetGatewayPortalConfig().Enabled {
			t.Fatal("select toggle enabled toolbar")
		}
	}
}

func TestDisabledSelectPageCanonicalPathsDoNotReachAuthOrUpstream(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("disabled selection page reached upstream")
	}))
	defer target.Close()
	bridge := testAuthBridge{verify: func(context.Context, *pb.VerifyAuthRequest) (*pb.VerifyAuthResponse, error) {
		t.Error("disabled selection page reached authentication")
		return &pb.VerifyAuthResponse{Success: true, Status: 200, LoginAuthenticated: true}, nil
	}}
	h := newPublicHostToolbarHandler(target.URL, bridge)
	h.HostRules[0].UseAuth = true
	h.GatewayPortal.SetSelectPageEnabled(false)
	h.Rules = []models.Rule{{Path: "/app/", Target: target.URL, UseRootMode: true}}
	h.publishRequestSnapshotLocked()
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPost} {
		for _, path := range []string{"/__select__", "/%5f%5fselect%5f%5f", "//__select__", "/app/../__select__", "/%2e/__select__"} {
			t.Run(method+path, func(t *testing.T) {
				req := httptest.NewRequest(method, "http://public.example.com"+path+"?tab=1", nil)
				req.Header.Set("Referer", "http://public.example.com/app/")
				req.AddCookie(&http.Cookie{Name: authSessionCookieName, Value: "ok"})
				req.AddCookie(&http.Cookie{Name: proxyPathCookieName, Value: "/app/"})
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, req)
				if rec.Code != http.StatusNotFound || rec.Header().Get("Location") != "" {
					t.Fatalf("disabled endpoint bypassed: status=%d location=%q", rec.Code, rec.Header().Get("Location"))
				}
				if !strings.Contains(rec.Header().Get("Cache-Control"), "no-store") {
					t.Fatal("disabled endpoint response can be cached")
				}
			})
		}
	}
}
