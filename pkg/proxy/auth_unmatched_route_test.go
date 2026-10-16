package proxy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go-reauth-proxy/pkg/config"
	"go-reauth-proxy/pkg/models"
)

func newAuthUnmatchedHandler(t *testing.T, upstream string, route string) *Handler {
	t.Helper()
	cfg := config.DefaultConfig()
	cfg.AuthConfig.AuthURL = ""
	cfg.AuthConfig.AuthHost = "auth.example.com"
	cfg.AuthConfig.AuthPort = testServerPort(t, upstream)
	cfg.UnmatchedRoute.Behavior = models.GatewayUnmatchedRouteBehaviorResetConnection
	cfg.HostRules = []models.HostRule{{Host: "auth.example.com", Target: upstream}}
	if route == "location" {
		cfg.HostRules[0].Target = "http://127.0.0.1:1"
		cfg.HostRules[0].Locations = []models.HostLocation{{
			Path: "/", Match: models.HostLocationMatchPrefix,
			Action: models.HostLocationActionProxy, Target: upstream,
		}}
	}
	if route == "path" || route == "untrusted_path" {
		cfg.HostRules = nil
		cfg.Rules = []models.Rule{{Path: "/auth-path/", Target: upstream, StripPath: true}}
	}
	if route == "untrusted" || route == "untrusted_path" {
		cfg.AuthConfig.AuthPort++
	}
	h := NewHandler(7996, 7999, nil, cfg, filepath.Join(t.TempDir(), "logs"), nil)
	t.Cleanup(h.gatewayLogManager.Close)
	return h
}

func TestAuthUnmatchedRoutePolicy(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/missing" {
			w.Header().Set(authRouteUnmatchedHeader, "1")
		}
		if r.URL.Path == "/ok" {
			_, _ = io.WriteString(w, "login-ok")
			return
		}
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
		_, _ = io.WriteString(w, "not-found")
	}))
	defer upstream.Close()
	for _, route := range []string{"host", "location", "prefix", "untrusted", "path", "untrusted_path"} {
		t.Run(route, func(t *testing.T) {
			h := newAuthUnmatchedHandler(t, upstream.URL, route)
			prefix := ""
			if route == "prefix" {
				prefix = "/__auth__"
			}
			if route == "path" || route == "untrusted_path" {
				prefix = "/auth-path"
			}
			for _, behavior := range []string{models.GatewayUnmatchedRouteBehaviorResetConnection, models.GatewayUnmatchedRouteBehaviorErrorPage, models.GatewayUnmatchedRouteBehaviorResetConnection} {
				if _, err := h.SetGatewayUnmatchedRouteConfig(models.GatewayUnmatchedRouteConfig{Behavior: behavior}); err != nil {
					t.Fatal(err)
				}
				for _, path := range []string{"/missing", "/business404", "/ok"} {
					for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPost} {
						req := httptest.NewRequest(method, "http://auth.example.com"+prefix+path, nil)
						rec := newHijackableResponseRecorder()
						h.ServeHTTP(rec, req)
						wantReset := path == "/missing" && route != "untrusted" && route != "untrusted_path" && behavior == models.GatewayUnmatchedRouteBehaviorResetConnection
						reset := rec.client != nil
						rec.Close()
						if reset != wantReset {
							t.Fatalf("%s %s %s: reset = %v, want %v", behavior, method, path, reset, wantReset)
						}
						if rec.Header().Get(authRouteUnmatchedHeader) != "" {
							t.Fatal("internal marker leaked to client")
						}
						if !wantReset {
							wantStatus := http.StatusNotFound
							if method == http.MethodPost {
								wantStatus = http.StatusMethodNotAllowed
							}
							if path == "/ok" {
								wantStatus = http.StatusOK
							}
							if rec.code != wantStatus {
								t.Fatalf("%s: status = %d, want %d", path, rec.code, wantStatus)
							}
						}
					}
				}
			}
		})
	}
}

func TestAuthUnmatchedHTTP2KeepsConnection(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/missing" {
			w.Header().Set(authRouteUnmatchedHeader, "1")
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = io.WriteString(w, "login-ok")
	}))
	defer upstream.Close()
	h := newAuthUnmatchedHandler(t, upstream.URL, "host")
	server := httptest.NewUnstartedServer(h)
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	client := server.Client()
	client.Timeout = 5 * time.Second
	blocked, _ := http.NewRequest(http.MethodGet, server.URL+"/missing", nil)
	blocked.Host = "auth.example.com"
	if resp, err := client.Do(blocked); err == nil {
		resp.Body.Close()
		t.Fatal("unmatched auth request returned an HTTP response")
	}
	var reused bool
	valid, _ := http.NewRequest(http.MethodGet, server.URL+"/login", nil)
	valid.Host = "auth.example.com"
	valid = valid.WithContext(httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) { reused = info.Reused },
	}))
	resp, err := client.Do(valid)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil || resp.ProtoMajor != 2 || !reused || string(body) != "login-ok" {
		t.Fatalf("valid request: protocol=%s reused=%v body=%q err=%v", resp.Proto, reused, body, err)
	}
}

func TestAuthUnmatchedHTTP1ClosesWithoutResponse(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(authRouteUnmatchedHeader, "1")
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, "must-not-reach-client")
	}))
	defer upstream.Close()
	h := newAuthUnmatchedHandler(t, upstream.URL, "host")
	server := httptest.NewServer(h)
	defer server.Close()
	client := server.Client()
	client.Timeout = 5 * time.Second
	req, err := http.NewRequest(http.MethodGet, server.URL+"/missing", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "auth.example.com"
	resp, err := client.Do(req)
	if resp != nil {
		resp.Body.Close()
		t.Fatalf("unmatched auth route returned HTTP status %d", resp.StatusCode)
	}
	if err == nil {
		t.Fatal("expected connection termination")
	}
}

func TestAuthUnmatchedMarkerNeverLeaksThroughTrailers(t *testing.T) {
	for _, announced := range []bool{false, true} {
		t.Run(fmt.Sprint(announced), func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set(authRouteUnmatchedHeader, "1")
				if announced {
					w.Header().Set("Trailer", authRouteUnmatchedHeader+", X-Checksum")
				}
				w.WriteHeader(http.StatusOK)
				w.(http.Flusher).Flush()
				_, _ = io.WriteString(w, "valid response")
				prefix := ""
				if !announced {
					prefix = http.TrailerPrefix
				}
				w.Header().Set(prefix+authRouteUnmatchedHeader, "1")
				w.Header().Set(prefix+"X-Checksum", "ordinary-trailer")
			}))
			defer upstream.Close()
			for _, route := range []string{"host", "path", "prefix", "untrusted"} {
				h := newAuthUnmatchedHandler(t, upstream.URL, route)
				server := httptest.NewServer(h)
				defer server.Close()
				path := "/ok"
				if route == "path" {
					path = "/auth-path/ok"
				}
				if route == "prefix" {
					path = "/__auth__/ok"
				}
				req, _ := http.NewRequest(http.MethodGet, server.URL+path, nil)
				req.Host = "auth.example.com"
				client := server.Client()
				client.Timeout = 5 * time.Second
				resp, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil || string(body) != "valid response" {
					t.Fatalf("body=%q err=%v", body, err)
				}
				for _, headers := range []http.Header{resp.Header, resp.Trailer} {
					for name := range headers {
						if strings.EqualFold(strings.TrimPrefix(name, http.TrailerPrefix), authRouteUnmatchedHeader) {
							t.Errorf("%s: internal marker escaped: %v", route, headers)
						}
					}
				}
				if resp.Trailer.Get("X-Checksum") != "ordinary-trailer" {
					t.Errorf("%s: ordinary trailer lost: %v", route, resp.Trailer)
				}
			}
		})
	}
}
