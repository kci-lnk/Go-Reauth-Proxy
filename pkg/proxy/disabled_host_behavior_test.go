package proxy

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"go-reauth-proxy/pkg/config"
	"go-reauth-proxy/pkg/gatewaylog"
	"go-reauth-proxy/pkg/models"
	"strings"
)

func TestDisabledHostResetConnectionHTTP1ClosesWithoutHTTPResponse(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.UnmatchedRoute.DisabledHostBehavior = models.GatewayUnmatchedRouteBehaviorResetConnection
	var upstreamHits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { upstreamHits.Add(1) }))
	defer upstream.Close()
	defer func() {
		if upstreamHits.Load() != 0 {
			t.Fatal("disabled host reached upstream")
		}
	}()
	cfg.HostRules = []models.HostRule{{Host: "disabled.example.com", Target: upstream.URL, Disabled: true}}

	handler := NewHandler(7996, 7999, nil, cfg, filepath.Join(t.TempDir(), "logs"), nil)
	t.Cleanup(handler.gatewayLogManager.Close)
	server := httptest.NewServer(handler)
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}
	conn, err := net.DialTimeout("tcp", serverURL.Host, 2*time.Second)
	if err != nil {
		t.Fatalf("dial test server: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.WriteString(conn, "GET /private HTTP/1.1\r\nHost: disabled.example.com\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatalf("write request: %v", err)
	}
	data, readErr := bufio.NewReader(conn).ReadBytes('\n')
	if len(data) != 0 {
		t.Fatalf("received an HTTP response before reset: %q", data)
	}
	if !isConnectionResetError(readErr) {
		t.Fatalf("read error = %v, want connection reset", readErr)
	}
}

func TestDisabledHostResetConnectionHTTP2AbortsOnlyCurrentStream(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.UnmatchedRoute.DisabledHostBehavior = models.GatewayUnmatchedRouteBehaviorResetConnection
	var upstreamHits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { upstreamHits.Add(1) }))
	defer upstream.Close()
	defer func() {
		if upstreamHits.Load() != 0 {
			t.Fatal("disabled host reached upstream")
		}
	}()
	cfg.HostRules = []models.HostRule{{Host: "disabled.example.com", Target: upstream.URL, Disabled: true}}

	handler := NewHandler(7996, 7999, nil, cfg, filepath.Join(t.TempDir(), "logs"), nil)
	t.Cleanup(handler.gatewayLogManager.Close)

	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	client := server.Client()

	blocked, err := http.NewRequest(http.MethodGet, server.URL+"/private", nil)
	if err != nil {
		t.Fatalf("build blocked request: %v", err)
	}
	blocked.Host = "disabled.example.com"
	if response, err := client.Do(blocked); err == nil {
		response.Body.Close()
		t.Fatal("HTTP/2 unmatched stream unexpectedly returned a response")
	}

	var gotConnInfo httptrace.GotConnInfo
	matched, err := http.NewRequest(http.MethodGet, server.URL+"/__assets__/favicon/favicon-16x16.png", nil)
	if err != nil {
		t.Fatalf("build matched request: %v", err)
	}
	matched = matched.WithContext(httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			gotConnInfo = info
		},
	}))
	response, err := client.Do(matched)
	if err != nil {
		t.Fatalf("matched HTTP/2 stream failed after reset: %v", err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, response.Body)
	if response.ProtoMajor != 2 {
		t.Fatalf("matched request protocol = %s, want HTTP/2", response.Proto)
	}
	if !gotConnInfo.Reused {
		t.Fatal("HTTP/2 connection was not reused after resetting one stream")
	}
}

func TestDisabledHostBehaviorPageAndResetLogging(t *testing.T) {
	for _, behavior := range []string{"", "error_page", "invalid", "reset_connection"} {
		for _, accept := range []string{"text/html", "application/json"} {
			t.Run(behavior+"/"+accept, func(t *testing.T) {
				logs := gatewaylog.NewManager(t.TempDir(), models.LoggingConfig{Enabled: true, MaxDays: 1})
				defer logs.Close()
				var upstreamHits atomic.Int32
				upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { upstreamHits.Add(1) }))
				defer upstream.Close()
				h := &Handler{
					HostRules:             []models.HostRule{{Host: "disabled.example.com", Target: upstream.URL, Disabled: true}},
					GatewayUnmatchedRoute: models.GatewayUnmatchedRouteConfig{DisabledHostBehavior: behavior},
					gatewayLogManager:     logs,
				}
				h.publishRequestSnapshotLocked()
				req := httptest.NewRequest("GET", "http://disabled.example.com/private", nil)
				req.Header.Set("Accept", accept)
				rec := httptest.NewRecorder()
				var aborted bool
				func() {
					defer func() {
						if value := recover(); value != nil {
							if value != http.ErrAbortHandler {
								panic(value)
							}
							aborted = true
						}
					}()
					h.ServeHTTP(rec, req)
				}()
				wantStatus := http.StatusServiceUnavailable
				if behavior == "reset_connection" {
					wantStatus = 499
					if !aborted || rec.Body.Len() != 0 || rec.Flushed {
						t.Fatalf("reset wrote response: %s", rec.Body.String())
					}
				} else {
					if aborted || rec.Code != wantStatus || rec.Body.Len() == 0 {
						t.Fatalf("page response: %d %s", rec.Code, rec.Body.String())
					}
					if accept == "application/json" && !strings.Contains(rec.Body.String(), `"reason":"disabled"`) {
						t.Fatal(rec.Body.String())
					}
				}
				if upstreamHits.Load() != 0 {
					t.Fatal("disabled host reached upstream")
				}
				logs.Flush()
				entries, err := h.QueryLogEntries("", 1, 20, "disabled", "", "", "", "", "page")
				if err != nil {
					t.Fatal(err)
				}
				if len(entries.Items) != 1 {
					t.Fatalf("logged entries = %d", len(entries.Items))
				}
				entry := entries.Items[0]
				if entry.Status != wantStatus || entry.RouteType != "host_unavailable" || entry.RouteKey != "disabled.example.com" || entry.AuthDecision != "disabled" {
					t.Fatalf("log entry = %#v", entry)
				}
			})
		}
	}
}
