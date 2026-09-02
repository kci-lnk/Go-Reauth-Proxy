package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go-reauth-proxy/pkg/models"

	"github.com/gorilla/websocket"
)

type websocketUpstreamRequest struct {
	path    string
	query   string
	traceID string
}

func newWebSocketEchoServer(t *testing.T, tls bool) (*httptest.Server, <-chan websocketUpstreamRequest) {
	t.Helper()

	seenRequests := make(chan websocketUpstreamRequest, 1)
	upgrader := websocket.Upgrader{
		CheckOrigin: func(_ *http.Request) bool {
			return true
		},
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case seenRequests <- websocketUpstreamRequest{
			path:    r.URL.Path,
			query:   r.URL.RawQuery,
			traceID: r.Header.Get(traceIDHeader),
		}:
		default:
		}

		upstreamResponseHeaders := http.Header{}
		upstreamResponseHeaders.Set(traceIDHeader, "upstream-supplied")
		upstreamResponseHeaders.Set("Traceparent", "00-upstream-parent")
		conn, err := upgrader.Upgrade(w, r, upstreamResponseHeaders)
		if err != nil {
			t.Errorf("upstream upgrade failed: %v", err)
			return
		}
		defer conn.Close()

		messageType, message, err := conn.ReadMessage()
		if err != nil {
			t.Errorf("upstream read failed: %v", err)
			return
		}
		if err := conn.WriteMessage(messageType, []byte("echo:"+string(message))); err != nil {
			t.Errorf("upstream write failed: %v", err)
		}
	})

	if tls {
		return httptest.NewTLSServer(handler), seenRequests
	}
	return httptest.NewServer(handler), seenRequests
}

func newWebSocketPathRuleProxy(target string, stripPath bool) *httptest.Server {
	handler := &Handler{
		Rules: []models.Rule{
			{
				Path:      "/chat",
				Target:    target,
				UseAuth:   false,
				StripPath: stripPath,
			},
		},
		authCache:      newAuthStateCache(),
		preflightCache: newPreflightStateCache(),
	}
	handler.publishRequestSnapshotLocked()
	return httptest.NewServer(handler)
}

func newWebSocketHostRuleProxy(target string) *httptest.Server {
	handler := &Handler{
		HostRules: []models.HostRule{
			{
				Host:    "photos.example.com",
				Target:  target,
				UseAuth: false,
			},
		},
		authCache:      newAuthStateCache(),
		preflightCache: newPreflightStateCache(),
	}
	handler.publishRequestSnapshotLocked()
	return httptest.NewServer(handler)
}

func TestPathRuleProxiesWebSocketTargets(t *testing.T) {
	tests := []struct {
		name           string
		upstreamTLS    bool
		targetScheme   string
		stripPath      bool
		requestPath    string
		wantUpstream   websocketUpstreamRequest
		wantEchoPrefix string
	}{
		{
			name:         "ws target strips path and preserves query",
			targetScheme: "ws",
			stripPath:    true,
			requestPath:  "/chat/socket?room=alpha",
			wantUpstream: websocketUpstreamRequest{
				path:  "/socket",
				query: "room=alpha",
			},
			wantEchoPrefix: "echo:",
		},
		{
			name:         "wss target strips path and preserves query",
			upstreamTLS:  true,
			targetScheme: "wss",
			stripPath:    true,
			requestPath:  "/chat/secure?room=beta",
			wantUpstream: websocketUpstreamRequest{
				path:  "/secure",
				query: "room=beta",
			},
			wantEchoPrefix: "echo:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			upstream, seenRequests := newWebSocketEchoServer(t, tt.upstreamTLS)
			defer upstream.Close()

			targetAuthority := strings.TrimPrefix(upstream.URL, "http://")
			targetAuthority = strings.TrimPrefix(targetAuthority, "https://")
			target := tt.targetScheme + "://" + targetAuthority
			proxyServer := newWebSocketPathRuleProxy(target, tt.stripPath)
			defer proxyServer.Close()

			wsURL := "ws" + strings.TrimPrefix(proxyServer.URL, "http") + tt.requestPath
			dialer := websocket.Dialer{HandshakeTimeout: 2 * time.Second}
			forgedTraceID := "trc_00000000-0000-4000-8000-000000000000"
			headers := http.Header{}
			headers.Set(traceIDHeader, forgedTraceID)
			conn, response, err := dialer.Dial(wsURL, headers)
			if err != nil {
				t.Fatalf("dial proxy websocket: %v", err)
			}
			defer conn.Close()
			if values := response.Header.Values(traceIDHeader); len(values) != 0 {
				t.Fatalf("websocket gateway trace response headers = %q, want none", values)
			}
			if values := response.Header.Values("Traceparent"); len(values) != 0 {
				t.Fatalf("websocket upstream trace response headers = %q, want none", values)
			}

			deadline := time.Now().Add(2 * time.Second)
			if err := conn.SetReadDeadline(deadline); err != nil {
				t.Fatalf("set read deadline: %v", err)
			}
			if err := conn.SetWriteDeadline(deadline); err != nil {
				t.Fatalf("set write deadline: %v", err)
			}

			payload := "ping"
			if err := conn.WriteMessage(websocket.TextMessage, []byte(payload)); err != nil {
				t.Fatalf("write websocket message: %v", err)
			}
			_, message, err := conn.ReadMessage()
			if err != nil {
				t.Fatalf("read websocket message: %v", err)
			}
			if got, want := string(message), tt.wantEchoPrefix+payload; got != want {
				t.Fatalf("echo message = %q, want %q", got, want)
			}

			select {
			case got := <-seenRequests:
				if got.path != tt.wantUpstream.path || got.query != tt.wantUpstream.query {
					t.Fatalf("upstream request = %+v, want %+v", got, tt.wantUpstream)
				}
				if got.traceID == "" || got.traceID == forgedTraceID {
					t.Fatalf("upstream trace id was not securely replaced: %q", got.traceID)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("timed out waiting for upstream websocket request")
			}
		})
	}
}

func TestPathRuleWebSocketTargetSkipsHTMLRewriteAndRootMode(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<html><body><a href="/asset">asset</a></body></html>`))
	}))
	defer upstream.Close()

	targetAuthority := strings.TrimPrefix(upstream.URL, "http://")
	handler := &Handler{
		Rules: []models.Rule{
			{
				Path:        "/chat",
				Target:      "ws://" + targetAuthority,
				UseAuth:     false,
				RewriteHTML: true,
				UseRootMode: true,
			},
		},
		authCache:      newAuthStateCache(),
		preflightCache: newPreflightStateCache(),
	}
	handler.publishRequestSnapshotLocked()

	req := httptest.NewRequest(http.MethodGet, "http://example.com/chat/socket", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `href="/asset"`) {
		t.Fatalf("response body missing original absolute path: %s", body)
	}
	if strings.Contains(body, `href="/chat/asset"`) {
		t.Fatalf("response body was rewritten for WebSocket target: %s", body)
	}
}

func TestHostRuleWebSocketTargetPathActsAsEntryPath(t *testing.T) {
	upstream, seenRequests := newWebSocketEchoServer(t, false)
	defer upstream.Close()

	targetAuthority := strings.TrimPrefix(upstream.URL, "http://")
	proxyServer := newWebSocketHostRuleProxy("ws://" + targetAuthority + "/p")
	defer proxyServer.Close()

	wsURL := "ws" + strings.TrimPrefix(proxyServer.URL, "http") + "/p/socket?room=photos"
	headers := http.Header{"Host": []string{"photos.example.com"}}
	dialer := websocket.Dialer{HandshakeTimeout: 2 * time.Second}
	conn, _, err := dialer.Dial(wsURL, headers)
	if err != nil {
		t.Fatalf("dial proxy websocket: %v", err)
	}
	defer conn.Close()

	deadline := time.Now().Add(2 * time.Second)
	if err := conn.SetReadDeadline(deadline); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	if err := conn.SetWriteDeadline(deadline); err != nil {
		t.Fatalf("set write deadline: %v", err)
	}
	if err := conn.WriteMessage(websocket.TextMessage, []byte("ping")); err != nil {
		t.Fatalf("write websocket message: %v", err)
	}
	if _, _, err := conn.ReadMessage(); err != nil {
		t.Fatalf("read websocket message: %v", err)
	}

	select {
	case got := <-seenRequests:
		want := websocketUpstreamRequest{path: "/p/socket", query: "room=photos"}
		if got.path != want.path || got.query != want.query {
			t.Fatalf("upstream request = %+v, want %+v", got, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for upstream websocket request")
	}
}
