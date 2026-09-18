package proxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"go-reauth-proxy/pkg/models"
)

func TestAuthTransportIsBoundedWithoutChangingBusinessTransport(t *testing.T) {
	h := &Handler{proxyTransport: newProxyTransport()}
	defer h.proxyTransport.CloseIdleConnections()
	tr := h.authTransport()
	defer tr.CloseIdleConnections()
	if tr == h.proxyTransport || tr.ResponseHeaderTimeout != 30*time.Second || h.proxyTransport.ResponseHeaderTimeout != 0 {
		t.Fatal("auth deadline leaked to business transport")
	}
	if h.authTransport() != tr {
		t.Fatal("auth connection pool is not reused")
	}
}

func TestAuthProxyReportsStoppedAndStalledService(t *testing.T) {
	for _, stopped := range []bool{false, true} {
		t.Run(strconv.FormatBool(stopped), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
			defer server.Close()
			target, _ := url.Parse(server.URL)
			port, _ := strconv.Atoi(target.Port())
			if stopped {
				server.Close()
			}
			h := &Handler{proxyTransport: newProxyTransport()}
			defer h.proxyTransport.CloseIdleConnections()
			tr := h.authTransport()
			tr.ResponseHeaderTimeout = 30 * time.Millisecond
			defer tr.CloseIdleConnections()
			req := httptest.NewRequest("GET", "http://auth.test/__auth__/api/auth/bootstrap", nil)
			w := httptest.NewRecorder()
			if !h.handleAuthProxyRoute(w, req, requestSnapshot{authConfig: models.AuthConfig{AuthPort: port}}, "127.0.0.1") {
				t.Fatal("auth route not handled")
			}
			want, class := http.StatusGatewayTimeout, "timeout"
			if stopped {
				want, class = http.StatusServiceUnavailable, "connect_unavailable"
			}
			if w.Code != want || w.Header().Get(upstreamErrorClassHeader) != class {
				t.Fatalf("got %d %s", w.Code, w.Header().Get(upstreamErrorClassHeader))
			}
		})
	}
}

func TestAuthDeadlineOnlyTargetsInternalListener(t *testing.T) {
	for _, raw := range []string{"http://127.0.0.1:7997", "http://[::1]:7997", "http://localhost:7997", "http://LOCALHOST:7997"} {
		u, _ := url.Parse(raw)
		if !isInternalAuthTarget(u, 7997) {
			t.Fatal(raw)
		}
	}
	for _, raw := range []string{"http://example.com:7997", "http://localhost.example.com:7997", "http://127.0.0.1:9000", "https://127.0.0.1:7997"} {
		u, _ := url.Parse(raw)
		if isInternalAuthTarget(u, 7997) {
			t.Fatal(raw)
		}
	}
}
