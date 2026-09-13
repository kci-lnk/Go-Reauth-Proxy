package proxy

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"

	"go-reauth-proxy/pkg/config"
	"go-reauth-proxy/pkg/models"
)

func TestCloudflareIngressRejectsMissingIdentityBeforeUpstream(t *testing.T) {
	for _, runtime := range []string{"fpk", "fpk-lite"} {
		t.Run(runtime, func(t *testing.T) {
			t.Setenv("FN_KNOCK_RUNTIME_TARGET", runtime)
			var calls atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Seen-IP", r.Header.Get("X-Forwarded-For"))
				w.WriteHeader(http.StatusNoContent)
			}))
			defer upstream.Close()
			cfg := config.DefaultConfig()
			cfg.HostRules = []models.HostRule{{Host: "app.example.com", Target: upstream.URL}}
			handler := NewHandler(7996, 7999, nil, cfg, filepath.Join(t.TempDir(), "logs"), nil)
			t.Cleanup(func() { handler.Close() })
			for _, tc := range []struct {
				name    string
				headers []string
				port    int
				status  int
				ip      string
			}{
				{"missing", nil, ManagedCloudflarePort(), http.StatusBadRequest, ""},
				{"loopback", []string{"127.0.0.1"}, ManagedCloudflarePort(), http.StatusBadRequest, ""},
				{"private", []string{"10.0.0.1"}, ManagedCloudflarePort(), http.StatusBadRequest, ""},
				{"malformed", []string{"not-an-ip"}, ManagedCloudflarePort(), http.StatusBadRequest, ""},
				{"duplicate", []string{"198.51.100.25", "198.51.100.26"}, ManagedCloudflarePort(), http.StatusBadRequest, ""},
				{"valid IPv4", []string{"198.51.100.25"}, ManagedCloudflarePort(), http.StatusNoContent, "198.51.100.25"},
				{"valid IPv6", []string{"2001:db8::25"}, ManagedCloudflarePort(), http.StatusNoContent, "2001:db8::25"},
				{"ordinary ingress ignores CF", []string{"198.51.100.25"}, 7999, http.StatusNoContent, "127.0.0.1"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					before := calls.Load()
					req := requestWithLocalAddress(httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil), "127.0.0.1", tc.port)
					req.RemoteAddr = "127.0.0.1:45678"
					for _, value := range tc.headers {
						req.Header.Add("CF-Connecting-IP", value)
					}
					req.Header.Set("X-Forwarded-For", "192.168.1.1")
					req.Header.Set("X-Real-IP", "192.168.1.1")
					rec := httptest.NewRecorder()
					handler.ServeHTTP(rec, req)
					if rec.Code != tc.status {
						t.Fatalf("status = %d, want %d: %s", rec.Code, tc.status, rec.Body.String())
					}
					if tc.status == http.StatusBadRequest {
						if calls.Load() != before {
							t.Fatal("invalid identity reached upstream")
						}
					} else if got := rec.Header().Get("Seen-IP"); got != tc.ip {
						t.Fatalf("upstream IP = %q, want %q (port %s)", got, tc.ip, strconv.Itoa(tc.port))
					}
				})
			}
		})
	}
}
