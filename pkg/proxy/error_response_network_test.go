package proxy

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"go-reauth-proxy/pkg/middleware"
	"go-reauth-proxy/pkg/models"
	"go-reauth-proxy/pkg/response"
)

func TestGateway404ResponseWireCompleteness(t *testing.T) {
	t.Setenv(middleware.AdminHTTPLogEnv, "true")
	full := &Handler{
		AuthConfig: models.AuthConfig{
			AuthURL:      "/api/auth/verify",
			PreflightURL: "/api/auth/preflight",
		},
		authCache:      newAuthStateCache(),
		preflightCache: newPreflightStateCache(),
	}
	full.publishRequestSnapshotLocked()
	templateHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response.RouteNotFound(w, r, nil, false)
	})
	trafficHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tw := &trafficResponseWriter{ResponseWriter: w, handler: full}
		response.RouteNotFound(tw, r, nil, false)
	})
	for _, tc := range []struct {
		name string
		h    http.Handler
	}{
		{"template", templateHandler},
		{"traffic_and_logging", middleware.Logger(trafficHandler)},
		{"complete_handler_and_logging", middleware.Logger(full)},
	} {
		for _, proto := range []int{1, 2} {
			for _, explicitLength := range []bool{false, true} {
				t.Run(tc.name+"/http"+strconv.Itoa(proto)+"/length="+strconv.FormatBool(explicitLength), func(t *testing.T) {
					req := httptest.NewRequest(http.MethodGet, "http://gateway.example.test/missing", nil)
					req.Header.Set("Accept-Language", "en")
					expected := httptest.NewRecorder()
					tc.h.ServeHTTP(expected, req)
					want := bytes.Clone(expected.Body.Bytes())
					if !strings.Contains(string(want), "</html>") {
						t.Fatalf("recorder reference incomplete: %q", want)
					}
					handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						if explicitLength {
							w.Header().Set("Content-Length", strconv.Itoa(len(want)))
						}
						tc.h.ServeHTTP(w, r)
					})
					server := httptest.NewUnstartedServer(handler)
					server.EnableHTTP2 = proto == 2
					server.Config.WriteTimeout = 2 * time.Second
					if proto == 2 {
						server.StartTLS()
					} else {
						server.Start()
					}
					defer server.Close()
					client := server.Client()
					client.Timeout = 3 * time.Second
					for n := 0; n < 3; n++ {
						req, _ := http.NewRequest(http.MethodGet, server.URL+"/missing", nil)
						req.Host = "gateway.example.test"
						req.Header.Set("Accept-Language", "en")
						start := time.Now()
						res, err := client.Do(req)
						if err != nil {
							t.Fatal(err)
						}
						headLatency := time.Since(start)
						got, readErr := io.ReadAll(res.Body)
						res.Body.Close()
						t.Logf("request=%d protocol=%s status=%d length_header=%q bytes=%d head=%s total=%s read_error=%v", n, res.Proto, res.StatusCode, res.Header.Get("Content-Length"), len(got), headLatency, time.Since(start), readErr)
						if readErr != nil || res.ProtoMajor != proto || res.StatusCode != 404 || !bytes.Equal(got, want) {
							t.Fatalf("wire response differs: proto=%s status=%d read=%v got=%d want=%d tail=%q", res.Proto, res.StatusCode, readErr, len(got), len(want), got[max(0, len(got)-128):])
						}
					}
				})
			}
		}
	}
}
