package proxy

import (
	"bytes"
	"encoding/json"
	"go-reauth-proxy/pkg/config"
	"go-reauth-proxy/pkg/logger"
	"go-reauth-proxy/pkg/models"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUpstreamFailureDiagnosticsCoverEveryReverseProxyRoute(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	target := upstream.URL
	upstream.Close()

	tests := []struct {
		name  string
		rules []models.Rule
		hosts []models.HostRule
		url   string
		host  string
	}{
		{
			name: "path rule",
			rules: []models.Rule{{
				Path:   "/app",
				Target: target,
			}},
			url:  "https://gateway.example.com/app/resource",
			host: "gateway.example.com",
		},
		{
			name: "host rule",
			hosts: []models.HostRule{{
				Host:   "app.example.com",
				Target: target,
			}},
			url:  "https://app.example.com/",
			host: "app.example.com",
		},
		{
			name: "host location",
			hosts: []models.HostRule{{
				Host:   "app.example.com",
				Target: "http://127.0.0.1:1",
				Locations: []models.HostLocation{{
					Path:   "/api",
					Match:  models.HostLocationMatchPrefix,
					Action: models.HostLocationActionProxy,
					Target: target,
				}},
			}},
			url:  "https://app.example.com/api/resource",
			host: "app.example.com",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.DefaultConfig()
			cfg.Rules = tc.rules
			cfg.HostRules = tc.hosts
			dir := t.TempDir()
			t.Cleanup(logger.Setup)
			t.Setenv(logger.DiagnosticLogDirEnv, dir)
			t.Setenv(logger.ConsoleLogEnv, "0")
			t.Setenv(logger.DebugLogEnv, "0")
			logger.Setup()
			handler := NewHandler(
				7996,
				7999,
				nil,
				cfg,
				filepath.Join(t.TempDir(), "logs"),
				nil,
			)
			t.Cleanup(handler.gatewayLogManager.Close)
			req := httptest.NewRequest(http.MethodGet, tc.url, nil)
			req.Host = tc.host
			req.ProtoMajor = 2
			req.ProtoMinor = 0
			req.Proto = "HTTP/2.0"

			writer := httptest.NewRecorder()
			handler.ServeHTTP(writer, req)
			if writer.Code != http.StatusServiceUnavailable {
				t.Fatalf("status=%d", writer.Code)
			}
			logger.FlushDiagnosticLogger()
			data, err := os.ReadFile(filepath.Join(dir, "gateway.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, line := range bytes.Split(data, []byte("\n")) {
				var record struct {
					Event  string         `json:"event"`
					Fields map[string]any `json:"fields"`
				}
				if json.Unmarshal(line, &record) != nil || record.Event != "upstream_failure" {
					continue
				}
				found = true
				want := strings.ReplaceAll(tc.name, " ", "_")
				if record.Fields["route_type"] != want || record.Fields["upstream_origin"] != target || record.Fields["stage"] != "dial" || record.Fields["error_kind"] != "connection_refused" || record.Fields["trace_id"] == nil {
					t.Fatalf("unexpected diagnostic: %s", line)
				}
			}
			if !found {
				t.Fatalf("missing upstream failure: %s", data)
			}

		})
	}
}
