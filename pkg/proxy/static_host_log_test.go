package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go-reauth-proxy/pkg/models"
)

func TestStaticHostAccessLogsUseRouteIdentityWithoutFilesystemPaths(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	if _, err := handler.SetLoggingConfig(models.LoggingConfig{
		Enabled:         true,
		RecordLocalhost: true,
		MaxDays:         1,
	}); err != nil {
		t.Fatal(err)
	}

	root := filepath.Join(t.TempDir(), "filesystem-secret-directory")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	filePath := filepath.Join(root, "filesystem-secret-file.bin")
	if err := os.WriteFile(filePath, []byte("file body"), 0o644); err != nil {
		t.Fatal(err)
	}
	missingRoot := filepath.Join(t.TempDir(), "filesystem-secret-missing")
	if err := handler.SetHostRules([]models.HostRule{
		{
			Host:        "file.static.example.test",
			TargetType:  models.HostRuleTargetTypeFile,
			StaticServe: &models.StaticServeConfig{Path: filePath},
		},
		{
			Host:       "directory.static.example.test",
			TargetType: models.HostRuleTargetTypeDirectory,
			StaticServe: &models.StaticServeConfig{
				Path: root,
			},
		},
		{
			Host:        "missing.static.example.test",
			TargetType:  models.HostRuleTargetTypeDirectory,
			StaticServe: &models.StaticServeConfig{Path: missingRoot},
		},
	}); err != nil {
		t.Fatal(err)
	}

	requests := []struct {
		url    string
		status int
	}{
		{url: "http://file.static.example.test/", status: http.StatusOK},
		{url: "http://directory.static.example.test/filesystem-secret-file.bin", status: http.StatusOK},
		{url: "http://missing.static.example.test/", status: http.StatusServiceUnavailable},
	}
	for _, testCase := range requests {
		request := httptest.NewRequest(http.MethodGet, testCase.url, nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != testCase.status {
			t.Fatalf("GET %s = %d %q, want %d", testCase.url, response.Code, response.Body.String(), testCase.status)
		}
	}

	handler.gatewayLogManager.Flush()
	result, err := handler.QueryLogEntries("", 1, 20, "static.example.test", "", "", "", "", "page")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Items) != len(requests) {
		t.Fatalf("logged entries = %d, want %d: %#v", len(result.Items), len(requests), result.Items)
	}
	wantTypes := map[string]string{
		"file.static.example.test":      "static_file",
		"directory.static.example.test": "static_directory",
		"missing.static.example.test":   "static_directory",
	}
	for _, entry := range result.Items {
		if entry.RouteType != wantTypes[entry.Host] || entry.RouteKey != entry.Host || entry.Upstream != "" || !entry.Matched {
			t.Errorf("static access log identity = %#v", entry)
		}
	}
	encoded, err := json.Marshal(result.Items)
	if err != nil {
		t.Fatal(err)
	}
	logText := string(encoded)
	for _, secret := range []string{root, filePath, missingRoot, "filesystem-secret-directory", "filesystem-secret-missing"} {
		if strings.Contains(logText, secret) {
			t.Fatalf("access log exposed filesystem path marker %q: %s", secret, logText)
		}
	}
}
