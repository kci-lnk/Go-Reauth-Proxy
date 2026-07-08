package proxy

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"go-reauth-proxy/pkg/logger"
	"go-reauth-proxy/pkg/models"
)

func enableDebugLogForTest(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	t.Cleanup(func() {
		logger.Setup()
		logger.SetDebugAdminPortForRedaction(0)
	})
	t.Setenv(logger.DebugLogEnv, "1")
	t.Setenv(logger.DebugLogDirEnv, dir)
	logger.Setup()
	return dir
}

func TestDebugLogRecordsProxyLifecycleWithRedaction(t *testing.T) {
	dir := enableDebugLogForTest(t)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	_, portText, err := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "http://"))
	if err != nil {
		t.Fatalf("failed to parse upstream port: %v", err)
	}
	adminPort, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("failed to parse upstream port: %v", err)
	}
	logger.SetDebugAdminPortForRedaction(adminPort)

	handler := &Handler{
		Rules: []models.Rule{
			{Path: "/app", Target: upstream.URL},
		},
		AdminPort: adminPort,
	}
	handler.publishRequestSnapshotLocked()

	req := httptest.NewRequest(http.MethodGet, "http://example.com/app/?token=supersecret&ok=1", nil)
	req.Header.Set("Authorization", "Bearer secret-token")
	req.Header.Set("Cookie", "sid=secret-cookie")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	logger.FlushDebugLogger()

	logPath := filepath.Join(dir, time.Now().Format("2006-01-02")+".log")
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("failed to read debug log: %v", err)
	}
	events := parseProxyDebugLogEvents(t, string(data))
	for _, want := range []string{"request_start", "route_match_evaluated", "reverse_proxy_start", "request_end"} {
		if !proxyDebugEventsContain(events, "event", want) {
			t.Fatalf("expected debug log event %q, got %q", want, string(data))
		}
	}
	if !proxyDebugEventsContainValue(events, "[admin-port]") {
		t.Fatalf("expected debug log to contain admin port redaction marker, got %q", string(data))
	}
	if !proxyDebugEventsContainValue(events, "[redacted]") {
		t.Fatalf("expected debug log to contain sensitive header redaction markers, got %q", string(data))
	}
	for _, forbidden := range []string{
		portText,
		"supersecret",
		"secret-token",
		"secret-cookie",
	} {
		if proxyDebugEventsContainValueExcludingTime(events, forbidden) {
			t.Fatalf("debug log leaked %q: %q", forbidden, string(data))
		}
	}
}

func parseProxyDebugLogEvents(t *testing.T, raw string) []map[string]any {
	t.Helper()

	lines := strings.Split(strings.TrimSpace(raw), "\n")
	events := make([]map[string]any, 0, len(lines))
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var event map[string]any
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("failed to parse debug log line %q: %v", line, err)
		}
		events = append(events, event)
	}
	return events
}

func proxyDebugEventsContain(events []map[string]any, key string, value string) bool {
	for _, event := range events {
		if event[key] == value {
			return true
		}
	}
	return false
}

func proxyDebugEventsContainValue(events []map[string]any, needle string) bool {
	for _, event := range events {
		if proxyDebugValueContains(event, needle) {
			return true
		}
	}
	return false
}

func proxyDebugEventsContainValueExcludingTime(events []map[string]any, needle string) bool {
	for _, event := range events {
		for key, value := range event {
			if key == "time" {
				continue
			}
			if proxyDebugValueContains(value, needle) {
				return true
			}
		}
	}
	return false
}

func proxyDebugValueContains(value any, needle string) bool {
	switch typed := value.(type) {
	case string:
		return strings.Contains(typed, needle)
	case []any:
		for _, item := range typed {
			if proxyDebugValueContains(item, needle) {
				return true
			}
		}
	case map[string]any:
		for _, item := range typed {
			if proxyDebugValueContains(item, needle) {
				return true
			}
		}
	}
	return false
}
