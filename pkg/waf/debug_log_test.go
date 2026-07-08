package waf

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go-reauth-proxy/pkg/logger"
	"go-reauth-proxy/pkg/models"
)

func enableDebugLogForWAFTest(t *testing.T) string {
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

func TestDebugLogRecordsWAFReloadWithAdminPortRedaction(t *testing.T) {
	dir := enableDebugLogForWAFTest(t)
	logger.SetDebugAdminPortForRedaction(7996)

	rt := NewRuntime(models.WAFConfig{Enabled: false, Mode: ModeOff}, t.TempDir())
	if _, err := rt.Reload(models.WAFConfig{Enabled: false, Mode: ModeOff}, "bundle", "http://127.0.0.1:7996/bundle"); err != nil {
		t.Fatalf("Reload returned error: %v", err)
	}
	logger.FlushDebugLogger()

	data, err := os.ReadFile(filepath.Join(dir, time.Now().Format("2006-01-02")+".log"))
	if err != nil {
		t.Fatalf("failed to read debug log: %v", err)
	}
	events := parseWAFDebugLogEvents(t, string(data))
	sawComponent := false
	sawReloadEnd := false
	sawRedactedPort := false
	for _, event := range events {
		if event["component"] == "waf" {
			sawComponent = true
		}
		if event["event"] == "reload_end" {
			sawReloadEnd = true
		}
		if wafDebugValueContains(event, "[admin-port]") {
			sawRedactedPort = true
		}
		for key, value := range event {
			if key == "time" {
				continue
			}
			if wafDebugValueContains(value, "7996") {
				t.Fatalf("expected admin port fields to be redacted, got %q", string(data))
			}
		}
	}
	if !sawComponent || !sawReloadEnd {
		t.Fatalf("expected WAF reload debug events, got %q", string(data))
	}
	if !sawRedactedPort {
		t.Fatalf("expected admin port redaction marker, got %q", string(data))
	}
}

func parseWAFDebugLogEvents(t *testing.T, raw string) []map[string]any {
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

func wafDebugValueContains(value any, needle string) bool {
	switch typed := value.(type) {
	case string:
		return strings.Contains(typed, needle)
	case []any:
		for _, item := range typed {
			if wafDebugValueContains(item, needle) {
				return true
			}
		}
	case map[string]any:
		for _, item := range typed {
			if wafDebugValueContains(item, needle) {
				return true
			}
		}
	}
	return false
}
