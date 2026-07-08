package iptables

import (
	"encoding/json"
	stderrors "errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go-reauth-proxy/pkg/logger"
)

type debugTestRunner struct{}

func (debugTestRunner) CombinedOutput(command string, args ...string) ([]byte, error) {
	for _, arg := range args {
		if arg == "-D" {
			return []byte("not found"), stderrors.New("not found")
		}
	}
	return []byte("ok"), nil
}

func (debugTestRunner) CombinedOutputWithInput(input string, command string, args ...string) ([]byte, error) {
	return []byte("ok"), nil
}

func enableDebugLogForIptablesTest(t *testing.T) string {
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

func TestDebugLogRecordsIptablesOperationWithAdminPortRedaction(t *testing.T) {
	dir := enableDebugLogForIptablesTest(t)
	logger.SetDebugAdminPortForRedaction(7996)

	manager := NewManager(Options{Tables: []string{"iptables"}})
	manager.runner = debugTestRunner{}

	if err := manager.EnsureTCPRedirect(7996, 7999); err != nil {
		t.Fatalf("EnsureTCPRedirect returned error: %v", err)
	}
	logger.FlushDebugLogger()

	data, err := os.ReadFile(filepath.Join(dir, time.Now().Format("2006-01-02")+".log"))
	if err != nil {
		t.Fatalf("failed to read debug log: %v", err)
	}
	events := parseDebugLogEvents(t, string(data))
	sawComponent := false
	sawEndEvent := false
	sawRedactedPort := false
	for _, event := range events {
		if event["component"] == "iptables" {
			sawComponent = true
		}
		if event["event"] == "tcp_redirect_ensure_end" {
			sawEndEvent = true
		}
		if debugEventValueContains(event, "[admin-port]") {
			sawRedactedPort = true
		}
		if debugEventValueContainsAdminPort(event) {
			t.Fatalf("expected admin port fields to be redacted, got %q", string(data))
		}
	}
	if !sawComponent || !sawEndEvent {
		t.Fatalf("expected iptables debug events, got %q", string(data))
	}
	if !sawRedactedPort {
		t.Fatalf("expected admin port redaction marker, got %q", string(data))
	}
}

func parseDebugLogEvents(t *testing.T, raw string) []map[string]any {
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

func debugEventValueContainsAdminPort(event map[string]any) bool {
	for key, value := range event {
		if key == "time" {
			continue
		}
		if debugEventValueContains(value, "7996") {
			return true
		}
	}
	return false
}

func debugEventValueContains(value any, needle string) bool {
	switch typed := value.(type) {
	case string:
		return strings.Contains(typed, needle)
	case []any:
		for _, item := range typed {
			if debugEventValueContains(item, needle) {
				return true
			}
		}
	case map[string]any:
		for _, item := range typed {
			if debugEventValueContains(item, needle) {
				return true
			}
		}
	}
	return false
}
