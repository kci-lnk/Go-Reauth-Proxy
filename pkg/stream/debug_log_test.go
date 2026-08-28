package stream

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go-reauth-proxy/pkg/logger"
	"go-reauth-proxy/pkg/models"
	"go-reauth-proxy/pkg/proxy"
)

func enableDebugLogForStreamTest(t *testing.T) string {
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

func TestDebugLogRecordsStreamReconcileWithAdminPortRedaction(t *testing.T) {
	dir := enableDebugLogForStreamTest(t)
	logger.SetDebugAdminPortForRedaction(7996)

	manager := &Manager{
		handler:   &proxy.Handler{AdminPort: 7996, ProxyPort: 7999},
		listeners: map[streamRuleKey]managedListener{},
		rules:     map[streamRuleKey]models.StreamRule{},
	}

	err := manager.Reconcile([]models.StreamRule{
		{Protocol: models.StreamProtocolTCP, ListenPort: 7996, Target: "127.0.0.1:8080"},
	})
	if err == nil {
		t.Fatal("expected reserved stream port error")
	}
	logger.FlushDebugLogger()

	data, err := os.ReadFile(filepath.Join(dir, time.Now().Format("2006-01-02")+".log"))
	if err != nil {
		t.Fatalf("failed to read debug log: %v", err)
	}
	got := string(data)
	if !strings.Contains(got, `"component":"stream"`) || !strings.Contains(got, `"event":"reconcile_failed"`) {
		t.Fatalf("expected stream reconcile debug events, got %q", got)
	}
	if !strings.Contains(got, `[admin-port]`) ||
		strings.Contains(got, `"listen_port":"7996"`) ||
		strings.Contains(got, `listen_port 7996 is reserved`) {
		t.Fatalf("expected admin port to be redacted, got %q", got)
	}
}
