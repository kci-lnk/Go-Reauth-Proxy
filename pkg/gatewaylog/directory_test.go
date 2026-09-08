package gatewaylog

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"go-reauth-proxy/pkg/models"
)

func TestDirectorySwitchPreservesOldLogsAndRestoresDefault(t *testing.T) {
	original := t.TempDir()
	custom := filepath.Join(t.TempDir(), "日志 folder")
	cfg := models.LoggingConfig{Enabled: true, MaxDays: 7}
	m := NewManager(original, cfg)
	defer m.Close()
	m.Log(Entry{TraceID: "old", Status: 200})
	if _, err := m.Analyze("", ""); err != nil {
		t.Fatal(err)
	}
	cfg.CustomLogsDir = custom
	info, err := m.UpdateConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if info.DefaultLogsDir != original || info.LogsDir != custom || info.CustomLogsDir != custom {
		t.Fatalf("config: %#v", info)
	}
	if len(m.analyticsCache) != 0 {
		t.Fatal("old analysis cache retained")
	}
	m.Log(Entry{TraceID: "new", Status: 201})
	result, err := m.Query("", 1, 100, "", "", "", "", "", "")
	if err != nil || len(result.Items) != 1 || result.Items[0].TraceID != "new" {
		t.Fatalf("new query: %#v %v", result, err)
	}
	cfg.CustomLogsDir = ""
	if _, err := m.UpdateConfig(cfg); err != nil {
		t.Fatal(err)
	}
	result, err = m.Query("", 1, 100, "", "", "", "", "", "")
	if err != nil || len(result.Items) != 1 || result.Items[0].TraceID != "old" {
		t.Fatalf("restored query: %#v %v", result, err)
	}
	if _, err := m.DeleteDate(time.Now().Format(dateLayout)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(custom, time.Now().Format(dateLayout)+fileExtension)); err != nil {
		t.Fatal("deleting original affected custom", err)
	}
	restarted := NewManager(original, models.LoggingConfig{Enabled: true, CustomLogsDir: custom})
	defer restarted.Close()
	if restarted.LogsDir() != custom || restarted.GetConfigInfo().DefaultLogsDir != original {
		t.Fatal("startup did not resolve custom/default directories")
	}
}

func TestDirectorySwitchValidationAndPersistenceFailure(t *testing.T) {
	original := t.TempDir()
	m := NewManager(original, models.LoggingConfig{Enabled: true})
	defer m.Close()
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"relative/logs", file} {
		called := false
		_, err := m.Configure(models.LoggingConfig{Enabled: true, CustomLogsDir: path}, func() error { called = true; return nil })
		if err == nil || called || m.LogsDir() != original {
			t.Fatalf("invalid path was applied: %q %v", path, err)
		}
	}
	_, err := m.Configure(models.LoggingConfig{Enabled: true, CustomLogsDir: t.TempDir()}, func() error { return errors.New("disk full") })
	if err == nil || m.LogsDir() != original || m.GetConfigInfo().CustomLogsDir != "" {
		t.Fatal("failed persistence changed active configuration")
	}
	m.Log(Entry{TraceID: "after-failure", Status: 200})
	result, err := m.Query("", 1, 100, "", "", "", "", "", "")
	if err != nil || len(result.Items) != 1 {
		t.Fatalf("old writer unavailable: %#v %v", result, err)
	}
}

func TestDirectorySwitchRejectsUnreadableOrUnwritableDirectory(t *testing.T) {
	for _, mode := range []os.FileMode{0500, 0300} {
		path := t.TempDir()
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		err := ValidateLogsDirectory(path)
		_ = os.Chmod(path, 0700)
		if err == nil {
			t.Skip("process can bypass directory permissions on this platform")
		}
	}
}

func TestDirectorySwitchConcurrentLogReadAnalyzeDelete(t *testing.T) {
	original, custom := t.TempDir(), t.TempDir()
	m := NewManager(original, models.LoggingConfig{Enabled: true})
	defer m.Close()
	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			m.Log(Entry{TraceID: fmt.Sprint(i), Status: 200})
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			if _, err := m.Query("", 1, 20, "", "", "", "", "", ""); err != nil {
				t.Error(err)
			}
			if _, err := m.Analyze("", ""); err != nil {
				t.Error(err)
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			if _, err := m.DeleteDate("2000-01-01"); err != nil {
				t.Error(err)
			}
			m.GetDates()
			m.FindByTraceID("0")
		}
	}()
	for i := 0; i < 20; i++ {
		path := custom
		if i%2 == 1 {
			path = ""
		}
		if _, err := m.UpdateConfig(models.LoggingConfig{Enabled: true, CustomLogsDir: path}); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
	m.Flush()
	count := 0
	for _, path := range []string{original, custom} {
		if _, err := m.UpdateConfig(models.LoggingConfig{Enabled: true, CustomLogsDir: path}); err != nil {
			t.Fatal(err)
		}
		result, err := m.Query("", 1, 200, "", "", "", "", "", "")
		if err != nil {
			t.Fatal(err)
		}
		count += result.Total
	}
	if count != 1000 {
		t.Fatalf("switch lost or duplicated entries: %d", count)
	}
}

func TestEnablingLoggingValidatesTodayFile(t *testing.T) {
	dir := t.TempDir()
	// The directory is writable, but today's log name cannot be opened as a file.
	if err := os.Mkdir(filepath.Join(dir, time.Now().Format(dateLayout)+fileExtension), 0700); err != nil {
		t.Fatal(err)
	}
	m := NewManager(dir, models.LoggingConfig{})
	defer m.Close()
	persisted := false
	if _, err := m.Configure(models.LoggingConfig{Enabled: true}, func() error { persisted = true; return nil }); err == nil {
		t.Fatal("enabled an unwritable daily log")
	}
	if persisted || m.Enabled() {
		t.Fatal("invalid enable was committed")
	}
}

type brokenLogWriter struct{}

func (brokenLogWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestDisableLoggingWithFailedStorage(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "logs")
	m := NewManager(dir, models.LoggingConfig{Enabled: true})
	defer m.Close()
	// Simulate a sticky bufio error and a directory that is no longer available.
	m.writer.mu.Lock()
	m.writer.currentBuffer = bufio.NewWriter(brokenLogWriter{})
	_, _ = m.writer.currentBuffer.WriteString("pending entry")
	_ = m.writer.currentBuffer.Flush()
	m.writer.mu.Unlock()
	if err := os.WriteFile(dir, []byte("not a directory"), 0600); err != nil {
		t.Fatal(err)
	}
	persisted := false
	info, err := m.Configure(models.LoggingConfig{Enabled: false}, func() error { persisted = true; return nil })
	if err != nil || info.Enabled || !persisted || m.Enabled() {
		t.Fatalf("cannot disable broken storage: %#v %v", info, err)
	}
}

func TestCanceledDirectoryChangeDoesNotCommitAfterReadCompletes(t *testing.T) {
	m := NewManager(t.TempDir(), models.LoggingConfig{})
	defer m.Close()
	m.directoryMu.RLock()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	persisted := false
	done := make(chan error, 1)
	go func() {
		_, err := m.ConfigureContext(ctx, models.LoggingConfig{CustomLogsDir: t.TempDir()}, func() error { persisted = true; return nil })
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("error = %v", err)
		}
	case <-time.After(time.Second):
		m.directoryMu.RUnlock()
		<-done
		t.Fatal("canceled change waited for the active read")
	}
	m.directoryMu.RUnlock()
	if persisted || m.GetConfigInfo().CustomLogsDir != "" {
		t.Fatal("canceled directory change committed")
	}
}

func TestCanceledQueriesDoNotWaitForDirectoryChange(t *testing.T) {
	m := NewManager(t.TempDir(), models.LoggingConfig{})
	defer m.Close()
	m.directoryMu.Lock()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan error, 1)
	go func() {
		_, q := m.QueryContext(ctx, "", 1, 20, "", "", "", "", "", "")
		_, a := m.AnalyzeContext(ctx, "", "")
		_, f := m.FindByTraceIDContext(ctx, "trace")
		if !errors.Is(q, context.Canceled) || !errors.Is(a, context.Canceled) || !errors.Is(f, context.Canceled) {
			done <- fmt.Errorf("cancellation: %v %v %v", q, a, f)
			return
		}
		done <- nil
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Error(err)
		}
	case <-time.After(time.Second):
		m.directoryMu.Unlock()
		<-done
		t.Fatal("canceled queries waited for a change")
	}
	m.directoryMu.Unlock()
}

func TestLegacyDirectoryPatchResolvesCurrentPathAtCommit(t *testing.T) {
	m := NewManager(t.TempDir(), models.LoggingConfig{})
	defer m.Close()
	current := t.TempDir()
	if _, err := m.UpdateConfig(models.LoggingConfig{CustomLogsDir: current}); err != nil {
		t.Fatal(err)
	}
	// A stale legacy caller must inherit the current path, not its earlier snapshot.
	var saved models.LoggingConfig
	info, err := m.ConfigurePatchContext(context.Background(), models.LoggingConfig{MaxDays: 3, CustomLogsDir: "stale"}, true, func(cfg models.LoggingConfig) error { saved = cfg; return nil })
	if err != nil || info.CustomLogsDir != current || saved.CustomLogsDir != current || saved.MaxDays != 3 {
		t.Fatalf("legacy patch: %#v %#v %v", info, saved, err)
	}
}
