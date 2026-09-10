package gatewaylog

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"go-reauth-proxy/pkg/models"
)

type recoveringLogSink struct {
	bytes.Buffer
	fail    bool
	partial int
}

func (s *recoveringLogSink) Write(p []byte) (int, error) {
	if s.fail {
		n := min(s.partial, len(p))
		s.partial = 0
		s.Buffer.Write(p[:n])
		return n, syscall.ENOSPC
	}
	return s.Buffer.Write(p)
}

func TestCapacityAuditDiskFullRecoveryRetainsAcceptedRecords(t *testing.T) {
	sink := &recoveringLogSink{fail: true, partial: 7}
	buffer := newRetryLogBuffer(sink, 64)
	first := "{\"path\":\"first\"}\n"
	if n, err := buffer.WriteString(first); err != nil || n != len(first) {
		t.Fatalf("admit: %d %v", n, err)
	}
	if err := buffer.Flush(); !errors.Is(err, syscall.ENOSPC) {
		t.Fatalf("flush: %v", err)
	}
	if n, err := buffer.WriteString("rejected\n"); n != 0 || !errors.Is(err, syscall.ENOSPC) {
		t.Fatalf("accepted a partial new record: %d %v", n, err)
	}
	sink.fail = false
	second := "{\"path\":\"second\"}\n"
	if _, err := buffer.WriteString(second); err != nil {
		t.Fatal(err)
	}
	if err := buffer.Flush(); err != nil {
		t.Fatal(err)
	}
	if sink.String() != first+second {
		t.Fatalf("lost or duplicated bytes: %q", sink.String())
	}
}

func TestCapacityAuditRestartDoesNotAppendToCrashTail(t *testing.T) {
	w := tinyWriter(t, 300, 400, 100)
	first := "{\"path\":\"before\"}\n"
	_, _ = w.Write([]byte(first))
	_ = w.Flush()
	old := w.currentFile.Name()
	_ = w.Close()
	file, err := os.OpenFile(old, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = file.WriteString("{\"path\":\"incomplete")
	_ = file.Close()
	other := NewDailyFileWriter(w.baseDir, 7)
	defer other.Close()
	_, _ = other.Write([]byte("{\"path\":\"after\"}\n"))
	_ = other.Flush()
	if other.currentFile.Name() == old {
		t.Fatal("reopened a possibly incomplete crash tail")
	}
	filter, _ := newQueryFilter("", "", "", "")
	items, _, _, _, err := querySegmentEntries(w.baseDir, time.Now().Format(dateLayout), filter, "", 1, 20, "page")
	if err != nil || len(items) != 2 || items[0].Path != "after" {
		t.Fatalf("records after restart: %+v %v", items, err)
	}
}

func TestCapacityAuditCompactionFailureInvalidatesOldIdentity(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "2026-09-10.log")
	target := filepath.Join(dir, "2026-09-10.00000000000000000000-00000000000000000001.log")
	tmp := filepath.Join(dir, "temp")
	original := []byte("original complete data\n")
	_ = os.WriteFile(source, original, 0o644)
	_ = os.WriteFile(tmp, []byte("tail\n"), 0o644)
	calls := 0
	path, err := replaceCompactedLog(source, target, tmp, func(a, b string) error {
		calls++
		if calls == 2 {
			return syscall.ENOSPC
		}
		return os.Rename(a, b)
	})
	if !errors.Is(err, syscall.ENOSPC) || path != target {
		t.Fatalf("replacement: %s %v", path, err)
	}
	actual, err := os.ReadFile(target)
	if err != nil || !bytes.Equal(actual, original) {
		t.Fatal("failed replacement destroyed source contents")
	}
	if _, err := os.Stat(source); !os.IsNotExist(err) {
		t.Fatal("old cursor identity still addresses replacement data")
	}
}

func TestCapacityAuditLoggingDoesNotWaitForConfiguration(t *testing.T) {
	m := NewManager(t.TempDir(), models.LoggingConfig{Enabled: true})
	defer m.Close()
	m.inputMu.Lock()
	done := make(chan struct{})
	go func() { m.Log(Entry{Status: 200}); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		m.inputMu.Unlock()
		t.Fatal("request thread blocked by configuration")
	}
	m.inputMu.Unlock()
	if m.DroppedLogEntries() != 1 {
		t.Fatal("configuration-time drop was not counted")
	}
}

func TestCapacityAuditWriterLockHonorsQueryCancellation(t *testing.T) {
	m := NewManager(t.TempDir(), models.LoggingConfig{})
	defer m.Close()
	m.writer.mu.Lock()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := m.QueryContext(ctx, "", 1, 20, "", "", "", "", "", "page"); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("query error: %v", err)
		}
	case <-time.After(time.Second):
		t.Error("query ignored cancellation while waiting for writer")
	}
	m.writer.mu.Unlock()
}

func TestCapacityAuditPageModeIgnoresCursor(t *testing.T) {
	w := tinyWriter(t, 300, 400, 100)
	_, _ = w.Write([]byte("{\"path\":\"latest\"}\n"))
	_ = w.Flush()
	filter, _ := newQueryFilter("", "", "", "")
	items, _, _, _, err := querySegmentEntries(w.baseDir, time.Now().Format(dateLayout), filter, "expired:123", 1, 20, "page")
	if err != nil || len(items) != 1 {
		t.Fatalf("page mode used a cursor: %+v %v", items, err)
	}
}

func TestCapacityAuditFailedFlushAccountingAndRecovery(t *testing.T) {
	w := tinyWriter(t, 300, 400, 100)
	first := []byte("{\"path\":\"before\"}\n")
	_, _ = w.Write(first)
	sink := &recoveringLogSink{fail: true, partial: 4}
	buffer := w.currentBuffer.(*retryLogBuffer)
	buffer.writer = sink
	if err := w.Flush(); !errors.Is(err, syscall.ENOSPC) {
		t.Fatal(err)
	}
	if w.storageStatus.Load().today != int64(len(first)) {
		t.Fatal("unflushed bytes stopped counting toward capacity")
	}
	if w.storageStatus.Load().error == "" {
		t.Fatal("flush error was not published")
	}
	_, _ = w.Write([]byte("{\"path\":\"rejected\"}\n"))
	if w.capacityDropped.Load() != 1 {
		t.Fatal("new record during disk-full failure was not counted")
	}
	sink.fail = false
	// Query/configuration paths use flushLocked too; they must clear a recovered
	// failure even if no new requests arrive after the storage repair.
	w.mu.Lock()
	err := w.flushLocked()
	w.mu.Unlock()
	if err != nil || w.storageStatus.Load().error != "" {
		t.Fatalf("error remained latched: %v", err)
	}
	if sink.String() != string(first) {
		t.Fatalf("accepted record damaged: %q", sink.String())
	}
}

func TestCapacityAuditCompactionPreservesPermissionsAndRejectsCollision(t *testing.T) {
	w := tinyWriter(t, 100, 100, 50)
	source := filepath.Join(w.baseDir, time.Now().Format(dateLayout)+fileExtension)
	_ = os.WriteFile(source, bytes.Repeat([]byte("{\"status\":200}\n"), 100), 0o600)
	originalInfo, err := os.Stat(source)
	if err != nil {
		t.Fatal(err)
	}
	expectedMode := originalInfo.Mode().Perm()
	if err := w.Cleanup(); err != nil {
		t.Fatal(err)
	}
	files, err := listLogSegments(w.baseDir)
	if err != nil || len(files) != 1 {
		t.Fatalf("files: %v %v", files, err)
	}
	info, err := os.Stat(files[0].path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != expectedMode {
		t.Fatalf("compaction broadened permissions: %v", info.Mode())
	}
	target := filepath.Join(w.baseDir, "existing")
	_ = os.WriteFile(target, []byte("do not overwrite"), 0o600)
	if _, err := replaceCompactedLog(files[0].path, target, "unused", os.Rename); !errors.Is(err, os.ErrExist) {
		t.Fatalf("collision accepted: %v", err)
	}
	data, _ := os.ReadFile(target)
	if string(data) != "do not overwrite" {
		t.Fatal("existing target overwritten")
	}
}

func TestCapacityAuditTodayUsageDoesNotCarryAcrossMidnight(t *testing.T) {
	m := NewManager(t.TempDir(), models.LoggingConfig{})
	defer m.Close()
	m.writer.storageStatus.Store(&logStorageStatus{today: 50, total: 100, day: time.Now().AddDate(0, 0, -1).Format(dateLayout)})
	if got := m.GetConfigInfo(); got.TodaySizeBytes != 0 || got.TotalSizeBytes != 100 {
		t.Fatalf("yesterday counted as today: %+v", got)
	}
}
