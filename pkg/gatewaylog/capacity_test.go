package gatewaylog

import (
	"context"
	"fmt"
	"go-reauth-proxy/pkg/models"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func tinyWriter(t *testing.T, daily, total, segment int64) *DailyFileWriter {
	t.Helper()
	w := NewDailyFileWriter(t.TempDir(), 7)
	w.dailyLimit = daily
	w.totalLimit = total
	w.segmentLimit = segment
	t.Cleanup(func() { _ = w.Close() })
	return w
}
func assertCapacity(t *testing.T, w *DailyFileWriter) {
	t.Helper()
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	files, err := listLogSegments(w.baseDir)
	if err != nil {
		t.Fatal(err)
	}
	var total int64
	days := map[string]int64{}
	for _, s := range files {
		total += s.size
		days[s.date] += s.size
	}
	if total > w.totalLimit {
		t.Fatalf("total %d > %d", total, w.totalLimit)
	}
	for day, size := range days {
		if size > w.dailyLimit {
			t.Fatalf("%s: %d > %d", day, size, w.dailyLimit)
		}
	}
}
func TestCapacityRotatesBeforeBufferedBytesExceedQuota(t *testing.T) {
	w := tinyWriter(t, 300, 450, 120)
	for i := 0; i < 50; i++ {
		line := fmt.Sprintf("{\"path\":\"/%03d\",\"status\":200}\n", i)
		if _, err := w.Write([]byte(line)); err != nil {
			t.Fatal(err)
		}
		status := w.storageStatus.Load()
		if status.total > w.totalLimit || status.today > w.dailyLimit {
			t.Fatalf("buffer not counted: %+v", status)
		}
	}
	assertCapacity(t, w)
	files, _ := listLogSegments(w.baseDir)
	if len(files) < 2 {
		t.Fatalf("expected multiple segments: %v", files)
	}
	data, err := os.ReadFile(files[len(files)-1].path)
	if err != nil || !strings.Contains(string(data), "/049") {
		t.Fatalf("latest entry missing: %s %v", data, err)
	}
	if w.capacityDropped.Load() != 0 {
		t.Fatal("normal rotation dropped new records")
	}
}
func TestCapacityRejectsOversizeEntryWithoutGrowingFile(t *testing.T) {
	w := tinyWriter(t, 100, 100, 40)
	_, _ = w.Write([]byte(strings.Repeat("x", 41)))
	assertCapacity(t, w)
	if w.capacityDropped.Load() != 1 || w.storageStatus.Load().total != 0 {
		t.Fatal("oversize entry was not rejected")
	}
}
func TestCapacityStartupCompactsLegacyAndIgnoresUnmanagedFiles(t *testing.T) {
	w := tinyWriter(t, 100, 150, 50)
	date := time.Now().Format(dateLayout)
	old := filepath.Join(w.baseDir, date+fileExtension)
	contents := strings.Repeat("{\"path\":\"old\"}\n", 100) + "{\"path\":\"latest\"}\n"
	if err := os.WriteFile(old, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
	unrelated := filepath.Join(w.baseDir, "other.log")
	_ = os.WriteFile(unrelated, []byte(strings.Repeat("x", 1000)), 0o644)
	stale := filepath.Join(w.baseDir, ".gateway-log-compact-interrupted")
	_ = os.WriteFile(stale, []byte("partial"), 0o644)
	if err := w.Cleanup(); err != nil {
		t.Fatal(err)
	}
	assertCapacity(t, w)
	files, _ := listLogSegments(w.baseDir)
	if len(files) != 1 {
		t.Fatalf("files: %v", files)
	}
	data, _ := os.ReadFile(files[0].path)
	if !strings.HasSuffix(string(data), "{\"path\":\"latest\"}\n") {
		t.Fatalf("latest missing: %q", data)
	}
	if len(data) > 0 && data[0] != '{' {
		t.Fatal("partial first line")
	}
	if _, err := os.Stat(unrelated); err != nil {
		t.Fatal("unmanaged file removed")
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatal("stale temporary file left behind")
	}
}
func TestCapacityRestartAndLowerLimits(t *testing.T) {
	w := tinyWriter(t, 300, 400, 100)
	for i := 0; i < 10; i++ {
		_, _ = w.Write([]byte("{\"path\":\"request-abcdefghijklmnop\"}\n"))
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	other := NewDailyFileWriter(w.baseDir, 7)
	defer other.Close()
	other.dailyLimit = 80
	other.totalLimit = 100
	other.segmentLimit = 40
	if err := other.Cleanup(); err != nil {
		t.Fatal(err)
	}
	assertCapacity(t, other)
	_, _ = other.Write([]byte("{\"path\":\"latest\"}\n"))
	assertCapacity(t, other)
	if other.capacityDropped.Load() != 0 {
		t.Fatal("write failed after restart")
	}
}
func TestCapacityDailyPruningPrecedesGlobalPruning(t *testing.T) {
	w := tinyWriter(t, 100, 180, 50)
	today := time.Now()
	yesterday := today.AddDate(0, 0, -1).Format(dateLayout)
	date := today.Format(dateLayout)
	for _, file := range []struct {
		name string
		size int
	}{{yesterday + ".00000000000000000001.log", 50}, {date + ".00000000000000000001.log", 60}, {date + ".00000000000000000002.log", 60}, {date + ".00000000000000000003.log", 60}} {
		if err := os.WriteFile(filepath.Join(w.baseDir, file.name), []byte(strings.Repeat("x", file.size)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Cleanup(); err != nil {
		t.Fatal(err)
	}
	assertCapacity(t, w)
	if _, err := os.Stat(filepath.Join(w.baseDir, yesterday+".00000000000000000001.log")); err != nil {
		t.Fatal("unrelated old day was needlessly removed")
	}
}
func TestCapacityCleanupFailureStopsGrowthAndRecovers(t *testing.T) {
	w := tinyWriter(t, 60, 60, 40)
	_, _ = w.Write([]byte("{\"path\":\"first\"}\n"))
	_ = w.Flush()
	// A nonempty directory at the indexed file path deterministically fails
	// removal on every platform, including tests run as root.
	path := w.segments[0].path
	_ = w.closeSegmentLocked()
	_ = os.Remove(path)
	_ = os.Mkdir(path, 0o755)
	_ = os.WriteFile(filepath.Join(path, "block"), []byte("x"), 0o644)
	w.segments[0].size = 60
	_, _ = w.Write([]byte("{\"path\":\"blocked\"}\n"))
	if w.capacityDropped.Load() != 1 || w.storageStatus.Load().error == "" {
		t.Fatal("cleanup failure was not reported")
	}
	_ = os.RemoveAll(path)
	_, _ = w.Write([]byte("{\"path\":\"recovered\"}\n"))
	assertCapacity(t, w)
	if w.storageStatus.Load().error != "" {
		t.Fatal("cleanup did not recover")
	}
}
func TestCapacitySegmentQueriesCursorEvictionAndAnalytics(t *testing.T) {
	m := NewManager(t.TempDir(), models.LoggingConfig{Enabled: true})
	defer m.Close()
	m.writer.dailyLimit = 600
	m.writer.totalLimit = 600
	m.writer.segmentLimit = 100
	date := time.Now().Format(dateLayout)
	for i := 0; i < 8; i++ {
		_, _ = m.writer.Write([]byte(fmt.Sprintf("{\"path\":\"/%d\",\"status\":200}\n", i)))
	}
	first, err := m.Query(date, 1, 3, "", "", "", "", "", "cursor")
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Items) != 3 || first.Items[0].Path != "/7" || !first.HasMore || !strings.Contains(first.NextCursor, ":") {
		t.Fatalf("first: %+v", first)
	}
	second, err := m.Query(date, 1, 3, "", "", "", "", first.NextCursor, "cursor")
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Items) != 3 || second.Items[0].Path != "/4" {
		t.Fatalf("second: %+v", second)
	}
	page, err := m.Query(date, 2, 3, "", "", "", "", "", "page")
	if err != nil || page.Total != 8 || page.Items[0].Path != "/4" {
		t.Fatalf("page: %+v %v", page, err)
	}
	before, err := m.Analyze(date, date)
	if err != nil || before.Summary.Requests != 8 {
		t.Fatalf("analytics before: %+v %v", before, err)
	}
	for i := 8; i < 80; i++ {
		_, _ = m.writer.Write([]byte(fmt.Sprintf("{\"path\":\"/%d\",\"status\":200}\n", i)))
	}
	if _, err := m.Query(date, 1, 3, "", "", "", "", first.NextCursor, "cursor"); err == nil || !strings.Contains(err.Error(), "cursor expired") {
		t.Fatalf("expected expired cursor: %v", err)
	}
	after, err := m.Analyze(date, date)
	if err != nil {
		t.Fatal(err)
	}
	all, err := m.Query(date, 1, 200, "", "", "", "", "", "page")
	if err != nil {
		t.Fatal(err)
	}
	if after.Summary.Requests != int64(all.Total) {
		t.Fatalf("stale statistics: %d vs %d", after.Summary.Requests, all.Total)
	}
	deleted, err := m.DeleteDate(date)
	if err != nil || !deleted.Deleted {
		t.Fatalf("delete: %+v %v", deleted, err)
	}
	files, _ := segmentsForDate(m.logsDir, date)
	if len(files) != 0 {
		t.Fatal("delete left segments")
	}
}
func TestCapacityConfigPatchPreservesLimitsAndRejectsInvalid(t *testing.T) {
	m := NewManager(t.TempDir(), models.LoggingConfig{MaxDailySizeMB: 10, MaxTotalSizeMB: 20})
	defer m.Close()
	info, err := m.ConfigurePatchContext(context.Background(), models.LoggingConfig{MaxDays: 3}, true, nil)
	if err != nil || info.MaxDailySizeMB != 10 || info.MaxTotalSizeMB != 20 {
		t.Fatalf("patch lost limits: %+v %v", info, err)
	}
	_, err = m.ConfigurePatchContext(context.Background(), models.LoggingConfig{MaxDailySizeMB: 30, MaxTotalSizeMB: 20}, true, nil)
	if err == nil {
		t.Fatal("accepted total less than daily")
	}
}

func TestCapacityCompactionFailurePreservesOriginal(t *testing.T) {
	w := tinyWriter(t, 100, 100, 50)
	path := filepath.Join(w.baseDir, time.Now().Format(dateLayout)+fileExtension)
	original := []byte(strings.Repeat("{\"status\":200}\n", 100))
	if err := os.WriteFile(path, original, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(w.baseDir, 0o555); err != nil {
		t.Skip(err)
	}
	defer os.Chmod(w.baseDir, 0o755)
	// Skip platforms/accounts that bypass mode bits.
	probe, err := os.CreateTemp(w.baseDir, "probe")
	if err == nil {
		probe.Close()
		os.Remove(probe.Name())
		t.Skip("directory permissions not enforced")
	}
	if err := w.Cleanup(); err == nil {
		t.Fatal("expected compaction failure")
	}
	actual, err := os.ReadFile(path)
	if err != nil || string(actual) != string(original) {
		t.Fatalf("original changed on failure: %v", err)
	}
	if w.storageStatus.Load().error == "" {
		t.Fatal("failure not visible")
	}
}

func TestCapacityDayRolloverAndLegacyCursor(t *testing.T) {
	w := tinyWriter(t, 100, 150, 50)
	yesterday := time.Now().AddDate(0, 0, -1)
	if err := w.openSegmentLocked(yesterday, false); err != nil {
		t.Fatal(err)
	}
	old := w.currentFile.Name()
	_, _ = w.Write([]byte("{\"path\":\"today\"}\n"))
	assertCapacity(t, w)
	if w.currentFile.Name() == old || w.currentDate != time.Now().Format(dateLayout) {
		t.Fatal("did not rotate to today")
	}
	legacy := filepath.Join(w.baseDir, yesterday.Format(dateLayout)+fileExtension)
	line := "{\"path\":\"legacy\",\"status\":200}\n"
	if err := os.WriteFile(legacy, []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	filter, _ := newQueryFilter("", "", "", "")
	entries, _, _, _, err := querySegmentEntries(w.baseDir, yesterday.Format(dateLayout), filter, fmt.Sprint(len(line)), 1, 20, "cursor")
	if err != nil || len(entries) != 1 || entries[0].Path != "legacy" {
		t.Fatalf("legacy cursor: %v %v", entries, err)
	}
}

func TestCapacityPersistFailureDoesNotApplyLowerLimit(t *testing.T) {
	m := NewManager(t.TempDir(), models.LoggingConfig{MaxDailySizeMB: 10, MaxTotalSizeMB: 20})
	defer m.Close()
	_, _ = m.writer.Write([]byte("{\"path\":\"keep\"}\n"))
	_ = m.writer.Flush()
	_, err := m.ConfigurePatchContext(context.Background(), models.LoggingConfig{MaxDailySizeMB: 1, MaxTotalSizeMB: 1}, true, func(models.LoggingConfig) error { return fmt.Errorf("persist failed") })
	if err == nil {
		t.Fatal("persist failure ignored")
	}
	if m.GetConfigInfo().MaxDailySizeMB != 10 || m.writer.dailyLimit != 10<<20 {
		t.Fatal("quota changed before persistence succeeded")
	}
	result, err := m.Query("", 1, 20, "", "", "", "", "", "")
	if err != nil || len(result.Items) != 1 {
		t.Fatalf("logs lost on failed save: %v %v", result, err)
	}
}
