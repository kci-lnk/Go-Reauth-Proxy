package gatewaylog

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"go-reauth-proxy/pkg/models"
)

func TestNormalizeConfigDefaultsMaxDays(t *testing.T) {
	got := NormalizeConfig(models.LoggingConfig{Enabled: true})
	if got.MaxDays != DefaultMaxDays {
		t.Fatalf("MaxDays = %d, want %d", got.MaxDays, DefaultMaxDays)
	}
}

func TestDefaultLogsDirUsesRuntimeDir(t *testing.T) {
	if got, want := DefaultLogsDir("/tmp/runtime"), filepath.Join("/tmp/runtime", "logs"); got != want {
		t.Fatalf("DefaultLogsDir() = %q, want %q", got, want)
	}
}

func TestNewManagerExposesConfigInfo(t *testing.T) {
	dir := t.TempDir()
	manager := NewManager(dir, models.LoggingConfig{Enabled: true, MaxDays: 3})
	t.Cleanup(manager.Close)
	info := manager.GetConfigInfo()
	if !info.Enabled || info.MaxDays != 3 || info.LogsDir != dir {
		t.Fatalf("ConfigInfo = %#v", info)
	}
}

func TestUpdateConfigNormalizesAndPersistsInMemory(t *testing.T) {
	manager := NewManager(t.TempDir(), models.LoggingConfig{})
	t.Cleanup(manager.Close)
	info := manager.UpdateConfig(models.LoggingConfig{Enabled: true, MaxDays: 0})
	if !info.Enabled || info.MaxDays != DefaultMaxDays {
		t.Fatalf("UpdateConfig() = %#v", info)
	}
}

func TestDailyFileWriterWriteCreatesTodayFile(t *testing.T) {
	dir := t.TempDir()
	writer := NewDailyFileWriter(dir, 7)
	t.Cleanup(func() { _ = writer.Close() })
	if _, err := writer.Write([]byte("hello\n")); err != nil {
		t.Fatalf("Write() returned error: %v", err)
	}
	if err := writer.Flush(); err != nil {
		t.Fatalf("Flush() returned error: %v", err)
	}
	path := filepath.Join(dir, time.Now().Format(dateLayout)+fileExtension)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	if string(data) != "hello\n" {
		t.Fatalf("log file = %q", string(data))
	}
}

func TestDailyFileWriterDeleteDateMissingReturnsFalse(t *testing.T) {
	writer := NewDailyFileWriter(t.TempDir(), 7)
	deleted, err := writer.DeleteDate("2001-01-01")
	if err != nil || deleted {
		t.Fatalf("DeleteDate() = %v, %v; want false nil", deleted, err)
	}
}

func TestDailyFileWriterCleanupRemovesOldLogFiles(t *testing.T) {
	dir := t.TempDir()
	oldDate := time.Now().AddDate(0, 0, -10).Format(dateLayout)
	newDate := time.Now().Format(dateLayout)
	if err := os.WriteFile(filepath.Join(dir, oldDate+fileExtension), []byte("{}\n"), 0o644); err != nil {
		t.Fatalf("write old log: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, newDate+fileExtension), []byte("{}\n"), 0o644); err != nil {
		t.Fatalf("write new log: %v", err)
	}
	if err := NewDailyFileWriter(dir, 2).Cleanup(); err != nil {
		t.Fatalf("Cleanup() returned error: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, oldDate+fileExtension)); !os.IsNotExist(err) {
		t.Fatalf("old log still exists or stat failed unexpectedly: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, newDate+fileExtension)); err != nil {
		t.Fatalf("new log missing: %v", err)
	}
}

func TestManagerLogDoesNothingWhenDisabled(t *testing.T) {
	dir := t.TempDir()
	manager := NewManager(dir, models.LoggingConfig{Enabled: false})
	t.Cleanup(manager.Close)
	if info := manager.GetConfigInfo(); info.QueueSize != 0 || info.QueueDepth != 0 {
		t.Fatalf("disabled logger allocated queue: %#v", info)
	}
	manager.Log(Entry{Method: "GET", Path: "/off", Status: 200})
	entries, err := os.ReadDir(dir)
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("ReadDir() returned error: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("disabled logger wrote files: %#v", entries)
	}
}

func TestManagerStartsWorkerLazilyWhenEnabled(t *testing.T) {
	dir := t.TempDir()
	manager := NewManager(dir, models.LoggingConfig{Enabled: false})
	t.Cleanup(manager.Close)

	info := manager.UpdateConfig(models.LoggingConfig{Enabled: true})
	if info.QueueSize != asyncLogQueueSize {
		t.Fatalf("enabled logger queue size = %d, want %d", info.QueueSize, asyncLogQueueSize)
	}
	manager.Log(Entry{Method: "GET", Path: "/enabled", Status: 200})
	manager.Flush()
	if depth := manager.GetConfigInfo().QueueDepth; depth != 0 {
		t.Fatalf("queue depth after Flush = %d, want 0", depth)
	}
}

func TestManagerBatchLoggingHasNoDropsAndFlushIsVisible(t *testing.T) {
	manager := NewManager(t.TempDir(), models.LoggingConfig{Enabled: true})
	t.Cleanup(manager.Close)

	const entries = 10_000
	for i := 0; i < entries; i++ {
		manager.Log(Entry{Method: "GET", Path: "/batch", Status: 200})
	}
	manager.Flush()
	if dropped := manager.DroppedLogEntries(); dropped != 0 {
		t.Fatalf("dropped entries = %d, want 0", dropped)
	}
	result, err := manager.Query("", 1, 1, "", "", "", "", "", "page")
	if err != nil {
		t.Fatalf("Query() returned error: %v", err)
	}
	if result.Total != entries {
		t.Fatalf("Query().Total = %d, want %d", result.Total, entries)
	}
}

func TestManagerLogWritesQueryEntryWhenEnabled(t *testing.T) {
	dir := t.TempDir()
	manager := NewManager(dir, models.LoggingConfig{Enabled: true})
	t.Cleanup(manager.Close)
	manager.Log(Entry{Method: "POST", Host: "app.example.test", Path: "/api", Status: 201, LoggedIn: true})
	result, err := manager.Query("", 1, 20, "app.example.test", "201", "true", "", "", "page")
	if err != nil {
		t.Fatalf("Query() returned error: %v", err)
	}
	if result.Total != 1 || len(result.Items) != 1 || result.Items[0].Method != "POST" {
		t.Fatalf("Query() = %#v", result)
	}
}

func TestManagerLogFiltersLocalhostIPv4HTTPButKeepsStreamEntries(t *testing.T) {
	dir := t.TempDir()
	manager := NewManager(dir, models.LoggingConfig{Enabled: true})
	t.Cleanup(manager.Close)

	manager.Log(Entry{Method: "GET", Path: "/local-ip", Status: 200, RemoteIP: "127.0.0.1"})
	manager.Log(Entry{Method: "GET", Path: "/local-addr", Status: 200, RemoteAddr: "127.0.0.1:12345"})
	manager.Log(Entry{
		Method:     "STREAM",
		Protocol:   "tcp",
		Status:     200,
		RemoteIP:   "127.0.0.1",
		RemoteAddr: "127.0.0.1:23456",
		RouteType:  "stream_rule",
		RouteKey:   "tcp/3306",
		Upstream:   "127.0.0.1:3307",
	})
	manager.Log(Entry{
		Method:     "GET",
		Path:       "/proxied",
		Status:     200,
		RemoteIP:   "198.51.100.7",
		RemoteAddr: "127.0.0.1:12345",
	})

	result, err := manager.Query("", 1, 20, "", "", "", "", "", "page")
	if err != nil {
		t.Fatalf("Query() returned error: %v", err)
	}
	if result.Total != 2 || len(result.Items) != 2 {
		t.Fatalf("Query() = %#v, want proxied HTTP and local protocol mapping entries", result)
	}
	if result.Items[0].Path != "/proxied" {
		t.Fatalf("latest Query() entry = %#v, want proxied external client entry", result.Items[0])
	}
	streamEntry := result.Items[1]
	if streamEntry.RouteType != "stream_rule" || streamEntry.RouteKey != "tcp/3306" {
		t.Fatalf("protocol mapping entry = %#v, want local stream access log", streamEntry)
	}
}

func TestManagerLogDropsWhenQueueIsFull(t *testing.T) {
	manager := &Manager{
		config: models.LoggingConfig{Enabled: true},
	}
	manager.entryPool.New = func() any { return new(Entry) }
	manager.enabled.Store(true)
	queue := &logQueueState{entries: make(chan *Entry, 1)}
	manager.logQueue.Store(queue)

	manager.Log(Entry{Path: "/queued"})
	manager.Log(Entry{Path: "/dropped"})

	if got := len(queue.entries); got != 1 {
		t.Fatalf("queued entries = %d, want 1", got)
	}
	if got := manager.DroppedLogEntries(); got != 1 {
		t.Fatalf("DroppedLogEntries() = %d, want 1", got)
	}
	info := manager.GetConfigInfo()
	if info.DroppedEntries != 1 || info.QueueSize != 1 || info.QueueDepth != 1 {
		t.Fatalf("ConfigInfo drop counters = %#v", info)
	}
}

func TestManagerGetDatesIncludesTodayWithoutFiles(t *testing.T) {
	result, err := NewManager(t.TempDir(), models.LoggingConfig{}).GetDates()
	if err != nil {
		t.Fatalf("GetDates() returned error: %v", err)
	}
	if len(result.Dates) != 1 || result.Dates[0] != result.Today {
		t.Fatalf("GetDates() = %#v", result)
	}
}

func TestManagerDeleteDateRemovesExistingLog(t *testing.T) {
	dir := t.TempDir()
	date := "2024-01-02"
	if err := os.WriteFile(filepath.Join(dir, date+fileExtension), []byte("{}\n"), 0o644); err != nil {
		t.Fatalf("write log: %v", err)
	}
	result, err := NewManager(dir, models.LoggingConfig{}).DeleteDate(date)
	if err != nil {
		t.Fatalf("DeleteDate() returned error: %v", err)
	}
	if !result.Deleted || result.Date != date {
		t.Fatalf("DeleteDate() = %#v", result)
	}
}

func TestNormalizeDateRejectsBadFormat(t *testing.T) {
	if _, err := normalizeDate("2024/01/02"); err == nil {
		t.Fatal("normalizeDate() returned nil error for bad format")
	}
}

func TestNormalizePaginationModeDefaultsToPage(t *testing.T) {
	if got := normalizePaginationMode(" offset "); got != "page" {
		t.Fatalf("normalizePaginationMode() = %q", got)
	}
}

func TestNormalizePaginationModeAcceptsCursorCaseInsensitively(t *testing.T) {
	if got := normalizePaginationMode(" Cursor "); got != "cursor" {
		t.Fatalf("normalizePaginationMode() = %q", got)
	}
}

func TestReverseEntriesReversesInPlace(t *testing.T) {
	items := []Entry{{Path: "/a"}, {Path: "/b"}, {Path: "/c"}}
	reverseEntries(items)
	got := []string{items[0].Path, items[1].Path, items[2].Path}
	if !reflect.DeepEqual(got, []string{"/c", "/b", "/a"}) {
		t.Fatalf("reversed paths = %#v", got)
	}
}

func TestNewQueryFilterRejectsInvalidStatus(t *testing.T) {
	if _, err := newQueryFilter("", "9xx", "", ""); err == nil {
		t.Fatal("newQueryFilter() returned nil error for invalid status class")
	}
}

func TestNewQueryFilterMatchesCredentialID(t *testing.T) {
	filter, err := newQueryFilter("", "", "", "cred-1")
	if err != nil {
		t.Fatalf("newQueryFilter() returned error: %v", err)
	}
	if !filter.matchCredential(Entry{AuthCredentialID: "CRED-1"}) {
		t.Fatal("credential filter did not match credential id case-insensitively")
	}
}

func TestNewQueryFilterMatchesUnrecordedCredentialContext(t *testing.T) {
	filter, err := newQueryFilter("", "", "", "missing")
	if err != nil {
		t.Fatalf("newQueryFilter() returned error: %v", err)
	}
	if !filter.matchCredential(Entry{AuthRequired: true, LoggedIn: true}) {
		t.Fatal("unrecorded credential filter did not match authenticated entry without credential")
	}
}

func TestParseFileDateRejectsNonLogExtension(t *testing.T) {
	if _, ok := parseFileDate("2024-01-02.txt"); ok {
		t.Fatal("parseFileDate() accepted non-log extension")
	}
}

func TestJSONLogLineLooksLikeEntryObjectRejectsArray(t *testing.T) {
	if jsonLogLineLooksLikeEntryObject([]byte(`[{"status":200}]`)) {
		t.Fatal("jsonLogLineLooksLikeEntryObject() accepted array")
	}
}

func TestRawJSONFieldValueFindsTopLevelField(t *testing.T) {
	line := []byte(`{"status":200,"nested":{"status":500},"path":"/ok"}`)
	value, ok := rawJSONFieldValue(line, []byte(`path`))
	if !ok || !strings.HasPrefix(string(value), `"/ok"`) {
		t.Fatalf("rawJSONFieldValue() = %q, %v", string(value), ok)
	}
}

func TestQuerySkipsMalformedJSONLines(t *testing.T) {
	dir := t.TempDir()
	date := time.Now().Format(dateLayout)
	writeAdditionalLogLines(t, filepath.Join(dir, date+fileExtension),
		`not-json`,
		mustJSONLogLine(t, Entry{Path: "/ok", Status: 200}),
	)
	result, err := NewManager(dir, models.LoggingConfig{}).Query(date, 1, 20, "", "200", "", "", "", "page")
	if err != nil {
		t.Fatalf("Query() returned error: %v", err)
	}
	if result.Total != 1 || result.Items[0].Path != "/ok" {
		t.Fatalf("Query() = %#v", result)
	}
}

func TestQueryCursorReturnsNextCursorWhenMoreItemsExist(t *testing.T) {
	dir := t.TempDir()
	date := time.Now().Format(dateLayout)
	writeAdditionalLogLines(t, filepath.Join(dir, date+fileExtension),
		mustJSONLogLine(t, Entry{Path: "/one", Status: 200}),
		mustJSONLogLine(t, Entry{Path: "/two", Status: 200}),
	)
	result, err := NewManager(dir, models.LoggingConfig{}).Query(date, 1, 1, "", "", "", "", "", "cursor")
	if err != nil {
		t.Fatalf("Query(cursor) returned error: %v", err)
	}
	if !result.HasMore || result.NextCursor == "" || len(result.Items) != 1 {
		t.Fatalf("cursor result = %#v", result)
	}
}

func TestContainsFoldASCIIBytesMatchesCaseInsensitively(t *testing.T) {
	if !containsFoldASCIIBytes([]byte("Hello Gateway"), "gateway") {
		t.Fatal("containsFoldASCIIBytes() did not match case-insensitively")
	}
}

func TestContainsFoldASCIIStringRejectsLongerSearch(t *testing.T) {
	if containsFoldASCIIString("short", "much longer") {
		t.Fatal("containsFoldASCIIString() matched longer search")
	}
}

func mustJSONLogLine(t *testing.T, entry Entry) string {
	t.Helper()
	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("marshal entry: %v", err)
	}
	return string(data)
}

func writeAdditionalLogLines(t *testing.T, path string, lines ...string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir logs: %v", err)
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatalf("write logs: %v", err)
	}
}

func BenchmarkManagerLogBatched(b *testing.B) {
	manager := NewManager(b.TempDir(), models.LoggingConfig{Enabled: true})
	b.Cleanup(manager.Close)
	entry := Entry{Method: "GET", Host: "bench.example.test", Path: "/api/items", Status: 200}
	b.ReportAllocs()
	count := 0
	for b.Loop() {
		manager.Log(entry)
		count++
		if count%4096 == 0 {
			manager.Flush()
		}
	}
	manager.Flush()
	if dropped := manager.DroppedLogEntries(); dropped != 0 {
		b.Fatalf("dropped entries = %d", dropped)
	}
}

func BenchmarkDailyFileWriterBuffered(b *testing.B) {
	writer := NewDailyFileWriter(b.TempDir(), DefaultMaxDays)
	b.Cleanup(func() { _ = writer.Close() })
	line := []byte(`{"time":"2026-01-01T00:00:00Z","method":"GET","host":"bench.example.test","path":"/api/items","status":200}` + "\n")
	b.SetBytes(int64(len(line)))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := writer.Write(line); err != nil {
			b.Fatal(err)
		}
	}
	if err := writer.Flush(); err != nil {
		b.Fatal(err)
	}
}
