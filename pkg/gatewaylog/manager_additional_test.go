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
	info := manager.GetConfigInfo()
	if !info.Enabled || info.MaxDays != 3 || info.LogsDir != dir {
		t.Fatalf("ConfigInfo = %#v", info)
	}
}

func TestUpdateConfigNormalizesAndPersistsInMemory(t *testing.T) {
	manager := NewManager(t.TempDir(), models.LoggingConfig{})
	info := manager.UpdateConfig(models.LoggingConfig{Enabled: true, MaxDays: 0})
	if !info.Enabled || info.MaxDays != DefaultMaxDays {
		t.Fatalf("UpdateConfig() = %#v", info)
	}
}

func TestDailyFileWriterWriteCreatesTodayFile(t *testing.T) {
	dir := t.TempDir()
	writer := NewDailyFileWriter(dir, 7)
	if _, err := writer.Write([]byte("hello\n")); err != nil {
		t.Fatalf("Write() returned error: %v", err)
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
	manager.Log(Entry{Method: "GET", Path: "/off", Status: 200})
	entries, err := os.ReadDir(dir)
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("ReadDir() returned error: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("disabled logger wrote files: %#v", entries)
	}
}

func TestManagerLogWritesQueryEntryWhenEnabled(t *testing.T) {
	dir := t.TempDir()
	manager := NewManager(dir, models.LoggingConfig{Enabled: true})
	manager.Log(Entry{Method: "POST", Host: "app.example.test", Path: "/api", Status: 201, LoggedIn: true})
	result, err := manager.Query("", 1, 20, "app.example.test", "201", "true", "", "", "page")
	if err != nil {
		t.Fatalf("Query() returned error: %v", err)
	}
	if result.Total != 1 || len(result.Items) != 1 || result.Items[0].Method != "POST" {
		t.Fatalf("Query() = %#v", result)
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
