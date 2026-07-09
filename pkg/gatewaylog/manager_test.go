package gatewaylog

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

var (
	gatewayLogBenchmarkEntriesSink []Entry
	gatewayLogBenchmarkStringSink  string
	gatewayLogBenchmarkBoolSink    bool
	gatewayLogBenchmarkIntSink     int
)

func writeLogEntries(t testing.TB, entries []Entry) string {
	t.Helper()

	dir := t.TempDir()
	logPath := filepath.Join(dir, "2026-06-18"+fileExtension)
	file, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("create log file: %v", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	for _, entry := range entries {
		if err := encoder.Encode(entry); err != nil {
			t.Fatalf("write log entry: %v", err)
		}
	}
	return logPath
}

func writeLogLines(t testing.TB, lines []string) string {
	t.Helper()

	dir := t.TempDir()
	logPath := filepath.Join(dir, "2026-06-18"+fileExtension)
	file, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("create log file: %v", err)
	}
	defer file.Close()

	for _, line := range lines {
		if _, err := file.WriteString(line + "\n"); err != nil {
			t.Fatalf("write log line: %v", err)
		}
	}
	return logPath
}

func makeLogEntries(count int) []Entry {
	entries := make([]Entry, count)
	for i := range entries {
		status := 200
		if i%2 == 1 {
			status = 500
		}
		entries[i] = Entry{
			Method:   "GET",
			Path:     "/item-" + strconv.Itoa(i),
			Status:   status,
			LoggedIn: i%3 == 0,
		}
	}
	return entries
}

func makeSparseStatusLogEntries(count int) []Entry {
	entries := makeLogEntries(count)
	for i := range entries {
		entries[i].Status = 200
		if i%20 == 0 {
			entries[i].Status = 500
		}
	}
	return entries
}

func TestQueryEntriesStreamingReturnsLatestPageInOnePassWindow(t *testing.T) {
	logPath := writeLogEntries(t, makeLogEntries(30))
	filter, err := newQueryFilter("", "", "", "")
	if err != nil {
		t.Fatalf("new query filter: %v", err)
	}

	firstPage, total, hasMore, err := queryEntries(logPath, filter, 1, 5)
	if err != nil {
		t.Fatalf("query first page: %v", err)
	}
	if total != 30 {
		t.Fatalf("first page total = %d, want 30", total)
	}
	if !hasMore {
		t.Fatalf("first page hasMore = false, want true")
	}
	for i, entry := range firstPage {
		want := "/item-" + strconv.Itoa(29-i)
		if entry.Path != want {
			t.Fatalf("first page item %d path = %q, want %q", i, entry.Path, want)
		}
	}

	secondPage, total, hasMore, err := queryEntries(logPath, filter, 2, 5)
	if err != nil {
		t.Fatalf("query second page: %v", err)
	}
	if total != 30 {
		t.Fatalf("second page total = %d, want 30", total)
	}
	if !hasMore {
		t.Fatalf("second page hasMore = false, want true")
	}
	for i, entry := range secondPage {
		want := "/item-" + strconv.Itoa(24-i)
		if entry.Path != want {
			t.Fatalf("second page item %d path = %q, want %q", i, entry.Path, want)
		}
	}
}

func TestQueryEntriesStreamingPreservesFilters(t *testing.T) {
	logPath := writeLogEntries(t, makeLogEntries(12))
	filter, err := newQueryFilter("ITEM-1", "5xx", "all", "")
	if err != nil {
		t.Fatalf("new query filter: %v", err)
	}

	items, total, hasMore, err := queryEntries(logPath, filter, 1, 10)
	if err != nil {
		t.Fatalf("query filtered entries: %v", err)
	}
	if total != 2 {
		t.Fatalf("total = %d, want 2", total)
	}
	if hasMore {
		t.Fatalf("hasMore = true, want false")
	}
	wantPaths := []string{"/item-11", "/item-1"}
	for i, want := range wantPaths {
		if items[i].Path != want {
			t.Fatalf("item %d path = %q, want %q", i, items[i].Path, want)
		}
	}
}

func TestQueryEntriesStreamingPreservesLoggedInFilter(t *testing.T) {
	logPath := writeLogEntries(t, makeLogEntries(9))
	filter, err := newQueryFilter("", "", "true", "")
	if err != nil {
		t.Fatalf("new query filter: %v", err)
	}

	items, total, hasMore, err := queryEntries(logPath, filter, 1, 10)
	if err != nil {
		t.Fatalf("query logged-in entries: %v", err)
	}
	if total != 3 {
		t.Fatalf("total = %d, want 3", total)
	}
	if hasMore {
		t.Fatalf("hasMore = true, want false")
	}
	wantPaths := []string{"/item-6", "/item-3", "/item-0"}
	for i, want := range wantPaths {
		if items[i].Path != want {
			t.Fatalf("item %d path = %q, want %q", i, items[i].Path, want)
		}
	}
}

func TestQueryEntriesStreamingFiltersByCredential(t *testing.T) {
	logPath := writeLogEntries(t, []Entry{
		{
			Method:               "GET",
			Path:                 "/direct-totp",
			Status:               200,
			LoggedIn:             true,
			AuthCredentialID:     "totp-alpha",
			AuthCredentialMethod: "TOTP",
		},
		{
			Method:               "GET",
			Path:                 "/other-totp",
			Status:               200,
			LoggedIn:             true,
			AuthCredentialID:     "totp-beta",
			AuthCredentialMethod: "TOTP",
		},
		{
			Method:               "GET",
			Path:                 "/bound-passkey",
			Status:               200,
			LoggedIn:             true,
			AuthCredentialID:     "passkey-alpha",
			AuthCredentialMethod: "PASSKEY",
			AuthLinkedTOTPID:     "totp-alpha",
		},
		{
			Method:   "GET",
			Path:     "/anonymous",
			Status:   200,
			LoggedIn: false,
		},
		{
			Method:       "GET",
			Path:         "/legacy-logged-in",
			Status:       200,
			LoggedIn:     true,
			AuthDecision: "passed",
		},
	})
	filter, err := newQueryFilter("", "", "all", "totp-alpha")
	if err != nil {
		t.Fatalf("new query filter: %v", err)
	}

	items, total, hasMore, err := queryEntries(logPath, filter, 1, 10)
	if err != nil {
		t.Fatalf("query credential entries: %v", err)
	}
	if total != 2 {
		t.Fatalf("total = %d, want 2", total)
	}
	if hasMore {
		t.Fatalf("hasMore = true, want false")
	}
	wantPaths := []string{"/bound-passkey", "/direct-totp"}
	for i, want := range wantPaths {
		if items[i].Path != want {
			t.Fatalf("item %d path = %q, want %q", i, items[i].Path, want)
		}
	}
}

func TestQueryEntriesStreamingFiltersUnrecordedCredential(t *testing.T) {
	logPath := writeLogEntries(t, []Entry{
		{
			Method:               "GET",
			Path:                 "/recorded",
			Status:               200,
			LoggedIn:             true,
			AuthCredentialID:     "totp-alpha",
			AuthCredentialMethod: "TOTP",
		},
		{
			Method:       "GET",
			Path:         "/legacy-logged-in",
			Status:       200,
			LoggedIn:     true,
			AuthDecision: "passed",
		},
		{
			Method:       "GET",
			Path:         "/legacy-denied",
			Status:       403,
			AuthDecision: "access_denied",
		},
		{
			Method:   "GET",
			Path:     "/anonymous",
			Status:   200,
			LoggedIn: false,
		},
	})
	filter, err := newQueryFilter("", "", "all", unrecordedCredentialFilter)
	if err != nil {
		t.Fatalf("new query filter: %v", err)
	}

	items, total, hasMore, err := queryEntries(logPath, filter, 1, 10)
	if err != nil {
		t.Fatalf("query unrecorded credential entries: %v", err)
	}
	if total != 2 {
		t.Fatalf("total = %d, want 2", total)
	}
	if hasMore {
		t.Fatalf("hasMore = true, want false")
	}
	wantPaths := []string{"/legacy-denied", "/legacy-logged-in"}
	for i, want := range wantPaths {
		if items[i].Path != want {
			t.Fatalf("item %d path = %q, want %q", i, items[i].Path, want)
		}
	}
}

func TestQueryEntriesStreamingRawTailFiltersTopLevelFieldsOnly(t *testing.T) {
	logPath := writeLogLines(t, []string{
		`{"method":"GET","path":"/nested-status","extra":{"status":500},"status":200,"logged_in":false}`,
		`{"method":"GET","path":"/nested-login","extra":{"logged_in":true},"status":200,"logged_in":false}`,
		`{"method":"GET","path":"/real-match","status":500,"logged_in":true}`,
	})
	filter, err := newQueryFilter("", "5xx", "true", "")
	if err != nil {
		t.Fatalf("new query filter: %v", err)
	}

	items, total, hasMore, err := queryEntries(logPath, filter, 1, 10)
	if err != nil {
		t.Fatalf("query entries: %v", err)
	}
	if total != 1 {
		t.Fatalf("total = %d, want 1", total)
	}
	if hasMore {
		t.Fatalf("hasMore = true, want false")
	}
	if len(items) != 1 || items[0].Path != "/real-match" {
		t.Fatalf("items = %#v, want only /real-match", items)
	}
}

func TestQueryEntriesStreamingRawTailSkipsMalformedJSON(t *testing.T) {
	logPath := writeLogLines(t, []string{
		`{"method":"GET","path":"/first","status":200}`,
		`not-json`,
		`[]`,
		`{"method":"GET","path":"/second","status":200}`,
	})
	filter, err := newQueryFilter("", "", "", "")
	if err != nil {
		t.Fatalf("new query filter: %v", err)
	}

	items, total, hasMore, err := queryEntries(logPath, filter, 1, 10)
	if err != nil {
		t.Fatalf("query entries: %v", err)
	}
	if total != 2 {
		t.Fatalf("total = %d, want 2", total)
	}
	if hasMore {
		t.Fatalf("hasMore = true, want false")
	}
	wantPaths := []string{"/second", "/first"}
	for i, want := range wantPaths {
		if items[i].Path != want {
			t.Fatalf("item %d path = %q, want %q", i, items[i].Path, want)
		}
	}
}

func TestQueryEntriesByCursorPreservesFilters(t *testing.T) {
	logPath := writeLogEntries(t, makeLogEntries(12))
	filter, err := newQueryFilter("", "5xx", "true", "")
	if err != nil {
		t.Fatalf("new query filter: %v", err)
	}

	items, nextCursor, hasMore, _, err := queryEntriesByCursor(logPath, filter, "", 1)
	if err != nil {
		t.Fatalf("query entries by cursor: %v", err)
	}
	if !hasMore {
		t.Fatal("hasMore = false, want true")
	}
	if nextCursor == "" {
		t.Fatal("next cursor is empty")
	}
	if len(items) != 1 {
		t.Fatalf("len(items) = %d, want 1", len(items))
	}
	if got := items[0].Path; got != "/item-9" {
		t.Fatalf("item path = %q, want /item-9", got)
	}
}

func TestScanLinesBackwardHandlesLinesAcrossChunks(t *testing.T) {
	longLine := strings.Repeat("a", cursorChunkSize+17)
	lines := []string{"first", longLine, "third"}

	dir := t.TempDir()
	logPath := filepath.Join(dir, "cursor.log")
	file, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("create log file: %v", err)
	}
	var starts []int64
	var offset int64
	for i, line := range lines {
		starts = append(starts, offset)
		rawLine := line
		if i == len(lines)-1 {
			rawLine += "\r"
		}
		n, err := file.WriteString(rawLine + "\n")
		if err != nil {
			t.Fatalf("write log line: %v", err)
		}
		offset += int64(n)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close log file: %v", err)
	}

	file, err = os.Open(logPath)
	if err != nil {
		t.Fatalf("open log file: %v", err)
	}
	defer file.Close()

	var gotLines []string
	var gotStarts []int64
	err = scanLinesBackward(file, offset, func(line []byte, lineStart int64) (bool, error) {
		gotLines = append(gotLines, string(line))
		gotStarts = append(gotStarts, lineStart)
		return true, nil
	})
	if err != nil {
		t.Fatalf("scan lines backward: %v", err)
	}

	wantLines := []string{"third", longLine, "first"}
	wantStarts := []int64{starts[2], starts[1], starts[0]}
	if len(gotLines) != len(wantLines) {
		t.Fatalf("len(gotLines) = %d, want %d", len(gotLines), len(wantLines))
	}
	for i := range wantLines {
		if gotLines[i] != wantLines[i] || gotStarts[i] != wantStarts[i] {
			t.Fatalf("line %d = (%q, %d), want (%q, %d)", i, gotLines[i], gotStarts[i], wantLines[i], wantStarts[i])
		}
	}
}

func BenchmarkQueryEntriesFirstPage(b *testing.B) {
	logPath := writeLogEntries(b, makeLogEntries(2000))
	filter, err := newQueryFilter("", "", "", "")
	if err != nil {
		b.Fatalf("new query filter: %v", err)
	}

	b.ReportAllocs()
	for b.Loop() {
		items, total, hasMore, err := queryEntries(logPath, filter, 1, 50)
		if err != nil {
			b.Fatalf("query entries: %v", err)
		}
		if len(items) != 50 || total != 2000 || !hasMore {
			b.Fatalf("unexpected result: len=%d total=%d hasMore=%v", len(items), total, hasMore)
		}
	}
}

func BenchmarkQueryEntriesFirstPageSearch(b *testing.B) {
	logPath := writeLogEntries(b, makeLogEntries(2000))
	filter, err := newQueryFilter("ITEM-1", "", "", "")
	if err != nil {
		b.Fatalf("new query filter: %v", err)
	}

	b.ReportAllocs()
	for b.Loop() {
		items, total, hasMore, err := queryEntries(logPath, filter, 1, 50)
		if err != nil {
			b.Fatalf("query entries: %v", err)
		}
		if len(items) != 50 || total != 1111 || !hasMore {
			b.Fatalf("unexpected result: len=%d total=%d hasMore=%v", len(items), total, hasMore)
		}
	}
}

func BenchmarkQueryEntriesFirstPageStatusFilter(b *testing.B) {
	logPath := writeLogEntries(b, makeLogEntries(2000))
	filter, err := newQueryFilter("", "5xx", "", "")
	if err != nil {
		b.Fatalf("new query filter: %v", err)
	}

	b.ReportAllocs()
	for b.Loop() {
		items, total, hasMore, err := queryEntries(logPath, filter, 1, 50)
		if err != nil {
			b.Fatalf("query entries: %v", err)
		}
		if len(items) != 50 || total != 1000 || !hasMore {
			b.Fatalf("unexpected result: len=%d total=%d hasMore=%v", len(items), total, hasMore)
		}
	}
}

func BenchmarkQueryEntriesFirstPageLoggedInFilter(b *testing.B) {
	logPath := writeLogEntries(b, makeLogEntries(2000))
	filter, err := newQueryFilter("", "", "true", "")
	if err != nil {
		b.Fatalf("new query filter: %v", err)
	}

	b.ReportAllocs()
	for b.Loop() {
		items, total, hasMore, err := queryEntries(logPath, filter, 1, 50)
		if err != nil {
			b.Fatalf("query entries: %v", err)
		}
		if len(items) != 50 || total != 667 || !hasMore {
			b.Fatalf("unexpected result: len=%d total=%d hasMore=%v", len(items), total, hasMore)
		}
	}
}

func BenchmarkQueryEntriesFirstPageTwoPass(b *testing.B) {
	logPath := writeLogEntries(b, makeLogEntries(2000))
	filter, err := newQueryFilter("", "", "", "")
	if err != nil {
		b.Fatalf("new query filter: %v", err)
	}

	b.ReportAllocs()
	for b.Loop() {
		items, total, hasMore, err := queryEntriesStreamingTwoPass(logPath, filter, 1, 50)
		if err != nil {
			b.Fatalf("query entries: %v", err)
		}
		if len(items) != 50 || total != 2000 || !hasMore {
			b.Fatalf("unexpected result: len=%d total=%d hasMore=%v", len(items), total, hasMore)
		}
	}
}

func BenchmarkQueryEntriesByCursorSparseStatusFilter(b *testing.B) {
	logPath := writeLogEntries(b, makeSparseStatusLogEntries(4000))
	filter, err := newQueryFilter("", "500", "", "")
	if err != nil {
		b.Fatalf("new query filter: %v", err)
	}

	b.ReportAllocs()
	for b.Loop() {
		items, nextCursor, hasMore, _, err := queryEntriesByCursor(logPath, filter, "", 50)
		if err != nil {
			b.Fatalf("query entries by cursor: %v", err)
		}
		if len(items) != 50 || !hasMore || nextCursor == "" {
			b.Fatalf("unexpected result: len=%d hasMore=%v next=%q", len(items), hasMore, nextCursor)
		}
		gatewayLogBenchmarkEntriesSink = items
		gatewayLogBenchmarkStringSink = nextCursor
		gatewayLogBenchmarkBoolSink = hasMore
	}
}

func BenchmarkQueryEntriesByCursorSparseStatusFilterOld(b *testing.B) {
	logPath := writeLogEntries(b, makeSparseStatusLogEntries(4000))
	filter, err := newQueryFilter("", "500", "", "")
	if err != nil {
		b.Fatalf("new query filter: %v", err)
	}

	b.ReportAllocs()
	for b.Loop() {
		items, nextCursor, hasMore, _, err := queryEntriesByCursorLegacyForBenchmark(logPath, filter, "", 50)
		if err != nil {
			b.Fatalf("query entries by cursor: %v", err)
		}
		if len(items) != 50 || !hasMore || nextCursor == "" {
			b.Fatalf("unexpected result: len=%d hasMore=%v next=%q", len(items), hasMore, nextCursor)
		}
		gatewayLogBenchmarkEntriesSink = items
		gatewayLogBenchmarkStringSink = nextCursor
		gatewayLogBenchmarkBoolSink = hasMore
	}
}

func BenchmarkScanLinesBackward(b *testing.B) {
	logPath := writeLogEntries(b, makeLogEntries(4000))
	file, err := os.Open(logPath)
	if err != nil {
		b.Fatalf("open log file: %v", err)
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil {
		b.Fatalf("stat log file: %v", err)
	}

	b.ReportAllocs()
	for b.Loop() {
		count := 0
		if err := scanLinesBackward(file, stat.Size(), func(_ []byte, _ int64) (bool, error) {
			count++
			return true, nil
		}); err != nil {
			b.Fatalf("scan lines backward: %v", err)
		}
		if count != 4000 {
			b.Fatalf("line count = %d, want 4000", count)
		}
		gatewayLogBenchmarkIntSink = count
	}
}

func BenchmarkScanLinesBackwardOld(b *testing.B) {
	logPath := writeLogEntries(b, makeLogEntries(4000))
	file, err := os.Open(logPath)
	if err != nil {
		b.Fatalf("open log file: %v", err)
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil {
		b.Fatalf("stat log file: %v", err)
	}

	b.ReportAllocs()
	for b.Loop() {
		count := 0
		if err := scanLinesBackwardLegacyForBenchmark(file, stat.Size(), func(_ []byte, _ int64) (bool, error) {
			count++
			return true, nil
		}); err != nil {
			b.Fatalf("scan lines backward: %v", err)
		}
		if count != 4000 {
			b.Fatalf("line count = %d, want 4000", count)
		}
		gatewayLogBenchmarkIntSink = count
	}
}

func queryEntriesByCursorLegacyForBenchmark(logPath string, filter queryFilter, cursor string, limit int) ([]Entry, string, bool, string, error) {
	file, err := os.Open(logPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []Entry{}, "", false, "", nil
		}
		return nil, "", false, "", err
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return nil, "", false, "", err
	}

	endOffset, resolvedCursor, err := resolveCursorOffset(stat.Size(), cursor)
	if err != nil {
		return nil, "", false, "", err
	}
	if endOffset == 0 {
		return []Entry{}, "", false, resolvedCursor, nil
	}

	items := make([]Entry, 0, limit)
	oldestReturnedStart := int64(0)
	hasMore := false

	err = scanLinesBackward(file, endOffset, func(line []byte, lineStart int64) (bool, error) {
		if !filter.matchLineBytes(line) {
			return true, nil
		}

		var entry Entry
		if err := json.Unmarshal(line, &entry); err != nil {
			return true, nil
		}
		if !filter.matchStatus(entry.Status) || !filter.matchLoggedIn(entry.LoggedIn) {
			return true, nil
		}

		if len(items) == limit {
			hasMore = true
			return false, nil
		}

		items = append(items, entry)
		oldestReturnedStart = lineStart
		return true, nil
	})
	if err != nil {
		return nil, "", false, "", err
	}

	nextCursor := ""
	if hasMore && oldestReturnedStart > 0 {
		nextCursor = strconv.FormatInt(oldestReturnedStart, 10)
	}

	return items, nextCursor, hasMore, resolvedCursor, nil
}

func scanLinesBackwardLegacyForBenchmark(file *os.File, endOffset int64, onLine func(line []byte, lineStart int64) (bool, error)) error {
	position := endOffset
	var remainder []byte
	firstPass := true

	for position > 0 {
		readSize := int64(cursorChunkSize)
		if readSize > position {
			readSize = position
		}

		start := position - readSize
		buffer := make([]byte, readSize)
		n, err := file.ReadAt(buffer, start)
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		buffer = buffer[:n]

		combined := append(append([]byte{}, buffer...), remainder...)
		scanEnd := len(combined)
		if firstPass {
			scanEnd = len(bytes.TrimRight(combined[:scanEnd], "\r\n"))
			firstPass = false
		}

		for scanEnd > 0 {
			index := bytes.LastIndexByte(combined[:scanEnd], '\n')
			if index == -1 {
				break
			}

			line := bytes.TrimRight(combined[index+1:scanEnd], "\r")
			lineStart := start + int64(index+1)
			scanEnd = index

			if len(line) == 0 {
				continue
			}

			keepScanning, err := onLine(line, lineStart)
			if err != nil {
				return err
			}
			if !keepScanning {
				return nil
			}
		}

		remainder = append(remainder[:0], combined[:scanEnd]...)
		position = start
	}

	line := bytes.TrimRight(remainder, "\r\n")
	if len(line) == 0 {
		return nil
	}

	_, err := onLine(line, 0)
	return err
}
