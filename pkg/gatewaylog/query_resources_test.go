package gatewaylog

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go-reauth-proxy/pkg/models"
)

func TestQueryAdmissionCanBeCanceled(t *testing.T) {
	m := NewManager(t.TempDir(), models.LoggingConfig{})
	t.Cleanup(m.Close)
	for i := 0; i < maxConcurrentLogQueries; i++ {
		release, err := m.acquireQuery(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(release)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := m.QueryContext(ctx, "", 1, 20, "", "", "", "", "", "page")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("blocked query error = %v", err)
	}
	_, err = m.FindByTraceIDContext(ctx, "trace")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("canceled trace lookup error = %v", err)
	}
}

func TestQueryScansStopOnCancellation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.log")
	if err := os.WriteFile(path, []byte(strings.Repeat("{\"status\":200}\n", 1000)), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	filter, _ := newQueryFilter("", "", "", "")
	filter.ctx = ctx
	matches := 0
	_, err := scanMatchingEntries(path, filter, func(Entry, int, int) error {
		matches++
		cancel()
		return nil
	})
	if !errors.Is(err, context.Canceled) || matches != 1 {
		t.Fatalf("forward matches=%d error=%v", matches, err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	info, _ := file.Stat()
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	matches = 0
	err = scanLinesBackwardContext(ctx, file, info.Size(), func([]byte, int64) (bool, error) {
		matches++
		cancel()
		return true, nil
	})
	if !errors.Is(err, context.Canceled) || matches != 1 {
		t.Fatalf("reverse matches=%d error=%v", matches, err)
	}
}

func TestLargeLogTailFallsBackWithoutChangingPage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.log")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	encoder := json.NewEncoder(file)
	large := strings.Repeat("x", pageQueryTailWindowMaxBytes/2)
	for _, name := range []string{"oldest", "middle", "newest"} {
		if err := encoder.Encode(Entry{Path: name, RequestURI: large, Status: 200}); err != nil {
			t.Fatal(err)
		}
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	filter, _ := newQueryFilter("", "", "", "")
	tail := newRawLineTailWindow(2)
	total, err := scanMatchingRawLinesToTail(path, filter, tail)
	if err != nil || total != 3 || !tail.overflowed || tail.allocated != 0 {
		t.Fatalf("tail total=%d overflow=%v retained=%d error=%v", total, tail.overflowed, tail.allocated, err)
	}
	entries, total, more, err := queryEntries(path, filter, 2, 1)
	if err != nil || total != 3 || !more || len(entries) != 1 || entries[0].Path != "middle" {
		t.Fatalf("page total=%d count=%d more=%v error=%v", total, len(entries), more, err)
	}
}

func TestReverseScanRejectsOversizeLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.log")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", maxScanToken+1)), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	err = scanLinesBackward(file, maxScanToken+1, func([]byte, int64) (bool, error) {
		t.Fatal("oversized line reached decoder")
		return false, nil
	})
	if err == nil {
		t.Fatal("oversized reverse scan was not bounded")
	}
}

func TestLargeLogTailFallbackCountsOnlyDecodableEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.log")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("{\"status\":\"invalid\"}\n"); err != nil {
		t.Fatal(err)
	}
	encoder := json.NewEncoder(file)
	large := strings.Repeat("x", pageQueryTailWindowMaxBytes/2)
	for _, name := range []string{"older", "newer"} {
		if err := encoder.Encode(Entry{Path: name, RequestURI: large, Status: 200}); err != nil {
			t.Fatal(err)
		}
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	entries, total, more, err := queryEntries(path, queryFilter{}, 1, 2)
	if err != nil || total != 2 || more || len(entries) != 2 {
		t.Fatalf("fallback count=%d total=%d more=%v error=%v", len(entries), total, more, err)
	}
	if entries[0].Path != "newer" || entries[1].Path != "older" {
		t.Fatal("fallback did not preserve newest-first order")
	}
}

func TestQueryRejectsOversizedResultInPageAndCursorModes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.log")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	encoder := json.NewEncoder(file)
	large := strings.Repeat("x", queryResultMaxBytes/4)
	for i := 0; i < 4; i++ {
		if err := encoder.Encode(Entry{RequestURI: large, Status: 200}); err != nil {
			t.Fatal(err)
		}
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	filter, _ := newQueryFilter("", "", "", "")
	_, _, _, err = queryEntries(path, filter, 1, 4)
	if !errors.Is(err, ErrQueryResultTooLarge) {
		t.Fatalf("oversized page error = %v", err)
	}
	_, _, _, _, err = queryEntriesByCursor(path, filter, "", 4)
	if !errors.Is(err, ErrQueryResultTooLarge) {
		t.Fatalf("oversized cursor page error = %v", err)
	}
	items, _, _, err := queryEntries(path, filter, 1, 1)
	if err != nil || len(items) != 1 {
		t.Fatalf("reduced limit should work: count=%d error=%v", len(items), err)
	}
}

func TestExtremePageDoesNotOverflow(t *testing.T) {
	maxInt := int(^uint(0) >> 1)
	for _, test := range [][3]int{{10, maxInt, 200}, {maxInt, maxInt, 200}, {maxInt, 2, maxInt - 1}} {
		start, end := resolveForwardWindow(test[0], test[1], test[2])
		if start < 0 || end < start || end > test[0] {
			t.Fatalf("window(%v) = [%d, %d]", test, start, end)
		}
	}
	path := filepath.Join(t.TempDir(), "events.log")
	if err := os.WriteFile(path, []byte("{\"status\":200}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	items, total, more, err := queryEntries(path, queryFilter{}, maxInt, 200)
	if err != nil || total != 1 || len(items) != 0 || more {
		t.Fatalf("extreme page: count=%d total=%d more=%v error=%v", len(items), total, more, err)
	}
}
