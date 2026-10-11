package gatewaylog

import (
	"context"
	"encoding/json"
	"errors"
	"go-reauth-proxy/pkg/models"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func rangeTestFile(t *testing.T, m *Manager, name string, entries ...Entry) string {
	t.Helper()
	if err := os.MkdirAll(m.LogsDir(), 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(m.LogsDir(), name)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if err = json.NewEncoder(file).Encode(entry); err != nil {
			t.Fatal(err)
		}
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}
func TestRangeQueriesSortRealInstantsAcrossDaysAndPageStably(t *testing.T) {
	m := NewManager(t.TempDir(), models.LoggingConfig{})
	t.Cleanup(m.Close)
	rangeTestFile(t, m, "2026-09-20.log", Entry{Time: "2026-09-21T03:00:00Z", Path: "c"}, Entry{Time: "invalid", Path: "invalid"}, Entry{Time: "2026-09-21T10:00:00+08:00", Path: "a"})
	rangeTestFile(t, m, "2026-09-21.log", Entry{Time: "2026-09-21T02:00:00Z", Path: "b"}, Entry{Time: "2026-09-21T04:00:00Z", Path: "d"})
	for _, order := range []string{"asc", "desc"} {
		q := RangeQuery{From: "2026-09-19", To: "2026-09-21", Order: order, Limit: 1}
		var paths []string
		for page := 0; page < 10; page++ {
			result, err := m.QueryRangeContext(context.Background(), q)
			if err != nil {
				t.Fatal(err)
			}
			if result.From != q.From || result.To != q.To {
				t.Fatal(result)
			}
			for _, entry := range result.Items {
				paths = append(paths, entry.Path)
			}
			if !result.HasMore {
				break
			}
			if result.NextCursor == q.Cursor || result.NextCursor == "" {
				t.Fatal("stalled cursor")
			}
			q.Cursor = result.NextCursor
		}
		want := []string{"a", "b", "c", "d", "invalid"}
		if order == "desc" {
			want = []string{"d", "c", "b", "a", "invalid"}
		}
		if !reflect.DeepEqual(paths, want) {
			t.Fatalf("%s: got %v want %v", order, paths, want)
		}
	}
}
func TestRangeCursorPinsAppendBoundaryAndDetectsDeletionTruncation(t *testing.T) {
	for _, mutation := range []string{"append", "rotate", "delete", "truncate"} {
		t.Run(mutation, func(t *testing.T) {
			m := NewManager(t.TempDir(), models.LoggingConfig{})
			t.Cleanup(m.Close)
			name := "2026-09-21.log"
			path := rangeTestFile(t, m, name, Entry{Time: "2026-09-21T01:00:00Z", Path: "a"}, Entry{Time: "2026-09-21T02:00:00Z", Path: "b"})
			q := RangeQuery{From: "2026-09-21", To: "2026-09-21", Order: "asc", Limit: 1}
			first, err := m.QueryRangeContext(context.Background(), q)
			if err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "append":
				rangeTestFile(t, m, name, Entry{Time: "2026-09-21T01:30:00Z", Path: "new"})
			case "rotate":
				rangeTestFile(t, m, "2026-09-21.01760000000000000000.log", Entry{Time: "2026-09-21T01:30:00Z", Path: "new"})
			case "delete":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			case "truncate":
				if err := os.Truncate(path, 1); err != nil {
					t.Fatal(err)
				}
			}
			q.Cursor = first.NextCursor
			second, err := m.QueryRangeContext(context.Background(), q)
			if mutation == "delete" || mutation == "truncate" {
				if err == nil || !strings.Contains(err.Error(), "log cursor expired") {
					t.Fatal(err)
				}
				return
			}
			if err != nil || len(second.Items) != 1 || second.Items[0].Path != "b" || second.HasMore {
				t.Fatalf("%+v %v", second, err)
			}
			q.Cursor = first.Cursor
			again, err := m.QueryRangeContext(context.Background(), q)
			if err != nil || again.Items[0].Path != "a" {
				t.Fatalf("first page: %+v %v", again, err)
			}
			q.Cursor = ""
			q.Limit = 20
			refreshed, err := m.QueryRangeContext(context.Background(), q)
			if err != nil || len(refreshed.Items) != 3 {
				t.Fatalf("refresh: %+v %v", refreshed, err)
			}
		})
	}
}
func TestRangeQueryValidationBindingEmptyAndCancellation(t *testing.T) {
	m := NewManager(t.TempDir(), models.LoggingConfig{})
	t.Cleanup(m.Close)
	for _, q := range []RangeQuery{{From: "2026-01-01"}, {From: "2026-02-29", To: "2026-03-01"}, {From: "2026-01-01", To: "2026-01-31"}, {From: "2026-01-02", To: "2026-01-01"}, {Date: "2026-01-01", From: "2026-01-01", To: "2026-01-01"}, {Order: "bad"}, {Sort: "bad"}} {
		if _, err := m.QueryRangeContext(context.Background(), q); err == nil {
			t.Fatalf("accepted %+v", q)
		}
	}
	q := RangeQuery{From: "2026-01-01", To: "2026-01-30"}
	empty, err := m.QueryRangeContext(context.Background(), q)
	if err != nil || len(empty.Items) != 0 || empty.HasMore {
		t.Fatalf("%+v %v", empty, err)
	}
	q.Cursor = empty.Cursor
	q.ClientIP = "1.1.1.1"
	if _, err = m.QueryRangeContext(context.Background(), q); err == nil {
		t.Fatal("cursor accepted changed filter")
	}
	q.ClientIP = ""
	q.Order = "asc"
	if _, err = m.QueryRangeContext(context.Background(), q); err == nil {
		t.Fatal("cursor accepted changed order")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = m.QueryRangeContext(ctx, RangeQuery{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	for i := 0; i < maxConcurrentLogQueries; i++ {
		release, err := m.acquireQuery(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(release)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err = m.QueryRangeContext(ctx, RangeQuery{}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
}
func TestRangeQueryPreservesFiltersAndBoundsResultSize(t *testing.T) {
	m := NewManager(t.TempDir(), models.LoggingConfig{})
	t.Cleanup(m.Close)
	big := strings.Repeat("x", queryResultMaxBytes/3)
	for i := 0; i < 4; i++ {
		rangeTestFile(t, m, "2026-09-21.log", Entry{Path: "/large", Status: 404, RequestURI: big})
	}
	q := RangeQuery{Date: "2026-09-21", Sort: "time", Limit: 4}
	if _, err := m.QueryRangeContext(context.Background(), q); !errors.Is(err, ErrQueryResultTooLarge) {
		t.Fatal(err)
	}
	q.Status = "200"
	filtered, err := m.QueryRangeContext(context.Background(), q)
	if err != nil || len(filtered.Items) != 0 {
		t.Fatalf("%+v %v", filtered, err)
	}
	q.Status = "404"
	q.Limit = 1
	if result, err := m.QueryRangeContext(context.Background(), q); err != nil || len(result.Items) != 1 || !result.HasMore {
		t.Fatalf("%+v %v", result, err)
	}
}

func TestRangeFiltersApplyBeforeSortedPagination(t *testing.T) {
	m := NewManager(t.TempDir(), models.LoggingConfig{})
	t.Cleanup(m.Close)
	for i := 0; i < 300; i++ {
		rangeTestFile(t, m, "2026-09-21.log", Entry{ClientIP: "1.1.1.1", Path: "noise"})
	}
	rangeTestFile(t, m, "2026-09-21.log", Entry{ClientIP: "2001:db8::1", Path: "v6", Time: "2026-09-21T00:00:00Z", WAFAction: "block"}, Entry{RemoteIP: "192.168.1.1", EOConnectingIP: "8.8.8.8", Path: "provider", Time: "2026-09-21T01:00:00Z"}, Entry{Path: "unknown"}, Entry{ClientIP: "::1", Path: "loopback"})
	for _, tc := range []struct{ ip, waf, want string }{{"2001:0db8:0:0:0:0:0:1", "has_waf", "v6"}, {"8.8.8.8", "none", "provider"}, {"unknown", "", "unknown"}, {"1.1.1.1", "has_waf", ""}, {"127.0.0.1", "", "loopback"}, {"0:0:0:0:0:0:0:1", "", "loopback"}} {
		result, err := m.QueryRangeContext(context.Background(), RangeQuery{From: "2026-09-21", To: "2026-09-21", ClientIP: tc.ip, WAFStatus: tc.waf, Limit: 1})
		if err != nil {
			t.Fatal(err)
		}
		if tc.want == "" {
			if len(result.Items) != 0 {
				t.Fatal(result)
			}
		} else if len(result.Items) != 1 || result.Items[0].Path != tc.want || result.HasMore {
			t.Fatalf("%+v", result)
		}
	}
}

func TestRangeFiltersCanonicalizeMappedProxyAddresses(t *testing.T) {
	m := NewManager(t.TempDir(), models.LoggingConfig{})
	t.Cleanup(m.Close)
	for _, remote := range []string{"::FFFF:C0A8:102", "[::ffff:c0a8:102]:443", "::ffff:192.168.1.2"} {
		rangeTestFile(t, m, "2026-09-21.log", Entry{RemoteIP: remote, XForwardedFor: "8.8.8.8"})
	}
	rangeTestFile(t, m, "2026-09-21.log", Entry{EOConnectingIP: "::FFFF:C0A8:102, 8.8.8.8"})
	result, err := m.QueryRangeContext(context.Background(), RangeQuery{Date: "2026-09-21", ClientIP: "8.8.8.8"})
	if err != nil || len(result.Items) != 4 {
		t.Fatalf("mapped proxy identity: %+v %v", result, err)
	}
}
