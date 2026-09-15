package gatewaylog

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unsafe"

	"go-reauth-proxy/pkg/models"
)

func TestAnalyticsCacheEmptyStopsTimer(t *testing.T) {
	for _, action := range []string{"invalidate", "prune", "oversize", "expire"} {
		t.Run(action, func(t *testing.T) {
			m := &Manager{analyticsCache: make(map[string]cachedDailyAnalytics)}
			t.Cleanup(func() {
				m.analyticsMu.Lock()
				defer m.analyticsMu.Unlock()
				m.clearAnalyticsCacheLocked()
			})
			m.storeAnalyticsCacheLocked("day", cachedDailyAnalytics{lastUsed: time.Now()})
			generation := m.analyticsGeneration
			switch action {
			case "invalidate":
				m.invalidateAnalyticsDate("day")
			case "prune":
				m.pruneAnalyticsCache(nil)
			case "oversize":
				m.storeAnalyticsCacheLocked("day", cachedDailyAnalytics{fingerprint: strings.Repeat("x", analyticsCacheMaxBytes)})
			case "expire":
				m.expireAnalyticsCacheLocked(time.Now().Add(analyticsCacheIdleTTL))
			}
			if len(m.analyticsCache) != 0 || m.analyticsTimer != nil || m.analyticsGeneration == generation {
				t.Fatal("empty cache retained its timer or allowed a stale callback")
			}
		})
	}
}

func TestAnalyticsFailedScanDoesNotRefreshIdleTime(t *testing.T) {
	directory := t.TempDir()
	m := NewManager(directory, models.LoggingConfig{MaxDays: 30})
	defer m.Close()
	date := dayStart(time.Now()).Format(dateLayout)
	writeAnalyticsEntries(t, directory, date, []Entry{{Status: 200}})
	if _, err := m.analyticsForDate(context.Background(), date); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-4 * time.Minute)
	m.analyticsMu.Lock()
	entry := m.analyticsCache[date]
	entry.lastUsed = old
	m.analyticsCache[date] = entry
	m.analyticsMu.Unlock()
	// An oversized line makes the rescan fail after the cache lookup.
	if err := os.WriteFile(filepath.Join(directory, date+fileExtension), []byte(strings.Repeat("x", maxScanToken+int(entry.size)+1)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := m.analyticsForDate(context.Background(), date); err == nil {
		t.Fatal("expected scan failure")
	}
	m.analyticsMu.Lock()
	defer m.analyticsMu.Unlock()
	if !m.analyticsCache[date].lastUsed.Equal(old) {
		t.Fatal("failed query prolonged stale cache retention")
	}
}

func TestAnalyticsKeysOwnStorageOnInsertAndUpdate(t *testing.T) {
	c := newAnalyticsCounter()
	for i := 0; i < 2; i++ {
		source := "https://example.test/" + strings.Repeat(fmt.Sprint(i), 128<<10)
		pathSource := "/short?" + strings.Repeat(fmt.Sprint(i), 128<<10)
		c.addEntry(Entry{Referer: source, RequestURI: pathSource, Status: 200}, time.Unix(0, 0))
		for _, source := range []string{source, pathSource} {
			start := uintptr(unsafe.Pointer(unsafe.StringData(source)))
			for _, values := range []map[string]int64{c.referrers, c.paths} {
				for key := range values {
					pointer := uintptr(unsafe.Pointer(unsafe.StringData(key)))
					if pointer >= start && pointer < start+uintptr(len(source)) {
						t.Fatalf("key %q retained a URL after operation %d", key, i)
					}
				}
			}
			runtime.KeepAlive(source)
		}
	}
	if c.referrers["example.test"] != 2 || c.paths["/short"] != 2 {
		t.Fatal("statistics changed")
	}
}

func TestAnalyticsCacheBudgetUsesLRU(t *testing.T) {
	now := time.Now()
	m := &Manager{analyticsCache: map[string]cachedDailyAnalytics{
		"2026-01-01": {memoryBytes: 3 << 20, lastUsed: now},
		"2026-01-02": {memoryBytes: 3 << 20, lastUsed: now.Add(-time.Minute)},
		"2026-01-03": {memoryBytes: 3 << 20, lastUsed: now},
	}}
	m.enforceAnalyticsCacheLimitLocked("2026-01-03")
	if len(m.analyticsCache) != 2 || m.analyticsCache["2026-01-02"].memoryBytes != 0 {
		t.Fatal("did not evict least recently used day under byte pressure")
	}
}

func TestAnalyticsCacheOversizedResultNotRetained(t *testing.T) {
	m := &Manager{analyticsCache: make(map[string]cachedDailyAnalytics)}
	data := &dailyAnalytics{analyticsCounter: newAnalyticsCounter()}
	data.requests = 17
	entry := cachedDailyAnalytics{data: data, lastUsed: time.Now(), fingerprint: strings.Repeat("x", analyticsCacheMaxBytes)}
	m.storeAnalyticsCacheLocked("2026-01-01", entry)
	if len(m.analyticsCache) != 0 || m.analyticsTimer != nil || data.requests != 17 {
		t.Fatal("oversized result was retained or altered")
	}
}

func TestAnalyticsCacheExpiresWithoutQueries(t *testing.T) {
	m := &Manager{analyticsCache: map[string]cachedDailyAnalytics{
		"expired": {lastUsed: time.Now().Add(-analyticsCacheIdleTTL + 20*time.Millisecond)},
	}}
	m.analyticsMu.Lock()
	m.scheduleAnalyticsExpiryLocked()
	m.analyticsMu.Unlock()
	t.Cleanup(func() {
		m.analyticsMu.Lock()
		m.clearAnalyticsCacheLocked()
		m.analyticsMu.Unlock()
	})
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		m.analyticsMu.Lock()
		empty := len(m.analyticsCache) == 0 && m.analyticsTimer == nil
		m.analyticsMu.Unlock()
		if empty {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("idle timer retained cache without further queries")
}

func TestAnalyticsCacheHitRefreshAndClose(t *testing.T) {
	directory := t.TempDir()
	m := NewManager(directory, models.LoggingConfig{MaxDays: 30})
	defer m.Close()
	date := dayStart(time.Now()).Format(dateLayout)
	writeAnalyticsEntries(t, directory, date, []Entry{{Status: 200, Path: "/", UserAgent: "Mozilla/5.0"}})
	first, err := m.analyticsForDate(context.Background(), date)
	if err != nil {
		t.Fatal(err)
	}
	m.analyticsMu.Lock()
	entry := m.analyticsCache[date]
	old := time.Now().Add(-4 * time.Minute)
	entry.lastUsed = old
	m.analyticsCache[date] = entry
	m.analyticsMu.Unlock()
	second, err := m.analyticsForDate(context.Background(), date)
	if err != nil || second != first {
		t.Fatalf("cache hit changed: %v", err)
	}
	m.analyticsMu.Lock()
	refreshed := m.analyticsCache[date].lastUsed.After(old)
	m.analyticsMu.Unlock()
	if !refreshed {
		t.Fatal("cache hit did not refresh idle time")
	}
	m.Close()
	m.analyticsMu.Lock()
	defer m.analyticsMu.Unlock()
	if len(m.analyticsCache) != 0 || m.analyticsTimer != nil {
		t.Fatal("closed manager retained cache or timer")
	}
	if first.requests != 1 {
		t.Fatal("eviction altered an existing reader's snapshot")
	}
}
