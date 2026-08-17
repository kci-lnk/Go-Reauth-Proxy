package gatewaylog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go-reauth-proxy/pkg/models"
)

func writeAnalyticsEntries(t *testing.T, directory string, date string, entries []Entry) {
	t.Helper()
	path := filepath.Join(directory, date+fileExtension)
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	for _, entry := range entries {
		line, err := json.Marshal(entry)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write(append(line, '\n')); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAnalyzeAggregatesRangeAndDimensions(t *testing.T) {
	directory := t.TempDir()
	manager := NewManager(directory, models.LoggingConfig{MaxDays: 30})
	defer manager.Close()
	today := dayStart(time.Now())
	yesterday := today.AddDate(0, 0, -1)
	chrome := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

	writeAnalyticsEntries(t, directory, yesterday.Format(dateLayout), []Entry{{
		Time:          yesterday.Add(10 * time.Hour).Format(time.RFC3339),
		Method:        "GET",
		Host:          "Example.COM:443",
		Path:          "/docs",
		Query:         "utm_source=newsletter&utm_medium=email",
		Status:        200,
		DurationMs:    40,
		BytesIn:       10,
		BytesOut:      100,
		RemoteIP:      "10.0.0.2",
		XForwardedFor: "198.51.100.10, 10.0.0.3",
		UserAgent:     chrome,
		Referer:       "https://search.example/path",
		RouteType:     "host_rule",
		RouteKey:      "example.com",
		AuthDecision:  "passed",
	}})
	writeAnalyticsEntries(t, directory, today.Format(dateLayout), []Entry{{
		Time:           today.Add(2 * time.Hour).Format(time.RFC3339),
		Method:         "POST",
		Host:           "example.com",
		Path:           "/api",
		Status:         503,
		DurationMs:     1200,
		BytesIn:        20,
		BytesOut:       200,
		RemoteIP:       "203.0.113.20",
		UserAgent:      chrome,
		AuthRequired:   true,
		AuthDecision:   "denied",
		WAFBlocked:     true,
		EOConnectingIP: "203.0.113.21",
	}})

	result, err := manager.Analyze(yesterday.Format(dateLayout), today.Format(dateLayout))
	if err != nil {
		t.Fatal(err)
	}
	if result.Summary.Requests != 2 || result.Summary.ServerErrors != 1 {
		t.Fatalf("unexpected summary: %+v", result.Summary)
	}
	if result.Summary.ServerErrorRate != 0.5 {
		t.Fatalf("unexpected server error rate: %f", result.Summary.ServerErrorRate)
	}
	if result.Summary.UniqueClients != 2 || result.Summary.BytesOut != 300 {
		t.Fatalf("unexpected clients/traffic: %+v", result.Summary)
	}
	if result.Granularity != "hour" || len(result.Series) == 0 {
		t.Fatalf("unexpected series: granularity=%s points=%d", result.Granularity, len(result.Series))
	}
	if result.Hosts[0].Key != "example.com" || result.Hosts[0].Count != 2 {
		t.Fatalf("unexpected hosts: %+v", result.Hosts)
	}
	if result.UTMSources[0].Key != "newsletter" {
		t.Fatalf("unexpected UTM sources: %+v", result.UTMSources)
	}
	if result.Referrers[0].Key != "direct" && result.Referrers[0].Key != "search.example" {
		t.Fatalf("unexpected referrers: %+v", result.Referrers)
	}
	if result.Devices[0].Key != "Desktop" || result.Browsers[0].Key != "Chrome" {
		t.Fatalf("unexpected client dimensions: devices=%+v browsers=%+v", result.Devices, result.Browsers)
	}
}

func TestAnalyzeCacheInvalidatesWhenFileGrows(t *testing.T) {
	directory := t.TempDir()
	manager := NewManager(directory, models.LoggingConfig{MaxDays: 7})
	defer manager.Close()
	date := time.Now().Format(dateLayout)
	path := filepath.Join(directory, date+fileExtension)
	writeAnalyticsEntries(t, directory, date, []Entry{{Status: 200, RemoteIP: "198.51.100.1"}})

	first, err := manager.Analyze(date, date)
	if err != nil || first.Summary.Requests != 1 {
		t.Fatalf("first analysis: result=%+v err=%v", first.Summary, err)
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	line, _ := json.Marshal(Entry{Status: 404, RemoteIP: "198.51.100.2"})
	if _, err := file.Write(append(line, '\n')); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	second, err := manager.Analyze(date, date)
	if err != nil || second.Summary.Requests != 2 || second.Summary.ClientErrors != 1 {
		t.Fatalf("second analysis: result=%+v err=%v", second.Summary, err)
	}
}

func TestAnalyzeSkipsMalformedLinesAndClassifiesBots(t *testing.T) {
	directory := t.TempDir()
	manager := NewManager(directory, models.LoggingConfig{MaxDays: 7})
	defer manager.Close()
	date := time.Now().Format(dateLayout)
	path := filepath.Join(directory, date+fileExtension)
	writeAnalyticsEntries(t, directory, date, []Entry{{
		Path:       "/crawl?ignored=1",
		Query:      "?utm_campaign=index",
		RequestURI: "/crawl?utm_campaign=fallback",
		Host:       "EXAMPLE.COM:443",
		Status:     404,
		DurationMs: 75,
		RemoteIP:   "203.0.113.8",
		UserAgent:  "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
	}})
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("{not-json}\n"); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	result, err := manager.Analyze(date, date)
	if err != nil {
		t.Fatal(err)
	}
	if result.Summary.Requests != 1 || result.InvalidEntries != 1 {
		t.Fatalf("unexpected quality result: summary=%+v invalid=%d", result.Summary, result.InvalidEntries)
	}
	if result.Paths[0].Key != "/crawl" || result.Hosts[0].Key != "example.com" {
		t.Fatalf("unexpected normalized targets: paths=%+v hosts=%+v", result.Paths, result.Hosts)
	}
	if result.UTMCampaigns[0].Key != "index" || result.Devices[0].Key != "Bot" {
		t.Fatalf("unexpected campaign/client classification: campaigns=%+v devices=%+v", result.UTMCampaigns, result.Devices)
	}
}

func TestAnalyzeKeepsPartialEntriesInExplicitUnknownBuckets(t *testing.T) {
	directory := t.TempDir()
	manager := NewManager(directory, models.LoggingConfig{MaxDays: 7})
	defer manager.Close()
	date := time.Now().Format(dateLayout)
	writeAnalyticsEntries(t, directory, date, []Entry{{Path: "/partial"}})

	result, err := manager.Analyze(date, date)
	if err != nil {
		t.Fatal(err)
	}
	if result.Summary.Requests != 1 || result.Statuses[0].Key != "unknown" {
		t.Fatalf("unexpected partial-entry analytics: summary=%+v statuses=%+v", result.Summary, result.Statuses)
	}
}

func TestAnalyzeLimitsDateRangeAndGeoCandidates(t *testing.T) {
	directory := t.TempDir()
	manager := NewManager(directory, models.LoggingConfig{MaxDays: 60})
	defer manager.Close()
	today := dayStart(time.Now())
	if _, err := manager.Analyze(today.AddDate(0, 0, -30).Format(dateLayout), today.Format(dateLayout)); err == nil {
		t.Fatal("expected a 31-day range to be rejected")
	}

	entries := make([]Entry, 0, 105)
	for index := 0; index < 105; index++ {
		entries = append(entries, Entry{Status: 200, RemoteIP: fmt.Sprintf("198.51.100.%d", index+1)})
	}
	date := today.Format(dateLayout)
	writeAnalyticsEntries(t, directory, date, entries)
	result, err := manager.Analyze(date, date)
	if err != nil {
		t.Fatal(err)
	}
	if result.Summary.UniqueClients != 105 || len(result.Clients) != analyticsTopClients {
		t.Fatalf("unexpected client limits: total=%d candidates=%d", result.Summary.UniqueClients, len(result.Clients))
	}
}

func TestAnalyzeBoundsHighCardinalityDimensions(t *testing.T) {
	directory := t.TempDir()
	manager := NewManager(directory, models.LoggingConfig{MaxDays: 30})
	defer manager.Close()
	date := time.Now().Format(dateLayout)
	entryCount := analyticsClientKeyLimit + 1024
	entries := make([]Entry, 0, entryCount)
	for index := 0; index < entryCount; index++ {
		entries = append(entries, Entry{
			Path:     fmt.Sprintf("/objects/%d", index),
			Status:   200,
			ClientIP: fmt.Sprintf("198.51.%d.%d", index/256, index%256),
		})
	}
	writeAnalyticsEntries(t, directory, date, entries)

	result, err := manager.Analyze(date, date)
	if err != nil {
		t.Fatal(err)
	}
	if result.Summary.Requests != int64(entryCount) {
		t.Fatalf("requests = %d, want %d", result.Summary.Requests, entryCount)
	}
	if result.Summary.UniqueClients < int64(entryCount*9/10) || result.Summary.UniqueClients > int64(entryCount*11/10) {
		t.Fatalf("estimated unique clients = %d, want within 10%% of %d", result.Summary.UniqueClients, entryCount)
	}

	manager.analyticsMu.Lock()
	cached := manager.analyticsCache[date].data
	manager.analyticsMu.Unlock()
	if cached == nil {
		t.Fatal("analytics result was not cached")
	}
	if len(cached.paths) > analyticsDimensionKeyLimit+1 {
		t.Fatalf("path cardinality = %d, want <= %d", len(cached.paths), analyticsDimensionKeyLimit+1)
	}
	if cached.paths[analyticsOverflowKey] == 0 {
		t.Fatal("overflow path bucket was not populated")
	}
	if len(cached.clientCounts) > analyticsClientKeyLimit {
		t.Fatalf("client cardinality = %d, want <= %d", len(cached.clientCounts), analyticsClientKeyLimit)
	}
	if !cached.clientOverflow {
		t.Fatal("client overflow was not recorded")
	}
}

func TestAnalyzeContextCancellationStopsScanAndWaiters(t *testing.T) {
	directory := t.TempDir()
	manager := NewManager(directory, models.LoggingConfig{MaxDays: 7})
	defer manager.Close()
	date := time.Now().Format(dateLayout)
	entries := make([]Entry, 1024)
	for index := range entries {
		entries[index] = Entry{Path: fmt.Sprintf("/cancel/%d", index), Status: 200}
	}
	writeAnalyticsEntries(t, directory, date, entries)

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	result := &dailyAnalytics{analyticsCounter: newAnalyticsCounter()}
	info, err := os.Stat(filepath.Join(directory, date+fileExtension))
	if err != nil {
		t.Fatal(err)
	}
	err = scanDailyAnalyticsRange(canceled, filepath.Join(directory, date+fileExtension), date, 0, info.Size(), result)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("scan error = %v, want context canceled", err)
	}

	manager.analyticsScan <- struct{}{}
	deadline, stop := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer stop()
	_, err = manager.AnalyzeContext(deadline, date, date)
	<-manager.analyticsScan
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waiter error = %v, want deadline exceeded", err)
	}

	blockedFlush := &Manager{
		flushQueue: make(chan chan struct{}),
		done:       make(chan struct{}),
	}
	blockedFlush.logQueue.Store(&logQueueState{})
	flushDeadline, stopFlush := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer stopFlush()
	if err := blockedFlush.FlushContext(flushDeadline); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("flush error = %v, want deadline exceeded", err)
	}
}

func TestAnalyzeCacheIsIncrementalAndDayBounded(t *testing.T) {
	directory := t.TempDir()
	manager := NewManager(directory, models.LoggingConfig{MaxDays: 60})
	defer manager.Close()
	today := dayStart(time.Now())
	date := today.Format(dateLayout)
	writeAnalyticsEntries(t, directory, date, []Entry{{Path: "/first", Status: 200}})
	if _, err := manager.Analyze(date, date); err != nil {
		t.Fatal(err)
	}
	manager.analyticsMu.Lock()
	firstSize := manager.analyticsCache[date].size
	manager.analyticsMu.Unlock()

	file, err := os.OpenFile(filepath.Join(directory, date+fileExtension), os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	line, _ := json.Marshal(Entry{Path: "/second", Status: 201})
	if _, err := file.Write(append(line, '\n')); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	updated, err := manager.Analyze(date, date)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Summary.Requests != 2 {
		t.Fatalf("incremental requests = %d, want 2", updated.Summary.Requests)
	}
	manager.analyticsMu.Lock()
	secondSize := manager.analyticsCache[date].size
	manager.analyticsMu.Unlock()
	if secondSize <= firstSize {
		t.Fatalf("cached size did not advance: %d -> %d", firstSize, secondSize)
	}

	for daysAgo := 1; daysAgo <= analyticsCacheDayLimit; daysAgo++ {
		otherDate := today.AddDate(0, 0, -daysAgo).Format(dateLayout)
		writeAnalyticsEntries(t, directory, otherDate, []Entry{{Status: 200}})
		if _, err := manager.Analyze(otherDate, otherDate); err != nil {
			t.Fatal(err)
		}
	}
	manager.analyticsMu.Lock()
	cacheDays := len(manager.analyticsCache)
	manager.analyticsMu.Unlock()
	if cacheDays != analyticsCacheDayLimit {
		t.Fatalf("cached days = %d, want %d", cacheDays, analyticsCacheDayLimit)
	}
}

func TestEffectiveClientIPUsesProviderThenTrustedForwarding(t *testing.T) {
	if got := EffectiveClientIP(Entry{
		RemoteIP:      "10.0.0.2",
		XForwardedFor: "198.51.100.10, 10.0.0.3",
	}); got != "198.51.100.10" {
		t.Fatalf("forwarded client IP = %q", got)
	}
	if got := EffectiveClientIP(Entry{
		RemoteIP:       "198.51.100.1",
		EOConnectingIP: "203.0.113.5",
	}); got != "203.0.113.5" {
		t.Fatalf("provider client IP = %q", got)
	}
	if got := EffectiveClientIP(Entry{ClientIP: "[fe80::1%en0]:443"}); got != "fe80::1" {
		t.Fatalf("zoned IPv6 client IP = %q", got)
	}
}
