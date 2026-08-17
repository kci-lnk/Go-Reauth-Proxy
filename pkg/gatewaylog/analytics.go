package gatewaylog

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/bits"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/medama-io/go-useragent"
)

const (
	analyticsMaxDays            = 30
	analyticsTopBuckets         = 8
	analyticsTopClients         = 100
	analyticsMaxKeyBytes        = 512
	analyticsDimensionKeyLimit  = 2048
	analyticsClientKeyLimit     = 8192
	analyticsCacheDayLimit      = analyticsMaxDays
	analyticsOverflowKey        = "other"
	analyticsCardinalityBits    = 12
	analyticsCardinalityBuckets = 1 << analyticsCardinalityBits
)

var (
	analyticsLatencyBounds = [...]int64{10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000}
	analyticsUAParser      = useragent.NewParser()
)

type AnalyticsSummary struct {
	Requests          int64
	UniqueClients     int64
	ClientErrors      int64
	ServerErrors      int64
	AverageDurationMs float64
	P95DurationMs     int64
	BytesIn           uint64
	BytesOut          uint64
	ServerErrorRate   float64
}

type AnalyticsPoint struct {
	BucketStart  string
	Requests     int64
	ClientErrors int64
	ServerErrors int64
}

type AnalyticsBucket struct {
	Key   string
	Count int64
}

type AnalyticsClient struct {
	IP    string
	Count int64
}

type AnalyticsResult struct {
	FromDate         string
	ToDate           string
	Timezone         string
	Granularity      string
	AvailableDates   []string
	Summary          AnalyticsSummary
	Series           []AnalyticsPoint
	Paths            []AnalyticsBucket
	Routes           []AnalyticsBucket
	Hosts            []AnalyticsBucket
	Upstreams        []AnalyticsBucket
	Referrers        []AnalyticsBucket
	UTMSources       []AnalyticsBucket
	UTMMediums       []AnalyticsBucket
	UTMCampaigns     []AnalyticsBucket
	Devices          []AnalyticsBucket
	Browsers         []AnalyticsBucket
	OperatingSystems []AnalyticsBucket
	Statuses         []AnalyticsBucket
	Methods          []AnalyticsBucket
	LatencyBands     []AnalyticsBucket
	AuthDecisions    []AnalyticsBucket
	WAFActions       []AnalyticsBucket
	Clients          []AnalyticsClient
	InvalidEntries   int64
}

type analyticsCounter struct {
	requests       int64
	clientErrors   int64
	serverErrors   int64
	durationTotal  int64
	maxDuration    int64
	durationCounts [len(analyticsLatencyBounds) + 1]int64
	bytesIn        uint64
	bytesOut       uint64
	invalidEntries int64
	hourly         map[int64]*analyticsSeriesCounter
	paths          map[string]int64
	routes         map[string]int64
	hosts          map[string]int64
	upstreams      map[string]int64
	referrers      map[string]int64
	utmSources     map[string]int64
	utmMediums     map[string]int64
	utmCampaigns   map[string]int64
	devices        map[string]int64
	browsers       map[string]int64
	operatingOS    map[string]int64
	statuses       map[string]int64
	methods        map[string]int64
	latencyBands   map[string]int64
	authDecisions  map[string]int64
	wafActions     map[string]int64
	clientCounts   map[string]int64
	clientUnique   analyticsCardinality
	clientOverflow bool
}

type analyticsSeriesCounter struct {
	requests     int64
	clientErrors int64
	serverErrors int64
}

type dailyAnalytics struct {
	analyticsCounter
}

type cachedDailyAnalytics struct {
	size       int64
	modifiedAt int64
	data       *dailyAnalytics
}

// analyticsCardinality is a compact HyperLogLog sketch used only after the
// exact, bounded client counter reaches its safety limit. Keeping the sketch
// populated from the first entry makes that transition deterministic and
// allows daily sketches to be merged without retaining every client address.
type analyticsCardinality struct {
	registers [analyticsCardinalityBuckets]uint8
}

func (c *analyticsCardinality) add(value string) {
	if c == nil || value == "" {
		return
	}
	const (
		fnvOffset = uint64(14695981039346656037)
		fnvPrime  = uint64(1099511628211)
	)
	hash := fnvOffset
	for i := 0; i < len(value); i++ {
		hash ^= uint64(value[i])
		hash *= fnvPrime
	}
	// FNV-1a's high bits are weak for similarly prefixed values such as IP
	// addresses. Apply a final avalanche before splitting index and rank bits.
	hash ^= hash >> 33
	hash *= 0xff51afd7ed558ccd
	hash ^= hash >> 33
	hash *= 0xc4ceb9fe1a85ec53
	hash ^= hash >> 33
	index := hash >> (64 - analyticsCardinalityBits)
	remainder := hash << analyticsCardinalityBits
	rank := uint8(bits.LeadingZeros64(remainder) + 1)
	maxRank := uint8(64 - analyticsCardinalityBits + 1)
	if rank > maxRank {
		rank = maxRank
	}
	if rank > c.registers[index] {
		c.registers[index] = rank
	}
}

func (c *analyticsCardinality) merge(source *analyticsCardinality) {
	if c == nil || source == nil {
		return
	}
	for i, rank := range source.registers {
		if rank > c.registers[i] {
			c.registers[i] = rank
		}
	}
}

func (c *analyticsCardinality) estimate() int64 {
	if c == nil {
		return 0
	}
	const m = float64(analyticsCardinalityBuckets)
	sum := 0.0
	zeros := 0
	for _, rank := range c.registers {
		sum += math.Ldexp(1, -int(rank))
		if rank == 0 {
			zeros++
		}
	}
	estimate := 0.7213 / (1 + 1.079/m) * m * m / sum
	if estimate <= 2.5*m && zeros > 0 {
		estimate = m * math.Log(m/float64(zeros))
	}
	return int64(math.Round(estimate))
}

func newAnalyticsCounter() analyticsCounter {
	return analyticsCounter{
		hourly:        make(map[int64]*analyticsSeriesCounter),
		paths:         make(map[string]int64),
		routes:        make(map[string]int64),
		hosts:         make(map[string]int64),
		upstreams:     make(map[string]int64),
		referrers:     make(map[string]int64),
		utmSources:    make(map[string]int64),
		utmMediums:    make(map[string]int64),
		utmCampaigns:  make(map[string]int64),
		devices:       make(map[string]int64),
		browsers:      make(map[string]int64),
		operatingOS:   make(map[string]int64),
		statuses:      make(map[string]int64),
		methods:       make(map[string]int64),
		latencyBands:  make(map[string]int64),
		authDecisions: make(map[string]int64),
		wafActions:    make(map[string]int64),
		clientCounts:  make(map[string]int64),
	}
}

func (m *Manager) Analyze(fromDate string, toDate string) (AnalyticsResult, error) {
	return m.AnalyzeContext(context.Background(), fromDate, toDate)
}

func (m *Manager) AnalyzeContext(ctx context.Context, fromDate string, toDate string) (AnalyticsResult, error) {
	if m == nil {
		return AnalyticsResult{}, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return AnalyticsResult{}, err
	}
	if err := m.FlushContext(ctx); err != nil {
		return AnalyticsResult{}, err
	}

	from, to, err := normalizeAnalyticsRange(fromDate, toDate)
	if err != nil {
		return AnalyticsResult{}, err
	}
	dates, err := m.listDates(true)
	if err != nil {
		return AnalyticsResult{}, err
	}
	m.pruneAnalyticsCache(dates)

	combined := newAnalyticsCounter()
	for cursor := from; !cursor.After(to); cursor = cursor.AddDate(0, 0, 1) {
		if err := ctx.Err(); err != nil {
			return AnalyticsResult{}, err
		}
		day, err := m.analyticsForDate(ctx, cursor.Format(dateLayout))
		if err != nil {
			return AnalyticsResult{}, err
		}
		mergeAnalyticsCounter(&combined, &day.analyticsCounter)
	}

	granularity, bucketHours := analyticsGranularity(from, to)
	zoneName := time.Local.String()
	if strings.TrimSpace(zoneName) == "" || zoneName == "Local" {
		abbreviation, zoneOffset := time.Now().Zone()
		zoneName = formatZoneOffset(zoneOffset)
		if strings.TrimSpace(abbreviation) != "" {
			zoneName = abbreviation + " (" + zoneName + ")"
		}
	}

	return AnalyticsResult{
		FromDate:         from.Format(dateLayout),
		ToDate:           to.Format(dateLayout),
		Timezone:         zoneName,
		Granularity:      granularity,
		AvailableDates:   dates,
		Summary:          combined.summary(),
		Series:           combined.series(from, to, bucketHours),
		Paths:            topAnalyticsBuckets(combined.paths, analyticsTopBuckets),
		Routes:           topAnalyticsBuckets(combined.routes, analyticsTopBuckets),
		Hosts:            topAnalyticsBuckets(combined.hosts, analyticsTopBuckets),
		Upstreams:        topAnalyticsBuckets(combined.upstreams, analyticsTopBuckets),
		Referrers:        topAnalyticsBuckets(combined.referrers, analyticsTopBuckets),
		UTMSources:       topAnalyticsBuckets(combined.utmSources, analyticsTopBuckets),
		UTMMediums:       topAnalyticsBuckets(combined.utmMediums, analyticsTopBuckets),
		UTMCampaigns:     topAnalyticsBuckets(combined.utmCampaigns, analyticsTopBuckets),
		Devices:          topAnalyticsBuckets(combined.devices, analyticsTopBuckets),
		Browsers:         topAnalyticsBuckets(combined.browsers, analyticsTopBuckets),
		OperatingSystems: topAnalyticsBuckets(combined.operatingOS, analyticsTopBuckets),
		Statuses:         topAnalyticsBuckets(combined.statuses, analyticsTopBuckets),
		Methods:          topAnalyticsBuckets(combined.methods, analyticsTopBuckets),
		LatencyBands:     topAnalyticsBuckets(combined.latencyBands, analyticsTopBuckets),
		AuthDecisions:    topAnalyticsBuckets(combined.authDecisions, analyticsTopBuckets),
		WAFActions:       topAnalyticsBuckets(combined.wafActions, analyticsTopBuckets),
		Clients:          topAnalyticsClients(combined.clientCounts, analyticsTopClients),
		InvalidEntries:   combined.invalidEntries,
	}, nil
}

func normalizeAnalyticsRange(fromDate string, toDate string) (time.Time, time.Time, error) {
	now := time.Now()
	today := dayStart(now)
	to := today
	from := today.AddDate(0, 0, -6)
	var err error
	if strings.TrimSpace(fromDate) != "" {
		from, err = time.ParseInLocation(dateLayout, strings.TrimSpace(fromDate), time.Local)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("invalid from date, expected format YYYY-MM-DD")
		}
	}
	if strings.TrimSpace(toDate) != "" {
		to, err = time.ParseInLocation(dateLayout, strings.TrimSpace(toDate), time.Local)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("invalid to date, expected format YYYY-MM-DD")
		}
	}
	if from.After(to) {
		return time.Time{}, time.Time{}, fmt.Errorf("from date must not be after to date")
	}
	if to.After(today) {
		return time.Time{}, time.Time{}, fmt.Errorf("to date must not be in the future")
	}
	if days := analyticsCalendarDays(from, to); days > analyticsMaxDays {
		return time.Time{}, time.Time{}, fmt.Errorf("analytics range must not exceed %d days", analyticsMaxDays)
	}
	return from, to, nil
}

func analyticsGranularity(from time.Time, to time.Time) (string, int) {
	days := analyticsCalendarDays(from, to)
	switch {
	case days <= 2:
		return "hour", 1
	case days <= 14:
		return "6h", 6
	default:
		return "day", 24
	}
}

func analyticsCalendarDays(from time.Time, to time.Time) int {
	fromUTC := time.Date(from.Year(), from.Month(), from.Day(), 0, 0, 0, 0, time.UTC)
	toUTC := time.Date(to.Year(), to.Month(), to.Day(), 0, 0, 0, 0, time.UTC)
	return int(toUTC.Sub(fromUTC).Hours()/24) + 1
}

func (m *Manager) analyticsForDate(ctx context.Context, date string) (*dailyAnalytics, error) {
	path := filepath.Join(m.logsDir, date+fileExtension)
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			empty := &dailyAnalytics{analyticsCounter: newAnalyticsCounter()}
			return empty, nil
		}
		return nil, err
	}
	if cached := m.cachedAnalytics(date, info); cached != nil {
		return cached, nil
	}

	select {
	case m.analyticsScan <- struct{}{}:
		defer func() { <-m.analyticsScan }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	// A previous waiter may have populated the cache while this request waited
	// for the single scan slot. Restat so append-only growth is incorporated.
	info, err = os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &dailyAnalytics{analyticsCounter: newAnalyticsCounter()}, nil
		}
		return nil, err
	}
	if cached := m.cachedAnalytics(date, info); cached != nil {
		return cached, nil
	}

	start := int64(0)
	var data *dailyAnalytics
	m.analyticsMu.Lock()
	cached, hasCached := m.analyticsCache[date]
	if hasCached && cached.data != nil && cached.size > 0 && cached.size < info.Size() && cached.modifiedAt <= info.ModTime().UnixNano() {
		start = cached.size
		data = cloneDailyAnalytics(cached.data)
	}
	m.analyticsMu.Unlock()
	if data == nil {
		data = &dailyAnalytics{analyticsCounter: newAnalyticsCounter()}
	}
	if err := scanDailyAnalyticsRange(ctx, path, date, start, info.Size(), data); err != nil {
		return nil, err
	}

	m.analyticsMu.Lock()
	m.analyticsCache[date] = cachedDailyAnalytics{
		size:       info.Size(),
		modifiedAt: info.ModTime().UnixNano(),
		data:       data,
	}
	m.enforceAnalyticsCacheLimitLocked(date)
	m.analyticsMu.Unlock()
	return data, nil
}

func (m *Manager) cachedAnalytics(date string, info os.FileInfo) *dailyAnalytics {
	if m == nil || info == nil {
		return nil
	}
	m.analyticsMu.Lock()
	defer m.analyticsMu.Unlock()
	cached, ok := m.analyticsCache[date]
	if !ok || cached.size != info.Size() || cached.modifiedAt != info.ModTime().UnixNano() {
		return nil
	}
	return cached.data
}

func (m *Manager) invalidateAnalyticsDate(date string) {
	if m == nil {
		return
	}
	m.analyticsMu.Lock()
	delete(m.analyticsCache, date)
	m.analyticsMu.Unlock()
}

func (m *Manager) pruneAnalyticsCache(dates []string) {
	retained := make(map[string]struct{}, len(dates))
	for _, date := range dates {
		retained[date] = struct{}{}
	}

	m.analyticsMu.Lock()
	defer m.analyticsMu.Unlock()
	for date := range m.analyticsCache {
		if _, ok := retained[date]; !ok {
			delete(m.analyticsCache, date)
		}
	}
	m.enforceAnalyticsCacheLimitLocked("")
}

func (m *Manager) enforceAnalyticsCacheLimitLocked(preserve string) {
	for len(m.analyticsCache) > analyticsCacheDayLimit {
		oldest := ""
		for date := range m.analyticsCache {
			if date == preserve {
				continue
			}
			if oldest == "" || date < oldest {
				oldest = date
			}
		}
		if oldest == "" {
			return
		}
		delete(m.analyticsCache, oldest)
	}
}

func scanDailyAnalytics(path string, date string) (*dailyAnalytics, error) {
	result := &dailyAnalytics{analyticsCounter: newAnalyticsCounter()}
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return result, nil
		}
		return nil, err
	}
	if err := scanDailyAnalyticsRange(context.Background(), path, date, 0, info.Size(), result); err != nil {
		return nil, err
	}
	return result, nil
}

func scanDailyAnalyticsRange(ctx context.Context, path string, date string, start int64, end int64, result *dailyAnalytics) error {
	file, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	defer file.Close()
	if start < 0 || end < start {
		return fmt.Errorf("invalid analytics scan range")
	}
	if result == nil {
		return fmt.Errorf("analytics result is required")
	}

	fallbackTime, _ := time.ParseInLocation(dateLayout, date, time.Local)
	reader := io.NewSectionReader(file, start, end-start)
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), maxScanToken)
	lines := 0
	for scanner.Scan() {
		lines++
		if lines&255 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		line := scanner.Bytes()
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}
		var entry Entry
		if err := json.Unmarshal(line, &entry); err != nil {
			result.invalidEntries++
			continue
		}
		result.addEntry(entry, fallbackTime)
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return ctx.Err()
}

func (counter *analyticsCounter) addEntry(entry Entry, fallbackTime time.Time) {
	counter.requests++
	statusClass := entry.Status / 100
	if statusClass == 4 {
		counter.clientErrors++
	}
	if statusClass == 5 {
		counter.serverErrors++
	}

	duration := entry.DurationMs
	if duration < 0 {
		duration = 0
	}
	counter.durationTotal += duration
	if duration > counter.maxDuration {
		counter.maxDuration = duration
	}
	counter.durationCounts[analyticsDurationBucketIndex(duration)]++
	counter.bytesIn += entry.BytesIn
	counter.bytesOut += entry.BytesOut

	eventTime := parseAnalyticsTime(entry.Time, fallbackTime)
	hour := time.Date(eventTime.Year(), eventTime.Month(), eventTime.Day(), eventTime.Hour(), 0, 0, 0, eventTime.Location()).Unix()
	point := counter.hourly[hour]
	if point == nil {
		point = &analyticsSeriesCounter{}
		counter.hourly[hour] = point
	}
	point.requests++
	if statusClass == 4 {
		point.clientErrors++
	}
	if statusClass == 5 {
		point.serverErrors++
	}

	path := strings.TrimSpace(entry.Path)
	if path == "" {
		path = strings.TrimSpace(entry.RequestURI)
	}
	path = strings.SplitN(path, "?", 2)[0]
	incrementAnalytics(counter.paths, defaultAnalyticsKey(path))
	incrementAnalytics(counter.hosts, normalizeAnalyticsHost(entry.Host))
	incrementAnalytics(counter.routes, analyticsRouteKey(entry))
	incrementAnalytics(counter.upstreams, defaultAnalyticsKey(strings.TrimSpace(entry.Upstream)))
	incrementAnalytics(counter.referrers, analyticsReferrer(entry.Referer))

	query := strings.TrimSpace(entry.Query)
	if query == "" {
		if parsed, err := url.Parse(entry.RequestURI); err == nil {
			query = parsed.RawQuery
		}
	}
	query = strings.TrimPrefix(query, "?")
	values, _ := url.ParseQuery(query)
	incrementAnalytics(counter.utmSources, defaultAnalyticsKey(values.Get("utm_source")))
	incrementAnalytics(counter.utmMediums, defaultAnalyticsKey(values.Get("utm_medium")))
	incrementAnalytics(counter.utmCampaigns, defaultAnalyticsKey(values.Get("utm_campaign")))

	agent := analyticsUAParser.Parse(entry.UserAgent)
	incrementAnalytics(counter.devices, defaultAnalyticsKey(agent.Device().String()))
	incrementAnalytics(counter.browsers, defaultAnalyticsKey(agent.Browser().String()))
	incrementAnalytics(counter.operatingOS, defaultAnalyticsKey(agent.OS().String()))
	statusKey := "unknown"
	if entry.Status >= 100 && entry.Status <= 599 {
		statusKey = strconv.Itoa(entry.Status)
	}
	incrementAnalytics(counter.statuses, statusKey)
	incrementAnalytics(counter.methods, defaultAnalyticsKey(strings.ToUpper(strings.TrimSpace(entry.Method))))
	incrementAnalytics(counter.latencyBands, analyticsLatencyBand(duration))
	incrementAnalytics(counter.authDecisions, analyticsAuthDecision(entry))
	incrementAnalytics(counter.wafActions, analyticsWAFAction(entry))

	if clientIP := EffectiveClientIP(entry); clientIP != "" {
		counter.clientUnique.add(clientIP)
		if _, exists := counter.clientCounts[clientIP]; exists {
			counter.clientCounts[clientIP]++
		} else if len(counter.clientCounts) < analyticsClientKeyLimit {
			counter.clientCounts[clientIP] = 1
		} else {
			counter.clientOverflow = true
		}
	}
}

func parseAnalyticsTime(value string, fallback time.Time) time.Time {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if parsed, err := time.Parse(layout, strings.TrimSpace(value)); err == nil {
			return parsed.In(time.Local)
		}
	}
	return fallback
}

func mergeAnalyticsCounter(target *analyticsCounter, source *analyticsCounter) {
	target.requests += source.requests
	target.clientErrors += source.clientErrors
	target.serverErrors += source.serverErrors
	target.durationTotal += source.durationTotal
	if source.maxDuration > target.maxDuration {
		target.maxDuration = source.maxDuration
	}
	for index := range target.durationCounts {
		target.durationCounts[index] += source.durationCounts[index]
	}
	target.bytesIn += source.bytesIn
	target.bytesOut += source.bytesOut
	target.invalidEntries += source.invalidEntries
	for timestamp, point := range source.hourly {
		merged := target.hourly[timestamp]
		if merged == nil {
			merged = &analyticsSeriesCounter{}
			target.hourly[timestamp] = merged
		}
		merged.requests += point.requests
		merged.clientErrors += point.clientErrors
		merged.serverErrors += point.serverErrors
	}
	for _, pair := range []struct {
		target map[string]int64
		source map[string]int64
	}{
		{target.paths, source.paths}, {target.routes, source.routes}, {target.hosts, source.hosts},
		{target.upstreams, source.upstreams}, {target.referrers, source.referrers},
		{target.utmSources, source.utmSources}, {target.utmMediums, source.utmMediums},
		{target.utmCampaigns, source.utmCampaigns}, {target.devices, source.devices},
		{target.browsers, source.browsers}, {target.operatingOS, source.operatingOS},
		{target.statuses, source.statuses}, {target.methods, source.methods},
		{target.latencyBands, source.latencyBands}, {target.authDecisions, source.authDecisions},
		{target.wafActions, source.wafActions},
	} {
		for key, count := range pair.source {
			incrementAnalyticsBy(pair.target, key, count)
		}
	}
	target.clientUnique.merge(&source.clientUnique)
	if source.clientOverflow {
		target.clientOverflow = true
	}
	for key, count := range source.clientCounts {
		if _, exists := target.clientCounts[key]; exists {
			target.clientCounts[key] += count
		} else if len(target.clientCounts) < analyticsClientKeyLimit {
			target.clientCounts[key] = count
		} else {
			target.clientOverflow = true
		}
	}
}

func (counter analyticsCounter) summary() AnalyticsSummary {
	average := 0.0
	serverErrorRate := 0.0
	if counter.requests > 0 {
		average = float64(counter.durationTotal) / float64(counter.requests)
		serverErrorRate = float64(counter.serverErrors) / float64(counter.requests)
	}
	uniqueClients := int64(len(counter.clientCounts))
	if counter.clientOverflow {
		if estimate := counter.clientUnique.estimate(); estimate > uniqueClients {
			uniqueClients = estimate
		}
	}
	return AnalyticsSummary{
		Requests:          counter.requests,
		UniqueClients:     uniqueClients,
		ClientErrors:      counter.clientErrors,
		ServerErrors:      counter.serverErrors,
		AverageDurationMs: average,
		P95DurationMs:     counter.percentileDuration(0.95),
		BytesIn:           counter.bytesIn,
		BytesOut:          counter.bytesOut,
		ServerErrorRate:   serverErrorRate,
	}
}

func (counter analyticsCounter) percentileDuration(percentile float64) int64 {
	if counter.requests == 0 {
		return 0
	}
	rank := int64(math.Ceil(float64(counter.requests) * percentile))
	var cumulative int64
	for index, count := range counter.durationCounts {
		cumulative += count
		if cumulative < rank {
			continue
		}
		if index < len(analyticsLatencyBounds) {
			return analyticsLatencyBounds[index]
		}
		return counter.maxDuration
	}
	return counter.maxDuration
}

func (counter analyticsCounter) series(from time.Time, to time.Time, bucketHours int) []AnalyticsPoint {
	buckets := make(map[int64]*analyticsSeriesCounter)
	for timestamp, point := range counter.hourly {
		value := time.Unix(timestamp, 0).In(time.Local)
		bucketHour := 0
		if bucketHours < 24 {
			bucketHour = (value.Hour() / bucketHours) * bucketHours
		}
		bucket := time.Date(value.Year(), value.Month(), value.Day(), bucketHour, 0, 0, 0, time.Local).Unix()
		merged := buckets[bucket]
		if merged == nil {
			merged = &analyticsSeriesCounter{}
			buckets[bucket] = merged
		}
		merged.requests += point.requests
		merged.clientErrors += point.clientErrors
		merged.serverErrors += point.serverErrors
	}

	advance := func(value time.Time) time.Time {
		if bucketHours == 24 {
			return value.AddDate(0, 0, 1)
		}
		return value.Add(time.Duration(bucketHours) * time.Hour)
	}
	end := to.AddDate(0, 0, 1)
	now := time.Now()
	if end.After(now) {
		bucketHour := 0
		if bucketHours < 24 {
			bucketHour = (now.Hour() / bucketHours) * bucketHours
		}
		end = advance(time.Date(now.Year(), now.Month(), now.Day(), bucketHour, 0, 0, 0, time.Local))
	}
	points := make([]AnalyticsPoint, 0)
	for cursor := from; cursor.Before(end); cursor = advance(cursor) {
		point := buckets[cursor.Unix()]
		if point == nil {
			point = &analyticsSeriesCounter{}
		}
		points = append(points, AnalyticsPoint{
			BucketStart:  cursor.Format(time.RFC3339),
			Requests:     point.requests,
			ClientErrors: point.clientErrors,
			ServerErrors: point.serverErrors,
		})
	}
	return points
}

func analyticsDurationBucketIndex(duration int64) int {
	for index, bound := range analyticsLatencyBounds {
		if duration <= bound {
			return index
		}
	}
	return len(analyticsLatencyBounds)
}

func analyticsLatencyBand(duration int64) string {
	switch {
	case duration < 50:
		return "lt_50"
	case duration < 100:
		return "50_100"
	case duration < 250:
		return "100_250"
	case duration < 500:
		return "250_500"
	case duration < 1000:
		return "500_1000"
	default:
		return "gte_1000"
	}
}

func analyticsRouteKey(entry Entry) string {
	routeType := strings.TrimSpace(entry.RouteType)
	routeKey := strings.TrimSpace(entry.RouteKey)
	switch {
	case routeType != "" && routeKey != "":
		return routeType + " · " + routeKey
	case routeKey != "":
		return routeKey
	default:
		return defaultAnalyticsKey(routeType)
	}
}

func analyticsReferrer(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "direct"
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Hostname() == "" {
		return "unknown"
	}
	return strings.ToLower(parsed.Hostname())
}

func analyticsAuthDecision(entry Entry) string {
	if decision := strings.TrimSpace(entry.AuthDecision); decision != "" {
		return decision
	}
	if !entry.AuthRequired {
		return "not_required"
	}
	if entry.LoggedIn {
		return "passed"
	}
	return "unknown"
}

func analyticsWAFAction(entry Entry) string {
	if entry.WAFBlocked {
		return "blocked"
	}
	if action := strings.ToLower(strings.TrimSpace(entry.WAFAction)); action != "" {
		return action
	}
	if entry.WAFTraceID != "" || entry.WAFBundle != "" || len(entry.WAFRuleIDs) > 0 {
		return "hit"
	}
	return "none"
}

func normalizeAnalyticsHost(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	}
	return defaultAnalyticsKey(value)
}

func defaultAnalyticsKey(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "unknown"
	}
	if len(value) > analyticsMaxKeyBytes {
		value = value[:analyticsMaxKeyBytes]
		for !utf8.ValidString(value) {
			value = value[:len(value)-1]
		}
		value += "…"
	}
	return value
}

func incrementAnalytics(values map[string]int64, key string) {
	incrementAnalyticsBy(values, key, 1)
}

func incrementAnalyticsBy(values map[string]int64, key string, count int64) {
	if values == nil {
		return
	}
	key = defaultAnalyticsKey(key)
	if _, exists := values[key]; exists {
		values[key] += count
		return
	}
	if len(values) < analyticsDimensionKeyLimit {
		values[key] = count
		return
	}
	values[analyticsOverflowKey] += count
}

func cloneDailyAnalytics(source *dailyAnalytics) *dailyAnalytics {
	if source == nil {
		return nil
	}
	cloned := &dailyAnalytics{analyticsCounter: source.analyticsCounter}
	cloned.hourly = make(map[int64]*analyticsSeriesCounter, len(source.hourly))
	for timestamp, point := range source.hourly {
		if point == nil {
			continue
		}
		copyPoint := *point
		cloned.hourly[timestamp] = &copyPoint
	}
	cloned.paths = cloneAnalyticsMap(source.paths)
	cloned.routes = cloneAnalyticsMap(source.routes)
	cloned.hosts = cloneAnalyticsMap(source.hosts)
	cloned.upstreams = cloneAnalyticsMap(source.upstreams)
	cloned.referrers = cloneAnalyticsMap(source.referrers)
	cloned.utmSources = cloneAnalyticsMap(source.utmSources)
	cloned.utmMediums = cloneAnalyticsMap(source.utmMediums)
	cloned.utmCampaigns = cloneAnalyticsMap(source.utmCampaigns)
	cloned.devices = cloneAnalyticsMap(source.devices)
	cloned.browsers = cloneAnalyticsMap(source.browsers)
	cloned.operatingOS = cloneAnalyticsMap(source.operatingOS)
	cloned.statuses = cloneAnalyticsMap(source.statuses)
	cloned.methods = cloneAnalyticsMap(source.methods)
	cloned.latencyBands = cloneAnalyticsMap(source.latencyBands)
	cloned.authDecisions = cloneAnalyticsMap(source.authDecisions)
	cloned.wafActions = cloneAnalyticsMap(source.wafActions)
	cloned.clientCounts = cloneAnalyticsMap(source.clientCounts)
	return cloned
}

func cloneAnalyticsMap(source map[string]int64) map[string]int64 {
	cloned := make(map[string]int64, len(source))
	for key, count := range source {
		cloned[key] = count
	}
	return cloned
}

func topAnalyticsBuckets(values map[string]int64, limit int) []AnalyticsBucket {
	items := make([]AnalyticsBucket, 0, len(values))
	for key, count := range values {
		items = append(items, AnalyticsBucket{Key: key, Count: count})
	}
	sort.Slice(items, func(left, right int) bool {
		if items[left].Count == items[right].Count {
			return items[left].Key < items[right].Key
		}
		return items[left].Count > items[right].Count
	})
	if len(items) > limit {
		items = items[:limit]
	}
	return items
}

func topAnalyticsClients(values map[string]int64, limit int) []AnalyticsClient {
	items := make([]AnalyticsClient, 0, len(values))
	for ip, count := range values {
		items = append(items, AnalyticsClient{IP: ip, Count: count})
	}
	sort.Slice(items, func(left, right int) bool {
		if items[left].Count == items[right].Count {
			return items[left].IP < items[right].IP
		}
		return items[left].Count > items[right].Count
	})
	if len(items) > limit {
		items = items[:limit]
	}
	return items
}

func formatZoneOffset(seconds int) string {
	sign := "+"
	if seconds < 0 {
		sign = "-"
		seconds = -seconds
	}
	return fmt.Sprintf("UTC%s%02d:%02d", sign, seconds/3600, (seconds%3600)/60)
}

func EffectiveClientIP(entry Entry) string {
	if value := normalizeAnalyticsIP(entry.ClientIP); value != "" {
		return value
	}
	providerCandidates := append(splitAnalyticsIPs(entry.EOConnectingIP), splitAnalyticsIPs(entry.AliRealClientIP)...)
	if value := preferredAnalyticsIP(providerCandidates); value != "" {
		return value
	}
	remoteIP := normalizeAnalyticsIP(entry.RemoteIP)
	if remoteIP != "" && isPrivateAnalyticsIP(remoteIP) {
		proxyCandidates := append(splitAnalyticsIPs(entry.XForwardedFor), splitAnalyticsIPs(entry.XRealIP)...)
		if value := preferredAnalyticsIP(proxyCandidates); value != "" {
			return value
		}
	}
	return remoteIP
}

func splitAnalyticsIPs(value string) []string {
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if normalized := normalizeAnalyticsIP(part); normalized != "" {
			result = append(result, normalized)
		}
	}
	return result
}

func preferredAnalyticsIP(values []string) string {
	for _, value := range values {
		if !isPrivateAnalyticsIP(value) {
			return value
		}
	}
	if len(values) > 0 {
		return values[0]
	}
	return ""
}

func normalizeAnalyticsIP(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if address, err := netip.ParseAddrPort(value); err == nil {
		return address.Addr().WithZone("").Unmap().String()
	}
	if address, err := netip.ParseAddr(value); err == nil {
		return address.WithZone("").Unmap().String()
	}
	if strings.HasPrefix(value, "[") {
		if end := strings.LastIndex(value, "]"); end > 1 {
			if address, err := netip.ParseAddr(value[1:end]); err == nil {
				return address.WithZone("").Unmap().String()
			}
		}
	}
	return ""
}

func isPrivateAnalyticsIP(value string) bool {
	address, err := netip.ParseAddr(value)
	if err != nil {
		return false
	}
	address = address.Unmap()
	if address.Is6() {
		return address.IsLoopback() || address.IsUnspecified() || address.IsPrivate() || address.IsLinkLocalUnicast()
	}
	octets := address.As4()
	return octets[0] == 0 || octets[0] == 10 || octets[0] == 127 ||
		(octets[0] == 169 && octets[1] == 254) ||
		(octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31) ||
		(octets[0] == 192 && octets[1] == 168) ||
		(octets[0] == 100 && octets[1] >= 64 && octets[1] <= 127)
}
