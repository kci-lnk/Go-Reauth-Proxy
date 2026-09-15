package gatewaylog

import "time"

const (
	analyticsCacheMaxBytes = 8 << 20
	analyticsCacheIdleTTL  = 5 * time.Minute
)

func (m *Manager) storeAnalyticsCacheLocked(date string, entry cachedDailyAnalytics) {
	entry.memoryBytes = analyticsCacheEntryBytes(entry)
	// An oversized result is returned normally but must not defeat the cache
	// budget. Cached results are immutable, so readers survive eviction.
	if !m.closed.Load() && entry.memoryBytes <= analyticsCacheMaxBytes {
		m.analyticsCache[date] = entry
		m.enforceAnalyticsCacheLimitLocked(date)
		m.scheduleAnalyticsExpiryLocked()
	} else {
		delete(m.analyticsCache, date)
		m.stopAnalyticsExpiryIfEmptyLocked()
	}
}

// analyticsCacheEntryBytes accounts for owned string payloads and conservative
// map/entry overhead. This is a cache budget, not an exact process RSS limit;
// live query results, temporary scans and allocator fragmentation are separate.
func analyticsCacheEntryBytes(entry cachedDailyAnalytics) int64 {
	bytes := int64(512 + len(entry.fingerprint) + cap(entry.modified)*8 + cap(entry.segments)*128)
	for _, segment := range entry.segments {
		bytes += int64(len(segment.path))
	}
	if entry.data == nil {
		return bytes
	}
	c := &entry.data.analyticsCounter
	bytes += int64(8192 + len(c.hourly)*96)
	for _, values := range []map[string]int64{
		c.paths, c.routes, c.hosts, c.upstreams, c.referrers,
		c.utmSources, c.utmMediums, c.utmCampaigns, c.devices, c.browsers,
		c.operatingOS, c.statuses, c.methods, c.latencyBands, c.authDecisions,
		c.wafActions, c.clientCounts,
	} {
		bytes += 256
		for key := range values {
			bytes += int64(96 + len(key))
		}
	}
	return bytes
}

// All cache/timer helpers require analyticsMu. A timer exists only while there
// are cached entries; it releases idle data even when no further queries arrive.
func (m *Manager) expireAnalyticsCacheLocked(now time.Time) {
	for date, entry := range m.analyticsCache {
		if now.Sub(entry.lastUsed) >= analyticsCacheIdleTTL {
			delete(m.analyticsCache, date)
		}
	}
	m.stopAnalyticsExpiryIfEmptyLocked()
}

func (m *Manager) stopAnalyticsExpiryIfEmptyLocked() {
	if len(m.analyticsCache) == 0 && m.analyticsTimer != nil {
		// Stop cannot cancel a callback already waiting for analyticsMu.
		// Invalidate it before a later insertion creates another timer.
		m.analyticsGeneration++
		m.analyticsTimer.Stop()
		m.analyticsTimer = nil
	}
}

func (m *Manager) scheduleAnalyticsExpiryLocked() {
	if m.analyticsTimer != nil || m.closed.Load() || len(m.analyticsCache) == 0 {
		return
	}
	var oldest time.Time
	for _, entry := range m.analyticsCache {
		if oldest.IsZero() || entry.lastUsed.Before(oldest) {
			oldest = entry.lastUsed
		}
	}
	generation := m.analyticsGeneration
	m.analyticsTimer = time.AfterFunc(time.Until(oldest.Add(analyticsCacheIdleTTL)), func() {
		m.analyticsMu.Lock()
		defer m.analyticsMu.Unlock()
		if generation != m.analyticsGeneration {
			return
		}
		m.analyticsTimer = nil
		m.expireAnalyticsCacheLocked(time.Now())
		m.scheduleAnalyticsExpiryLocked()
	})
}

func (m *Manager) clearAnalyticsCacheLocked() {
	m.analyticsGeneration++
	if m.analyticsTimer != nil {
		m.analyticsTimer.Stop()
		m.analyticsTimer = nil
	}
	m.analyticsCache = make(map[string]cachedDailyAnalytics)
}
