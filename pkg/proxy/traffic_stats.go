package proxy

import (
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type TrafficStats struct {
	TotalIn     uint64               `json:"total_in"`
	TotalOut    uint64               `json:"total_out"`
	ActiveConns int64                `json:"active_conns"`
	Error5xx    uint64               `json:"error_5xx"`
	ByHost      []HostTrafficStats   `json:"by_host,omitempty"`
	ByStream    []StreamTrafficStats `json:"by_stream,omitempty"`
}

type HostTrafficStats struct {
	Host          string `json:"host"`
	TotalIn       uint64 `json:"total_in"`
	TotalOut      uint64 `json:"total_out"`
	Error5xx      uint64 `json:"error_5xx"`
	ActiveIPCount int    `json:"active_ip_count"`
}

type StreamTrafficStats struct {
	Protocol    string `json:"protocol"`
	ListenPort  int    `json:"listen_port"`
	Key         string `json:"key"`
	TotalIn     uint64 `json:"total_in"`
	TotalOut    uint64 `json:"total_out"`
	Error5xx    uint64 `json:"error_5xx"`
	ActiveConns int64  `json:"active_conns"`
}

type streamTrafficCounters struct {
	protocol    string
	listenPort  int
	totalIn     atomic.Uint64
	totalOut    atomic.Uint64
	error5xx    atomic.Uint64
	activeConns atomic.Int64
}

// StreamTrafficRecorder keeps the hot-path counter lookup out of each relay
// write while publishing every completed write to the realtime snapshot.
type StreamTrafficRecorder struct {
	handler  *Handler
	counters *streamTrafficCounters
}

type HostActiveIPStats struct {
	IP          string    `json:"ip"`
	LastSeenAt  time.Time `json:"last_seen_at"`
	ActiveConns int64     `json:"active_conns"`
}

type HostActiveIPsStats struct {
	Host          string              `json:"host"`
	WindowSeconds int                 `json:"window_seconds"`
	Items         []HostActiveIPStats `json:"items"`
}

type hostTrafficCounters struct {
	totalIn                     atomic.Uint64
	totalOut                    atomic.Uint64
	error5xx                    atomic.Uint64
	activeIPs                   sync.Map
	activeIPEntries             atomic.Int64
	activeIPLastCleanupUnixNano atomic.Int64
}

type hostActiveIPRecord struct {
	ip               string
	lastSeenUnixNano atomic.Int64
	activeConns      atomic.Int64
}

func normalizeTrafficHost(host string) string {
	return strings.TrimSuffix(normalizeRequestHost(host), ".")
}

const (
	hostActiveIPWindow          = 2 * time.Minute
	hostActiveIPCleanupInterval = 30 * time.Second
	hostActiveIPMaxItems        = 256
	hostActiveIPHardLimit       = 4096
)

func (c *hostTrafficCounters) deleteActiveIP(key any) {
	if c == nil {
		return
	}
	if _, loaded := c.activeIPs.LoadAndDelete(key); loaded {
		if c.activeIPEntries.Add(-1) < 0 {
			c.activeIPEntries.Store(0)
		}
	}
}

func (c *hostTrafficCounters) cleanupActiveIPs(now time.Time) {
	if c == nil {
		return
	}
	cutoff := now.Add(-hostActiveIPWindow).UnixNano()
	c.activeIPs.Range(func(key, value any) bool {
		record, ok := value.(*hostActiveIPRecord)
		if !ok || record == nil {
			c.deleteActiveIP(key)
			return true
		}
		lastSeen := record.lastSeenUnixNano.Load()
		activeConns := record.activeConns.Load()
		if activeConns <= 0 && lastSeen < cutoff {
			c.deleteActiveIP(key)
		}
		return true
	})
	c.enforceActiveIPLimit()
}

func (c *hostTrafficCounters) cleanupActiveIPsIfNeeded(now time.Time) {
	if c == nil {
		return
	}
	nowUnixNano := now.UnixNano()
	lastCleanup := c.activeIPLastCleanupUnixNano.Load()
	if lastCleanup > 0 && nowUnixNano-lastCleanup < int64(hostActiveIPCleanupInterval) {
		return
	}
	if !c.activeIPLastCleanupUnixNano.CompareAndSwap(lastCleanup, nowUnixNano) {
		return
	}
	c.cleanupActiveIPs(now)
}

func (c *hostTrafficCounters) enforceActiveIPLimit() {
	if c == nil || c.activeIPEntries.Load() <= hostActiveIPHardLimit {
		return
	}
	type activeIPCandidate struct {
		key         any
		lastSeen    int64
		activeConns int64
	}
	candidates := make([]activeIPCandidate, 0)
	c.activeIPs.Range(func(key, value any) bool {
		record, ok := value.(*hostActiveIPRecord)
		if !ok || record == nil {
			candidates = append(candidates, activeIPCandidate{key: key})
			return true
		}
		candidates = append(candidates, activeIPCandidate{
			key:         key,
			lastSeen:    record.lastSeenUnixNano.Load(),
			activeConns: record.activeConns.Load(),
		})
		return true
	})
	sort.Slice(candidates, func(i, j int) bool {
		if (candidates[i].activeConns <= 0) != (candidates[j].activeConns <= 0) {
			return candidates[i].activeConns <= 0
		}
		return candidates[i].lastSeen < candidates[j].lastSeen
	})
	for _, candidate := range candidates {
		if c.activeIPEntries.Load() <= hostActiveIPHardLimit {
			return
		}
		c.deleteActiveIP(candidate.key)
	}
}

func (c *hostTrafficCounters) markActiveIP(clientIP string, now time.Time) *hostActiveIPRecord {
	if c == nil {
		return nil
	}
	ip := normalizeIPAddress(clientIP)
	if ip == "" {
		return nil
	}

	c.cleanupActiveIPsIfNeeded(now)
	record, loaded := c.activeIPs.Load(ip)
	activeRecord, ok := record.(*hostActiveIPRecord)
	if !loaded || !ok || activeRecord == nil {
		candidate := &hostActiveIPRecord{ip: ip}
		actual, wasLoaded := c.activeIPs.LoadOrStore(ip, candidate)
		loaded = wasLoaded
		if existing, valid := actual.(*hostActiveIPRecord); valid && existing != nil {
			activeRecord = existing
		} else {
			activeRecord = candidate
		}
	}

	activeRecord.lastSeenUnixNano.Store(now.UnixNano())
	activeRecord.activeConns.Add(1)
	if !loaded {
		if c.activeIPEntries.Add(1) > hostActiveIPHardLimit {
			c.cleanupActiveIPs(now)
		}
	}

	return activeRecord
}

func releaseHostActiveIP(record *hostActiveIPRecord, now time.Time) {
	if record == nil {
		return
	}
	record.lastSeenUnixNano.Store(now.UnixNano())
	if record.activeConns.Add(-1) < 0 {
		record.activeConns.Store(0)
	}
}

func (c *hostTrafficCounters) activeIPCount(now time.Time) int {
	if c == nil {
		return 0
	}
	c.cleanupActiveIPs(now)

	cutoff := now.Add(-hostActiveIPWindow).UnixNano()
	count := 0
	c.activeIPs.Range(func(key, value any) bool {
		record, ok := value.(*hostActiveIPRecord)
		if !ok || record == nil {
			c.deleteActiveIP(key)
			return true
		}
		lastSeen := record.lastSeenUnixNano.Load()
		activeConns := record.activeConns.Load()
		if activeConns <= 0 && lastSeen < cutoff {
			c.deleteActiveIP(key)
			return true
		}
		if lastSeen > 0 {
			count++
		}
		return true
	})
	return count
}

func (c *hostTrafficCounters) activeIPStats(now time.Time) []HostActiveIPStats {
	if c == nil {
		return []HostActiveIPStats{}
	}
	c.cleanupActiveIPs(now)

	cutoff := now.Add(-hostActiveIPWindow).UnixNano()
	items := make([]HostActiveIPStats, 0)
	c.activeIPs.Range(func(key, value any) bool {
		record, ok := value.(*hostActiveIPRecord)
		if !ok || record == nil {
			c.deleteActiveIP(key)
			return true
		}

		lastSeen := record.lastSeenUnixNano.Load()
		activeConns := record.activeConns.Load()
		if activeConns <= 0 && lastSeen < cutoff {
			c.deleteActiveIP(key)
			return true
		}
		if lastSeen <= 0 {
			return true
		}

		items = append(items, HostActiveIPStats{
			IP:          record.ip,
			LastSeenAt:  time.Unix(0, lastSeen).UTC(),
			ActiveConns: activeConns,
		})
		return true
	})

	sort.Slice(items, func(i, j int) bool {
		if items[i].LastSeenAt.Equal(items[j].LastSeenAt) {
			return items[i].IP < items[j].IP
		}
		return items[i].LastSeenAt.After(items[j].LastSeenAt)
	})
	if len(items) > hostActiveIPMaxItems {
		items = items[:hostActiveIPMaxItems]
	}
	return items
}

func (h *Handler) lookupHostTrafficCounters(host string) (*hostTrafficCounters, string) {
	normalizedHost := normalizeTrafficHost(host)
	if normalizedHost == "" {
		return nil, ""
	}
	value, ok := h.trafficByHost.Load(normalizedHost)
	if !ok {
		return nil, normalizedHost
	}
	counters, ok := value.(*hostTrafficCounters)
	if !ok || counters == nil {
		return nil, normalizedHost
	}
	return counters, normalizedHost
}

func (h *Handler) getHostTrafficCounters(host string) *hostTrafficCounters {
	normalizedHost := normalizeTrafficHost(host)
	if normalizedHost == "" {
		return nil
	}
	if value, ok := h.trafficByHost.Load(normalizedHost); ok {
		if counters, ok := value.(*hostTrafficCounters); ok {
			return counters
		}
	}
	counters := &hostTrafficCounters{}
	actual, _ := h.trafficByHost.LoadOrStore(normalizedHost, counters)
	if existing, ok := actual.(*hostTrafficCounters); ok {
		return existing
	}
	return counters
}

func (h *Handler) activeTrafficHosts() map[string]struct{} {
	h.mu.RLock()
	defer h.mu.RUnlock()

	hosts := make(map[string]struct{}, len(h.HostRules))
	for _, rule := range h.HostRules {
		host := normalizeTrafficHost(rule.Host)
		if host == "" {
			continue
		}
		hosts[host] = struct{}{}
	}
	return hosts
}

func (h *Handler) GetTrafficStats(timestamp time.Time) TrafficStats {
	byHost := make([]HostTrafficStats, 0)
	activeHosts := h.activeTrafficHosts()
	h.trafficByHost.Range(func(key, value any) bool {
		host, ok := key.(string)
		if !ok || host == "" {
			return true
		}
		if _, ok := activeHosts[host]; !ok {
			h.trafficByHost.Delete(host)
			return true
		}
		counters, ok := value.(*hostTrafficCounters)
		if !ok || counters == nil {
			return true
		}
		byHost = append(byHost, HostTrafficStats{
			Host:          host,
			TotalIn:       counters.totalIn.Load(),
			TotalOut:      counters.totalOut.Load(),
			Error5xx:      counters.error5xx.Load(),
			ActiveIPCount: counters.activeIPCount(timestamp),
		})
		return true
	})
	sort.Slice(byHost, func(i, j int) bool {
		return byHost[i].Host < byHost[j].Host
	})

	byStream := make([]StreamTrafficStats, 0)
	activeStreams := h.activeTrafficStreams()
	h.trafficByStream.Range(func(key, value any) bool {
		streamKey, ok := key.(string)
		if !ok || streamKey == "" {
			return true
		}
		if _, ok := activeStreams[streamKey]; !ok {
			h.trafficByStream.Delete(streamKey)
			return true
		}
		counters, ok := value.(*streamTrafficCounters)
		if !ok || counters == nil {
			return true
		}
		byStream = append(byStream, StreamTrafficStats{
			Protocol:    counters.protocol,
			ListenPort:  counters.listenPort,
			Key:         streamKey,
			TotalIn:     counters.totalIn.Load(),
			TotalOut:    counters.totalOut.Load(),
			Error5xx:    counters.error5xx.Load(),
			ActiveConns: counters.activeConns.Load(),
		})
		return true
	})
	sort.Slice(byStream, func(i, j int) bool {
		return byStream[i].Key < byStream[j].Key
	})

	return TrafficStats{
		TotalIn:     h.trafficTotalIn.Load(),
		TotalOut:    h.trafficTotalOut.Load(),
		ActiveConns: h.activeLoggedInCount(timestamp),
		Error5xx:    h.trafficError5xx.Load(),
		ByHost:      byHost,
		ByStream:    byStream,
	}
}

func (h *Handler) GetHostActiveIPs(host string, timestamp time.Time) HostActiveIPsStats {
	normalizedHost := normalizeTrafficHost(host)
	result := HostActiveIPsStats{
		Host:          normalizedHost,
		WindowSeconds: int(hostActiveIPWindow.Seconds()),
		Items:         []HostActiveIPStats{},
	}
	if normalizedHost == "" {
		return result
	}

	activeHosts := h.activeTrafficHosts()
	if _, ok := activeHosts[normalizedHost]; !ok {
		h.trafficByHost.Delete(normalizedHost)
		return result
	}

	counters, _ := h.lookupHostTrafficCounters(normalizedHost)
	if counters == nil {
		return result
	}

	result.Items = counters.activeIPStats(timestamp)
	return result
}

func (h *Handler) AddStreamTraffic(protocol string, listenPort int, bytesIn, bytesOut uint64, status int) {
	var counters *streamTrafficCounters
	if protocol != "" && listenPort > 0 {
		counters = h.getStreamTrafficCounters(protocol, listenPort)
	}
	h.addStreamTraffic(counters, bytesIn, bytesOut, status)
}

// NewStreamTrafficRecorder resolves a stream counter once for use by a relay's
// per-write hot path. Invalid stream identities return nil.
func (h *Handler) NewStreamTrafficRecorder(protocol string, listenPort int) *StreamTrafficRecorder {
	if protocol == "" || listenPort <= 0 {
		return nil
	}
	return &StreamTrafficRecorder{
		handler:  h,
		counters: h.getStreamTrafficCounters(protocol, listenPort),
	}
}

// Add publishes completed relay writes and an optional final status.
func (r *StreamTrafficRecorder) Add(bytesIn, bytesOut uint64, status int) {
	if r == nil || r.handler == nil {
		return
	}
	r.handler.addStreamTraffic(r.counters, bytesIn, bytesOut, status)
}

func (h *Handler) addStreamTraffic(counters *streamTrafficCounters, bytesIn, bytesOut uint64, status int) {
	if bytesIn > 0 {
		h.trafficTotalIn.Add(bytesIn)
	}
	if bytesOut > 0 {
		h.trafficTotalOut.Add(bytesOut)
	}
	if status >= 500 {
		h.trafficError5xx.Add(1)
	}
	if counters == nil {
		return
	}
	if bytesIn > 0 {
		counters.totalIn.Add(bytesIn)
	}
	if bytesOut > 0 {
		counters.totalOut.Add(bytesOut)
	}
	if status >= 500 {
		counters.error5xx.Add(1)
	}
}

func (h *Handler) AddStreamConn(protocol string, listenPort int, delta int64) {
	if protocol == "" || listenPort <= 0 {
		return
	}
	counters := h.getStreamTrafficCounters(protocol, listenPort)
	counters.activeConns.Add(delta)
	if counters.activeConns.Load() < 0 {
		counters.activeConns.Store(0)
	}
}

func (h *Handler) getStreamTrafficCounters(protocol string, listenPort int) *streamTrafficCounters {
	key := protocol + "/" + strconv.Itoa(listenPort)
	if value, ok := h.trafficByStream.Load(key); ok {
		if counters, ok := value.(*streamTrafficCounters); ok {
			return counters
		}
	}
	counters := &streamTrafficCounters{protocol: protocol, listenPort: listenPort}
	actual, _ := h.trafficByStream.LoadOrStore(key, counters)
	if existing, ok := actual.(*streamTrafficCounters); ok {
		return existing
	}
	return counters
}

func (h *Handler) activeTrafficStreams() map[string]struct{} {
	h.mu.RLock()
	defer h.mu.RUnlock()

	streams := make(map[string]struct{}, len(h.StreamRules))
	for _, rule := range h.StreamRules {
		key := streamRuleMapKey(rule)
		if key == "" {
			continue
		}
		streams[key] = struct{}{}
	}
	return streams
}
