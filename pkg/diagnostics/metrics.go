package diagnostics

import (
	"encoding/json"
	"net/http"
	"runtime"
	"strconv"
	"sync/atomic"
	"time"
)

var latencyUpperBoundsMS = [...]uint64{1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000}

type counters struct {
	requestTotal         atomic.Uint64
	request2xx           atomic.Uint64
	request3xx           atomic.Uint64
	request4xx           atomic.Uint64
	request5xx           atomic.Uint64
	requestLatency       [len(latencyUpperBoundsMS) + 1]atomic.Uint64
	authBridgeRequests   atomic.Uint64
	authBridgeQueueDrops atomic.Uint64
	authBridgeQueueDepth atomic.Uint64
	authBridgeQueuePeak  atomic.Uint64
	authCacheHits        atomic.Uint64
	authCacheMisses      atomic.Uint64
	ruleEvaluations      atomic.Uint64
	ruleMatches          atomic.Uint64
	grantIssued          atomic.Uint64
	grantRenewed         atomic.Uint64
	grantReused          atomic.Uint64
	grantTransient       atomic.Uint64
	grantVersionRejected atomic.Uint64
	grantRateLimited     atomic.Uint64
	grantStorageErrors   atomic.Uint64
	udpQueueDrops        atomic.Uint64
	gatewayLogDrops      atomic.Uint64
}

var global counters
var enabled atomic.Bool

// SetEnabled controls hot-path metric collection. The diagnostics listener is
// disabled by default, so production requests pay only one atomic load unless
// the explicitly configured loopback endpoint is running.
func SetEnabled(value bool) {
	enabled.Store(value)
}

func Enabled() bool {
	return enabled.Load()
}

func ObserveHTTPRequest(elapsed time.Duration, status int) {
	if !enabled.Load() {
		return
	}
	global.requestTotal.Add(1)
	switch {
	case status >= 200 && status < 300:
		global.request2xx.Add(1)
	case status >= 300 && status < 400:
		global.request3xx.Add(1)
	case status >= 400 && status < 500:
		global.request4xx.Add(1)
	case status >= 500:
		global.request5xx.Add(1)
	}
	milliseconds := uint64(max(elapsed.Milliseconds(), 0))
	index := len(latencyUpperBoundsMS)
	for i, upperBound := range latencyUpperBoundsMS {
		if milliseconds <= upperBound {
			index = i
			break
		}
	}
	global.requestLatency[index].Add(1)
}

func RecordAuthBridgeRequest() {
	if enabled.Load() {
		global.authBridgeRequests.Add(1)
	}
}
func RecordAuthBridgeQueueDrop() {
	if enabled.Load() {
		global.authBridgeQueueDrops.Add(1)
	}
}

// ObserveAuthBridgeQueueDepth records the current depth of the active auth
// bridge writer queue and retains the highest observed depth. Queue depth is a
// process-level gauge, so it intentionally has no labels.
func ObserveAuthBridgeQueueDepth(depth uint64) {
	if !enabled.Load() {
		return
	}
	global.authBridgeQueueDepth.Store(depth)
	for {
		peak := global.authBridgeQueuePeak.Load()
		if depth <= peak || global.authBridgeQueuePeak.CompareAndSwap(peak, depth) {
			return
		}
	}
}

func RecordAuthCacheHit() {
	if enabled.Load() {
		global.authCacheHits.Add(1)
	}
}
func RecordAuthCacheMiss() {
	if enabled.Load() {
		global.authCacheMisses.Add(1)
	}
}
func RecordSubdomainRuleEvaluation() {
	if enabled.Load() {
		global.ruleEvaluations.Add(1)
	}
}
func RecordSubdomainRuleMatch() {
	if enabled.Load() {
		global.ruleMatches.Add(1)
	}
}
func RecordSubdomainGrantState(state string) {
	if !enabled.Load() {
		return
	}
	switch state {
	case "issued":
		global.grantIssued.Add(1)
	case "renewed":
		global.grantRenewed.Add(1)
	case "reused":
		global.grantReused.Add(1)
	case "transient":
		global.grantTransient.Add(1)
	}
}
func RecordSubdomainGrantVersionRejected() {
	if enabled.Load() {
		global.grantVersionRejected.Add(1)
	}
}
func RecordSubdomainGrantRateLimited() {
	if enabled.Load() {
		global.grantRateLimited.Add(1)
	}
}
func RecordSubdomainGrantStorageError() {
	if enabled.Load() {
		global.grantStorageErrors.Add(1)
	}
}
func RecordUDPQueueDrop() {
	if enabled.Load() {
		global.udpQueueDrops.Add(1)
	}
}
func RecordGatewayLogDrop() {
	if enabled.Load() {
		global.gatewayLogDrops.Add(1)
	}
}

type histogramBucket struct {
	UpperBoundMS string `json:"upper_bound_ms"`
	Count        uint64 `json:"count"`
}

type snapshot struct {
	Requests struct {
		Total   uint64            `json:"total"`
		ByClass map[string]uint64 `json:"by_status_class"`
		Latency []histogramBucket `json:"latency_buckets"`
	} `json:"requests"`
	Auth struct {
		BridgeRequests                uint64 `json:"bridge_requests"`
		BridgeQueueDrops              uint64 `json:"bridge_queue_drops"`
		BridgeQueueDepth              uint64 `json:"bridge_queue_depth"`
		BridgeQueueDepthPeak          uint64 `json:"bridge_queue_depth_peak"`
		CacheHits                     uint64 `json:"cache_hits"`
		CacheMisses                   uint64 `json:"cache_misses"`
		SubdomainRuleEvaluations      uint64 `json:"subdomain_rule_evaluations"`
		SubdomainRuleMatches          uint64 `json:"subdomain_rule_matches"`
		SubdomainGrantIssued          uint64 `json:"subdomain_grant_issued"`
		SubdomainGrantRenewed         uint64 `json:"subdomain_grant_renewed"`
		SubdomainGrantReused          uint64 `json:"subdomain_grant_reused"`
		SubdomainGrantTransient       uint64 `json:"subdomain_grant_transient"`
		SubdomainGrantVersionRejected uint64 `json:"subdomain_grant_version_rejected"`
		SubdomainGrantRateLimited     uint64 `json:"subdomain_grant_rate_limited"`
		SubdomainGrantStorageErrors   uint64 `json:"subdomain_grant_storage_errors"`
	} `json:"auth"`
	UDP struct {
		QueueDrops uint64 `json:"queue_drops"`
	} `json:"udp"`
	GatewayLog struct {
		QueueDrops uint64 `json:"queue_drops"`
	} `json:"gateway_log"`
	Runtime struct {
		Goroutines   int    `json:"goroutines"`
		HeapAlloc    uint64 `json:"heap_alloc_bytes"`
		HeapInUse    uint64 `json:"heap_inuse_bytes"`
		SystemMemory uint64 `json:"system_memory_bytes"`
		NumGC        uint32 `json:"num_gc"`
	} `json:"runtime"`
}

func Snapshot() any {
	var result snapshot
	result.Requests.Total = global.requestTotal.Load()
	result.Requests.ByClass = map[string]uint64{
		"2xx": global.request2xx.Load(),
		"3xx": global.request3xx.Load(),
		"4xx": global.request4xx.Load(),
		"5xx": global.request5xx.Load(),
	}
	result.Requests.Latency = make([]histogramBucket, 0, len(global.requestLatency))
	for i := range global.requestLatency {
		upperBound := "+Inf"
		if i < len(latencyUpperBoundsMS) {
			upperBound = strconv.FormatUint(latencyUpperBoundsMS[i], 10)
		}
		result.Requests.Latency = append(result.Requests.Latency, histogramBucket{
			UpperBoundMS: upperBound,
			Count:        global.requestLatency[i].Load(),
		})
	}
	result.Auth.BridgeRequests = global.authBridgeRequests.Load()
	result.Auth.BridgeQueueDrops = global.authBridgeQueueDrops.Load()
	result.Auth.BridgeQueueDepth = global.authBridgeQueueDepth.Load()
	result.Auth.BridgeQueueDepthPeak = global.authBridgeQueuePeak.Load()
	result.Auth.CacheHits = global.authCacheHits.Load()
	result.Auth.CacheMisses = global.authCacheMisses.Load()
	result.Auth.SubdomainRuleEvaluations = global.ruleEvaluations.Load()
	result.Auth.SubdomainRuleMatches = global.ruleMatches.Load()
	result.Auth.SubdomainGrantIssued = global.grantIssued.Load()
	result.Auth.SubdomainGrantRenewed = global.grantRenewed.Load()
	result.Auth.SubdomainGrantReused = global.grantReused.Load()
	result.Auth.SubdomainGrantTransient = global.grantTransient.Load()
	result.Auth.SubdomainGrantVersionRejected = global.grantVersionRejected.Load()
	result.Auth.SubdomainGrantRateLimited = global.grantRateLimited.Load()
	result.Auth.SubdomainGrantStorageErrors = global.grantStorageErrors.Load()
	result.UDP.QueueDrops = global.udpQueueDrops.Load()
	result.GatewayLog.QueueDrops = global.gatewayLogDrops.Load()
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	result.Runtime.Goroutines = runtime.NumGoroutine()
	result.Runtime.HeapAlloc = memory.HeapAlloc
	result.Runtime.HeapInUse = memory.HeapInuse
	result.Runtime.SystemMemory = memory.Sys
	result.Runtime.NumGC = memory.NumGC
	return result
}

func Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		if err := json.NewEncoder(w).Encode(Snapshot()); err != nil {
			http.Error(w, "failed to encode metrics", http.StatusInternalServerError)
		}
	})
}
