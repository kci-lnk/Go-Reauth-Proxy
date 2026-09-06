package diagnostics

import "sync/atomic"

// BufferPoolSnapshot describes one fixed-capacity coalescing tier. Counters
// are lifetime totals; byte gauges count backing capacity, not payload length.
// IdleBytes and Discards are null for sync.Pool: GC can clear entries without
// notifying the application, so reporting exact values would be misleading.
type BufferPoolSnapshot struct {
	CachePolicy   string  `json:"cache_policy"`
	CapacityBytes int     `json:"capacity_bytes"`
	ActiveBytes   int64   `json:"active_bytes"`
	IdleBytes     *int    `json:"idle_bytes"`
	ReuseHits     uint64  `json:"reuse_hits"`
	Allocations   uint64  `json:"allocations"`
	Discards      *uint64 `json:"discards"`
}

var bufferPoolSnapshotSource atomic.Value

// SetBufferPoolSnapshotSource installs a cheap snapshot callback at startup.
// It avoids a diagnostics -> proxy dependency and does not inspect requests.
func SetBufferPoolSnapshotSource(source func() []BufferPoolSnapshot) {
	bufferPoolSnapshotSource.Store(source)
}
