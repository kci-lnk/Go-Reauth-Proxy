package proxy

import (
	"sync"
	"sync/atomic"

	"go-reauth-proxy/pkg/diagnostics"
)

// Observe fixed-capacity reuse without changing GC-managed retention.
// Aggressive idle limits increase allocations under concurrent downloads.
type coalescingBufferPool struct {
	pool        sync.Pool
	size        int
	active      atomic.Int64
	gets        atomic.Uint64
	allocations atomic.Uint64
}

func newCoalescingBufferPool(size int) *coalescingBufferPool {
	p := &coalescingBufferPool{size: size}
	p.pool.New = func() any {
		p.allocations.Add(1)
		b := make([]byte, size)
		return &b
	}
	return p
}

func (p *coalescingBufferPool) get() []byte {
	p.gets.Add(1)
	p.active.Add(int64(p.size))
	return acquireExactSizeBuffer(&p.pool)
}

func (p *coalescingBufferPool) put(buf []byte) {
	if cap(buf) != p.size {
		return
	}
	p.active.Add(-int64(p.size))
	releaseExactSizeBuffer(&p.pool, buf)
}

func (p *coalescingBufferPool) snapshot() diagnostics.BufferPoolSnapshot {
	// Read allocations first: an allocation is always preceded by a get.
	// Counters are independent atomic observations, not a transactional snapshot.
	allocations := p.allocations.Load()
	gets := p.gets.Load()
	return diagnostics.BufferPoolSnapshot{
		CapacityBytes: p.size,
		ActiveBytes:   p.active.Load(),
		ReuseHits:     gets - allocations,
		Allocations:   allocations,
		CachePolicy:   "gc_managed",
	}
}

func init() {
	diagnostics.SetBufferPoolSnapshotSource(func() []diagnostics.BufferPoolSnapshot {
		return []diagnostics.BufferPoolSnapshot{
			proxyResponseCoalesceMediumBufferPool.snapshot(),
			proxyResponseCoalesceBufferPool.snapshot(),
		}
	})
}
