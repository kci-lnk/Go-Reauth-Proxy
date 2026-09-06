package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"sync"
	"testing"
	"time"

	"go-reauth-proxy/pkg/diagnostics"
)

func TestProxyBufferPoolKeepsRequestedCapacity(t *testing.T) {
	for _, size := range []int{proxySmallCopyBufferSize, proxyCopyBufferSize} {
		p := newProxyBufferPool(size)
		p.Put(make([]byte, size*2))
		for i := 0; i < 8; i++ {
			b := p.Get()
			if len(b) != size || cap(b) != size {
				t.Fatalf("got %d/%d want %d", len(b), cap(b), size)
			}
			p.Put(b[:0])
		}
		// Exercise the empty-pool invalid-value fallback without depending on
		// sync.Pool's nondeterministic retention across a garbage collection.
		p = &proxyBufferPool{size: size, pool: sync.Pool{New: func() any { return "invalid" }}}
		if b := p.Get(); len(b) != size || cap(b) != size {
			t.Fatal("fallback ignored target size")
		}
	}
}

func TestCoalescingInvalidTierDoesNotReserve(t *testing.T) {
	before := proxyResponseCoalesceActiveBytes.Load()
	if tryAcquireProxyResponseCoalesceBuffer(1) != nil || proxyResponseCoalesceActiveBytes.Load() != before {
		t.Fatal("invalid tier acquired a reservation")
	}
}

type cancelledCoalescingBody struct {
	data   []byte
	cancel func()
}

func (b *cancelledCoalescingBody) Read(dst []byte) (int, error) {
	if len(b.data) > 0 {
		n := copy(dst, b.data[:min(len(b.data), 32<<10)])
		b.data = b.data[n:]
		return n, nil
	}
	b.cancel()
	return 0, context.Canceled
}
func (b *cancelledCoalescingBody) Close() error { return nil }

type failedCoalescingWriter struct{ *coalescingTestResponseWriter }

func (w failedCoalescingWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestCoalescingPoolReleaseOnProxyFailure(t *testing.T) {
	for _, cancelled := range []bool{true, false} {
		t.Run(fmt.Sprint("cancelled=", cancelled), func(t *testing.T) {
			before := proxyResponseCoalesceActiveBytes.Load()
			mediumBefore := proxyResponseCoalesceMediumBufferPool.snapshot().ActiveBytes
			largeBefore := proxyResponseCoalesceBufferPool.snapshot().ActiveBytes
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var dst http.ResponseWriter = newCoalescingTestResponseWriter()
			if !cancelled {
				dst = failedCoalescingWriter{newCoalescingTestResponseWriter()}
			}
			proxy := &httputil.ReverseProxy{BufferPool: sharedProxyBufferPool, Rewrite: func(*httputil.ProxyRequest) {}, Transport: coalescingTestRoundTripper(func(r *http.Request) (*http.Response, error) {
				var body io.ReadCloser = io.NopCloser(&coalescingTestChunkReader{reader: bytes.NewReader(make([]byte, 512<<10)), size: 32 << 10})
				if cancelled {
					body = &cancelledCoalescingBody{data: make([]byte, 32<<10), cancel: cancel}
				}
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/octet-stream"}}, ContentLength: -1, Body: body, Request: r}, nil
			})}
			writer := newProxyResponseCoalescer(dst)
			writer.maxLatency = time.Hour
			func() {
				defer func() {
					if r := recover(); r != nil && r != http.ErrAbortHandler {
						panic(r)
					}
				}()
				serveReverseProxyWithResponseCoalescer(proxy, writer, httptest.NewRequest("GET", "http://proxy.test/", nil).WithContext(ctx))
			}()
			writer.finish(false) // idempotence must not double-return the reservation
			if proxyResponseCoalesceActiveBytes.Load() != before || proxyResponseCoalesceMediumBufferPool.snapshot().ActiveBytes != mediumBefore || proxyResponseCoalesceBufferPool.snapshot().ActiveBytes != largeBefore {
				t.Fatal("failure leaked or double-released a reservation")
			}
		})
	}
}

func TestCoalescingMetricsFollowReservation(t *testing.T) {
	before := proxyResponseCoalesceMediumBufferPool.snapshot().ActiveBytes
	b := tryAcquireProxyResponseCoalesceBuffer(proxyResponseCoalesceMediumBufferSize)
	if b == nil {
		t.Fatal("unexpected exhausted budget")
	}
	defer releaseProxyResponseCoalesceBuffer(b)
	data, err := json.Marshal(diagnostics.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	var snapshot struct {
		Pools []diagnostics.BufferPoolSnapshot `json:"coalescing_buffers"`
	}
	if err = json.Unmarshal(data, &snapshot); err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Pools) != 2 || snapshot.Pools[0].CapacityBytes != proxyResponseCoalesceMediumBufferSize || snapshot.Pools[0].ActiveBytes != before+proxyResponseCoalesceMediumBufferSize {
		t.Fatalf("unexpected pool metrics: %+v", snapshot.Pools)
	}
}

func TestCoalescingPoolObservesGCManagedReuse(t *testing.T) {
	p := newCoalescingBufferPool(proxyResponseCoalesceMediumBufferSize)
	b := p.get()
	p.put(make([]byte, 1))
	if s := p.snapshot(); s.ActiveBytes != int64(p.size) || s.Allocations != 1 || s.IdleBytes != nil || s.Discards != nil {
		t.Fatalf("initial: %+v", s)
	}
	p.put(b)
	for i := 0; i < 8; i++ {
		b = p.get()
		p.put(b)
	}
	s := p.snapshot()
	if s.ActiveBytes != 0 || s.Allocations+s.ReuseHits != 9 || s.CachePolicy != "gc_managed" {
		t.Fatalf("after reuse: %+v", s)
	}
	// sync.Pool is allowed to discard entries at any GC, so do not require a hit.
}

func TestCoalescingPoolConcurrentMetrics(t *testing.T) {
	p := newCoalescingBufferPool(proxyResponseCoalesceMediumBufferSize)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				b := p.get()
				p.put(b)
			}
		}()
	}
	wg.Wait()
	s := p.snapshot()
	if s.ActiveBytes != 0 || s.Allocations+s.ReuseHits != 3200 {
		t.Fatalf("concurrent metrics: %+v", s)
	}
}
