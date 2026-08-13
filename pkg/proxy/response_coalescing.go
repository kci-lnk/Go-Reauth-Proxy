package proxy

import (
	"io"
	"mime"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	proxyResponseCoalesceSmallBufferSize  = 16 * 1024
	proxyResponseCoalesceMediumBufferSize = 64 * 1024
	proxyResponseCoalesceBufferSize       = 256 * 1024
	proxyResponseCoalesceMaxLatency       = 10 * time.Millisecond
	proxyResponseDirectWriteSize          = proxyCopyBufferSize
)

var (
	proxyResponseCoalesceSmallBufferPool  = newExactSizeBufferPool(proxyResponseCoalesceSmallBufferSize)
	proxyResponseCoalesceMediumBufferPool = newExactSizeBufferPool(proxyResponseCoalesceMediumBufferSize)
	proxyResponseCoalesceBufferPool       = newExactSizeBufferPool(proxyResponseCoalesceBufferSize)
)

// newExactSizeBufferPool returns a pool whose Get always yields a buffer with
// exactly the requested capacity. Unlike proxyBufferPool (whose empty-pool
// fallback allocates proxyCopyBufferSize), tiered coalescing buffers must keep
// their declared size so growth can reliably move to the next tier.
func newExactSizeBufferPool(size int) sync.Pool {
	return sync.Pool{
		New: func() any {
			buf := make([]byte, size)
			return &buf
		},
	}
}

func acquireExactSizeBuffer(pool *sync.Pool) []byte {
	bufp := pool.Get().(*[]byte)
	return (*bufp)[:0]
}

func releaseExactSizeBuffer(pool *sync.Pool, buf []byte) {
	buf = buf[:cap(buf)]
	pool.Put(&buf)
}

func acquireProxyResponseCoalesceBuffer() []byte {
	return acquireExactSizeBuffer(&proxyResponseCoalesceSmallBufferPool)
}

func releaseProxyResponseCoalesceBuffer(buf []byte) {
	if buf == nil {
		return
	}
	switch cap(buf) {
	case proxyResponseCoalesceSmallBufferSize:
		releaseExactSizeBuffer(&proxyResponseCoalesceSmallBufferPool, buf)
	case proxyResponseCoalesceMediumBufferSize:
		releaseExactSizeBuffer(&proxyResponseCoalesceMediumBufferPool, buf)
	default:
		releaseExactSizeBuffer(&proxyResponseCoalesceBufferPool, buf)
	}
}

func growProxyResponseCoalesceBuffer(buf []byte) []byte {
	var next []byte
	if cap(buf) < proxyResponseCoalesceMediumBufferSize {
		next = acquireExactSizeBuffer(&proxyResponseCoalesceMediumBufferPool)
	} else {
		next = acquireExactSizeBuffer(&proxyResponseCoalesceBufferPool)
	}
	next = append(next, buf...)
	releaseProxyResponseCoalesceBuffer(buf)
	return next
}

// proxyResponseCoalescer combines successive writes for bulk, unknown-length
// responses. ReverseProxy otherwise flushes every write for these responses,
// which turns a large upstream chunk into several smaller downstream writes.
type proxyResponseCoalescer struct {
	http.ResponseWriter

	mu         sync.Mutex
	buffer     []byte
	timer      *time.Timer
	maxLatency time.Duration
	enabled    atomic.Bool
	closed     bool
	flushError error
}

func newProxyResponseCoalescer(w http.ResponseWriter) *proxyResponseCoalescer {
	return &proxyResponseCoalescer{
		ResponseWriter: w,
		maxLatency:     proxyResponseCoalesceMaxLatency,
	}
}

func shouldCoalesceProxyResponse(resp *http.Response) bool {
	if resp == nil ||
		resp.ContentLength != -1 ||
		resp.StatusCode < http.StatusOK ||
		resp.StatusCode == http.StatusNoContent ||
		resp.StatusCode == http.StatusNotModified ||
		len(resp.Trailer) > 0 {
		return false
	}
	if resp.Request != nil && resp.Request.Method == http.MethodHead {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(resp.Header.Get("X-Accel-Buffering")), "no") {
		return false
	}

	contentType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	return err == nil && strings.EqualFold(contentType, "application/octet-stream")
}

func (w *proxyResponseCoalescer) configure(resp *http.Response) {
	if w == nil || !shouldCoalesceProxyResponse(resp) {
		return
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed || w.enabled.Load() {
		return
	}
	w.enabled.Store(true)
}

func (w *proxyResponseCoalescer) WriteHeader(statusCode int) {
	if !w.enabled.Load() {
		w.ResponseWriter.WriteHeader(statusCode)
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *proxyResponseCoalescer) Write(p []byte) (int, error) {
	if !w.enabled.Load() {
		return w.ResponseWriter.Write(p)
	}
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return 0, io.ErrClosedPipe
	}
	if w.flushError != nil {
		return 0, w.flushError
	}
	if len(p) >= proxyResponseDirectWriteSize {
		if err := w.flushBufferLocked(); err != nil {
			return 0, err
		}
		n, err := w.ResponseWriter.Write(p)
		if err == nil && n != len(p) {
			err = io.ErrShortWrite
		}
		if err != nil {
			w.flushError = err
		}
		w.scheduleFlushLocked()
		return n, err
	}
	if w.buffer == nil {
		w.buffer = acquireProxyResponseCoalesceBuffer()
	}

	accepted := 0
	for len(p) > 0 {
		available := cap(w.buffer) - len(w.buffer)
		if available == 0 {
			if cap(w.buffer) >= proxyResponseCoalesceBufferSize {
				if err := w.flushBufferLocked(); err != nil {
					return accepted, err
				}
			} else {
				w.buffer = growProxyResponseCoalesceBuffer(w.buffer)
			}
			available = cap(w.buffer) - len(w.buffer)
		}

		next := len(p)
		if next > available {
			next = available
		}
		w.buffer = append(w.buffer, p[:next]...)
		p = p[next:]
		accepted += next

		// Smaller tiers grow into the next size class; only a full max-size
		// buffer is flushed immediately (matching the previous single-tier
		// behavior where the 1 MiB buffer was written as soon as it filled).
		if len(w.buffer) == cap(w.buffer) && cap(w.buffer) >= proxyResponseCoalesceBufferSize {
			if err := w.flushBufferLocked(); err != nil {
				return accepted, err
			}
		}
	}
	w.scheduleFlushLocked()
	return accepted, nil
}

func (w *proxyResponseCoalescer) Flush() {
	_ = w.FlushError()
}

func (w *proxyResponseCoalescer) FlushError() error {
	if !w.enabled.Load() {
		return http.NewResponseController(w.ResponseWriter).Flush()
	}
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed || w.flushError != nil {
		return w.flushError
	}
	w.scheduleFlushLocked()
	return nil
}

func (w *proxyResponseCoalescer) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func (w *proxyResponseCoalescer) scheduleFlushLocked() {
	if w.timer != nil || w.closed {
		return
	}
	w.timer = time.AfterFunc(w.maxLatency, w.flushAfterDelay)
}

func (w *proxyResponseCoalescer) flushAfterDelay() {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.timer = nil
	if w.closed || w.flushError != nil {
		return
	}
	if err := w.flushBufferLocked(); err != nil {
		return
	}
	if err := http.NewResponseController(w.ResponseWriter).Flush(); err != nil {
		w.flushError = err
	}
}

func (w *proxyResponseCoalescer) flushBufferLocked() error {
	if len(w.buffer) == 0 {
		return nil
	}
	n, err := w.ResponseWriter.Write(w.buffer)
	if err == nil && n != len(w.buffer) {
		err = io.ErrShortWrite
	}
	w.buffer = w.buffer[:0]
	if err != nil {
		w.flushError = err
	}
	return err
}

func (w *proxyResponseCoalescer) finish(completed bool) {
	if w == nil || !w.enabled.Load() {
		return
	}

	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return
	}
	w.closed = true
	if w.timer != nil {
		w.timer.Stop()
		w.timer = nil
	}

	if completed && w.flushError == nil {
		if err := w.flushBufferLocked(); err == nil {
			if err := http.NewResponseController(w.ResponseWriter).Flush(); err != nil {
				w.flushError = err
			}
		}
	} else {
		w.buffer = w.buffer[:0]
	}

	buffer := w.buffer
	w.buffer = nil
	w.mu.Unlock()

	if buffer != nil {
		releaseProxyResponseCoalesceBuffer(buffer)
	}
}

func serveReverseProxyWithResponseCoalescing(proxy *httputil.ReverseProxy, w http.ResponseWriter, r *http.Request) {
	if proxy == nil {
		return
	}

	writer := newProxyResponseCoalescer(w)
	proxyCopy := *proxy
	originalModifyResponse := proxy.ModifyResponse
	proxyCopy.ModifyResponse = func(resp *http.Response) error {
		if originalModifyResponse != nil {
			if err := originalModifyResponse(resp); err != nil {
				return err
			}
		}
		writer.configure(resp)
		return nil
	}

	completed := false
	defer func() {
		writer.finish(completed)
	}()
	proxyCopy.ServeHTTP(writer, r)
	completed = true
}
