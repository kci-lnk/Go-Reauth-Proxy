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
	proxyResponseCoalesceMediumBufferSize = 256 * 1024
	proxyResponseCoalesceBufferSize       = 2 * 1024 * 1024
	proxyResponseCoalesceMaxLatency       = 10 * time.Millisecond
	proxyResponseCoalesceSlowWrite        = 5 * time.Millisecond
	proxyResponseCoalesceBudgetBytes      = 64 * 1024 * 1024
	proxySmallCopyBufferSize              = 32 * 1024
	proxyResponseDirectWriteSize          = proxyCopyBufferSize
)

var (
	proxyResponseCoalesceSmallBufferPool  = newExactSizeBufferPool(proxyResponseCoalesceSmallBufferSize)
	proxyResponseCoalesceMediumBufferPool = newExactSizeBufferPool(proxyResponseCoalesceMediumBufferSize)
	proxyResponseCoalesceBufferPool       = newExactSizeBufferPool(proxyResponseCoalesceBufferSize)
	proxyResponseCoalesceActiveBytes      atomic.Int64
	sharedProxySmallBufferPool            = newProxyBufferPool(proxySmallCopyBufferSize)
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

// Reserve before obtaining a large buffer. Exhaustion keeps the smaller tier
// usable, so concurrent downloads share a process budget without being rejected.
func tryAcquireProxyResponseCoalesceBuffer(size int) []byte {
	for {
		used := proxyResponseCoalesceActiveBytes.Load()
		if int64(size) > proxyResponseCoalesceBudgetBytes-used {
			return nil
		}
		if proxyResponseCoalesceActiveBytes.CompareAndSwap(used, used+int64(size)) {
			break
		}
	}
	if size == proxyResponseCoalesceMediumBufferSize {
		return acquireExactSizeBuffer(&proxyResponseCoalesceMediumBufferPool)
	}
	return acquireExactSizeBuffer(&proxyResponseCoalesceBufferPool)
}

func releaseProxyResponseCoalesceBuffer(buf []byte) {
	if buf == nil {
		return
	}
	switch cap(buf) {
	case proxyResponseCoalesceSmallBufferSize:
		releaseExactSizeBuffer(&proxyResponseCoalesceSmallBufferPool, buf)
	case proxyResponseCoalesceMediumBufferSize:
		proxyResponseCoalesceActiveBytes.Add(-int64(cap(buf)))
		releaseExactSizeBuffer(&proxyResponseCoalesceMediumBufferPool, buf)
	case proxyResponseCoalesceBufferSize:
		proxyResponseCoalesceActiveBytes.Add(-int64(cap(buf)))
		releaseExactSizeBuffer(&proxyResponseCoalesceBufferPool, buf)
	}
}

func growProxyResponseCoalesceBuffer(buf []byte) []byte {
	if cap(buf) >= proxyResponseCoalesceBufferSize {
		return buf
	}
	var next []byte
	if cap(buf) < proxyResponseCoalesceMediumBufferSize {
		next = tryAcquireProxyResponseCoalesceBuffer(proxyResponseCoalesceMediumBufferSize)
	} else {
		next = tryAcquireProxyResponseCoalesceBuffer(proxyResponseCoalesceBufferSize)
	}
	if next == nil {
		return buf
	}
	next = append(next, buf...)
	releaseProxyResponseCoalesceBuffer(buf)
	return next
}

func promoteProxyResponseCoalesceBuffer(buf []byte) []byte {
	if cap(buf) >= proxyResponseCoalesceBufferSize {
		return buf
	}
	next := tryAcquireProxyResponseCoalesceBuffer(proxyResponseCoalesceBufferSize)
	if next == nil {
		return buf
	}
	next = append(next, buf...)
	releaseProxyResponseCoalesceBuffer(buf)
	return next
}

// proxyResponseCoalescer combines successive writes for bulk responses when
// ReverseProxy's normal copy cadence is measurably slow. Unknown-length binary
// responses start buffered because ReverseProxy otherwise flushes every write;
// known-length responses remain direct until downstream backpressure is seen.
type proxyResponseCoalescer struct {
	http.ResponseWriter

	mu         sync.Mutex
	buffer     []byte
	timer      *time.Timer
	maxLatency time.Duration
	mode       atomic.Uint32
	closed     bool
	flushError error
	preferMax  bool
	adaptive   bool
	remaining  int64
}

func newProxyResponseCoalescer(w http.ResponseWriter) *proxyResponseCoalescer {
	return &proxyResponseCoalescer{
		ResponseWriter: w,
		maxLatency:     proxyResponseCoalesceMaxLatency,
		remaining:      -1,
	}
}

type proxyResponseCoalescingMode uint8

const (
	proxyResponseCoalescingDisabled proxyResponseCoalescingMode = iota
	proxyResponseCoalescingBuffered
	proxyResponseCoalescingAdaptive
)

func responseCoalescingMode(resp *http.Response) proxyResponseCoalescingMode {
	if resp == nil ||
		resp.StatusCode < http.StatusOK ||
		resp.StatusCode == http.StatusNoContent ||
		resp.StatusCode == http.StatusNotModified ||
		len(resp.Trailer) > 0 {
		return proxyResponseCoalescingDisabled
	}
	if resp.Request != nil && resp.Request.Method == http.MethodHead {
		return proxyResponseCoalescingDisabled
	}
	if strings.EqualFold(strings.TrimSpace(resp.Header.Get("X-Accel-Buffering")), "no") {
		return proxyResponseCoalescingDisabled
	}

	if resp.ContentLength != -1 {
		if resp.ContentLength < 2*proxyResponseDirectWriteSize {
			return proxyResponseCoalescingDisabled
		}
		contentType := responseMediaType(resp.Header.Get("Content-Type"))
		if strings.EqualFold(contentType, "text/event-stream") || hasPrefixFold(contentType, "application/grpc") {
			return proxyResponseCoalescingDisabled
		}
		return proxyResponseCoalescingAdaptive
	}
	contentType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err == nil && strings.EqualFold(contentType, "application/octet-stream") {
		return proxyResponseCoalescingBuffered
	}
	return proxyResponseCoalescingDisabled
}

func responseMediaType(value string) string {
	value = strings.TrimSpace(value)
	if separator := strings.IndexByte(value, ';'); separator >= 0 {
		value = strings.TrimSpace(value[:separator])
	}
	return value
}

func hasPrefixFold(value string, prefix string) bool {
	return len(value) >= len(prefix) && strings.EqualFold(value[:len(prefix)], prefix)
}

func shouldCoalesceProxyResponse(resp *http.Response) bool {
	return responseCoalescingMode(resp) != proxyResponseCoalescingDisabled
}

func (w *proxyResponseCoalescer) configure(resp *http.Response) bool {
	mode := responseCoalescingMode(resp)
	if w == nil || mode == proxyResponseCoalescingDisabled {
		return false
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed || proxyResponseCoalescingMode(w.mode.Load()) != proxyResponseCoalescingDisabled {
		return false
	}
	w.adaptive = mode == proxyResponseCoalescingAdaptive
	w.remaining = resp.ContentLength
	w.mode.Store(uint32(mode))
	return mode == proxyResponseCoalescingBuffered
}

func (w *proxyResponseCoalescer) WriteHeader(statusCode int) {
	mode := proxyResponseCoalescingMode(w.mode.Load())
	if mode == proxyResponseCoalescingDisabled {
		w.ResponseWriter.WriteHeader(statusCode)
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *proxyResponseCoalescer) Write(p []byte) (int, error) {
	mode := proxyResponseCoalescingMode(w.mode.Load())
	if mode == proxyResponseCoalescingDisabled {
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
	if len(p) == 0 {
		return 0, nil
	}
	if mode == proxyResponseCoalescingAdaptive || len(p) >= proxyResponseDirectWriteSize && !w.preferMax {
		if err := w.flushBufferLocked(); err != nil {
			return 0, err
		}
		started := time.Now()
		n, err := w.ResponseWriter.Write(p)
		if err == nil && n != len(p) {
			err = io.ErrShortWrite
		}
		w.observeWriteLocked(time.Since(started), err)
		w.acceptBytesLocked(n)
		if err != nil {
			w.flushError = err
		}
		if mode == proxyResponseCoalescingAdaptive && w.preferMax {
			w.mode.Store(uint32(proxyResponseCoalescingBuffered))
		} else if !w.adaptive {
			w.scheduleFlushLocked()
		}
		return n, err
	}
	if w.buffer == nil {
		w.buffer = acquireProxyResponseCoalesceBuffer()
	}

	accepted := 0
	for len(p) > 0 {
		available := cap(w.buffer) - len(w.buffer)
		if available == 0 {
			// Grow only in response to actual buffered data, never because a
			// previous single write happened to be slow. Known response tails
			// cannot promote beyond their required size class.
			maximum := w.maxBufferCapacityLocked()
			if cap(w.buffer) == proxyResponseCoalesceSmallBufferSize && w.preferMax &&
				maximum == proxyResponseCoalesceBufferSize &&
				len(p) >= proxyResponseCoalesceMediumBufferSize-len(w.buffer) {
				// A full medium tier is already available in this Write. Skip
				// its temporary allocation and copy; if the bulk reservation
				// fails, the normal tiered growth below can still use a smaller
				// buffer. Small bursts continue to grow one tier at a time.
				w.buffer = promoteProxyResponseCoalesceBuffer(w.buffer)
			}
			if cap(w.buffer) < maximum {
				w.buffer = growProxyResponseCoalesceBuffer(w.buffer)
			}
			if len(w.buffer) == cap(w.buffer) {
				if err := w.flushBufferLocked(); err != nil {
					return accepted, err
				}
			}
			available = cap(w.buffer) - len(w.buffer)
		}
		next := min(len(p), available)
		w.buffer = append(w.buffer, p[:next]...)
		p = p[next:]
		accepted += next
		w.acceptBytesLocked(next)
		if len(w.buffer) == proxyResponseCoalesceBufferSize {
			if err := w.flushBufferLocked(); err != nil {
				return accepted, err
			}
		}
	}
	w.scheduleFlushLocked()
	return accepted, nil
}

func (w *proxyResponseCoalescer) observeWriteLocked(elapsed time.Duration, err error) {
	if err == nil && elapsed >= proxyResponseCoalesceSlowWrite {
		// TCP backpressure can alternate slow writes with short, fast writes.
		// Keep the preference for this response; actual buffered data, the
		// remaining body and the process budget still govern buffer growth.
		w.preferMax = true
	}
}

func (w *proxyResponseCoalescer) acceptBytesLocked(n int) {
	if w.remaining >= 0 {
		w.remaining = max(0, w.remaining-int64(n))
	}
}

func (w *proxyResponseCoalescer) maxBufferCapacityLocked() int {
	maximum := proxyResponseCoalesceMediumBufferSize
	if w.preferMax {
		maximum = proxyResponseCoalesceBufferSize
	}
	if w.remaining >= 0 {
		pending := w.remaining + int64(len(w.buffer))
		if pending <= proxyResponseCoalesceSmallBufferSize {
			return proxyResponseCoalesceSmallBufferSize
		}
		if pending <= proxyResponseCoalesceMediumBufferSize {
			return proxyResponseCoalesceMediumBufferSize
		}
	}
	return maximum
}

func (w *proxyResponseCoalescer) Flush() {
	_ = w.FlushError()
}

func (w *proxyResponseCoalescer) FlushError() error {
	mode := proxyResponseCoalescingMode(w.mode.Load())
	if mode == proxyResponseCoalescingDisabled {
		return http.NewResponseController(w.ResponseWriter).Flush()
	}
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed || w.flushError != nil {
		return w.flushError
	}
	if w.adaptive {
		if err := w.flushBufferLocked(); err != nil {
			return err
		}
		w.releaseIdleBufferLocked()
		w.flushError = http.NewResponseController(w.ResponseWriter).Flush()
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
		w.releaseIdleBufferLocked()
		return
	}
	// A latency flush marks a gap in upstream data. Do not keep a bulk
	// buffer reserved while an otherwise idle stream waits for more data.
	w.releaseIdleBufferLocked()
	if err := http.NewResponseController(w.ResponseWriter).Flush(); err != nil {
		w.flushError = err
	}
}

func (w *proxyResponseCoalescer) releaseIdleBufferLocked() {
	if len(w.buffer) == 0 && cap(w.buffer) >= proxyResponseCoalesceMediumBufferSize {
		releaseProxyResponseCoalesceBuffer(w.buffer)
		w.buffer = nil
	}
}

func (w *proxyResponseCoalescer) flushBufferLocked() error {
	if len(w.buffer) == 0 {
		return nil
	}
	started := time.Now()
	n, err := w.ResponseWriter.Write(w.buffer)
	if err == nil && n != len(w.buffer) {
		err = io.ErrShortWrite
	}
	w.observeWriteLocked(time.Since(started), err)
	w.buffer = w.buffer[:0]
	if err != nil {
		w.flushError = err
	}
	return err
}

func (w *proxyResponseCoalescer) finish(completed bool) {
	if w == nil {
		return
	}
	mode := proxyResponseCoalescingMode(w.mode.Load())
	if mode == proxyResponseCoalescingDisabled {
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
	if w.adaptive && w.buffer == nil {
		w.mu.Unlock()
		return
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
	serveReverseProxyWithResponseCoalescer(proxy, writer, r)
}

func serveReverseProxyWithResponseCoalescer(proxy *httputil.ReverseProxy, writer *proxyResponseCoalescer, r *http.Request) {
	proxyCopy := *proxy
	originalModifyResponse := proxy.ModifyResponse
	proxyCopy.ModifyResponse = func(resp *http.Response) error {
		if originalModifyResponse != nil {
			if err := originalModifyResponse(resp); err != nil {
				return err
			}
		}
		stripTraceResponseHeaders(resp.Header)
		stripTraceResponseHeaders(resp.Trailer)
		if (proxy.BufferPool == nil || proxy.BufferPool == sharedProxyBufferPool) && useSmallProxyCopyBuffer(resp) {
			// This is a per-request ReverseProxy copy: selection cannot change
			// the buffer size used by another request or the shared proxy.
			proxyCopy.BufferPool = sharedProxySmallBufferPool
		}
		if writer.configure(resp) {
			// ReverseProxy treats an unknown content length as a streaming
			// response and installs its own immediate-flush timer. The writer
			// above already provides bounded coalescing for this response, so
			// suppress that redundant layer without publishing a Content-Length
			// header or changing the body copied downstream.
			resp.ContentLength = 0
		}
		return nil
	}

	completed := false
	defer func() {
		writer.finish(completed)
	}()
	proxyCopy.ServeHTTP(writer, r)
	completed = true
}

func useSmallProxyCopyBuffer(resp *http.Response) bool {
	if resp == nil {
		return true
	}
	contentType := responseMediaType(resp.Header.Get("Content-Type"))
	if strings.EqualFold(contentType, "text/event-stream") || hasPrefixFold(contentType, "application/grpc") ||
		strings.EqualFold(strings.TrimSpace(resp.Header.Get("X-Accel-Buffering")), "no") {
		return true
	}
	if resp.ContentLength < 0 {
		return !strings.EqualFold(contentType, "application/octet-stream")
	}
	return resp.ContentLength < 2*proxyResponseDirectWriteSize
}
