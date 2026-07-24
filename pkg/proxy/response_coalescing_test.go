package proxy

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"sync"
	"testing"
	"time"
)

type coalescingTestResponseWriter struct {
	mu      sync.Mutex
	header  http.Header
	status  int
	writes  [][]byte
	flushes int
	flushCh chan struct{}
}

func newCoalescingTestResponseWriter() *coalescingTestResponseWriter {
	return &coalescingTestResponseWriter{
		header:  make(http.Header),
		flushCh: make(chan struct{}, 1),
	}
}

func (w *coalescingTestResponseWriter) Header() http.Header {
	return w.header
}

func (w *coalescingTestResponseWriter) WriteHeader(statusCode int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.status == 0 {
		w.status = statusCode
	}
}

func (w *coalescingTestResponseWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.writes = append(w.writes, bytes.Clone(p))
	return len(p), nil
}

func (w *coalescingTestResponseWriter) FlushError() error {
	w.mu.Lock()
	w.flushes++
	w.mu.Unlock()
	select {
	case w.flushCh <- struct{}{}:
	default:
	}
	return nil
}

func (w *coalescingTestResponseWriter) snapshot() (writes [][]byte, flushes int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	writes = make([][]byte, len(w.writes))
	for i := range w.writes {
		writes[i] = bytes.Clone(w.writes[i])
	}
	return writes, w.flushes
}

func proxyResponseForCoalescing(contentType string) *http.Response {
	return &http.Response{
		StatusCode:    http.StatusOK,
		ContentLength: -1,
		Header:        http.Header{"Content-Type": []string{contentType}},
		Request:       &http.Request{Method: http.MethodGet},
	}
}

func TestShouldCoalesceProxyResponse(t *testing.T) {
	tests := []struct {
		name string
		resp *http.Response
		want bool
	}{
		{name: "octet stream", resp: proxyResponseForCoalescing("application/octet-stream"), want: true},
		{name: "octet stream parameters", resp: proxyResponseForCoalescing("application/octet-stream; charset=binary"), want: true},
		{name: "server sent events", resp: proxyResponseForCoalescing("text/event-stream"), want: false},
		{name: "grpc", resp: proxyResponseForCoalescing("application/grpc"), want: false},
		{name: "missing content type", resp: proxyResponseForCoalescing(""), want: false},
		{name: "nil response", resp: nil, want: false},
	}

	knownLength := proxyResponseForCoalescing("application/octet-stream")
	knownLength.ContentLength = 1024
	tests = append(tests, struct {
		name string
		resp *http.Response
		want bool
	}{name: "known length", resp: knownLength, want: false})

	streamingOptOut := proxyResponseForCoalescing("application/octet-stream")
	streamingOptOut.Header.Set("X-Accel-Buffering", "no")
	tests = append(tests, struct {
		name string
		resp *http.Response
		want bool
	}{name: "explicit streaming opt out", resp: streamingOptOut, want: false})

	withTrailer := proxyResponseForCoalescing("application/octet-stream")
	withTrailer.Trailer = http.Header{"X-Checksum": nil}
	tests = append(tests, struct {
		name string
		resp *http.Response
		want bool
	}{name: "response trailer", resp: withTrailer, want: false})

	headResponse := proxyResponseForCoalescing("application/octet-stream")
	headResponse.Request.Method = http.MethodHead
	tests = append(tests, struct {
		name string
		resp *http.Response
		want bool
	}{name: "head request", resp: headResponse, want: false})

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := shouldCoalesceProxyResponse(test.resp); got != test.want {
				t.Fatalf("shouldCoalesceProxyResponse() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestProxyResponseCoalescerCombinesWritesUpToBufferSize(t *testing.T) {
	dst := newCoalescingTestResponseWriter()
	writer := newProxyResponseCoalescer(dst)
	writer.maxLatency = time.Hour
	writer.configure(proxyResponseForCoalescing("application/octet-stream"))

	part := bytes.Repeat([]byte{0x5a}, 32*1024)
	for range proxyResponseCoalesceBufferSize / len(part) {
		n, err := writer.Write(part)
		if err != nil {
			t.Fatalf("Write() error = %v", err)
		}
		if n != len(part) {
			t.Fatalf("Write() = %d, want %d", n, len(part))
		}
		writer.Flush()
	}

	writes, flushes := dst.snapshot()
	if len(writes) != 1 {
		t.Fatalf("underlying writes = %d, want 1", len(writes))
	}
	if len(writes[0]) != proxyResponseCoalesceBufferSize {
		t.Fatalf("underlying write size = %d, want %d", len(writes[0]), proxyResponseCoalesceBufferSize)
	}
	if flushes != 0 {
		t.Fatalf("underlying flushes before finish = %d, want 0", flushes)
	}

	writer.finish(true)
	_, flushes = dst.snapshot()
	if flushes != 1 {
		t.Fatalf("underlying flushes after finish = %d, want 1", flushes)
	}
}

func TestProxyResponseCoalescerPassesLargeWritesThrough(t *testing.T) {
	dst := newCoalescingTestResponseWriter()
	writer := newProxyResponseCoalescer(dst)
	writer.maxLatency = time.Hour
	writer.configure(proxyResponseForCoalescing("application/octet-stream"))

	part := bytes.Repeat([]byte{0x3f}, proxyResponseDirectWriteSize)
	for range 2 {
		if _, err := writer.Write(part); err != nil {
			t.Fatalf("Write() error = %v", err)
		}
		writer.Flush()
	}

	writes, flushes := dst.snapshot()
	if len(writes) != 2 {
		t.Fatalf("underlying writes = %d, want 2", len(writes))
	}
	for i := range writes {
		if !bytes.Equal(writes[i], part) {
			t.Fatalf("underlying write %d differs from input", i)
		}
	}
	if flushes != 0 {
		t.Fatalf("underlying flushes before finish = %d, want 0", flushes)
	}
	writer.finish(true)
}

func TestProxyResponseCoalescerFlushesAfterMaximumLatency(t *testing.T) {
	dst := newCoalescingTestResponseWriter()
	writer := newProxyResponseCoalescer(dst)
	writer.maxLatency = time.Millisecond
	writer.configure(proxyResponseForCoalescing("application/octet-stream"))
	t.Cleanup(func() {
		writer.finish(true)
	})

	payload := bytes.Repeat([]byte{0x6b}, 32*1024)
	if _, err := writer.Write(payload); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	writer.Flush()

	select {
	case <-dst.flushCh:
	case <-time.After(time.Second):
		t.Fatal("maximum-latency flush did not run")
	}

	writes, flushes := dst.snapshot()
	if len(writes) != 1 || !bytes.Equal(writes[0], payload) {
		t.Fatalf("delayed writes = %d, want one intact payload", len(writes))
	}
	if flushes != 1 {
		t.Fatalf("delayed flushes = %d, want 1", flushes)
	}
}

func TestProxyResponseCoalescerPassesStreamingResponsesThrough(t *testing.T) {
	dst := newCoalescingTestResponseWriter()
	writer := newProxyResponseCoalescer(dst)
	writer.configure(proxyResponseForCoalescing("text/event-stream"))

	payload := []byte("data: ready\n\n")
	if _, err := writer.Write(payload); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if err := writer.FlushError(); err != nil {
		t.Fatalf("FlushError() error = %v", err)
	}

	writes, flushes := dst.snapshot()
	if len(writes) != 1 || !bytes.Equal(writes[0], payload) {
		t.Fatalf("streaming writes = %d, want one intact payload", len(writes))
	}
	if flushes != 1 {
		t.Fatalf("streaming flushes = %d, want 1", flushes)
	}
	writer.finish(true)
}

type coalescingTestRoundTripper func(*http.Request) (*http.Response, error)

func (fn coalescingTestRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

type coalescingTestChunkReader struct {
	reader *bytes.Reader
	size   int
}

func (r *coalescingTestChunkReader) Read(p []byte) (int, error) {
	if len(p) > r.size {
		p = p[:r.size]
	}
	return r.reader.Read(p)
}

func TestServeReverseProxyWithResponseCoalescing(t *testing.T) {
	payload := bytes.Repeat([]byte{0x2c}, proxyResponseCoalesceBufferSize)
	proxy := &httputil.ReverseProxy{
		BufferPool: sharedProxyBufferPool,
		Rewrite:    func(*httputil.ProxyRequest) {},
		Transport: coalescingTestRoundTripper(func(request *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/octet-stream"}},
				Body: io.NopCloser(&coalescingTestChunkReader{
					reader: bytes.NewReader(payload),
					size:   32 * 1024,
				}),
				ContentLength: -1,
				Request:       request,
			}, nil
		}),
	}

	dst := newCoalescingTestResponseWriter()
	request := httptest.NewRequest(http.MethodGet, "http://proxy.test/download", nil)
	serveReverseProxyWithResponseCoalescing(proxy, dst, request)

	writes, flushes := dst.snapshot()
	if len(writes) != 1 {
		t.Fatalf("underlying writes = %d, want 1", len(writes))
	}
	if !bytes.Equal(writes[0], payload) {
		t.Fatal("coalesced proxy payload differs from upstream")
	}
	if flushes != 1 {
		t.Fatalf("underlying flushes = %d, want 1", flushes)
	}
}
