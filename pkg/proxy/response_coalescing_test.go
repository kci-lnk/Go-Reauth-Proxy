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
	mu         sync.Mutex
	header     http.Header
	status     int
	writes     [][]byte
	flushes    int
	flushCh    chan struct{}
	delay      time.Duration
	delayAfter int
}

type proxyCopyTestRoundTripper func(*http.Request) (*http.Response, error)

func (fn proxyCopyTestRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
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
	if w.delay > 0 && len(w.writes) >= w.delayAfter {
		time.Sleep(w.delay)
	}
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

func (w *coalescingTestResponseWriter) Flush() {
	_ = w.FlushError()
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

func TestProxyResponseCoalescingUsesHighThroughputCapacities(t *testing.T) {
	if got, want := proxyResponseCoalesceMediumBufferSize, 256*1024; got != want {
		t.Fatalf("medium coalescing buffer = %d, want %d", got, want)
	}
	if got, want := proxyResponseCoalesceBufferSize, 2*1024*1024; got != want {
		t.Fatalf("maximum coalescing buffer = %d, want %d", got, want)
	}
	if got, want := proxyResponseDirectWriteSize, 256*1024; got != want {
		t.Fatalf("direct write size = %d, want %d", got, want)
	}
	buf := acquireProxyResponseCoalesceBuffer()
	buf = append(buf, 0x01)
	buf = growProxyResponseCoalesceBuffer(buf)
	if got, want := cap(buf), proxyResponseCoalesceMediumBufferSize; got != want {
		t.Fatalf("promoted coalescing buffer capacity = %d, want %d", got, want)
	}
	buf = promoteProxyResponseCoalesceBuffer(buf)
	if got, want := cap(buf), proxyResponseCoalesceBufferSize; got != want {
		t.Fatalf("maximum coalescing buffer capacity = %d, want %d", got, want)
	}
	releaseProxyResponseCoalesceBuffer(buf)
}

func TestReverseProxyUsesHighThroughputWriteGranularity(t *testing.T) {
	payload := bytes.Repeat([]byte{0x5a}, 2*1024*1024)
	proxy := &httputil.ReverseProxy{
		Director: func(*http.Request) {},
		Transport: proxyCopyTestRoundTripper(func(request *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode:    http.StatusOK,
				Header:        http.Header{"Content-Type": []string{"application/javascript"}},
				Body:          io.NopCloser(bytes.NewReader(payload)),
				ContentLength: int64(len(payload)),
				Request:       request,
			}, nil
		}),
		BufferPool: sharedProxyBufferPool,
	}
	w := newCoalescingTestResponseWriter()
	serveReverseProxyWithResponseCoalescing(proxy, w, httptest.NewRequest(http.MethodGet, "http://gateway.test/assets/app.js", nil))

	writes, _ := w.snapshot()
	if got, want := len(writes), len(payload)/proxyCopyBufferSize; got != want {
		t.Fatalf("downstream writes = %d, want %d writes of at most %d bytes", got, want, proxyCopyBufferSize)
	}
	if body := bytes.Join(writes, nil); !bytes.Equal(body, payload) {
		t.Fatal("downstream response differs from upstream payload")
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

	largeKnownLength := proxyResponseForCoalescing("application/javascript")
	largeKnownLength.ContentLength = 2 * 1024 * 1024
	tests = append(tests, struct {
		name string
		resp *http.Response
		want bool
	}{name: "large known length", resp: largeKnownLength, want: true})

	largeKnownSSE := proxyResponseForCoalescing("text/event-stream")
	largeKnownSSE.ContentLength = 2 * 1024 * 1024
	tests = append(tests, struct {
		name string
		resp *http.Response
		want bool
	}{name: "large known server sent events", resp: largeKnownSSE, want: false})

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

	for _, status := range []int{http.StatusSwitchingProtocols, http.StatusNoContent, http.StatusNotModified} {
		response := proxyResponseForCoalescing("application/octet-stream")
		response.StatusCode = status
		tests = append(tests, struct {
			name string
			resp *http.Response
			want bool
		}{name: http.StatusText(status), resp: response, want: false})
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := shouldCoalesceProxyResponse(test.resp); got != test.want {
				t.Fatalf("shouldCoalesceProxyResponse() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestProxyResponseCoalescerUsesMediumBufferForFastDownstream(t *testing.T) {
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
	wantWrites := proxyResponseCoalesceBufferSize / proxyResponseCoalesceMediumBufferSize
	if len(writes) != wantWrites-1 {
		t.Fatalf("underlying writes before finish = %d, want %d", len(writes), wantWrites-1)
	}
	for i := range writes {
		if len(writes[i]) != proxyResponseCoalesceMediumBufferSize {
			t.Fatalf("underlying write %d size = %d, want %d", i, len(writes[i]), proxyResponseCoalesceMediumBufferSize)
		}
	}
	if flushes != 0 {
		t.Fatalf("underlying flushes before finish = %d, want 0", flushes)
	}

	writer.finish(true)
	writes, flushes = dst.snapshot()
	if len(writes) != wantWrites {
		t.Fatalf("underlying writes after finish = %d, want %d", len(writes), wantWrites)
	}
	if len(writes[len(writes)-1]) != proxyResponseCoalesceMediumBufferSize {
		t.Fatalf("final underlying write size = %d, want %d", len(writes[len(writes)-1]), proxyResponseCoalesceMediumBufferSize)
	}
	if flushes != 1 {
		t.Fatalf("underlying flushes after finish = %d, want 1", flushes)
	}
}

func TestProxyResponseCoalescerPromotesBufferForSlowDownstream(t *testing.T) {
	dst := newCoalescingTestResponseWriter()
	dst.delay = 2 * proxyResponseCoalesceSlowWrite
	writer := newProxyResponseCoalescer(dst)
	writer.maxLatency = time.Hour
	writer.configure(proxyResponseForCoalescing("application/octet-stream"))

	part := bytes.Repeat([]byte{0x6b}, 32*1024)
	for range proxyResponseCoalesceBufferSize / len(part) {
		if _, err := writer.Write(part); err != nil {
			t.Fatalf("Write() error = %v", err)
		}
	}
	writer.finish(true)

	writes, _ := dst.snapshot()
	if got, want := len(writes), 2; got != want {
		t.Fatalf("underlying writes = %d, want %d after slow-downstream promotion", got, want)
	}
	if got, want := len(writes[0]), proxyResponseCoalesceMediumBufferSize; got != want {
		t.Fatalf("probe write size = %d, want %d", got, want)
	}
	if got, want := len(writes[1]), proxyResponseCoalesceBufferSize-proxyResponseCoalesceMediumBufferSize; got != want {
		t.Fatalf("promoted write size = %d, want %d", got, want)
	}
}

func TestProxyResponseCoalescerAdaptsKnownLengthForSlowDownstream(t *testing.T) {
	dst := newCoalescingTestResponseWriter()
	dst.delay = 2 * proxyResponseCoalesceSlowWrite
	writer := newProxyResponseCoalescer(dst)
	writer.maxLatency = time.Hour
	response := proxyResponseForCoalescing("application/javascript")
	response.ContentLength = 2 * 1024 * 1024
	if suppressUnknownLengthFlush := writer.configure(response); suppressUnknownLengthFlush {
		t.Fatal("known-length adaptive response requested unknown-length flush suppression")
	}

	part := bytes.Repeat([]byte{0x7c}, proxyResponseDirectWriteSize)
	for range int(response.ContentLength) / len(part) {
		if _, err := writer.Write(part); err != nil {
			t.Fatalf("Write() error = %v", err)
		}
	}
	writer.finish(true)

	writes, _ := dst.snapshot()
	if got, want := len(writes), 2; got != want {
		t.Fatalf("underlying writes = %d, want %d after adaptive promotion", got, want)
	}
	if got, want := len(writes[0]), proxyResponseDirectWriteSize; got != want {
		t.Fatalf("probe write size = %d, want %d", got, want)
	}
	if got, want := len(writes[1]), int(response.ContentLength)-proxyResponseDirectWriteSize; got != want {
		t.Fatalf("promoted write size = %d, want %d", got, want)
	}
}

func TestProxyResponseCoalescerDetectsLateKnownLengthBackpressure(t *testing.T) {
	dst := newCoalescingTestResponseWriter()
	dst.delay = 2 * proxyResponseCoalesceSlowWrite
	dst.delayAfter = 1
	writer := newProxyResponseCoalescer(dst)
	writer.maxLatency = time.Hour
	response := proxyResponseForCoalescing("application/javascript")
	response.ContentLength = 2 * 1024 * 1024
	writer.configure(response)

	part := bytes.Repeat([]byte{0x4d}, proxyResponseDirectWriteSize)
	for range int(response.ContentLength) / len(part) {
		if _, err := writer.Write(part); err != nil {
			t.Fatalf("Write() error = %v", err)
		}
	}
	writer.finish(true)

	writes, _ := dst.snapshot()
	if got, want := len(writes), 3; got != want {
		t.Fatalf("underlying writes = %d, want %d after late backpressure detection", got, want)
	}
	if got, want := len(writes[len(writes)-1]), int(response.ContentLength)-2*proxyResponseDirectWriteSize; got != want {
		t.Fatalf("coalesced tail size = %d, want %d", got, want)
	}
}

func TestProxyResponseCoalescerHonorsFlushAfterAdaptivePromotion(t *testing.T) {
	dst := newCoalescingTestResponseWriter()
	dst.delay = 2 * proxyResponseCoalesceSlowWrite
	writer := newProxyResponseCoalescer(dst)
	writer.maxLatency = time.Hour
	response := proxyResponseForCoalescing("application/javascript")
	response.ContentLength = 2 * 1024 * 1024
	writer.configure(response)

	part := bytes.Repeat([]byte{0x2a}, proxyResponseDirectWriteSize)
	if _, err := writer.Write(part); err != nil {
		t.Fatalf("probe Write() error = %v", err)
	}
	if _, err := writer.Write(part); err != nil {
		t.Fatalf("buffered Write() error = %v", err)
	}
	if err := writer.FlushError(); err != nil {
		t.Fatalf("FlushError() error = %v", err)
	}

	writes, flushes := dst.snapshot()
	if got, want := len(writes), 2; got != want {
		t.Fatalf("underlying writes = %d, want %d after explicit flush", got, want)
	}
	if !bytes.Equal(writes[1], part) {
		t.Fatal("explicit flush did not preserve the buffered payload")
	}
	if got, want := flushes, 1; got != want {
		t.Fatalf("underlying flushes = %d, want %d", got, want)
	}
	writer.finish(true)
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
	writer := newProxyResponseCoalescer(dst)
	writer.maxLatency = time.Hour
	request := httptest.NewRequest(http.MethodGet, "http://proxy.test/download", nil)
	serveReverseProxyWithResponseCoalescer(proxy, writer, request)

	writes, flushes := dst.snapshot()
	wantWrites := proxyResponseCoalesceBufferSize / proxyResponseCoalesceMediumBufferSize
	if len(writes) != wantWrites {
		t.Fatalf("underlying writes = %d, want %d for fast downstream", len(writes), wantWrites)
	}
	if !bytes.Equal(bytes.Join(writes, nil), payload) {
		t.Fatal("coalesced proxy payload differs from upstream")
	}
	if flushes != 1 {
		t.Fatalf("underlying flushes = %d, want 1", flushes)
	}
	if got := dst.Header().Get("Content-Length"); got != "" {
		t.Fatalf("Content-Length = %q, want no synthesized header", got)
	}
}

func TestServeReverseProxyWithResponseCoalescingKeepsStreamingOptOut(t *testing.T) {
	payload := []byte("data: ready\n\n")
	proxy := &httputil.ReverseProxy{
		Rewrite: func(*httputil.ProxyRequest) {},
		Transport: coalescingTestRoundTripper(func(request *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode:    http.StatusOK,
				Header:        http.Header{"Content-Type": []string{"text/event-stream"}},
				Body:          io.NopCloser(bytes.NewReader(payload)),
				ContentLength: -1,
				Request:       request,
			}, nil
		}),
	}

	dst := newCoalescingTestResponseWriter()
	serveReverseProxyWithResponseCoalescing(proxy, dst, httptest.NewRequest(http.MethodGet, "http://proxy.test/events", nil))

	writes, flushes := dst.snapshot()
	if len(writes) != 1 || !bytes.Equal(writes[0], payload) {
		t.Fatalf("streaming writes = %d, want one intact payload", len(writes))
	}
	if flushes == 0 {
		t.Fatal("streaming response did not preserve immediate flushing")
	}
	if got := dst.Header().Get("Content-Length"); got != "" {
		t.Fatalf("Content-Length = %q, want unknown-length streaming semantics", got)
	}
}

func TestServeReverseProxyWithResponseCoalescingPreservesUnknownLengthOnWire(t *testing.T) {
	payload := bytes.Repeat([]byte{0x7b}, 32*1024)
	proxy := &httputil.ReverseProxy{
		BufferPool: sharedProxyBufferPool,
		Rewrite:    func(*httputil.ProxyRequest) {},
		Transport: coalescingTestRoundTripper(func(request *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode:    http.StatusOK,
				Header:        http.Header{"Content-Type": []string{"application/octet-stream"}},
				Body:          io.NopCloser(bytes.NewReader(payload)),
				ContentLength: -1,
				Request:       request,
			}, nil
		}),
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		serveReverseProxyWithResponseCoalescing(proxy, w, request)
	}))
	t.Cleanup(server.Close)

	response, err := server.Client().Get(server.URL + "/download")
	if err != nil {
		t.Fatalf("GET coalesced response: %v", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read coalesced response: %v", err)
	}
	if !bytes.Equal(body, payload) {
		t.Fatal("wire response differs from upstream payload")
	}
	if response.ContentLength == 0 || response.Header.Get("Content-Length") == "0" {
		t.Fatalf("unknown-length body was advertised as empty: length=%d header=%q", response.ContentLength, response.Header.Get("Content-Length"))
	}
	if response.ContentLength > 0 && response.ContentLength != int64(len(payload)) {
		t.Fatalf("ContentLength = %d, want unknown or %d", response.ContentLength, len(payload))
	}
}
