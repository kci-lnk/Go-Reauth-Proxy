package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type acceptanceWireCase struct {
	name             string
	http2, tls, slow bool
	scenario         handlerEndToEndBenchmarkScenario
}

func acceptanceWireCases() []acceptanceWireCase {
	small := handlerEndToEndBenchmarkScenario{routeKind: "path", authMode: handlerBenchmarkAuthOff, responseBytes: 1 << 10}
	large := small
	large.responseBytes = 2 << 20
	medium := small
	medium.responseBytes = 256 << 10
	portal := handlerEndToEndBenchmarkScenario{routeKind: "host", authMode: handlerBenchmarkAuthHit, responseBytes: 64 << 10, htmlResponse: true, portalEnabled: true}
	unknown := large
	unknown.unknownLength = true
	return []acceptanceWireCase{
		{name: "HTTP1/Small1KiB", scenario: small},
		{name: "HTTPS1/Small1KiB", tls: true, scenario: small},
		{name: "HTTP2/Small1KiB", tls: true, http2: true, scenario: small},
		{name: "HTTPS1/Medium256KiB", tls: true, scenario: medium},
		{name: "HTTP2/Medium256KiB", tls: true, http2: true, scenario: medium},
		{name: "HTTPS1/Download2MiB", tls: true, scenario: large},
		{name: "HTTP2/Download2MiB", tls: true, http2: true, scenario: large},
		{name: "HTTP2/Toolbar64KiB", tls: true, http2: true, scenario: portal},
		{name: "HTTPS1/SlowDownload2MiB", tls: true, slow: true, scenario: large},
		{name: "HTTP2/SlowDownload2MiB", tls: true, http2: true, slow: true, scenario: large},
		{name: "HTTP2/UnknownBinary2MiB", tls: true, http2: true, scenario: unknown},
	}
}

type acceptanceSmallSendListener struct{ net.Listener }

func (l acceptanceSmallSendListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetWriteBuffer(32 << 10)
	}
	return conn, err
}

func acceptanceWireServer(tb testing.TB, fixture *handlerEndToEndBenchmarkFixture, test acceptanceWireCase) (*http.Client, func() *http.Request) {
	tb.Helper()
	server := httptest.NewUnstartedServer(fixture.handler)
	if test.slow {
		server.Listener = acceptanceSmallSendListener{server.Listener}
	}
	server.EnableHTTP2 = test.http2
	if test.tls {
		server.StartTLS()
	} else {
		server.Start()
	}
	client := server.Client()
	client.Timeout = 30 * time.Second
	transport := client.Transport.(*http.Transport)
	if test.slow {
		transport.HTTP2 = &http.HTTP2Config{MaxReceiveBufferPerStream: 64 << 10, MaxReceiveBufferPerConnection: 128 << 10}
	}
	tb.Cleanup(func() {
		transport.CloseIdleConnections()
		server.Close()
		fixture.handler.proxyTransport.CloseIdleConnections()
		fixture.handler.Close()
		if fixture.target != nil {
			fixture.target.Close()
		}
	})
	base, err := url.Parse(server.URL)
	if err != nil {
		tb.Fatal(err)
	}
	request := func() *http.Request {
		r := fixture.newRequest()
		r.Host = r.URL.Host
		r.URL.Scheme, r.URL.Host = base.Scheme, base.Host
		r.RequestURI = ""
		return r
	}
	return client, request
}

func acceptanceReadWire(tb testing.TB, client *http.Client, request *http.Request, test acceptanceWireCase, dst io.Writer) int64 {
	tb.Helper()
	response, err := client.Do(request)
	if err != nil {
		tb.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || (response.ProtoMajor == 2) != test.http2 {
		tb.Fatalf("wire response: status=%d protocol=%s", response.StatusCode, response.Proto)
	}
	if !test.slow {
		n, err := io.Copy(dst, response.Body)
		if err != nil {
			tb.Fatal(err)
		}
		return n
	}
	buffer := make([]byte, 64<<10)
	var total int64
	for {
		// Pace fixed-size chunks rather than individual Read calls: TCP/TLS
		// fragmentation must not change the number of artificial sleeps in A/B.
		n, err := io.ReadFull(response.Body, buffer)
		if n > 0 {
			_, _ = dst.Write(buffer[:n])
			total += int64(n)
			time.Sleep(200 * time.Microsecond)
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return total
		}
		if err != nil {
			tb.Fatal(err)
		}
	}
}

func TestAcceptanceWireProtocolsAndBodies(t *testing.T) {
	for _, test := range acceptanceWireCases() {
		t.Run(test.name, func(t *testing.T) {
			fixture := newHandlerEndToEndBenchmarkFixture(t, test.scenario, false)
			client, request := acceptanceWireServer(t, fixture, test)
			for range 2 { // Also exercise connection reuse and warmed auth.
				var body bytes.Buffer
				acceptanceReadWire(t, client, request(), test, &body)
				if test.scenario.portalEnabled {
					if !bytes.Contains(body.Bytes(), []byte("reauth-proxy-toolbar-bootstrap")) || !bytes.HasSuffix(body.Bytes(), []byte("</body></html>")) {
						t.Fatal("toolbar response was missing its injection or original closing tags")
					}
				} else if !bytes.Equal(body.Bytes(), handlerBenchmarkResponseBody(test.scenario.responseBytes, test.scenario.htmlResponse)) {
					t.Fatal("wire response body changed or was truncated")
				}
			}
			if test.scenario.authMode == handlerBenchmarkAuthHit && fixture.authorizeRPC.Load() != 1 {
				t.Fatalf("warm auth RPC calls = %d, want 1", fixture.authorizeRPC.Load())
			}
		})
	}
}

func BenchmarkAcceptanceWire(b *testing.B) {
	for _, test := range acceptanceWireCases() {
		b.Run(test.name, func(b *testing.B) {
			b.StopTimer()
			fixture := newHandlerEndToEndBenchmarkFixture(b, test.scenario, false)
			client, request := acceptanceWireServer(b, fixture, test)
			expected := acceptanceReadWire(b, client, request(), test, io.Discard)
			b.SetBytes(int64(test.scenario.responseBytes))
			b.ReportAllocs()
			b.ResetTimer()
			b.StartTimer()
			for b.Loop() {
				if n := acceptanceReadWire(b, client, request(), test, io.Discard); n != expected {
					b.Fatalf("response length = %d, want %d", n, expected)
				}
			}
			if test.slow {
				b.ReportMetric(float64((expected+(64<<10)-1)/(64<<10)), "paced_chunks/op")
			}
		})
	}
}

type acceptanceSSEActivity struct {
	mu     sync.Mutex
	active int
	idle   chan struct{}
}

func (a *acceptanceSSEActivity) start() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.active == 0 {
		a.idle = make(chan struct{})
	}
	a.active++
}

func (a *acceptanceSSEActivity) finish() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.active--
	if a.active == 0 {
		close(a.idle)
	}
}

func (a *acceptanceSSEActivity) snapshot() (int, <-chan struct{}) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.active, a.idle
}

type acceptanceSSETransport struct {
	payload  []byte
	activity *acceptanceSSEActivity
}

func (rt acceptanceSSETransport) RoundTrip(r *http.Request) (*http.Response, error) {
	rt.activity.start()
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/event-stream"}},
		ContentLength: -1, Request: r, Body: &acceptanceIdleBody{Reader: bytes.NewReader(rt.payload), ctx: r.Context(), stop: make(chan struct{}), activity: rt.activity}}, nil
}

type acceptanceIdleBody struct {
	*bytes.Reader
	ctx      context.Context
	stop     chan struct{}
	once     sync.Once
	activity *acceptanceSSEActivity
}

func (b *acceptanceIdleBody) Read(p []byte) (int, error) {
	if b.Reader.Len() > 0 {
		return b.Reader.Read(p)
	}
	select {
	case <-b.ctx.Done():
	case <-b.stop:
	}
	return 0, io.EOF
}

func (b *acceptanceIdleBody) Close() error {
	b.once.Do(func() {
		close(b.stop)
		b.activity.finish()
	})
	return nil
}

func acceptanceMemorySample(t *testing.T, phase string, count int) {
	t.Helper()
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	var rss int64
	if data, err := os.ReadFile("/proc/self/status"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 3 && fields[0] == "VmRSS:" {
				rss, _ = strconv.ParseInt(fields[1], 10, 64)
				rss *= 1024
			}
		}
	}
	data, _ := json.Marshal(map[string]any{"phase": phase, "streams": count, "heap_alloc": stats.HeapAlloc,
		"heap_inuse": stats.HeapInuse, "rss": rss, "goroutines": runtime.NumGoroutine()})
	t.Logf("ACCEPTANCE_MEMORY %s", data)
}

// Opt-in integration probe: each stream transfers 1 MiB then stays open. The
// controlled source fills the actual ReverseProxy copy buffer; the downstream
// uses real HTTP sockets. Linux VmRSS is sampled in addition to Go heap data.
func TestAcceptanceIdleSSEMemory(t *testing.T) {
	if os.Getenv("FN_KNOCK_ACCEPTANCE_MEMORY") != "1" {
		t.Skip("opt-in Linux RSS/heap A/B probe")
	}
	count := 128
	if value, err := strconv.Atoi(os.Getenv("FN_KNOCK_ACCEPTANCE_STREAMS")); err == nil && value > 0 && value <= 1024 {
		count = value
	}
	scenario := handlerEndToEndBenchmarkScenario{routeKind: "path", authMode: handlerBenchmarkAuthOff, responseBytes: 1 << 20}
	fixture := newHandlerEndToEndBenchmarkFixture(t, scenario, true)
	payload := append([]byte("data: "), bytes.Repeat([]byte("x"), (1<<20)-8)...)
	payload = append(payload, '\n', '\n')
	activity := &acceptanceSSEActivity{}
	fixture.handler.proxyRoundTripper = acceptanceSSETransport{payload: payload, activity: activity}
	client, request := acceptanceWireServer(t, fixture, acceptanceWireCase{})
	client.Timeout = 0
	runtime.GC()
	debug.FreeOSMemory()
	acceptanceMemorySample(t, "baseline", 0)
	baselineGoroutines := runtime.NumGoroutine()
	responses := make([]*http.Response, 0, count)
	t.Cleanup(func() {
		for _, r := range responses {
			_ = r.Body.Close()
		}
	})
	for i := 0; i < count; i++ {
		response, err := client.Do(request())
		if err != nil {
			t.Fatal(err)
		}
		responses = append(responses, response)
		if response.StatusCode != 200 {
			t.Fatal(response.Status)
		}
		if n, err := io.CopyN(io.Discard, response.Body, int64(len(payload))); err != nil || n != int64(len(payload)) {
			t.Fatalf("stream %d received %d bytes: %v", i, n, err)
		}
	}
	active, sourcesDone := activity.snapshot()
	if active != count {
		t.Fatalf("active SSE sources = %d, want %d", active, count)
	}
	acceptanceMemorySample(t, "idle_before_gc", active)
	runtime.GC()
	debug.FreeOSMemory()
	acceptanceMemorySample(t, "idle_after_gc", active)
	for _, response := range responses {
		_ = response.Body.Close()
	}
	responses = nil
	client.Transport.(*http.Transport).CloseIdleConnections()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	select {
	case <-sourcesDone:
	case <-deadline.C:
		active, _ = activity.snapshot()
		t.Fatalf("SSE sources did not close: active=%d goroutines=%d baseline=%d", active, runtime.NumGoroutine(), baselineGoroutines)
	}
	// Body.Close releases the source before the surrounding server and client
	// goroutines have necessarily returned. Wait for those goroutines too.
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for runtime.NumGoroutine() > baselineGoroutines {
		select {
		case <-tick.C:
		case <-deadline.C:
			t.Fatalf("SSE goroutines did not exit: got=%d baseline=%d", runtime.NumGoroutine(), baselineGoroutines)
		}
	}
	active, _ = activity.snapshot()
	t.Logf("SSE sources closed: active=%d goroutines=%d baseline_goroutines=%d", active, runtime.NumGoroutine(), baselineGoroutines)
	runtime.GC()
	debug.FreeOSMemory()
	acceptanceMemorySample(t, "closed_after_gc", active)
}
