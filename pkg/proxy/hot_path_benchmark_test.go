package proxy

import (
	"net/http"
	"strings"
	"testing"
)

// Keep request parsing outside the gateway benchmark. The existing end-to-end
// benchmarks deliberately retain httptest.NewRequest's parser allocations.
func BenchmarkHandlerHotPathAuthOff(b *testing.B) {
	benchmarkHandlerHotPath(b, handlerBenchmarkAuthOff)
}

func BenchmarkHandlerHotPathCacheHit(b *testing.B) {
	benchmarkHandlerHotPath(b, handlerBenchmarkAuthHit)
}

func benchmarkHandlerHotPath(b *testing.B, authMode string) {
	fixture := newHandlerEndToEndBenchmarkFixture(b, handlerEndToEndBenchmarkScenario{
		routeKind: "host", authMode: authMode, responseBytes: 1 << 10,
	}, true)
	b.Cleanup(func() {
		fixture.handler.proxyTransport.CloseIdleConnections()
		fixture.handler.Close()
	})
	template := fixture.newRequest()
	serve := func() {
		request := *template
		requestURL := *template.URL
		request.URL = &requestURL
		request.Header = template.Header.Clone()
		writer := newHandlerBenchmarkResponseWriter()
		fixture.handler.ServeHTTP(writer, &request)
		if writer.status != http.StatusOK || writer.bytes != 1<<10 {
			b.Fatalf("response status=%d bytes=%d", writer.status, writer.bytes)
		}
	}
	serve()
	calls := fixture.authorizeRPC.Load()
	b.ReportAllocs()
	b.SetBytes(1 << 10)
	b.ResetTimer()
	for b.Loop() {
		serve()
	}
	b.StopTimer()
	if got := fixture.authorizeRPC.Load(); got != calls {
		b.Fatalf("timed loop made %d authorization calls", got-calls)
	}
}

func BenchmarkReservedCookieStripping(b *testing.B) {
	for _, tc := range []struct {
		name  string
		count int
	}{{"One", 1}, {"Eight", 8}, {"ThirtyTwo", 32}} {
		b.Run(tc.name, func(b *testing.B) {
			header := http.Header{"Cookie": {strings.Repeat("session=value; ", tc.count)}}
			b.ReportAllocs()
			for b.Loop() {
				stripAdvancedAuthGrantCookie(header)
			}
		})
	}
}

func BenchmarkTraceHeaderClassification(b *testing.B) {
	names := []string{"Content-Type", "Content-Length", "Cache-Control", "X-Application-ID", "Trailer: X-B3-SpanId"}
	b.ReportAllocs()
	for b.Loop() {
		for _, name := range names {
			benchmarkBoolSink = isTraceResponseHeader(name)
		}
	}
}
