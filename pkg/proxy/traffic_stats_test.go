package proxy

import (
	"fmt"
	"go-reauth-proxy/pkg/models"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTrafficStatsIncludesHostBreakdown(t *testing.T) {
	handler := &Handler{
		HostRules: []models.HostRule{{Host: "app.example.com"}},
	}
	writer := &trafficResponseWriter{
		ResponseWriter: httptest.NewRecorder(),
		handler:        handler,
	}
	writer.metrics.statusCode = http.StatusOK
	metrics := &writer.metrics
	metrics.bindHost(handler, "App.Example.COM:443")

	body := &trafficReadCloser{
		ReadCloser: io.NopCloser(strings.NewReader("request")),
		handler:    handler,
		metrics:    metrics,
	}
	if _, err := io.ReadAll(body); err != nil {
		t.Fatalf("read request body: %v", err)
	}

	if _, err := writer.Write([]byte("response")); err != nil {
		t.Fatalf("write response body: %v", err)
	}
	metrics.flush(handler)
	metrics.add5xx()

	stats := handler.GetTrafficStats(time.Now())
	if stats.TotalIn != 7 {
		t.Fatalf("TotalIn = %d, want 7", stats.TotalIn)
	}
	if stats.TotalOut != 8 {
		t.Fatalf("TotalOut = %d, want 8", stats.TotalOut)
	}
	if len(stats.ByHost) != 1 {
		t.Fatalf("ByHost length = %d, want 1: %#v", len(stats.ByHost), stats.ByHost)
	}

	hostStats := stats.ByHost[0]
	if hostStats.Host != "app.example.com" {
		t.Fatalf("Host = %q, want app.example.com", hostStats.Host)
	}
	if hostStats.TotalIn != 7 {
		t.Fatalf("host TotalIn = %d, want 7", hostStats.TotalIn)
	}
	if hostStats.TotalOut != 8 {
		t.Fatalf("host TotalOut = %d, want 8", hostStats.TotalOut)
	}
	if hostStats.Error5xx != 1 {
		t.Fatalf("host Error5xx = %d, want 1", hostStats.Error5xx)
	}
}

func TestHostTrafficCountersEnforceActiveIPLimitOnWrite(t *testing.T) {
	counters := &hostTrafficCounters{}
	now := time.Unix(100, 0)
	for i := 0; i < hostActiveIPHardLimit+25; i++ {
		record := counters.markActiveIP(fmt.Sprintf("198.51.%d.%d", i/255, i%255), now.Add(time.Duration(i)*time.Millisecond))
		if record != nil {
			releaseHostActiveIP(record, now)
		}
	}

	if got := counters.activeIPEntries.Load(); got > hostActiveIPHardLimit {
		t.Fatalf("active IP entries = %d, want <= %d", got, hostActiveIPHardLimit)
	}
}

func TestLoggedInActiveEnforcesMaxEntriesOnWrite(t *testing.T) {
	handler := &Handler{}
	now := time.Unix(100, 0)
	for i := 0; i < loggedInActiveMaxEntries+25; i++ {
		handler.storeLoggedInActive(fmt.Sprintf("identity-%d", i), now.Add(time.Duration(i)*time.Millisecond))
	}

	if got := handler.activeLoggedInCount(now.Add(time.Minute)); got > loggedInActiveMaxEntries {
		t.Fatalf("logged-in active count = %d, want <= %d", got, loggedInActiveMaxEntries)
	}
}

func TestTrafficStatsBatchFlushesCounters(t *testing.T) {
	handler := &Handler{
		HostRules: []models.HostRule{{Host: "app.example.com"}},
	}
	writer := &trafficResponseWriter{
		ResponseWriter: httptest.NewRecorder(),
		handler:        handler,
	}
	writer.metrics.statusCode = http.StatusOK
	metrics := &writer.metrics
	metrics.bindHost(handler, "app.example.com")
	chunk := strings.Repeat("x", trafficCounterFlushBytes/2)
	if _, err := writer.Write([]byte(chunk)); err != nil {
		t.Fatalf("write first chunk: %v", err)
	}
	if got := handler.trafficTotalOut.Load(); got != 0 {
		t.Fatalf("trafficTotalOut after first partial chunk = %d, want 0", got)
	}
	if _, err := writer.Write([]byte(chunk)); err != nil {
		t.Fatalf("write second chunk: %v", err)
	}
	if got := handler.trafficTotalOut.Load(); got != trafficCounterFlushBytes {
		t.Fatalf("trafficTotalOut after flush threshold = %d, want %d", got, trafficCounterFlushBytes)
	}
	if _, err := writer.Write([]byte("tail")); err != nil {
		t.Fatalf("write tail: %v", err)
	}
	if got := handler.trafficTotalOut.Load(); got != trafficCounterFlushBytes {
		t.Fatalf("trafficTotalOut before final flush = %d, want %d", got, trafficCounterFlushBytes)
	}
	metrics.flush(handler)
	if got := handler.trafficTotalOut.Load(); got != trafficCounterFlushBytes+4 {
		t.Fatalf("trafficTotalOut after final flush = %d, want %d", got, trafficCounterFlushBytes+4)
	}

	stats := handler.GetTrafficStats(time.Now())
	if stats.TotalOut != trafficCounterFlushBytes+4 {
		t.Fatalf("TotalOut = %d, want %d", stats.TotalOut, trafficCounterFlushBytes+4)
	}
	if len(stats.ByHost) != 1 || stats.ByHost[0].TotalOut != trafficCounterFlushBytes+4 {
		t.Fatalf("ByHost = %#v, want total out %d", stats.ByHost, trafficCounterFlushBytes+4)
	}
	if metrics.outBytes != trafficCounterFlushBytes+4 {
		t.Fatalf("metrics.outBytes = %d, want %d", metrics.outBytes, trafficCounterFlushBytes+4)
	}
}

func TestWrapRequestBodyForTrafficSkipsRequestsWithoutBodies(t *testing.T) {
	handler := &Handler{}
	metrics := &requestTrafficMetrics{}
	request := httptest.NewRequest(http.MethodGet, "https://app.example.test/", nil)
	original := request.Body
	wrapRequestBodyForTraffic(request, handler, metrics)
	if request.Body != original {
		t.Fatalf("body %T was wrapped for a bodyless request", original)
	}

	request = httptest.NewRequest(http.MethodPost, "https://app.example.test/", strings.NewReader("body"))
	wrapRequestBodyForTraffic(request, handler, metrics)
	if _, ok := request.Body.(*trafficReadCloser); !ok {
		t.Fatalf("body = %T, want trafficReadCloser", request.Body)
	}

	unknownLength := &http.Request{
		Body:          io.NopCloser(strings.NewReader("body")),
		ContentLength: 0,
	}
	wrapRequestBodyForTraffic(unknownLength, handler, metrics)
	if _, ok := unknownLength.Body.(*trafficReadCloser); !ok {
		t.Fatalf("zero-length body = %T, want trafficReadCloser because non-nil Body may be unknown length", unknownLength.Body)
	}
	if _, err := io.ReadAll(unknownLength.Body); err != nil {
		t.Fatalf("read zero-length body: %v", err)
	}
	if metrics.inBytes != 4 {
		t.Fatalf("recorded input bytes = %d, want 4", metrics.inBytes)
	}
}

func TestHostActiveIPsTracksRecentClients(t *testing.T) {
	now := time.Date(2026, 5, 14, 10, 0, 0, 0, time.UTC)
	handler := &Handler{
		HostRules: []models.HostRule{{Host: "app.example.com"}},
	}
	metrics := &requestTrafficMetrics{statusCode: http.StatusOK}
	metrics.bindHost(handler, "app.example.com")

	metrics.markActiveIP("192.0.2.10:4321", now)
	if metrics.activeIPRecord == nil {
		t.Fatal("expected active IP record")
	}

	active := handler.GetHostActiveIPs("App.Example.COM:443", now)
	if active.Host != "app.example.com" {
		t.Fatalf("Host = %q, want app.example.com", active.Host)
	}
	if active.WindowSeconds != int(hostActiveIPWindow.Seconds()) {
		t.Fatalf("WindowSeconds = %d, want %d", active.WindowSeconds, int(hostActiveIPWindow.Seconds()))
	}
	if len(active.Items) != 1 {
		t.Fatalf("active IP count = %d, want 1: %#v", len(active.Items), active.Items)
	}
	if active.Items[0].IP != "192.0.2.10" {
		t.Fatalf("IP = %q, want 192.0.2.10", active.Items[0].IP)
	}
	if active.Items[0].ActiveConns != 1 {
		t.Fatalf("ActiveConns = %d, want 1", active.Items[0].ActiveConns)
	}
	if !active.Items[0].LastSeenAt.Equal(now) {
		t.Fatalf("LastSeenAt = %s, want %s", active.Items[0].LastSeenAt, now)
	}

	stats := handler.GetTrafficStats(now)
	if len(stats.ByHost) != 1 || stats.ByHost[0].ActiveIPCount != 1 {
		t.Fatalf("host ActiveIPCount = %#v, want 1", stats.ByHost)
	}

	releasedAt := time.Now()
	metrics.releaseActiveIP(releasedAt)
	stillRecent := handler.GetHostActiveIPs("app.example.com", releasedAt.Add(hostActiveIPWindow-time.Second))
	if len(stillRecent.Items) != 1 {
		t.Fatalf("recent active IP count = %d, want 1", len(stillRecent.Items))
	}
	if stillRecent.Items[0].ActiveConns != 0 {
		t.Fatalf("recent ActiveConns = %d, want 0", stillRecent.Items[0].ActiveConns)
	}
	if stillRecent.Items[0].LastSeenAt.Before(releasedAt.Add(-time.Second)) {
		t.Fatalf("recent LastSeenAt = %s, want refreshed around release time %s", stillRecent.Items[0].LastSeenAt, releasedAt)
	}

	expired := handler.GetHostActiveIPs("app.example.com", releasedAt.Add(hostActiveIPWindow+time.Second))
	if len(expired.Items) != 0 {
		t.Fatalf("expired active IP count = %d, want 0: %#v", len(expired.Items), expired.Items)
	}
}

func TestStreamActiveIPsTracksConnections(t *testing.T) {
	now := time.Now().UTC()
	handler := &Handler{
		StreamRules: []models.StreamRule{
			{Protocol: models.StreamProtocolTCP, ListenPort: 3306, Target: "127.0.0.1:5432"},
			{Protocol: models.StreamProtocolUDP, ListenPort: 53, Target: "127.0.0.1:5353"},
		},
	}
	recorder := handler.NewStreamTrafficRecorder("tcp", 3306)
	recorder.Activate("192.0.2.10:4321", now)
	recorder.Add(3, 4, 0)
	udpRecorder := handler.NewStreamTrafficRecorder("udp", 53)
	udpRecorder.Activate("[2001:db8::1]:5353", now)

	active := handler.GetStreamActiveIPs("TCP", 3306, time.Now())
	if active.Key != "tcp/3306" || active.Protocol != "tcp" || active.ListenPort != 3306 {
		t.Fatalf("stream identity = %#v", active)
	}
	if active.WindowSeconds != int(hostActiveIPWindow.Seconds()) {
		t.Fatalf("WindowSeconds = %d, want %d", active.WindowSeconds, int(hostActiveIPWindow.Seconds()))
	}
	if len(active.Items) != 1 || active.Items[0].IP != "192.0.2.10" || active.Items[0].ActiveConns != 1 {
		t.Fatalf("active stream IPs = %#v", active.Items)
	}
	udpActive := handler.GetStreamActiveIPs("udp", 53, time.Now())
	if len(udpActive.Items) != 1 || udpActive.Items[0].IP != "2001:db8::1" || udpActive.Items[0].ActiveConns != 1 {
		t.Fatalf("active UDP stream IPs = %#v", udpActive.Items)
	}

	stats := handler.GetTrafficStats(time.Now())
	if len(stats.ByStream) != 2 || stats.ByStream[0].ActiveConns != 1 || stats.ByStream[0].ActiveIPCount != 1 || stats.ByStream[1].ActiveIPCount != 1 {
		t.Fatalf("stream traffic stats = %#v", stats.ByStream)
	}

	releasedAt := time.Now()
	recorder.Finalize(http.StatusBadGateway, releasedAt)
	udpRecorder.Finalize(http.StatusOK, releasedAt)
	recent := handler.GetStreamActiveIPs("tcp", 3306, releasedAt.Add(hostActiveIPWindow-time.Second))
	if len(recent.Items) != 1 || recent.Items[0].ActiveConns != 0 {
		t.Fatalf("recent stream IPs = %#v", recent.Items)
	}
	stats = handler.GetTrafficStats(releasedAt)
	if stats.ByStream[0].ActiveConns != 0 || stats.ByStream[0].Error5xx != 1 {
		t.Fatalf("final stream traffic stats = %#v", stats.ByStream[0])
	}

	expired := handler.GetStreamActiveIPs("tcp", 3306, releasedAt.Add(hostActiveIPWindow+time.Second))
	if len(expired.Items) != 0 {
		t.Fatalf("expired stream IPs = %#v", expired.Items)
	}
}
