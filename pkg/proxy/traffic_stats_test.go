package proxy

import (
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
	metrics := &requestTrafficMetrics{statusCode: http.StatusOK}
	metrics.bindHost(handler, "App.Example.COM:443")

	body := &trafficReadCloser{
		ReadCloser: io.NopCloser(strings.NewReader("request")),
		handler:    handler,
		metrics:    metrics,
	}
	if _, err := io.ReadAll(body); err != nil {
		t.Fatalf("read request body: %v", err)
	}

	writer := &trafficResponseWriter{
		ResponseWriter: httptest.NewRecorder(),
		handler:        handler,
		metrics:        metrics,
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

func TestTrafficStatsBatchFlushesCounters(t *testing.T) {
	handler := &Handler{
		HostRules: []models.HostRule{{Host: "app.example.com"}},
	}
	metrics := &requestTrafficMetrics{statusCode: http.StatusOK}
	metrics.bindHost(handler, "app.example.com")

	writer := &trafficResponseWriter{
		ResponseWriter: httptest.NewRecorder(),
		handler:        handler,
		metrics:        metrics,
	}
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

func TestHostActiveIPsTracksRecentClients(t *testing.T) {
	now := time.Date(2026, 5, 14, 10, 0, 0, 0, time.UTC)
	handler := &Handler{
		HostRules: []models.HostRule{{Host: "app.example.com"}},
	}
	metrics := &requestTrafficMetrics{statusCode: http.StatusOK}
	metrics.bindHost(handler, "app.example.com")

	release := metrics.markActiveIP("192.0.2.10:4321", now)
	if release == nil {
		t.Fatal("expected active IP release function")
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

	release()
	releasedAt := time.Now()
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
