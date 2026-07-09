package diagnostics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHandlerReturnsLowCardinalitySnapshot(t *testing.T) {
	SetEnabled(true)
	t.Cleanup(func() { SetEnabled(false) })
	ObserveHTTPRequest(4*time.Millisecond, http.StatusNoContent)
	RecordAuthBridgeRequest()
	RecordAuthCacheHit()
	RecordUDPQueueDrop()

	recorder := httptest.NewRecorder()
	Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/debug/metrics", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
	for _, expected := range []string{`"requests"`, `"2xx"`, `"bridge_requests"`, `"bridge_queue_depth"`, `"bridge_queue_depth_peak"`, `"queue_drops"`, `"runtime"`} {
		if !strings.Contains(recorder.Body.String(), expected) {
			t.Fatalf("metrics body missing %s: %s", expected, recorder.Body.String())
		}
	}
}

func TestObserveAuthBridgeQueueDepthTracksCurrentAndPeak(t *testing.T) {
	SetEnabled(true)
	t.Cleanup(func() { SetEnabled(false) })
	global.authBridgeQueueDepth.Store(0)
	global.authBridgeQueuePeak.Store(0)
	t.Cleanup(func() {
		global.authBridgeQueueDepth.Store(0)
		global.authBridgeQueuePeak.Store(0)
	})

	ObserveAuthBridgeQueueDepth(3)
	ObserveAuthBridgeQueueDepth(1)

	got := Snapshot().(snapshot)
	if got.Auth.BridgeQueueDepth != 1 {
		t.Fatalf("bridge queue depth = %d, want 1", got.Auth.BridgeQueueDepth)
	}
	if got.Auth.BridgeQueueDepthPeak != 3 {
		t.Fatalf("bridge queue depth peak = %d, want 3", got.Auth.BridgeQueueDepthPeak)
	}
}

func TestDisabledDiagnosticsSkipHotPathCounters(t *testing.T) {
	SetEnabled(false)
	before := global.requestTotal.Load()
	ObserveHTTPRequest(time.Millisecond, http.StatusOK)
	RecordAuthCacheHit()
	RecordUDPQueueDrop()
	if got := global.requestTotal.Load(); got != before {
		t.Fatalf("disabled diagnostics request total = %d, want %d", got, before)
	}
}
