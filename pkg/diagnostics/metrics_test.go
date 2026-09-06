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

func TestResourceAdmissionMetricsTrackCompletionAndRejection(t *testing.T) {
	global.authBridgeInFlight.Store(0)
	global.authBridgeInFlightPeak.Store(0)
	beforeAuthDrops := global.authBridgeInFlightDrops.Load()
	beforeUDPDrops := global.udpBufferBudgetDrops.Load()
	t.Cleanup(func() {
		global.authBridgeInFlight.Store(0)
		global.authBridgeInFlightPeak.Store(0)
		global.authBridgeInFlightDrops.Store(beforeAuthDrops)
		global.udpBufferBudgetDrops.Store(beforeUDPDrops)
	})
	AddAuthBridgeInFlight(1)
	AddAuthBridgeInFlight(1)
	AddAuthBridgeInFlight(-1)
	RecordAuthBridgeInFlightDrop()
	RecordUDPBufferBudgetDrop()
	got := Snapshot().(snapshot)
	if got.Auth.BridgeInFlight != 1 || got.Auth.BridgeInFlightPeak != 2 || got.Auth.BridgeInFlightDrops != beforeAuthDrops+1 || got.UDP.BufferBudgetDrops != beforeUDPDrops+1 {
		t.Fatalf("unexpected admission metrics: auth=%+v UDP=%+v", got.Auth, got.UDP)
	}
	AddAuthBridgeInFlight(-1)
	AddAuthBridgeInFlight(0)
	got = Snapshot().(snapshot)
	if got.Auth.BridgeInFlight != 0 || got.Auth.BridgeInFlightPeak != 2 {
		t.Fatalf("finished requests changed current/peak to %d/%d, want 0/2", got.Auth.BridgeInFlight, got.Auth.BridgeInFlightPeak)
	}
}

func TestSubdomainGrantTransientStateIsObservable(t *testing.T) {
	SetEnabled(true)
	t.Cleanup(func() { SetEnabled(false) })
	before := global.grantTransient.Load()
	t.Cleanup(func() { global.grantTransient.Store(before) })

	RecordSubdomainGrantState("transient")

	got := Snapshot().(snapshot)
	if got.Auth.SubdomainGrantTransient != before+1 {
		t.Fatalf("transient grants = %d, want %d", got.Auth.SubdomainGrantTransient, before+1)
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

func TestClientConnectionTransitionsTrackActiveAndIdleGauges(t *testing.T) {
	activeBefore := runtimeGlobal.activeClientConnections.Load()
	idleBefore := runtimeGlobal.idleClientConnections.Load()
	t.Cleanup(func() {
		runtimeGlobal.activeClientConnections.Store(activeBefore)
		runtimeGlobal.idleClientConnections.Store(idleBefore)
	})

	ObserveClientConnectionTransition(http.StateNew, http.StateActive)
	got := RuntimeMetrics()
	if got.ActiveClientConnections != activeBefore+1 || got.IdleClientConnections != idleBefore {
		t.Fatalf("active transition = %#v", got)
	}
	ObserveClientConnectionTransition(http.StateActive, http.StateIdle)
	got = RuntimeMetrics()
	if got.ActiveClientConnections != activeBefore || got.IdleClientConnections != idleBefore+1 {
		t.Fatalf("idle transition = %#v", got)
	}
	ObserveClientConnectionTransition(http.StateIdle, http.StateClosed)
	got = RuntimeMetrics()
	if got.ActiveClientConnections != activeBefore || got.IdleClientConnections != idleBefore {
		t.Fatalf("closed transition = %#v", got)
	}
}

func TestMemoryBreakdownFields(t *testing.T) {
	recorder := httptest.NewRecorder()
	Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/debug/metrics", nil))
	for _, key := range []string{"heap_idle_bytes", "heap_released_bytes", "stack_inuse_bytes", "heap_objects", "next_gc_bytes", "total_alloc_bytes", "coalescing_buffers"} {
		if !strings.Contains(recorder.Body.String(), `"`+key+`"`) {
			t.Fatalf("missing %s", key)
		}
	}
	s := Snapshot().(snapshot)
	if s.Runtime.HeapReleased > s.Runtime.HeapIdle || s.Runtime.TotalAlloc < s.Runtime.HeapAlloc {
		t.Fatal("inconsistent memory snapshot")
	}
}
