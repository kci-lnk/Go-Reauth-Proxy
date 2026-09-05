package rpcbridge

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	"go-reauth-proxy/pkg/grpc/pb"
)

func TestAuthBridgeLimitsSentRequestsAndReusesCompletedSlots(t *testing.T) {
	manager := NewAuthBridgeManager("secret")
	manager.inFlightLimit = 4
	stream := &blockingAuthBridgeStream{ctx: context.Background(), sent: make(chan *pb.AuthBridgeEnvelope, 1)}
	active := manager.attachStream(stream)
	t.Cleanup(func() { manager.detachStream(active) })
	type request struct {
		cancel  context.CancelFunc
		result  chan error
		message *pb.AuthBridgeEnvelope
	}
	requests := make([]request, 4)
	for i := range requests {
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		result := make(chan error, 1)
		go func() { _, err := manager.roundTrip(ctx, verifyEnvelope()); result <- err }()
		select {
		case message := <-stream.sent:
			requests[i] = request{cancel: cancel, result: result, message: message}
		case <-time.After(time.Second):
			t.Fatal("request was not sent")
		}
	}
	if len(active.sendQueue) != 0 || manager.inFlight.Load() != 4 {
		t.Fatal("sent requests were not counted as in flight")
	}
	if _, err := manager.roundTrip(context.Background(), verifyEnvelope()); !errors.Is(err, ErrAuthBridgeQueueFull) {
		t.Fatalf("overflow = %v", err)
	}
	response := &pb.AuthBridgeEnvelope{RequestId: requests[0].message.RequestId}
	manager.dispatchResponse(active, response)
	if err := <-requests[0].result; err != nil {
		t.Fatal(err)
	}
	requests[1].cancel()
	if err := <-requests[1].result; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled request = %v", err)
	}
	manager.dispatchResponse(active, response)
	manager.dispatchResponse(active, &pb.AuthBridgeEnvelope{RequestId: requests[1].message.RequestId})
	if got := manager.inFlight.Load(); got != 2 {
		t.Fatalf("late responses double released slots: %d", got)
	}
	manager.detachStream(active)
	for _, request := range requests[2:] {
		if err := <-request.result; !errors.Is(err, ErrAuthBridgeDisconnected) {
			t.Fatalf("disconnect = %v", err)
		}
	}
	manager.detachStream(active)
	if got := manager.inFlight.Load(); got != 0 {
		t.Fatalf("disconnected requests retained %d slots", got)
	}
	for range 4 {
		if !manager.reserveInFlight() {
			t.Fatal("released slot was not reusable")
		}
	}
	for range 4 {
		manager.releaseInFlight(&authBridgePendingCall{stream: active})
	}
	if got := manager.inFlight.Load(); got != 0 {
		t.Fatalf("slot reuse left %d calls in flight", got)
	}
}

func TestAuthBridgeAdmissionReleaseResponseCancelRace(t *testing.T) {
	manager := NewAuthBridgeManager("secret")
	stream := &authBridgeStream{}
	for i := range 100 {
		id := strconv.Itoa(i)
		if !manager.reserveInFlight() {
			t.Fatal("slot unavailable")
		}
		call := newAuthBridgePendingCall(stream)
		shard := manager.pendingShard(id)
		shard.Lock()
		shard.calls[id] = call
		shard.Unlock()
		var ready sync.WaitGroup
		ready.Add(3)
		go func() { defer ready.Done(); manager.dispatchResponse(stream, &pb.AuthBridgeEnvelope{RequestId: id}) }()
		go func() { defer ready.Done(); manager.completePending(id, call, nil, context.Canceled) }()
		go func() { defer ready.Done(); manager.failPendingForStream(stream, ErrAuthBridgeDisconnected) }()
		ready.Wait()
		call.wait()
		if got := manager.inFlight.Load(); got != 0 {
			t.Fatalf("completion race retained %d slots", got)
		}
	}
}

func TestAuthBridgeUntrackedCompletionPreservesAdmittedSlot(t *testing.T) {
	manager := NewAuthBridgeManager("secret")
	stream := &authBridgeStream{}
	if !manager.reserveInFlight() {
		t.Fatal("slot unavailable")
	}
	admitted := newAuthBridgePendingCall(stream)
	shard := manager.pendingShard("admitted")
	shard.Lock()
	shard.calls["admitted"] = admitted
	shard.Unlock()
	t.Cleanup(func() { manager.failPendingForStream(stream, context.Canceled) })

	// Completion-only fixtures share the manager without owning its slot. A
	// completion (including a duplicate) must not decrement another call's slot.
	untracked := newAuthBridgePendingCall(nil)
	shard = manager.pendingShard("untracked")
	shard.Lock()
	shard.calls["untracked"] = untracked
	shard.Unlock()
	manager.completePending("untracked", untracked, nil, context.Canceled)
	manager.completePending("untracked", untracked, nil, context.Canceled)
	untracked.wait()
	if got := manager.inFlight.Load(); got != 1 {
		t.Fatalf("untracked completion changed admitted count to %d", got)
	}
	manager.failPendingForStream(stream, context.Canceled)
	admitted.wait()
	if got := manager.inFlight.Load(); got != 0 {
		t.Fatalf("admitted completion left %d calls in flight", got)
	}
}

// This benchmark includes roundTrip's context, admission, queue and response
// completion. The existing PendingCompletion benchmarks continue to isolate
// completion mechanics and remain comparable with the baseline implementation.
func BenchmarkAuthBridgeRoundTripAdmission(b *testing.B) {
	for _, saturated := range []bool{false, true} {
		name := "Success"
		if saturated {
			name = "InFlightLimit"
		}
		b.Run(name, func(b *testing.B) {
			manager := NewAuthBridgeManager("benchmark-token")
			server := &authBridgeAdmissionBenchmarkStream{manager: manager}
			active := manager.attachStream(server)
			server.active = active // Published before any enqueue to the writer.
			b.Cleanup(func() { manager.detachStream(active) })
			if saturated {
				manager.inFlightLimit = 1
				if !manager.reserveInFlight() {
					b.Fatal("could not occupy the admission slot")
				}
				// Keep one real pending-map slot occupied without a request timer
				// expiring during long benchmark runs. Every measured rejection
				// still goes through the production roundTrip entry point.
				call := newAuthBridgePendingCall(active)
				shard := manager.pendingShard("occupied")
				shard.Lock()
				shard.calls["occupied"] = call
				shard.Unlock()
			}
			ctx := context.Background()
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				response, err := manager.roundTrip(ctx, verifyEnvelope())
				if saturated {
					if !errors.Is(err, ErrAuthBridgeQueueFull) {
						b.Fatalf("saturated round trip = %v", err)
					}
				} else if err != nil || response == nil || response.RequestId == "" {
					b.Fatalf("successful round trip = (%v, %v)", response, err)
				}
			}
			b.StopTimer()
			want := int64(0)
			if saturated {
				want = 1
			}
			if got := manager.inFlight.Load(); got != want {
				b.Fatalf("in flight = %d, want %d", got, want)
			}
		})
	}
}

type authBridgeAdmissionBenchmarkStream struct {
	blockingAuthBridgeStream
	manager *AuthBridgeManager
	active  *authBridgeStream
}

func (s *authBridgeAdmissionBenchmarkStream) Send(request *pb.AuthBridgeEnvelope) error {
	s.manager.dispatchResponse(s.active, &pb.AuthBridgeEnvelope{RequestId: request.RequestId})
	return nil
}

func TestAuthBridgeAdmissionEnvironment(t *testing.T) {
	for _, test := range []struct {
		value string
		want  int64
	}{
		{"", authBridgeInFlightLimit}, {"42", 42}, {"0", authBridgeInFlightLimit}, {"invalid", authBridgeInFlightLimit},
	} {
		t.Setenv("FN_KNOCK_AUTH_BRIDGE_MAX_IN_FLIGHT", test.value)
		if got := NewAuthBridgeManager("secret").inFlightLimit; got != test.want {
			t.Fatalf("value %q = %d, want %d", test.value, got, test.want)
		}
	}
}
