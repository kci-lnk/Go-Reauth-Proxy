package rpcbridge

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"go-reauth-proxy/pkg/grpc/pb"
)

type authBridgeObservedReadyContext struct {
	context.Context
	entered chan<- struct{}
	once    sync.Once
}

func (c *authBridgeObservedReadyContext) Done() <-chan struct{} {
	c.once.Do(func() { c.entered <- struct{}{} })
	return c.Context.Done()
}

func startAuthBridgeReadyWaiters(t *testing.T, manager *AuthBridgeManager, count int) ([]<-chan error, []context.CancelFunc) {
	t.Helper()
	entered := make(chan struct{}, count)
	results := make([]<-chan error, count)
	cancels := make([]context.CancelFunc, count)
	for i := range count {
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		t.Cleanup(cancel)
		cancels[i] = cancel
		observed := &authBridgeObservedReadyContext{Context: ctx, entered: entered}
		result := make(chan error, 1)
		results[i] = result
		go func() { result <- manager.WaitReady(observed) }()
	}
	for range count {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("readiness waiter did not reach its blocking select")
		}
	}
	return results, cancels
}

func finishAuthBridgeReadyWaiters(t *testing.T, results []<-chan error) {
	t.Helper()
	for _, result := range results {
		select {
		case err := <-result:
			if err != nil {
				t.Fatalf("WaitReady returned %v after readiness was published", err)
			}
		case <-time.After(time.Second):
			t.Fatal("ready notification left a concurrent waiter blocked")
		}
	}
}

func publishAuthBridgeReady(manager *AuthBridgeManager, active *authBridgeStream) {
	manager.handleIncoming(active, &pb.AuthBridgeEnvelope{
		Payload: &pb.AuthBridgeEnvelope_Ready{Ready: &pb.AuthBridgeReady{}},
	})
}

func TestAuthBridgeWaitReadyBroadcastsToConcurrentWaiters(t *testing.T) {
	manager := NewAuthBridgeManager("secret")
	results, _ := startAuthBridgeReadyWaiters(t, manager, 16)
	active := manager.attachStream(&blockingAuthBridgeStream{ctx: t.Context()})
	defer manager.detachStream(active)
	publishAuthBridgeReady(manager, active)
	finishAuthBridgeReadyWaiters(t, results)
}

func TestAuthBridgeWaitReadyCancellationDoesNotConsumeOtherWaitersNotification(t *testing.T) {
	manager := NewAuthBridgeManager("secret")
	results, cancels := startAuthBridgeReadyWaiters(t, manager, 8)
	cancels[0]()
	select {
	case err := <-results[0]:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled WaitReady = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("readiness waiter ignored cancellation")
	}
	active := manager.attachStream(&blockingAuthBridgeStream{ctx: t.Context()})
	defer manager.detachStream(active)
	publishAuthBridgeReady(manager, active)
	finishAuthBridgeReadyWaiters(t, results[1:])
}

func TestAuthBridgeWaitReadyBroadcastsAcrossReconnect(t *testing.T) {
	manager := NewAuthBridgeManager("secret")
	first := manager.attachStream(&blockingAuthBridgeStream{ctx: t.Context()})
	defer manager.detachStream(first)
	firstResults, _ := startAuthBridgeReadyWaiters(t, manager, 8)
	publishAuthBridgeReady(manager, first)
	finishAuthBridgeReadyWaiters(t, firstResults)
	manager.detachStream(first)

	results, _ := startAuthBridgeReadyWaiters(t, manager, 8)
	second := manager.attachStream(&blockingAuthBridgeStream{ctx: t.Context()})
	defer manager.detachStream(second)
	// Neither reconnect itself nor a late Ready from the old stream may make
	// callers proceed before the new stream has finished its handshake.
	publishAuthBridgeReady(manager, first)
	if manager.IsReady() {
		t.Fatal("old stream readiness leaked into its replacement")
	}
	for _, result := range results {
		select {
		case err := <-result:
			t.Fatalf("replacement was not ready, but WaitReady returned %v", err)
		default:
		}
	}
	publishAuthBridgeReady(manager, second)
	finishAuthBridgeReadyWaiters(t, results)
}

func TestAuthBridgeWaitReadyConcurrentSubscriptionAndNotification(t *testing.T) {
	for range 100 {
		manager := NewAuthBridgeManager("secret")
		active := &authBridgeStream{done: make(chan struct{})}
		manager.stream.Store(active)
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		start := make(chan struct{})
		results := make([]<-chan error, 8)
		for i := range results {
			result := make(chan error, 1)
			results[i] = result
			go func() { <-start; result <- manager.WaitReady(ctx) }()
		}
		published := make(chan struct{})
		go func() { <-start; publishAuthBridgeReady(manager, active); close(published) }()
		close(start)
		finishAuthBridgeReadyWaiters(t, results)
		<-published
		cancel()
		manager.detachStream(active)
	}
}

func TestAuthBridgeReadyHookCanReenterWaitReady(t *testing.T) {
	manager := NewAuthBridgeManager("secret")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	manager.SetReadyChangeHook(func(bool) {
		if err := manager.WaitReady(ctx); !errors.Is(err, context.Canceled) {
			t.Errorf("hook's canceled WaitReady = %v", err)
		}
	})
	finished := make(chan struct{})
	go func() { manager.notifyReadyChange(false); close(finished) }()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("readiness notification held its lock while invoking the hook")
	}
}
