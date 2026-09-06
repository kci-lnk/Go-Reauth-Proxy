package waf

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestEventWaitExistingAndTimeout(t *testing.T) {
	s := NewEventStore(1000, time.Minute)
	if ok, err := s.Wait(context.Background(), time.Millisecond); ok || err != nil {
		t.Fatalf("empty wait: %v %v", ok, err)
	}
	s.Add(Event{TraceID: "existing"})
	if ok, err := s.Wait(context.Background(), time.Second); !ok || err != nil {
		t.Fatalf("existing wait: %v %v", ok, err)
	}
	if s.Pending() != 1 || len(s.leases) != 0 {
		t.Fatal("wait consumed or leased an event")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Wait(ctx, time.Second); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
}

func TestEventWaitConcurrentRegistrationAndBroadcast(t *testing.T) {
	for iteration := 0; iteration < 100; iteration++ {
		s := NewEventStore(10, time.Minute)
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if ok, err := s.Wait(context.Background(), time.Second); !ok || err != nil {
					t.Errorf("lost wakeup: %v %v", ok, err)
				}
			}()
		}
		s.Add(Event{TraceID: "race"})
		wg.Wait()
		s.Drain(10)
	}
}

func TestEventWaitLeaseReleaseAndExpiry(t *testing.T) {
	for _, expiry := range []bool{false, true} {
		t.Run(fmt.Sprint(expiry), func(t *testing.T) {
			s := NewEventStore(10, time.Minute)
			s.leaseTTL = 20 * time.Millisecond
			s.Add(Event{TraceID: "leased"})
			lease := s.Lease(1)
			if ok, err := s.Wait(context.Background(), time.Millisecond); ok || err != nil {
				t.Fatalf("leased event available: %v %v", ok, err)
			}
			if !expiry {
				time.AfterFunc(10*time.Millisecond, func() { s.Release(lease.LeaseID) })
			}
			if ok, err := s.Wait(context.Background(), time.Second); !ok || err != nil {
				t.Fatalf("released/expired lease: %v %v", ok, err)
			}
		})
	}
}

func TestEventWaitRechecksAfterOtherConsumer(t *testing.T) {
	s := NewEventStore(10, time.Minute)
	result := make(chan bool, 1)
	go func() { ok, _ := s.Wait(context.Background(), 40*time.Millisecond); result <- ok }()
	// Simulate a broadcast whose event is claimed before the waiter reacquires
	// the lock. A closed notification by itself must not mean availability.
	s.mu.Lock()
	s.notifyLocked()
	s.mu.Unlock()
	if <-result {
		t.Fatal("spurious notification reported availability")
	}
	s.Add(Event{TraceID: "claimed"})
	lease := s.Lease(1)
	s.Acknowledge(lease.LeaseID)
	if ok, _ := s.Wait(context.Background(), time.Millisecond); ok {
		t.Fatal("acknowledged event reported available")
	}
}

func TestEventWaitCancellationAndBoundedBacklog(t *testing.T) {
	s := NewEventStore(1000, time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := s.Wait(ctx, time.Minute); done <- err }()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("wait did not cancel")
	}
	for i := 0; i < 1100; i++ {
		s.Add(Event{TraceID: fmt.Sprint(i)})
	}
	for batch := 0; batch < 2; batch++ {
		if ok, _ := s.Wait(context.Background(), time.Second); !ok {
			t.Fatal("missing backlog")
		}
		lease := s.Lease(500)
		if len(lease.Events) != 500 {
			t.Fatalf("batch size %d", len(lease.Events))
		}
		ack := s.Acknowledge(lease.LeaseID)
		if ack.Remaining != (1-batch)*500 {
			t.Fatalf("remaining %d", ack.Remaining)
		}
	}
	if s.Pending() != 0 {
		t.Fatal("backlog not cleared")
	}
}

func TestEventWaitDoesNotReviveExpiredEvents(t *testing.T) {
	s := NewEventStore(10, 5*time.Millisecond)
	s.Add(Event{TraceID: "expired"})
	s.Lease(1)
	if ok, err := s.Wait(context.Background(), 30*time.Millisecond); ok || err != nil {
		t.Fatalf("expired event revived: %v %v", ok, err)
	}
}
