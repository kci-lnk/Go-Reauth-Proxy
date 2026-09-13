package proxy

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestOnlineIPsSnapshotIdentityAggregation(t *testing.T) {
	h := &Handler{}
	now := time.Now().UTC()
	h.storeLoggedInActive("one", "::ffff:192.0.2.1", now)
	h.storeLoggedInActive("two", "192.0.2.1", now)
	h.storeLoggedInActive("one", "2001:db8::1", now.Add(time.Second))
	// An out-of-order request must not restore the identity's old address.
	h.storeLoggedInActive("one", "192.0.2.99", now.Add(-time.Second))
	h.storeLoggedInActive("unknown", "invalid", now)
	h.storeLoggedInActive("expired", "192.0.2.2", now.Add(-loggedInActiveWindow-time.Nanosecond))
	h.storeLoggedInActive("boundary", "192.0.2.1", now.Add(-loggedInActiveWindow))
	got := h.GetOnlineIPs(now)
	if got.OnlineCount != 4 || len(got.Items) != 3 || got.WindowSeconds != 120 || got.Timestamp != now.UnixMilli() {
		t.Fatalf("unexpected snapshot: %+v", got)
	}
	if got.Items[0].IP != "2001:db8::1" || !got.Items[0].LastSeenAt.Equal(now.Add(time.Second)) {
		t.Fatalf("latest address: %+v", got.Items[0])
	}
	counts := map[string]int64{}
	for _, item := range got.Items {
		counts[item.IP] = item.IdentityCount
	}
	if counts["192.0.2.1"] != 2 || counts[""] != 1 {
		t.Fatalf("aggregation: %v", counts)
	}
	if got.OnlineCount != h.activeLoggedInCount(now) {
		t.Fatal("snapshot count differs from dashboard")
	}
	if got := h.GetOnlineIPs(now.Add(loggedInActiveWindow + 2*time.Second)); got.OnlineCount != 0 || len(got.Items) != 0 {
		t.Fatalf("expired snapshot: %+v", got)
	}
}

func TestOnlineIPsConcurrentSnapshotAndCapacity(t *testing.T) {
	h := &Handler{}
	now := time.Now().UTC()
	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 1200; i++ {
				h.storeLoggedInActive(fmt.Sprintf("%d-%d", worker, i), fmt.Sprintf("192.0.2.%d", worker+1), now)
				if i%100 == 0 {
					snapshot := h.GetOnlineIPs(now)
					var total int64
					for _, item := range snapshot.Items {
						total += item.IdentityCount
						if !item.LastSeenAt.Equal(now) {
							t.Error("torn activity record")
						}
					}
					if total != snapshot.OnlineCount || total > loggedInActiveMaxEntries {
						t.Errorf("invalid counts: %d, %d", total, snapshot.OnlineCount)
					}
				}
			}
		}(worker)
	}
	wg.Wait()
	snapshot := h.GetOnlineIPs(now)
	if snapshot.OnlineCount != h.activeLoggedInCount(now) || snapshot.OnlineCount > loggedInActiveMaxEntries {
		t.Fatalf("invalid final snapshot: %+v", snapshot)
	}
}

func TestOnlineIPConcurrentMovesKeepLatestAddressAndTimeTogether(t *testing.T) {
	h := &Handler{}
	start := time.Now().UTC()
	var writers sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		writers.Add(1)
		go func(worker int) {
			defer writers.Done()
			for i := 0; i < 100; i++ {
				sequence := worker*100 + i
				h.storeLoggedInActive("same-identity", fmt.Sprintf("192.0.2.%d", sequence%250+1), start.Add(time.Duration(sequence)*time.Nanosecond))
				snapshot := h.GetOnlineIPs(start)
				if snapshot.OnlineCount != 1 || len(snapshot.Items) != 1 {
					t.Errorf("duplicate identity: %+v", snapshot)
					return
				}
				item := snapshot.Items[0]
				expected := fmt.Sprintf("192.0.2.%d", item.LastSeenAt.Sub(start).Nanoseconds()%250+1)
				if item.IP != expected {
					t.Errorf("mismatched IP and timestamp: %+v, want %s", item, expected)
				}
			}
		}(worker)
	}
	writers.Wait()
	latest := h.GetOnlineIPs(start).Items[0]
	if !latest.LastSeenAt.Equal(start.Add(799*time.Nanosecond)) || latest.IP != "192.0.2.50" {
		t.Fatalf("latest activity lost: %+v", latest)
	}
}
