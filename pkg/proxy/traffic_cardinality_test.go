package proxy

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"go-reauth-proxy/pkg/models"
)

func TestActiveIPChurnPreservesActiveRecords(t *testing.T) {
	tracker := &activeIPTracker{}
	now := time.Unix(100, 0)
	active := tracker.markActiveIP("192.0.2.1", now)
	for i := 0; i < hostActiveIPHardLimit+100; i++ {
		ts := now.Add(time.Duration(i + 1))
		record := tracker.markActiveIP(fmt.Sprintf("10.0.%d.%d", i/256, i%256), ts)
		releaseHostActiveIP(record, ts)
	}
	retained, ok := tracker.activeIPs.Load("192.0.2.1")
	if !ok || retained != active || active.activeConns.Load() != 1 {
		t.Fatal("inactive churn evicted the ongoing connection")
	}
	releaseHostActiveIP(active, now.Add(time.Second))
	tracker.cleanupActiveIPs(now.Add(3 * time.Minute))
	if count := tracker.activeIPEntries.Load(); count != 0 {
		t.Fatalf("expired records retained: %d", count)
	}
}

func TestActivityMembershipCountsStayBoundedDuringConcurrentChurn(t *testing.T) {
	tracker := &activeIPTracker{}
	handler := &Handler{}
	now := time.Unix(100, 0)
	var workers sync.WaitGroup
	for worker := 0; worker < 16; worker++ {
		workers.Go(func() {
			for i := 0; i < 1024; i++ {
				ip := fmt.Sprintf("10.%d.%d.%d", worker, i/256, i%256)
				r := tracker.markActiveIP(ip, now)
				releaseHostActiveIP(r, now)
				handler.storeLoggedInActive(ip, now)
				if i%128 == 0 {
					tracker.cleanupActiveIPs(now)
					handler.cleanupLoggedInActive(now)
				}
			}
		})
	}
	workers.Wait()
	count := int64(0)
	tracker.activeIPs.Range(func(_, _ any) bool { count++; return true })
	if count != tracker.activeIPEntries.Load() || count > hostActiveIPHardLimit {
		t.Fatalf("active IP membership=%d gauge=%d", count, tracker.activeIPEntries.Load())
	}
	count = 0
	handler.loggedInActive.Range(func(_, _ any) bool { count++; return true })
	if count != handler.loggedInActiveCount.Load() || count > loggedInActiveMaxEntries {
		t.Fatalf("login membership=%d gauge=%d", count, handler.loggedInActiveCount.Load())
	}
}

func TestThrottleLRURetainsRecentlyBlockedClient(t *testing.T) {
	throttle := newReverseProxyThrottle(models.ReverseProxyThrottleConfig{Enabled: true, RequestsPerSecond: 1, Burst: 1, BlockSeconds: 30})
	ips := throttleBenchmarkIPs(reverseProxyThrottleMaxEntriesPerShard + 1)
	now := time.Unix(100, 0)
	for _, ip := range ips[:len(ips)-1] {
		throttle.evaluate(ip, now)
	}
	if decision := throttle.evaluate(ips[0], now); decision.Allowed || !decision.NewlyBlocked {
		t.Fatal("expected the refreshed identity to be blocked")
	}
	throttle.evaluate(ips[len(ips)-1], now)
	shard := throttle.shardForIdentity(ips[0])
	if _, ok := shard.entries[ips[1]]; ok {
		t.Fatal("least recently used client was not evicted")
	}
	if decision := throttle.evaluate(ips[0], now.Add(time.Second)); decision.Allowed {
		t.Fatal("churn reset the recently blocked client")
	}
	shard.cleanupLocked(now.Add(3*time.Minute), throttle.config)
	if len(shard.entries) != 0 || shard.oldest != nil || shard.newest != nil {
		t.Fatal("expired throttle entries or LRU links retained")
	}
}

func throttleBenchmarkIPs(count int) []string {
	ips := make([]string, 0, count)
	for i := 0; len(ips) < count; i++ {
		ip := fmt.Sprintf("10.%d.%d.%d", i>>16, (i>>8)&255, i&255)
		if reverseProxyThrottleHash(ip)%reverseProxyThrottleShardCount == 0 {
			ips = append(ips, ip)
		}
	}
	return ips
}

// The >capacity working sets deliberately force steady-state admissions;
// timestamps never reach TTL expiry during a practical benchmark run.
func BenchmarkActiveIPCardinality(b *testing.B) {
	for _, count := range []int{4096, 4097, 8192} {
		b.Run(fmt.Sprintf("IPs%d", count), func(b *testing.B) {
			tracker := &activeIPTracker{}
			ips := make([]string, count)
			now := time.Now()
			for i := range ips {
				ips[i] = fmt.Sprintf("10.0.%d.%d", i/256, i%256)
				ts := now.Add(time.Duration(i))
				releaseHostActiveIP(tracker.markActiveIP(ips[i], ts), ts)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				ts := now.Add(time.Duration(count + i))
				releaseHostActiveIP(tracker.markActiveIP(ips[i%count], ts), ts)
			}
		})
	}
}

func BenchmarkThrottleShardCardinality(b *testing.B) {
	for _, count := range []int{2048, 2049} {
		b.Run(fmt.Sprintf("IPs%d", count), func(b *testing.B) {
			throttle := newReverseProxyThrottle(models.ReverseProxyThrottleConfig{Enabled: true, RequestsPerSecond: 1000000000, Burst: 1000000000, BlockSeconds: 30})
			ips := throttleBenchmarkIPs(count)
			now := time.Now()
			for i, ip := range ips {
				throttle.evaluate(ip, now.Add(time.Duration(i)))
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				throttle.evaluate(ips[i%count], now.Add(time.Duration(count+i)))
			}
		})
	}
}
