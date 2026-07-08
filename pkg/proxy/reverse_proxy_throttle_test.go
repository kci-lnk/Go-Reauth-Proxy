package proxy

import (
	"fmt"
	"go-reauth-proxy/pkg/models"
	"net"
	"strings"
	"testing"
	"time"
)

var reverseProxyThrottleBenchmarkSink string

func TestReverseProxyThrottleTracksIdentitiesIndependently(t *testing.T) {
	throttle := newReverseProxyThrottle(models.ReverseProxyThrottleConfig{
		Enabled:           true,
		RequestsPerSecond: 1,
		Burst:             1,
		BlockSeconds:      5,
	})
	now := time.Unix(100, 0)

	if decision := throttle.evaluate("192.0.2.1", now); !decision.Allowed {
		t.Fatal("first request for first identity should be allowed")
	}
	if decision := throttle.evaluate("192.0.2.1", now); decision.Allowed || !decision.NewlyBlocked {
		t.Fatalf("second request for first identity = %#v, want newly blocked", decision)
	}
	if decision := throttle.evaluate("192.0.2.2", now); !decision.Allowed {
		t.Fatalf("first request for second identity = %#v, want allowed", decision)
	}
}

func TestReverseProxyThrottleDisableClearsEntries(t *testing.T) {
	throttle := newReverseProxyThrottle(models.ReverseProxyThrottleConfig{
		Enabled:           true,
		RequestsPerSecond: 1,
		Burst:             1,
		BlockSeconds:      5,
	})
	now := time.Unix(100, 0)

	_ = throttle.evaluate("192.0.2.1", now)
	if decision := throttle.evaluate("192.0.2.1", now); decision.Allowed {
		t.Fatal("identity should be blocked before disabling throttle")
	}

	throttle.updateConfig(models.ReverseProxyThrottleConfig{Enabled: false})
	if decision := throttle.evaluate("192.0.2.1", now); !decision.Allowed {
		t.Fatalf("disabled throttle decision = %#v, want allowed", decision)
	}

	throttle.updateConfig(models.ReverseProxyThrottleConfig{
		Enabled:           true,
		RequestsPerSecond: 1,
		Burst:             1,
		BlockSeconds:      5,
	})
	if decision := throttle.evaluate("192.0.2.1", now); !decision.Allowed {
		t.Fatalf("re-enabled throttle decision = %#v, want allowed after clearing entries", decision)
	}
}

func TestReverseProxyThrottleShardEnforcesMaxEntries(t *testing.T) {
	throttle := newReverseProxyThrottle(models.ReverseProxyThrottleConfig{
		Enabled:           true,
		RequestsPerSecond: 100,
		Burst:             100,
		BlockSeconds:      5,
	})
	shard := &throttle.shards[0]
	for i := 0; i < reverseProxyThrottleMaxEntriesPerShard+25; i++ {
		shard.entries[fmt.Sprintf("identity-%d", i)] = &reverseProxyThrottleEntry{
			lastSeen: time.Unix(int64(i), 0),
		}
	}

	shard.enforceMaxEntriesLocked()

	if got := len(shard.entries); got != reverseProxyThrottleMaxEntriesPerShard {
		t.Fatalf("entry count = %d, want %d", got, reverseProxyThrottleMaxEntriesPerShard)
	}
	if _, ok := shard.entries["identity-0"]; ok {
		t.Fatal("oldest identity was not evicted")
	}
}

func TestNormalizeIPAddressMatchesLegacyBehavior(t *testing.T) {
	cases := []string{
		"",
		"198.51.100.10",
		" 198.51.100.10 ",
		"198.51.100.10:12345",
		"198.51.100.10:",
		"198.51.100.10:abc",
		"[2001:db8::1]:443",
		"2001:db8::1",
		"[2001:db8::1]",
		"::ffff:192.0.2.1",
		"example.com:443",
		"bad-ip",
	}

	for _, tc := range cases {
		if got, want := normalizeIPAddress(tc), normalizeIPAddressLegacyForBenchmark(tc); got != want {
			t.Fatalf("normalizeIPAddress(%q) = %q, want legacy %q", tc, got, want)
		}
	}
}

func TestNormalizeClientIPMatchesLegacyBehavior(t *testing.T) {
	cases := []string{
		"",
		"198.51.100.10",
		"198.51.100.10:12345",
		"198.51.100.10:",
		"198.51.100.10:abc",
		"[2001:db8::1]:443",
		"[2001:db8::1]",
		"example.com:443",
		"bad-client",
	}

	for _, tc := range cases {
		if got, want := normalizeClientIP(tc), normalizeClientIPLegacyForBenchmark(tc); got != want {
			t.Fatalf("normalizeClientIP(%q) = %q, want legacy %q", tc, got, want)
		}
	}
}

func TestFirstForwardedClientIPMatchesLegacyBehavior(t *testing.T) {
	cases := []string{
		"",
		"198.51.100.10, 198.51.100.11",
		"bad, 198.51.100.12",
		"[2001:db8::1]:443, 198.51.100.13",
	}

	for _, tc := range cases {
		if got, want := firstForwardedClientIP(tc), firstForwardedClientIPLegacyForBenchmark(tc); got != want {
			t.Fatalf("firstForwardedClientIP(%q) = %q, want legacy %q", tc, got, want)
		}
	}
}

func BenchmarkNormalizeIPAddressIPv4(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		reverseProxyThrottleBenchmarkSink = normalizeIPAddress("198.51.100.10")
	}
}

func BenchmarkNormalizeIPAddressIPv4Old(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		reverseProxyThrottleBenchmarkSink = normalizeIPAddressLegacyForBenchmark("198.51.100.10")
	}
}

func BenchmarkNormalizeIPAddressIPv4Port(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		reverseProxyThrottleBenchmarkSink = normalizeIPAddress("198.51.100.10:12345")
	}
}

func BenchmarkNormalizeIPAddressIPv4PortOld(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		reverseProxyThrottleBenchmarkSink = normalizeIPAddressLegacyForBenchmark("198.51.100.10:12345")
	}
}

func BenchmarkNormalizeClientIPRemoteAddr(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		reverseProxyThrottleBenchmarkSink = normalizeClientIP("198.51.100.10:12345")
	}
}

func BenchmarkNormalizeClientIPRemoteAddrOld(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		reverseProxyThrottleBenchmarkSink = normalizeClientIPLegacyForBenchmark("198.51.100.10:12345")
	}
}

func BenchmarkFirstForwardedClientIP(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		reverseProxyThrottleBenchmarkSink = firstForwardedClientIP("198.51.100.10, 198.51.100.11")
	}
}

func BenchmarkFirstForwardedClientIPOld(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		reverseProxyThrottleBenchmarkSink = firstForwardedClientIPLegacyForBenchmark("198.51.100.10, 198.51.100.11")
	}
}

func normalizeClientIPLegacyForBenchmark(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}

	if ip := normalizeIPAddressLegacyForBenchmark(value); ip != "" {
		return ip
	}

	if host, _, err := net.SplitHostPort(value); err == nil {
		host = strings.TrimSpace(host)
		if ip := normalizeIPAddressLegacyForBenchmark(host); ip != "" {
			return ip
		}
		return strings.Trim(host, "[]")
	}

	if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
		trimmed := strings.Trim(value, "[]")
		if ip := normalizeIPAddressLegacyForBenchmark(trimmed); ip != "" {
			return ip
		}
		return trimmed
	}

	return value
}

func firstForwardedClientIPLegacyForBenchmark(value string) string {
	for {
		part, rest, found := strings.Cut(value, ",")
		if ip := normalizeIPAddressLegacyForBenchmark(part); ip != "" {
			return ip
		}
		if !found {
			return ""
		}
		value = rest
	}
}

func normalizeIPAddressLegacyForBenchmark(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}

	if ip := net.ParseIP(value); ip != nil {
		return ip.String()
	}

	if host, _, err := net.SplitHostPort(value); err == nil {
		host = strings.TrimSpace(host)
		if ip := net.ParseIP(host); ip != nil {
			return ip.String()
		}
		trimmed := strings.Trim(host, "[]")
		if ip := net.ParseIP(trimmed); ip != nil {
			return ip.String()
		}
	}

	if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
		trimmed := strings.Trim(value, "[]")
		if ip := net.ParseIP(trimmed); ip != nil {
			return ip.String()
		}
	}

	return ""
}
