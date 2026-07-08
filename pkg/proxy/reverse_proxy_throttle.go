package proxy

import (
	"go-reauth-proxy/pkg/models"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	defaultReverseProxyThrottleRPS         = 100
	defaultReverseProxyThrottleBurst       = 200
	defaultReverseProxyThrottleBlockSecs   = 30
	reverseProxyThrottleCleanupInterval    = 1 * time.Minute
	reverseProxyThrottleMinimumEntryTTL    = 2 * time.Minute
	reverseProxyThrottleShardCount         = 64
	reverseProxyThrottleMaxEntriesPerShard = 2048
)

type reverseProxyThrottle struct {
	configMu sync.RWMutex
	config   models.ReverseProxyThrottleConfig
	shards   [reverseProxyThrottleShardCount]reverseProxyThrottleShard
}

type reverseProxyThrottleShard struct {
	mu          sync.Mutex
	entries     map[string]*reverseProxyThrottleEntry
	nextCleanup time.Time
}

type reverseProxyThrottleDecision struct {
	Allowed      bool
	NewlyBlocked bool
	BlockedUntil time.Time
	Config       models.ReverseProxyThrottleConfig
}

type reverseProxyThrottleEntry struct {
	tokens       float64
	lastSeen     time.Time
	blockedUntil time.Time
}

func newReverseProxyThrottle(cfg models.ReverseProxyThrottleConfig) *reverseProxyThrottle {
	throttle := &reverseProxyThrottle{
		config: normalizeReverseProxyThrottleConfig(cfg),
	}
	for i := range throttle.shards {
		throttle.shards[i].entries = make(map[string]*reverseProxyThrottleEntry)
	}
	return throttle
}

func normalizeReverseProxyThrottleConfig(cfg models.ReverseProxyThrottleConfig) models.ReverseProxyThrottleConfig {
	if !cfg.Enabled {
		return cfg
	}

	if cfg.RequestsPerSecond <= 0 {
		cfg.RequestsPerSecond = defaultReverseProxyThrottleRPS
	}
	if cfg.Burst <= 0 {
		cfg.Burst = defaultReverseProxyThrottleBurst
	}
	if cfg.BlockSeconds <= 0 {
		cfg.BlockSeconds = defaultReverseProxyThrottleBlockSecs
	}
	return cfg
}

func (t *reverseProxyThrottle) updateConfig(cfg models.ReverseProxyThrottleConfig) {
	t.configMu.Lock()
	t.config = normalizeReverseProxyThrottleConfig(cfg)
	if t.config.Enabled {
		t.configMu.Unlock()
		return
	}

	for i := range t.shards {
		shard := &t.shards[i]
		shard.mu.Lock()
		shard.entries = make(map[string]*reverseProxyThrottleEntry)
		shard.nextCleanup = time.Time{}
		shard.mu.Unlock()
	}
	t.configMu.Unlock()
}

func (t *reverseProxyThrottle) evaluate(clientIP string, now time.Time) reverseProxyThrottleDecision {
	decision := reverseProxyThrottleDecision{Allowed: true}
	if t == nil {
		return decision
	}

	identity := normalizeClientIP(clientIP)
	if identity == "" {
		return decision
	}

	t.configMu.RLock()
	cfg := normalizeReverseProxyThrottleConfig(t.config)
	decision.Config = cfg
	if !cfg.Enabled {
		t.configMu.RUnlock()
		return decision
	}

	shard := t.shardForIdentity(identity)
	shard.mu.Lock()
	defer func() {
		shard.mu.Unlock()
		t.configMu.RUnlock()
	}()

	if shard.entries == nil {
		shard.entries = make(map[string]*reverseProxyThrottleEntry)
	}
	shard.cleanupLocked(now, cfg)

	entry := shard.entries[identity]
	if entry == nil {
		entry = &reverseProxyThrottleEntry{
			tokens: float64(cfg.Burst),
		}
		shard.entries[identity] = entry
	}

	if entry.blockedUntil.After(now) {
		entry.lastSeen = now
		decision.Allowed = false
		decision.BlockedUntil = entry.blockedUntil
		return decision
	}
	if !entry.blockedUntil.IsZero() && !entry.blockedUntil.After(now) {
		entry.blockedUntil = time.Time{}
		if entry.tokens < 1 {
			entry.tokens = float64(cfg.Burst)
		}
	}

	if !entry.lastSeen.IsZero() {
		elapsed := now.Sub(entry.lastSeen).Seconds()
		if elapsed > 0 {
			entry.tokens += elapsed * float64(cfg.RequestsPerSecond)
			if entry.tokens > float64(cfg.Burst) {
				entry.tokens = float64(cfg.Burst)
			}
		}
	}

	entry.lastSeen = now
	if entry.tokens < 1 {
		entry.blockedUntil = now.Add(time.Duration(cfg.BlockSeconds) * time.Second)
		shard.enforceMaxEntriesLocked()
		decision.Allowed = false
		decision.NewlyBlocked = true
		decision.BlockedUntil = entry.blockedUntil
		return decision
	}

	entry.tokens -= 1
	shard.enforceMaxEntriesLocked()
	return decision
}

func (t *reverseProxyThrottle) shardForIdentity(identity string) *reverseProxyThrottleShard {
	return &t.shards[int(reverseProxyThrottleHash(identity)%reverseProxyThrottleShardCount)]
}

func reverseProxyThrottleHash(identity string) uint32 {
	const (
		offset32 = 2166136261
		prime32  = 16777619
	)
	hash := uint32(offset32)
	for i := 0; i < len(identity); i++ {
		hash ^= uint32(identity[i])
		hash *= prime32
	}
	return hash
}

func (s *reverseProxyThrottleShard) cleanupLocked(now time.Time, cfg models.ReverseProxyThrottleConfig) {
	if now.Before(s.nextCleanup) {
		return
	}

	entryTTL := reverseProxyThrottleEntryTTL(cfg)
	for identity, entry := range s.entries {
		if entry == nil {
			delete(s.entries, identity)
			continue
		}
		if entry.blockedUntil.After(now) {
			continue
		}
		if entry.lastSeen.IsZero() || now.Sub(entry.lastSeen) > entryTTL {
			delete(s.entries, identity)
		}
	}
	s.nextCleanup = now.Add(reverseProxyThrottleCleanupInterval)
	s.enforceMaxEntriesLocked()
}

func (s *reverseProxyThrottleShard) enforceMaxEntriesLocked() {
	if s == nil || len(s.entries) <= reverseProxyThrottleMaxEntriesPerShard {
		return
	}
	type throttleCandidate struct {
		identity string
		lastSeen time.Time
	}
	candidates := make([]throttleCandidate, 0, len(s.entries))
	for identity, entry := range s.entries {
		if entry == nil {
			delete(s.entries, identity)
			continue
		}
		candidates = append(candidates, throttleCandidate{
			identity: identity,
			lastSeen: entry.lastSeen,
		})
	}
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].lastSeen.Before(candidates[j].lastSeen)
	})
	for _, candidate := range candidates {
		if len(s.entries) <= reverseProxyThrottleMaxEntriesPerShard {
			return
		}
		delete(s.entries, candidate.identity)
	}
}

func reverseProxyThrottleEntryTTL(cfg models.ReverseProxyThrottleConfig) time.Duration {
	ttl := time.Duration(cfg.BlockSeconds*2) * time.Second
	if ttl < reverseProxyThrottleMinimumEntryTTL {
		ttl = reverseProxyThrottleMinimumEntryTTL
	}
	return ttl
}

func normalizeClientIP(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}

	if ip := normalizeIPAddress(value); ip != "" {
		return ip
	}

	if host, _, err := net.SplitHostPort(value); err == nil {
		host = strings.TrimSpace(host)
		if ip := normalizeIPAddress(host); ip != "" {
			return ip
		}
		return strings.Trim(host, "[]")
	}

	if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
		trimmed := strings.Trim(value, "[]")
		if ip := normalizeIPAddress(trimmed); ip != "" {
			return ip
		}
		return trimmed
	}

	return value
}

func firstForwardedClientIP(value string) string {
	for {
		part, rest, found := strings.Cut(value, ",")
		if ip := normalizeIPAddress(part); ip != "" {
			return ip
		}
		if !found {
			return ""
		}
		value = rest
	}
}

func normalizeIPAddress(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}

	if isCanonicalIPv4(value) {
		return value
	}

	if host, ok := canonicalIPv4HostPort(value); ok {
		return host
	}

	if ip, ok := parseNetipAddrString(value); ok {
		return ip
	}

	if addrPort, err := netip.ParseAddrPort(value); err == nil {
		return netipAddrString(addrPort.Addr())
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

func isCanonicalIPv4(value string) bool {
	octets := 0
	start := 0
	for i := 0; i <= len(value); i++ {
		if i < len(value) && value[i] != '.' {
			continue
		}
		if i == start || i-start > 3 {
			return false
		}
		if i-start > 1 && value[start] == '0' {
			return false
		}
		n := 0
		for j := start; j < i; j++ {
			c := value[j]
			if c < '0' || c > '9' {
				return false
			}
			n = n*10 + int(c-'0')
		}
		if n > 255 {
			return false
		}
		octets++
		start = i + 1
	}
	return octets == 4
}

func canonicalIPv4HostPort(value string) (string, bool) {
	idx := strings.IndexByte(value, ':')
	if idx <= 0 || strings.IndexByte(value[idx+1:], ':') != -1 {
		return "", false
	}
	host := value[:idx]
	if !isCanonicalIPv4(host) {
		return "", false
	}
	return host, true
}

func parseNetipAddrString(value string) (string, bool) {
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return "", false
	}
	return netipAddrString(addr), true
}

func netipAddrString(addr netip.Addr) string {
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	return addr.String()
}
