package proxy

import (
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"time"
)

const loggedInActiveWindow = 2 * time.Minute
const loggedInActiveCleanupInterval = 30 * time.Second
const loggedInActiveMaxEntries = 8192

// loggedInActivity is immutable once published. Membership and updates share
// loggedInActiveMu so snapshots observe each identity's IP and timestamp together.
type loggedInActivity struct {
	ip   string
	seen int64
}

func (h *Handler) storeLoggedInActive(key, clientIP string, now time.Time) {
	if key == "" {
		return
	}
	ip := strings.TrimSpace(clientIP)
	if address, err := netip.ParseAddr(ip); err == nil {
		ip = address.Unmap().WithZone("").String()
	} else {
		ip = ""
	}
	h.loggedInActiveMu.Lock()
	previous, exists := h.loggedInActive.Load(key)
	if !exists || previous.(loggedInActivity).seen <= now.UnixNano() {
		h.loggedInActive.Store(key, loggedInActivity{ip: ip, seen: now.UnixNano()})
		if !exists {
			h.loggedInActiveCount.Add(1)
		}
	}
	h.enforceLoggedInActiveLimitLocked()
	h.loggedInActiveMu.Unlock()
	h.cleanupLoggedInActiveIfNeeded(now)
}

func (h *Handler) markLoggedInActive(r *http.Request, clientIP string, now time.Time) {
	h.storeLoggedInActive(activeIdentityKey(r, clientIP), clientIP, now)
}

func (h *Handler) MarkLoggedInActiveByClientIP(clientIP string, now time.Time) {
	h.storeLoggedInActive(activeIdentityKeyFromClientIP(clientIP), clientIP, now)
}

func (h *Handler) hasRecentLoggedInActive(r *http.Request, clientIP string, now time.Time) bool {
	key := activeIdentityKey(r, clientIP)
	if key == "" {
		return false
	}
	h.loggedInActiveMu.Lock()
	value, ok := h.loggedInActive.Load(key)
	activity, valid := value.(loggedInActivity)
	recent := ok && valid && activity.seen >= now.Add(-loggedInActiveWindow).UnixNano()
	if ok && !recent {
		h.deleteLoggedInActiveLocked(key)
	}
	h.loggedInActiveMu.Unlock()
	if recent {
		h.cleanupLoggedInActiveIfNeeded(now)
	}
	return recent
}

type OnlineIPStats struct {
	IP            string
	LastSeenAt    time.Time
	IdentityCount int64
}

type OnlineIPsStats struct {
	Items         []OnlineIPStats
	OnlineCount   int64
	WindowSeconds int32
	Timestamp     int64
}

// GetOnlineIPs takes one bounded snapshot, including an empty-IP bucket for
// identities whose latest activity has no valid address. No identity keys escape.
func (h *Handler) GetOnlineIPs(now time.Time) OnlineIPsStats {
	result := OnlineIPsStats{Items: []OnlineIPStats{}, WindowSeconds: int32(loggedInActiveWindow / time.Second), Timestamp: now.UnixMilli()}
	// Freeze immutable records under the membership lock. Aggregation and time
	// conversion can allocate and must not hold up authenticated request updates.
	activities := make([]loggedInActivity, 0, loggedInActiveMaxEntries)
	h.loggedInActiveMu.Lock()
	h.cleanupLoggedInActiveLocked(now)
	h.loggedInActive.Range(func(_, value any) bool {
		activities = append(activities, value.(loggedInActivity))
		return true
	})
	h.loggedInActiveMu.Unlock()
	result.OnlineCount = int64(len(activities))
	groups := make(map[string]OnlineIPStats)
	for _, activity := range activities {
		item := groups[activity.ip]
		item.IP = activity.ip
		item.IdentityCount++
		seen := time.Unix(0, activity.seen).UTC()
		if seen.After(item.LastSeenAt) {
			item.LastSeenAt = seen
		}
		groups[activity.ip] = item
	}
	for _, item := range groups {
		result.Items = append(result.Items, item)
	}
	sort.Slice(result.Items, func(i, j int) bool {
		if result.Items[i].LastSeenAt.Equal(result.Items[j].LastSeenAt) {
			return result.Items[i].IP < result.Items[j].IP
		}
		return result.Items[i].LastSeenAt.After(result.Items[j].LastSeenAt)
	})
	return result
}

func (h *Handler) activeLoggedInCount(now time.Time) int64 {
	h.cleanupLoggedInActive(now)
	return h.loggedInActiveCount.Load()
}

func (h *Handler) cleanupLoggedInActiveIfNeeded(now time.Time) {
	nowUnixNano := now.UnixNano()
	lastCleanup := h.loggedInActiveCleanupNano.Load()
	if lastCleanup > 0 && nowUnixNano-lastCleanup < int64(loggedInActiveCleanupInterval) {
		return
	}
	if !h.loggedInActiveCleanupNano.CompareAndSwap(lastCleanup, nowUnixNano) {
		return
	}
	h.cleanupLoggedInActive(now)
}

func (h *Handler) cleanupLoggedInActive(now time.Time) {
	h.loggedInActiveMu.Lock()
	defer h.loggedInActiveMu.Unlock()
	h.cleanupLoggedInActiveLocked(now)
}

func (h *Handler) cleanupLoggedInActiveLocked(now time.Time) {
	cutoff := now.Add(-loggedInActiveWindow).UnixNano()
	h.loggedInActive.Range(func(key, value any) bool {
		ts, ok := value.(loggedInActivity)
		if !ok || ts.seen < cutoff {
			h.deleteLoggedInActiveLocked(key)
			return true
		}
		return true
	})
	h.enforceLoggedInActiveLimitLocked()
}

func (h *Handler) deleteLoggedInActive(key any) {
	h.loggedInActiveMu.Lock()
	defer h.loggedInActiveMu.Unlock()
	h.deleteLoggedInActiveLocked(key)
}

func (h *Handler) deleteLoggedInActiveLocked(key any) {
	if _, loaded := h.loggedInActive.LoadAndDelete(key); loaded {
		if h.loggedInActiveCount.Add(-1) < 0 {
			h.loggedInActiveCount.Store(0)
		}
	}
}

func (h *Handler) enforceLoggedInActiveLimitLocked() {
	if h.loggedInActiveCount.Load() <= loggedInActiveMaxEntries {
		return
	}
	type loggedInActiveCandidate struct {
		key any
		ts  int64
	}
	candidates := make([]loggedInActiveCandidate, 0, h.loggedInActiveCount.Load())
	h.loggedInActive.Range(func(key, value any) bool {
		seen, _ := value.(loggedInActivity)
		ts := seen.seen
		candidates = append(candidates, loggedInActiveCandidate{key: key, ts: ts})
		return true
	})
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].ts < candidates[j].ts
	})
	for _, candidate := range candidates {
		if h.loggedInActiveCount.Load() <= loggedInActiveMaxEntries-loggedInActiveMaxEntries/16 {
			return
		}
		h.deleteLoggedInActiveLocked(candidate.key)
	}
}
