package proxy

import (
	"net/http"
	"sort"
	"sync/atomic"
	"time"
)

const loggedInActiveWindow = 2 * time.Minute
const loggedInActiveCleanupInterval = 30 * time.Second
const loggedInActiveMaxEntries = 8192

func (h *Handler) storeLoggedInActive(key string, now time.Time) {
	if key == "" {
		return
	}
	nowUnixNano := now.UnixNano()
	if value, ok := h.loggedInActive.Load(key); ok {
		value.(*atomic.Int64).Store(nowUnixNano)
	} else {
		h.loggedInActiveMu.Lock()
		if value, ok := h.loggedInActive.Load(key); ok {
			value.(*atomic.Int64).Store(nowUnixNano)
		} else {
			seen := new(atomic.Int64)
			seen.Store(nowUnixNano)
			h.loggedInActive.Store(key, seen)
			h.loggedInActiveCount.Add(1)
			h.enforceLoggedInActiveLimitLocked()
		}
		h.loggedInActiveMu.Unlock()
	}
	h.cleanupLoggedInActiveIfNeeded(now)
}

func (h *Handler) markLoggedInActive(r *http.Request, clientIP string, now time.Time) {
	h.storeLoggedInActive(activeIdentityKey(r, clientIP), now)
}

func (h *Handler) MarkLoggedInActiveByClientIP(clientIP string, now time.Time) {
	h.storeLoggedInActive(activeIdentityKeyFromClientIP(clientIP), now)
}

func (h *Handler) hasRecentLoggedInActive(r *http.Request, clientIP string, now time.Time) bool {
	key := activeIdentityKey(r, clientIP)
	if key == "" {
		return false
	}
	value, ok := h.loggedInActive.Load(key)
	lastSeen, valid := value.(*atomic.Int64)
	if !ok || !valid || lastSeen.Load() < now.Add(-loggedInActiveWindow).UnixNano() {
		if ok {
			h.deleteLoggedInActive(key)
		}
		return false
	}
	h.cleanupLoggedInActiveIfNeeded(now)
	return true
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
	cutoff := now.Add(-loggedInActiveWindow).UnixNano()
	h.loggedInActive.Range(func(key, value any) bool {
		ts, ok := value.(*atomic.Int64)
		if !ok || ts.Load() < cutoff {
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
		seen, _ := value.(*atomic.Int64)
		var ts int64
		if seen != nil {
			ts = seen.Load()
		}
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
