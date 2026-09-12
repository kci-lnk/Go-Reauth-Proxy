package proxy

import (
	"container/list"
	"fmt"
	"log"
	"time"

	"go-reauth-proxy/pkg/models"
	proxywaf "go-reauth-proxy/pkg/waf"
)

const maxWAFViolationBuckets = 100000

type wafViolationBucket struct {
	ip      string
	tokens  float64
	updated time.Time
	pending bool
	retryAt time.Time
}

// All access is serialized by Handler.mu, including blacklist persistence and
// manual removal. This prevents an in-flight automatic ban from undoing removal.
type wafViolationLimiter struct {
	buckets     map[string]*list.Element
	lru         list.List
	lastSweep   time.Time
	lastWarning time.Time
}

func newWAFViolationLimiter() *wafViolationLimiter {
	return &wafViolationLimiter{buckets: make(map[string]*list.Element)}
}

func (l *wafViolationLimiter) remove(ip string) {
	if e := l.buckets[ip]; e != nil {
		l.lru.Remove(e)
		delete(l.buckets, ip)
	}
}

func (l *wafViolationLimiter) exceeded(ip string, now time.Time, capacity int, refillSeconds int) bool {
	refill := time.Duration(refillSeconds) * time.Second
	// Sweep on activity, at most once a minute; no background worker survives a reset.
	if l.lastSweep.IsZero() || now.Sub(l.lastSweep) >= time.Minute {
		for key, e := range l.buckets {
			b := e.Value.(*wafViolationBucket)
			if !b.pending && b.tokens+now.Sub(b.updated).Seconds()/refill.Seconds() >= float64(capacity) {
				l.remove(key)
			}
		}
		l.lastSweep = now
	}
	e := l.buckets[ip]
	if e == nil {
		if len(l.buckets) >= maxWAFViolationBuckets {
			l.remove(l.lru.Back().Value.(*wafViolationBucket).ip)
			if l.lastWarning.IsZero() || now.Sub(l.lastWarning) >= time.Minute {
				log.Printf("WAF violation bucket capacity reached (%d); evicted least recently used IP", maxWAFViolationBuckets)
				l.lastWarning = now
			}
		}
		e = l.lru.PushFront(&wafViolationBucket{ip: ip, tokens: float64(capacity), updated: now})
		l.buckets[ip] = e
	}
	l.lru.MoveToFront(e)
	b := e.Value.(*wafViolationBucket)
	elapsed := now.Sub(b.updated).Seconds()
	if elapsed > 0 {
		b.tokens = min(float64(capacity), b.tokens+elapsed/refill.Seconds())
		b.updated = now
	}
	if b.pending {
		if now.Before(b.retryAt) {
			return false
		}
	} else if b.tokens >= 1 {
		b.tokens--
		return false
	}
	b.pending = true
	b.retryAt = now.Add(5 * time.Second)
	return true
}

func violationRateSettingsChanged(a, b models.WAFConfig) bool {
	return a.Enabled != b.Enabled || a.Mode != b.Mode ||
		a.ViolationRateLimitEnabled != b.ViolationRateLimitEnabled ||
		a.ViolationRateLimitCapacity != b.ViolationRateLimitCapacity ||
		a.ViolationRateLimitRefillSeconds != b.ViolationRateLimitRefillSeconds
}

func (h *Handler) recordWAFViolation(clientIP string, decision proxywaf.Decision, epoch uint64) {
	if !decision.ViolationRateLimitEnabled || !decision.Enabled || decision.Allowed || decision.DetectionOnly || decision.Err != nil {
		return
	}
	ip, _, valid := normalizeGeneralBlacklistIP(clientIP)
	if !valid {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	// Requests evaluated before a reset/removal belong to the previous allowance.
	// Check under the mutation lock so they cannot recreate a freshly cleared bucket.
	if epoch != h.wafViolationEpoch.Load() {
		return
	}
	cfg := h.WAFConfig
	if !proxywaf.IsActive(cfg) || !cfg.ViolationRateLimitEnabled {
		return
	}
	if h.generalBlacklist != nil {
		if _, exists := h.generalBlacklist.contains(ip); exists {
			return
		}
	}
	if h.wafViolationLimiter == nil {
		h.wafViolationLimiter = newWAFViolationLimiter()
	}
	if !h.wafViolationLimiter.exceeded(ip, time.Now(), cfg.ViolationRateLimitCapacity, cfg.ViolationRateLimitRefillSeconds) {
		return
	}
	comment := fmt.Sprintf("WAF violation frequency: capacity=%d, refill=1/%ds, trace_id=%s", cfg.ViolationRateLimitCapacity, cfg.ViolationRateLimitRefillSeconds, decision.TraceID)
	_, err := h.addGeneralBlacklistLocked([]string{ip}, models.GeneralBlacklistSourceWAFRateLimit, comment)
	if err != nil {
		log.Printf("WAF automatic blacklist failed: ip=%s trace_id=%s error=%v", ip, decision.TraceID, err)
		return
	}
	h.wafViolationLimiter.remove(ip)
	log.Printf("WAF automatic blacklist added: ip=%s trace_id=%s", ip, decision.TraceID)
}
