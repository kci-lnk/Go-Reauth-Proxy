package waf

import (
	"sync"
	"time"
)

type EventStore struct {
	mu         sync.Mutex
	items      map[string]storedEvent
	order      []string
	leases     map[string]eventLease
	leased     map[string]string
	maxEntries int
	ttl        time.Duration
	leaseTTL   time.Duration
}

type storedEvent struct {
	event     Event
	expiresAt time.Time
}

type eventLease struct {
	ids       []string
	expiresAt time.Time
}

func NewEventStore(maxEntries int, ttl time.Duration) *EventStore {
	if maxEntries <= 0 {
		maxEntries = DefaultMaxEvents
	}
	if ttl <= 0 {
		ttl = DefaultEventTTL
	}
	return &EventStore{
		items:      make(map[string]storedEvent),
		order:      []string{},
		leases:     make(map[string]eventLease),
		leased:     make(map[string]string),
		maxEntries: maxEntries,
		ttl:        ttl,
		leaseTTL:   DefaultLeaseTTL,
	}
}

func (s *EventStore) Add(event Event) {
	if s == nil || event.TraceID == "" {
		return
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked(now)
	if _, exists := s.items[event.TraceID]; !exists {
		s.order = append(s.order, event.TraceID)
	}
	s.items[event.TraceID] = storedEvent{
		event:     event,
		expiresAt: now.Add(s.ttl),
	}
	for len(s.order) > s.maxEntries {
		oldest := s.order[0]
		s.order = s.order[1:]
		delete(s.items, oldest)
		delete(s.leased, oldest)
	}
}

func (s *EventStore) Pending() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked(time.Now())
	return len(s.items)
}

func (s *EventStore) Drain(limit int) DrainResult {
	if s == nil {
		return DrainResult{Events: []Event{}}
	}
	if limit <= 0 || limit > s.maxEntries {
		limit = s.maxEntries
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked(time.Now())

	events := make([]Event, 0, min(limit, len(s.order)))
	next := s.order[:0]
	for _, id := range s.order {
		item, ok := s.items[id]
		if !ok {
			continue
		}
		if _, isLeased := s.leased[id]; !isLeased && len(events) < limit {
			events = append(events, item.event)
			delete(s.items, id)
			continue
		}
		next = append(next, id)
	}
	s.order = next
	return DrainResult{
		Events:    events,
		Drained:   len(events),
		Remaining: s.availableLocked(),
	}
}

// Lease reserves events without deleting them. The caller must acknowledge
// the lease after durable persistence or release it after a failed handoff.
// Expired leases automatically become available for retry.
func (s *EventStore) Lease(limit int) DrainResult {
	if s == nil {
		return DrainResult{Events: []Event{}}
	}
	if limit <= 0 || limit > s.maxEntries {
		limit = s.maxEntries
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked(now)

	ids := make([]string, 0, min(limit, len(s.order)))
	events := make([]Event, 0, cap(ids))
	for _, id := range s.order {
		if len(events) >= limit {
			break
		}
		if _, isLeased := s.leased[id]; isLeased {
			continue
		}
		item, ok := s.items[id]
		if !ok {
			continue
		}
		ids = append(ids, id)
		events = append(events, item.event)
	}
	if len(ids) == 0 {
		return DrainResult{Events: []Event{}, Remaining: s.availableLocked()}
	}

	leaseID := "waf_lease_" + newTraceID()[len("waf_"):]
	for _, id := range ids {
		s.leased[id] = leaseID
	}
	s.leases[leaseID] = eventLease{
		ids:       ids,
		expiresAt: now.Add(s.leaseTTL),
	}
	return DrainResult{
		Events:    events,
		Drained:   len(events),
		Remaining: s.availableLocked(),
		LeaseID:   leaseID,
	}
}

// Acknowledge deletes the events owned by a successfully persisted lease.
// It is idempotent: unknown or expired leases acknowledge zero events.
func (s *EventStore) Acknowledge(leaseID string) DrainResult {
	if s == nil {
		return DrainResult{Events: []Event{}}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked(time.Now())

	lease, ok := s.leases[leaseID]
	if !ok {
		return DrainResult{Events: []Event{}, Remaining: s.availableLocked()}
	}
	acknowledged := 0
	for _, id := range lease.ids {
		owner, isLeased := s.leased[id]
		if isLeased && owner != leaseID {
			continue
		}
		if isLeased {
			delete(s.leased, id)
			delete(s.items, id)
			acknowledged++
		} else if _, exists := s.items[id]; !exists {
			// A bounded queue may evict an already delivered event while its
			// lease is being persisted. Treat that delivery as acknowledged;
			// the consumer already owns the durable copy.
			acknowledged++
		}
	}
	delete(s.leases, leaseID)
	s.compactOrderLocked()
	return DrainResult{
		Events:       []Event{},
		Remaining:    s.availableLocked(),
		Acknowledged: acknowledged,
	}
}

// Release makes a failed handoff immediately available for retry.
func (s *EventStore) Release(leaseID string) DrainResult {
	if s == nil {
		return DrainResult{Events: []Event{}}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked(time.Now())
	s.releaseLeaseLocked(leaseID)
	return DrainResult{Events: []Event{}, Remaining: s.availableLocked()}
}

func (s *EventStore) cleanupLocked(now time.Time) {
	for leaseID, lease := range s.leases {
		if !now.Before(lease.expiresAt) {
			s.releaseLeaseLocked(leaseID)
		}
	}
	if len(s.order) == 0 {
		return
	}
	next := s.order[:0]
	for _, id := range s.order {
		item, ok := s.items[id]
		if !ok {
			continue
		}
		if now.After(item.expiresAt) {
			delete(s.items, id)
			delete(s.leased, id)
			continue
		}
		next = append(next, id)
	}
	s.order = next
}

func (s *EventStore) releaseLeaseLocked(leaseID string) {
	lease, ok := s.leases[leaseID]
	if !ok {
		return
	}
	for _, id := range lease.ids {
		if s.leased[id] == leaseID {
			delete(s.leased, id)
		}
	}
	delete(s.leases, leaseID)
}

func (s *EventStore) compactOrderLocked() {
	next := s.order[:0]
	for _, id := range s.order {
		if _, ok := s.items[id]; ok {
			next = append(next, id)
		}
	}
	s.order = next
}

func (s *EventStore) availableLocked() int {
	available := 0
	for id := range s.items {
		if _, isLeased := s.leased[id]; !isLeased {
			available++
		}
	}
	return available
}
