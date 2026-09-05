package waf

import (
	"strings"
	"sync"
	"time"
)

const (
	maxStoredEventBytes  = 256 << 10
	maxStoredEventsBytes = 16 << 20
)

type EventStore struct {
	mu          sync.Mutex
	items       map[string]storedEvent
	order       []string
	leases      map[string]eventLease
	leased      map[string]string
	maxEntries  int
	ttl         time.Duration
	leaseTTL    time.Duration
	bytes       int
	nextExpiry  time.Time
	expiryTimer *time.Timer
}

type storedEvent struct {
	event     Event
	bytes     int
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
	size := eventMemoryBytes(event)
	if size > maxStoredEventBytes {
		event = compactOversizedEvent(event)
		size = eventMemoryBytes(event)
	} else {
		event = cloneStoredEvent(event)
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked(now)
	if _, exists := s.items[event.TraceID]; !exists {
		s.order = append(s.order, event.TraceID)
	}
	if previous, ok := s.items[event.TraceID]; ok {
		s.bytes -= previous.bytes
	}
	s.bytes += size
	s.items[event.TraceID] = storedEvent{
		bytes:     size,
		event:     event,
		expiresAt: now.Add(s.ttl),
	}
	s.scheduleExpiryLocked(now.Add(s.ttl))
	for len(s.order) > s.maxEntries || s.bytes > maxStoredEventsBytes {
		oldest := s.order[0]
		s.order[0] = ""
		s.order = s.order[1:]
		s.deleteItemLocked(oldest)
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
			s.deleteItemLocked(id)
			continue
		}
		next = append(next, id)
	}
	clear(s.order[len(next):])
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

	leaseID := "waf_lease_" + newTraceID()[len("trc_"):]
	for _, id := range ids {
		s.leased[id] = leaseID
	}
	s.leases[leaseID] = eventLease{
		ids:       ids,
		expiresAt: now.Add(s.leaseTTL),
	}
	s.scheduleExpiryLocked(now.Add(s.leaseTTL))
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
			s.deleteItemLocked(id)
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
	if !s.nextExpiry.IsZero() && now.Before(s.nextExpiry) {
		return
	}
	s.nextExpiry = time.Time{}
	if s.expiryTimer != nil {
		s.expiryTimer.Stop()
		s.expiryTimer = nil
	}
	for leaseID, lease := range s.leases {
		if !now.Before(lease.expiresAt) {
			s.releaseLeaseLocked(leaseID)
		} else {
			s.scheduleExpiryLocked(lease.expiresAt)
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
		if !now.Before(item.expiresAt) {
			s.deleteItemLocked(id)
			delete(s.leased, id)
			continue
		}
		s.scheduleExpiryLocked(item.expiresAt)
		next = append(next, id)
	}
	clear(s.order[len(next):])
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
	clear(s.order[len(next):])
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

func (s *EventStore) deleteItemLocked(id string) {
	if item, ok := s.items[id]; ok {
		s.bytes -= item.bytes
		delete(s.items, id)
	}
}

// Most Add calls cannot expire anything. One timer releases idle stores too;
// renewed IDs need not be reordered, and lease expiry remains independent.
func (s *EventStore) scheduleExpiryLocked(at time.Time) {
	if !s.nextExpiry.IsZero() && !at.Before(s.nextExpiry) {
		return
	}
	s.nextExpiry = at
	if s.expiryTimer != nil {
		s.expiryTimer.Stop()
	}
	s.expiryTimer = time.AfterFunc(time.Until(at), func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.cleanupLocked(time.Now())
	})
}

func eventMemoryBytes(event Event) int {
	size := 512 + len(event.RuleIDs)*8 + len(event.Rules)*192
	for _, value := range eventStrings(&event) {
		size += len(*value)
	}
	for _, rule := range event.Rules {
		size += len(rule.Message) + len(rule.Data) + len(rule.Severity) + len(rule.File) + len(rule.Tags)*16 + len(rule.MatchedVariables)*48
		for _, tag := range rule.Tags {
			size += len(tag)
		}
		for _, match := range rule.MatchedVariables {
			size += len(match.Variable) + len(match.Key) + len(match.ValuePreview)
		}
	}
	if event.Interruption != nil {
		size += 32 + len(event.Interruption.Action)
	}
	return size
}

func eventStrings(event *Event) []*string {
	return []*string{&event.TraceID, &event.TransactionID, &event.Time, &event.Mode, &event.Action,
		&event.ClientIP, &event.RemoteAddr, &event.Method, &event.Scheme, &event.Host, &event.Path,
		&event.Query, &event.RequestURI, &event.UserAgent, &event.Referer, &event.RouteType,
		&event.RouteKey, &event.Upstream, &event.BundleID, &event.BundleHash, &event.Error}
}

// Own every string and slice at the storage boundary so substrings cannot
// retain request buffers and callers cannot mutate a queued event.
func cloneStoredEvent(event Event) Event {
	for _, value := range eventStrings(&event) {
		*value = strings.Clone(*value)
	}
	event.RuleIDs = append([]int(nil), event.RuleIDs...)
	event.Rules = append([]RuleMatch(nil), event.Rules...)
	for i := range event.Rules {
		rule := &event.Rules[i]
		rule.Message, rule.Data = strings.Clone(rule.Message), strings.Clone(rule.Data)
		rule.Severity, rule.File = strings.Clone(rule.Severity), strings.Clone(rule.File)
		rule.Tags = append([]string(nil), rule.Tags...)
		for j := range rule.Tags {
			rule.Tags[j] = strings.Clone(rule.Tags[j])
		}
		rule.MatchedVariables = append([]MatchedVariable(nil), rule.MatchedVariables...)
		for j := range rule.MatchedVariables {
			match := &rule.MatchedVariables[j]
			match.Variable, match.Key, match.ValuePreview = strings.Clone(match.Variable), strings.Clone(match.Key), strings.Clone(match.ValuePreview)
		}
	}
	if event.Interruption != nil {
		value := *event.Interruption
		value.Action = strings.Clone(value.Action)
		event.Interruption = &value
	}
	return event
}

// Preserve the security decision when request-controlled details exceed the
// storage budget. All fields have independent bounds, including rule counts,
// so oversized URIs or match details cannot suppress the audit event entirely.
func compactOversizedEvent(event Event) Event {
	const maxFieldBytes = 2048
	const maxRuleIDs = 128
	const maxRuleSummaries = 8
	for _, value := range eventStrings(&event) {
		*value = truncate(*value, maxFieldBytes)
	}
	event.RuleIDs = append([]int(nil), event.RuleIDs[:min(len(event.RuleIDs), maxRuleIDs)]...)
	if event.Interruption != nil && event.Interruption.RuleID != 0 {
		blockedID := event.Interruption.RuleID
		found := false
		for _, id := range event.RuleIDs {
			if id == blockedID {
				found = true
				break
			}
		}
		if !found {
			if len(event.RuleIDs) == maxRuleIDs {
				event.RuleIDs[len(event.RuleIDs)-1] = blockedID
			} else {
				event.RuleIDs = append(event.RuleIDs, blockedID)
			}
		}
	}
	rules := event.Rules
	event.Rules = make([]RuleMatch, 0, min(len(rules), maxRuleSummaries))
	for _, rule := range rules[:min(len(rules), maxRuleSummaries)] {
		event.Rules = append(event.Rules, RuleMatch{ID: rule.ID, Message: truncate(rule.Message, 512),
			Data: truncate(rule.Data, 512), Severity: truncate(rule.Severity, 64), Phase: rule.Phase,
			File: truncate(rule.File, 512), Line: rule.Line, Disruptive: rule.Disruptive})
	}
	if event.Interruption != nil {
		interruption := *event.Interruption
		interruption.Action = truncate(interruption.Action, 256)
		event.Interruption = &interruption
	}
	if event.Error != "" {
		event.Error += "; "
	}
	event.Error += "event_details_truncated"
	return event
}
