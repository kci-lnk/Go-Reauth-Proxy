package waf

import (
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
	"unsafe"
)

func TestTruncateOwnsPreviewStorage(t *testing.T) {
	source := strings.Repeat("x", 1<<20)
	for _, value := range []string{source, source[32:64]} {
		preview := truncate(value, 256)
		if len(preview) != min(len(value), 256) {
			t.Fatalf("preview length = %d", len(preview))
		}
		pointer := uintptr(unsafe.Pointer(unsafe.StringData(preview)))
		start := uintptr(unsafe.Pointer(unsafe.StringData(source)))
		if pointer >= start && pointer < start+uintptr(len(source)) {
			t.Fatal("preview retains the source allocation")
		}
	}
}

func TestTruncatePreservesUTF8BoundariesAndOwnedStorage(t *testing.T) {
	source := strings.Repeat("中🙂a", 4)
	start := uintptr(unsafe.Pointer(unsafe.StringData(source)))
	for limit := 1; limit <= len(source)+1; limit++ {
		preview := truncate(source, limit)
		if len(preview) > limit || !utf8.ValidString(preview) || !strings.HasPrefix(source, preview) {
			t.Fatalf("limit=%d produced invalid or oversized prefix %q", limit, preview)
		}
		if len(preview) < len(source) {
			_, nextBytes := utf8.DecodeRuneInString(source[len(preview):])
			if len(preview)+nextBytes <= limit {
				t.Fatalf("limit=%d unnecessarily dropped a complete character", limit)
			}
		}
		if len(preview) != 0 {
			pointer := uintptr(unsafe.Pointer(unsafe.StringData(preview)))
			if pointer >= start && pointer < start+uintptr(len(source)) {
				t.Fatalf("limit=%d retained source allocation", limit)
			}
		}
	}
}

func TestEventStoreOwnsStoredStringsAndSlices(t *testing.T) {
	source := strings.Repeat("x", 1<<20)
	event := Event{TraceID: "owned", Path: source[15:31], Rules: []RuleMatch{{MatchedVariables: []MatchedVariable{{Key: source[32:64], ValuePreview: source[:256]}}}}}
	store := NewEventStore(10, time.Minute)
	store.Add(event)
	event.Rules[0].MatchedVariables[0].ValuePreview = "mutated"
	result := store.Drain(1).Events[0]
	if result.Rules[0].MatchedVariables[0].ValuePreview == "mutated" {
		t.Fatal("caller mutated queued event")
	}
	start := uintptr(unsafe.Pointer(unsafe.StringData(source)))
	for _, value := range []string{result.Path, result.Rules[0].MatchedVariables[0].Key, result.Rules[0].MatchedVariables[0].ValuePreview} {
		pointer := uintptr(unsafe.Pointer(unsafe.StringData(value)))
		if pointer >= start && pointer < start+uintptr(len(source)) {
			t.Fatal("stored substring retains source allocation")
		}
	}
	if store.bytes != 0 {
		t.Fatalf("drain retained budget: %d", store.bytes)
	}
}

func TestEventStoreByteBudgetAndIdleExpiry(t *testing.T) {
	store := NewEventStore(1000, 25*time.Millisecond)
	payload := strings.Repeat("x", maxStoredEventBytes/2)
	for i := 0; i < 150; i++ {
		store.Add(Event{TraceID: fmt.Sprint(i), Error: payload})
	}
	store.mu.Lock()
	if store.bytes > maxStoredEventsBytes {
		t.Fatalf("budget exceeded: %d", store.bytes)
	}
	store.mu.Unlock()
	// Inspect the backing store directly so no accessor triggers the cleanup.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		store.mu.Lock()
		empty := len(store.items) == 0 && store.bytes == 0
		store.mu.Unlock()
		if empty {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("idle events retained after expiry")
}

func TestEventStoreOversizedEventPreservesSecurityDecision(t *testing.T) {
	store := NewEventStore(10, time.Minute)
	huge := strings.Repeat("x", maxStoredEventBytes)
	event := Event{TraceID: "large", Time: "2026-09-05T12:00:00Z", Mode: ModeBlocking, Action: "deny", Status: 403,
		ClientIP: "203.0.113.1", RequestURI: "/attack?q=" + huge, UserAgent: huge,
		RuleIDs: make([]int, 1000), Rules: make([]RuleMatch, 100),
		Interruption: &InterruptionInfo{RuleID: 123, Action: "deny", Status: 403}, Error: "rule evaluation"}
	for i := range event.RuleIDs {
		event.RuleIDs[i] = 123 + i
	}
	for i := range event.Rules {
		event.Rules[i] = RuleMatch{ID: 123 + i, Message: "attack blocked", Data: huge, MatchedVariables: []MatchedVariable{{Key: "arg", ValuePreview: huge}}}
	}
	store.Add(event)
	lease := store.Lease(1)
	if len(lease.Events) != 1 {
		t.Fatalf("oversized event was dropped: %#v", lease)
	}
	got := lease.Events[0]
	if got.TraceID != event.TraceID || got.Time != event.Time || got.Mode != ModeBlocking || got.Action != "deny" || got.Status != 403 || got.ClientIP != event.ClientIP || got.Interruption == nil || got.Interruption.RuleID != 123 || got.Interruption.Action != "deny" {
		t.Fatalf("security decision lost: %#v", got)
	}
	if !strings.Contains(got.Error, "event_details_truncated") || !strings.Contains(got.Error, "rule evaluation") || len(got.RuleIDs) == 0 || got.RuleIDs[0] != 123 || len(got.Rules) == 0 || got.Rules[0].Message != "attack blocked" {
		t.Fatalf("audit reason lost: %#v", got)
	}
	if size := eventMemoryBytes(got); size > maxStoredEventBytes || size != store.bytes {
		t.Fatalf("invalid compacted budget: size=%d charged=%d", size, store.bytes)
	}
	if len(got.Rules[0].MatchedVariables) != 0 {
		t.Fatal("oversized matched details retained")
	}
	if len(event.Rules[0].MatchedVariables) != 1 || event.Rules[0].Data != huge {
		t.Fatal("compaction mutated caller event")
	}
	store.Acknowledge(lease.LeaseID)
	if store.bytes != 0 {
		t.Fatalf("acknowledgement retained budget: %d", store.bytes)
	}
}

func TestOversizedEventKeepsInterruptingRuleAfterIDLimit(t *testing.T) {
	store := NewEventStore(10, time.Minute)
	ids := make([]int, 130)
	for i := range ids {
		ids[i] = 1000 + i
	}
	blockedID := ids[len(ids)-1]
	store.Add(Event{TraceID: "last-rule", Action: "deny", RuleIDs: ids,
		RequestURI:   strings.Repeat("x", maxStoredEventBytes),
		Interruption: &InterruptionInfo{RuleID: blockedID, Action: "deny", Status: 403}})
	lease := store.Lease(1)
	if len(lease.Events) != 1 {
		t.Fatal("oversized event was dropped")
	}
	got := lease.Events[0]
	if len(got.RuleIDs) > 128 {
		t.Fatalf("rule IDs exceed bound: %d", len(got.RuleIDs))
	}
	for _, id := range got.RuleIDs {
		if id == blockedID {
			return
		}
	}
	t.Fatalf("interrupting rule %d missing from compacted IDs: %v", blockedID, got.RuleIDs)
}
