package deepmonitor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unsafe"

	"go-reauth-proxy/pkg/grpc/pb"
	"google.golang.org/protobuf/proto"
)

func memoryTestManager() *Manager {
	m := &Manager{sessions: map[string]*sessionState{"test": {meta: sessionMeta{ID: "test", Host: "example.com", State: "active", QuotaBytes: SessionQuotaBytes, NextSequence: 1}, byID: make(map[string]eventLocation)}}, activeByHost: map[string]string{"example.com": "test"}, queue: make(chan writeJob, 128), metaWake: make(chan struct{}, 1), now: time.Now}
	m.publishActiveHostsLocked()
	return m
}

func TestRecordRejectsBeforeCopyingPayload(t *testing.T) {
	m := memoryTestManager()
	m.queuedBytes.Store(MaxQueuedBytes)
	payload := bytes.Repeat([]byte{0x71}, int(PayloadLimitBytes))
	event := &pb.DeepMonitorEvent{Summary: &pb.DeepMonitorEventSummary{Type: "http_exchange"}}
	_ = proto.Size(event) // Warm generated descriptors outside the allocation measurement.
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	if m.Record("test", event, map[string][]byte{"body": payload}) {
		t.Fatal("full queue accepted event")
	}
	runtime.ReadMemStats(&after)
	t.Logf("rejected 16 MiB payload allocated %d bytes", after.TotalAlloc-before.TotalAlloc)
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 1<<20 {
		t.Fatalf("rejection copied large payload: %d bytes allocated", allocated)
	}
	if m.queuedBytes.Load() != MaxQueuedBytes || m.BufferedBytes() != 0 {
		t.Fatalf("reservation leaked: queue=%d total=%d", m.queuedBytes.Load(), m.BufferedBytes())
	}
}

func TestCaptureBudgetTruncatesPrefixAndPreservesHash(t *testing.T) {
	m := memoryTestManager()
	m.bufferedBytes.Store(MaxQueuedBytes - 4096)
	capture := m.NewCapture()
	payload := bytes.Repeat([]byte("ab"), 4096)
	capture.Write(payload[:2048])
	capture.Write(payload[2048:])
	ref := capture.Reference("body", "text/plain")
	digest := sha256.Sum256(payload)
	if ref.ObservedBytes != uint64(len(payload)) || ref.CapturedBytes != 4096 || !ref.Truncated || ref.Sha256 != hex.EncodeToString(digest[:]) {
		t.Fatalf("bad metadata: %v", ref)
	}
	if !bytes.Equal(capture.Snapshot(), payload[:4096]) {
		t.Fatal("capture is not a contiguous prefix")
	}
	if m.BufferedBytes() > MaxQueuedBytes {
		t.Fatal("capture exceeded shared budget")
	}
	capture.Release()
	capture.Release()
	if m.BufferedBytes() != MaxQueuedBytes-4096 {
		t.Fatalf("release was not exactly once: %d", m.BufferedBytes())
	}
}

func TestRecordCapturedTransfersAllocationAndReleasesRejection(t *testing.T) {
	m := memoryTestManager()
	capture := m.NewCapture()
	capture.Write([]byte("captured"))
	original := &capture.data[0]
	ref := capture.Reference("body", "text/plain")
	event := &pb.DeepMonitorEvent{Summary: &pb.DeepMonitorEventSummary{Type: "http_exchange"}, Payloads: []*pb.DeepMonitorPayloadRef{ref}}
	if !m.RecordCaptured("test", event, map[string]*Capture{"body": capture}) {
		t.Fatal("record rejected")
	}
	job := <-m.queue
	if &job.payloads["body"][0] != original {
		t.Fatal("handoff copied payload allocation")
	}
	if len(capture.data) != 0 {
		t.Fatal("capture still owns transferred payload")
	}
	capture.Release()
	if m.BufferedBytes() != job.bytes {
		t.Fatalf("handoff lost reservation: %d vs %d", m.BufferedBytes(), job.bytes)
	}
	m.bufferedBytes.Add(-job.bytes)
	m.queuedBytes.Add(-job.bytes)
	rejected := m.NewCapture()
	rejected.Write([]byte("discard"))
	if m.RecordCaptured("missing", event, map[string]*Capture{"body": rejected}) {
		t.Fatal("inactive session accepted capture")
	}
	if m.BufferedBytes() != 0 {
		t.Fatalf("rejection leaked capture budget: %d", m.BufferedBytes())
	}
}

func writeMemoryTestJournal(t *testing.T, logs string, count int, stopped time.Time) (string, string) {
	t.Helper()
	root := filepath.Join(logs, "deep-monitor")
	id := "fixture"
	dir := filepath.Join(root, id)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	var journal, index bytes.Buffer
	headerValue := strings.Repeat("large-metadata-", 256)
	for i := 1; i <= count; i++ {
		event := &pb.DeepMonitorEvent{Summary: &pb.DeepMonitorEventSummary{Id: fmt.Sprintf("event-%d", i), SessionId: id, Sequence: uint64(i), Type: "http_exchange", Path: fmt.Sprintf("/page/%d", i)}, ClientRequestHeaders: &pb.HeaderList{Headers: []*pb.Header{{Name: "X-Detail", Values: []string{headerValue}}}}}
		data, err := proto.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&index, "%d\t%d\t%d\t%s\n", i, journal.Len(), len(data)+4, event.Summary.Id)
		var header [4]byte
		binary.BigEndian.PutUint32(header[:], uint32(len(data)))
		journal.Write(header[:])
		journal.Write(data)
	}
	if err := os.WriteFile(filepath.Join(dir, "events.pb"), journal.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "events.idx"), index.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	meta := sessionMeta{ID: id, Host: "example.com", State: "stopped", StartedAt: stopped.Add(-time.Minute), StoppedAt: stopped, EventCount: uint64(count), QuotaBytes: SessionQuotaBytes}
	if err := writeSessionMeta(root, meta); err != nil {
		t.Fatal(err)
	}
	return id, headerValue
}

func TestHistoricalCacheIsBoundedAndOldEventsRemainReadable(t *testing.T) {
	logs := t.TempDir()
	id, headerValue := writeMemoryTestJournal(t, logs, MaxCachedEvents+20, time.Now())
	manager, err := NewManager(logs)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	s := manager.sessions[id]
	if len(s.events) > MaxCachedEvents || s.cachedBytes > MaxCachedSummaryBytes {
		t.Fatalf("unbounded cache: count=%d bytes=%d", len(s.events), s.cachedBytes)
	}
	if _, cached := s.byID["event-1"]; cached {
		t.Fatal("fixture did not evict old event")
	}
	items, _, more, err := manager.Query(id, "", 10, "http_exchange", "", "")
	if err != nil || !more || len(items) != 10 || items[0].Id != "event-1" {
		t.Fatalf("old page unavailable: %v %v %v", items, more, err)
	}
	for _, eventID := range []string{"event-1", fmt.Sprintf("event-%d", MaxCachedEvents+20)} {
		event, err := manager.GetEvent(id, eventID)
		if err != nil || event.GetClientRequestHeaders().GetHeaders()[0].GetValues()[0] != headerValue {
			t.Fatalf("lazy event read failed for %s: %v", eventID, err)
		}
	}
	// Sidecar compatibility: older journals can still find uncached events.
	if err := os.Remove(filepath.Join(manager.sessionDir(id), "events.idx")); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.GetEvent(id, "event-1"); err != nil {
		t.Fatal(err)
	}
}

func TestStartupDiscardsExpiredSessionBeforeReadingJournal(t *testing.T) {
	logs := t.TempDir()
	id, _ := writeMemoryTestJournal(t, logs, 1, time.Now().Add(-Retention-time.Hour))
	// An unreadable/invalid expired journal must not be parsed on startup.
	if err := os.WriteFile(filepath.Join(logs, "deep-monitor", id, "events.pb"), []byte("invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	manager, err := NewManager(logs)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	if _, err := manager.GetSession(id); err != ErrNotFound {
		t.Fatalf("expired session loaded: %v", err)
	}
	if _, err := os.Stat(manager.sessionDir(id)); !os.IsNotExist(err) {
		t.Fatalf("expired files retained: %v", err)
	}
}

func TestCaptureSealPreventsLateWritesFromChangingPayload(t *testing.T) {
	m := memoryTestManager()
	capture := m.NewCapture()
	capture.Write([]byte("before"))
	ref := capture.Seal("body", "text/plain")
	capture.Write([]byte("after"))
	if ref.ObservedBytes != 6 || !bytes.Equal(capture.Snapshot(), []byte("before")) {
		t.Fatalf("sealed capture changed: %v", ref)
	}
	capture.Release()
	if m.BufferedBytes() != 0 {
		t.Fatal("sealed capture leaked reservation")
	}
}

func TestHistoricalSubscribeStreamsBoundedReplayInOrder(t *testing.T) {
	logs := t.TempDir()
	id, _ := writeMemoryTestJournal(t, logs, MaxCachedEvents+20, time.Now())
	manager, err := NewManager(logs)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	backlog, stream, err := manager.Subscribe(ctx, id, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(backlog) != 0 || cap(stream) > 128 {
		t.Fatalf("replay was not bounded: backlog=%d channel=%d", len(backlog), cap(stream))
	}
	for want := uint64(1); want <= MaxCachedEvents+20; want++ {
		select {
		case summary := <-stream:
			if summary.GetSequence() != want {
				t.Fatalf("sequence=%d want=%d", summary.GetSequence(), want)
			}
		case <-time.After(time.Second):
			t.Fatalf("replay stalled at %d", want)
		}
	}
	cancel()
	select {
	case <-stream:
	case <-time.After(time.Second):
		t.Fatal("subscription did not close on cancellation")
	}
}

func TestActiveSummaryCacheIsBoundedAndStopReleasesIt(t *testing.T) {
	m := memoryTestManager()
	s := m.sessions["test"]
	for i := 1; i <= MaxCachedEvents+10; i++ {
		s.cacheEvent(&pb.DeepMonitorEventSummary{Id: fmt.Sprint(i), Sequence: uint64(i), Path: strings.Repeat("x", 2048)}, eventLocation{})
	}
	if len(s.events) > MaxCachedEvents || s.cachedBytes > MaxCachedSummaryBytes {
		t.Fatalf("active cache exceeded budget: %d events %d bytes", len(s.events), s.cachedBytes)
	}
	m.Stop("test", "manual")
	if len(s.events) != 0 || len(s.byID) != 0 || s.cachedBytes != 0 || s.lastSequence != MaxCachedEvents+10 {
		t.Fatalf("stop retained history or lost cursor: %#v", s)
	}
}

func TestSummaryCacheDetachesRequestSubstrings(t *testing.T) {
	m := memoryTestManager()
	backing := "/short?q=" + strings.Repeat("x", 4<<20)
	summary := &pb.DeepMonitorEventSummary{Id: "event", Sequence: 1, Path: backing[:6], Notice: backing[4:8]}
	s := m.sessions["test"]
	s.cacheEvent(summary, eventLocation{})
	start := uintptr(unsafe.Pointer(unsafe.StringData(backing)))
	for _, value := range []string{s.events[0].Path, s.events[0].Notice} {
		pointer := uintptr(unsafe.Pointer(unsafe.StringData(value)))
		if pointer >= start && pointer < start+uintptr(len(backing)) {
			t.Fatal("summary substring retained request backing storage")
		}
	}
	summary.Path = "mutated"
	if s.events[0].Path != "/short" {
		t.Fatal("caller mutated summary cache")
	}
}

func TestManagerCloseTerminatesSubscriptionsWithoutContextCancellation(t *testing.T) {
	for _, replay := range []bool{false, true} {
		t.Run(fmt.Sprint(replay), func(t *testing.T) {
			logs := t.TempDir()
			id, _ := writeMemoryTestJournal(t, logs, MaxCachedEvents+20, time.Now())
			manager, err := NewManager(logs)
			if err != nil {
				t.Fatal(err)
			}
			after := uint64(MaxCachedEvents + 20)
			if replay {
				after = 0
			}
			_, stream, err := manager.Subscribe(context.Background(), id, after)
			if err != nil {
				manager.Close()
				t.Fatal(err)
			}
			if replay {
				deadline := time.Now().Add(time.Second)
				for len(stream) < cap(stream) && time.Now().Before(deadline) {
					time.Sleep(time.Millisecond)
				}
				if len(stream) != cap(stream) {
					manager.Close()
					t.Fatal("replay did not fill output queue")
				}
			}
			closed := make(chan struct{})
			go func() { manager.Close(); close(closed) }()
			select {
			case <-closed:
			case <-time.After(time.Second):
				t.Fatal("manager close did not terminate subscription")
			}
			for range stream {
			} // Close waits until the output channel has closed.
			manager.mu.RLock()
			watchers := len(manager.sessions[id].watchers)
			manager.mu.RUnlock()
			if watchers != 0 {
				t.Fatalf("subscription registration retained: %d", watchers)
			}
			if _, _, err := manager.Subscribe(context.Background(), id, after); err == nil {
				t.Fatal("closed manager accepted subscription")
			}
		})
	}
}
