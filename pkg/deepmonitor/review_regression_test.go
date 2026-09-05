package deepmonitor

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"go-reauth-proxy/pkg/grpc/pb"
)

func TestRecordQueueDetachesAllMetadataStrings(t *testing.T) {
	m := memoryTestManager()
	backing := "test/body/metadata/" + strings.Repeat("x", 4<<20)
	event := &pb.DeepMonitorEvent{
		Summary:    &pb.DeepMonitorEventSummary{Type: "http_exchange", Path: backing[4:9], Notice: backing[9:17]},
		RequestUri: backing[4:17], Upstream: backing[9:17],
		ClientRequestHeaders: &pb.HeaderList{Headers: []*pb.Header{{Name: backing[9:17], Values: []string{backing[4:9], backing[9:17]}}}},
		Payloads:             []*pb.DeepMonitorPayloadRef{{Part: backing[5:9], ContentType: backing[9:17]}},
		WebsocketFrame:       &pb.DeepMonitorWebSocketFrame{CloseReason: backing[9:17]},
	}
	if !m.Record(backing[:4], event, map[string][]byte{backing[5:9]: []byte("payload")}) {
		t.Fatal("record rejected")
	}
	job := <-m.queue
	values := []string{job.sessionID, job.event.Summary.SessionId, job.event.Summary.Path, job.event.Summary.Notice, job.event.RequestUri, job.event.Upstream, job.event.ClientRequestHeaders.Headers[0].Name, job.event.ClientRequestHeaders.Headers[0].Values[0], job.event.ClientRequestHeaders.Headers[0].Values[1], job.event.Payloads[0].Part, job.event.Payloads[0].ContentType, job.event.WebsocketFrame.CloseReason}
	for key := range job.payloads {
		values = append(values, key)
	}
	start := uintptr(unsafe.Pointer(unsafe.StringData(backing)))
	for _, value := range values {
		address := uintptr(unsafe.Pointer(unsafe.StringData(value)))
		if address >= start && address < start+uintptr(len(backing)) {
			t.Fatalf("queued string %q retained the 4 MiB backing allocation", value)
		}
	}
	if job.bytes > 32<<10 {
		t.Fatalf("small metadata received unexpected charge: %d", job.bytes)
	}
	runtime.KeepAlive(backing)
}

func TestSessionStopReleasesIdleCapturesAndRejectsLateCapture(t *testing.T) {
	m := memoryTestManager()
	capture := m.NewCapture("test")
	capture.Write(make([]byte, 8192))
	if m.BufferedBytes() != 8192 {
		t.Fatalf("capture charge=%d", m.BufferedBytes())
	}
	before := capture.Reference("body", "").ObservedBytes
	if _, err := m.Stop("test", "manual"); err != nil {
		t.Fatal(err)
	}
	capture.Write(make([]byte, 8192))
	if m.BufferedBytes() != 0 || len(capture.Snapshot()) != 0 || capture.Reference("body", "").ObservedBytes != before {
		t.Fatalf("stopped capture continued retaining/hashing: bytes=%d", m.BufferedBytes())
	}
	late := m.NewCapture("test")
	late.Write(make([]byte, 8192))
	if m.BufferedBytes() != 0 || late.Reference("body", "") != nil {
		t.Fatal("late capture was admitted after stop")
	}
	capture.Release()
	late.Release()
	if m.BufferedBytes() != 0 || len(m.captures) != 0 {
		t.Fatal("capture release double-counted or retained registry")
	}
}

func TestManagerCloseReleasesIdleCaptures(t *testing.T) {
	m, err := NewManager(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	session, err := m.Start("close.example", MinDuration)
	if err != nil {
		m.Close()
		t.Fatal(err)
	}
	captures := []*Capture{m.NewCapture(session.Id), m.NewCapture(session.Id), m.NewCapture(session.Id)}
	for _, capture := range captures {
		capture.Write(make([]byte, 8192))
	}
	m.Close()
	if m.BufferedBytes() != 0 || len(m.captures) != 0 {
		t.Fatalf("close retained idle captures: %d", m.BufferedBytes())
	}
	for _, capture := range captures {
		capture.Release()
	}
	if m.BufferedBytes() != 0 {
		t.Fatal("release after close changed budget")
	}
}

func TestManagerCloseKeepsOtherSessionsInactiveAfterLateStop(t *testing.T) {
	for _, operation := range []string{"stop", "maintenance"} {
		t.Run(operation, func(t *testing.T) {
			m, err := NewManager(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(m.Close)
			first, err := m.Start("first.example", MinDuration)
			if err != nil {
				t.Fatal(err)
			}
			second, err := m.Start("second.example", MinDuration)
			if err != nil {
				t.Fatal(err)
			}
			m.Close()
			switch operation {
			case "stop":
				if _, err := m.Stop(first.Id, "manual"); err != nil {
					t.Fatal(err)
				}
			case "maintenance":
				// A maintenance tick already selected before Close may reach
				// its locked expiry check after the active snapshot was cleared.
				m.mu.Lock()
				m.sessions[first.Id].meta.DeadlineAt = time.Now().Add(-time.Second)
				m.mu.Unlock()
				m.maintain()
			}
			if id, active := m.ActiveSession(second.Host); active || m.IsActive(second.Id) {
				t.Errorf("closed manager republished active session %q", id)
			}
			late := m.NewCapture(second.Id)
			defer late.Release()
			late.Write(make([]byte, 8192))
			if m.BufferedBytes() != 0 || late.Reference("body", "") != nil {
				t.Errorf("closed manager admitted late capture: bytes=%d", m.BufferedBytes())
			}
		})
	}
}

func TestCaptureWriteStopAndHandoffRace(t *testing.T) {
	for iteration := 0; iteration < 100; iteration++ {
		m := memoryTestManager()
		capture := m.NewCapture("test")
		capture.Write([]byte("prefix"))
		start := make(chan struct{})
		var workers sync.WaitGroup
		workers.Add(3)
		go func() {
			defer workers.Done()
			<-start
			for i := 0; i < 20; i++ {
				capture.Write(make([]byte, 512))
			}
		}()
		go func() {
			defer workers.Done()
			<-start
			m.RecordCaptured("test", &pb.DeepMonitorEvent{Summary: &pb.DeepMonitorEventSummary{Type: "http_exchange"}}, map[string]*Capture{"body": capture})
		}()
		go func() {
			defer workers.Done()
			<-start
			m.Stop("test", "manual")
			late := m.NewCapture("test")
			late.Write([]byte("late"))
			late.Release()
		}()
		close(start)
		done := make(chan struct{})
		go func() { workers.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("capture Write/Stop/handoff deadlocked")
		}
		capture.Release()
		select {
		case job := <-m.queue:
			m.bufferedBytes.Add(-job.bytes)
			m.queuedBytes.Add(-job.bytes)
		default:
		}
		if m.BufferedBytes() != 0 || m.queuedBytes.Load() != 0 || len(m.captures) != 0 {
			t.Fatalf("capture reservation leaked on iteration %d: buffered=%d queued=%d registry=%d", iteration, m.BufferedBytes(), m.queuedBytes.Load(), len(m.captures))
		}
	}
}

func TestFailedPayloadDoesNotAppearInHistoricalQuery(t *testing.T) {
	m := memoryTestManager()
	m.dir = t.TempDir()
	if err := os.MkdirAll(m.sessionDir("test"), 0700); err != nil {
		t.Fatal(err)
	}
	failed := &pb.DeepMonitorEvent{Summary: &pb.DeepMonitorEventSummary{Type: "http_exchange", Path: "/failed"}, Payloads: []*pb.DeepMonitorPayloadRef{{Part: "body"}}}
	following := &pb.DeepMonitorEvent{Summary: &pb.DeepMonitorEventSummary{Type: "http_exchange", Path: "/following"}}
	if !m.Record("test", failed, map[string][]byte{"body": []byte("payload")}) || !m.Record("test", following, nil) {
		t.Fatal("fixture admission failed")
	}
	first, second := <-m.queue, <-m.queue
	// Only this payload write fails; the already queued following event can persist.
	if err := os.Mkdir(m.payloadPath("test", first.event.Summary.Id, "body"), 0700); err != nil {
		t.Fatal(err)
	}
	m.writeJob(first)
	m.writeJob(second)
	items, _, _, err := m.Query("test", "", 10, "", "", "")
	if err != nil || len(items) != 1 || items[0].Path != "/following" {
		t.Fatalf("failed event became visible through journal fallback: items=%v err=%v", items, err)
	}
	if _, err := m.GetEvent("test", first.event.Summary.Id); err != ErrEventNotFound {
		t.Fatalf("failed event was addressable: %v", err)
	}
	if m.BufferedBytes() != 0 {
		t.Fatalf("failed write leaked budget: %d", m.BufferedBytes())
	}
}

func TestRetentionRechecksArchiveProtectionBeforeDeleting(t *testing.T) {
	m, err := NewManager(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	session, err := m.Start("archive.example", MinDuration)
	if err != nil {
		t.Fatal(err)
	}
	m.Stop(session.Id, "manual")
	m.mu.Lock()
	m.sessions[session.Id].meta.StoppedAt = time.Now().Add(-Retention - time.Minute)
	m.mu.Unlock()
	m.diskMu.Lock()
	done := make(chan struct{})
	go func() { m.maintain(); close(done) }()
	// Wait until maintain has selected the expired candidate and is blocked on
	// diskMu. This observes goroutine state, without timing a scheduler window.
	deadline := time.Now().Add(time.Second)
	blocked := false
	for time.Now().Before(deadline) {
		stack := make([]byte, 64<<10)
		n := runtime.Stack(stack, true)
		for _, goroutine := range strings.Split(string(stack[:n]), "\n\n") {
			if strings.Contains(goroutine, "(*Manager).maintain") && strings.Contains(goroutine, "sync.(*Mutex).Lock") {
				blocked = true
				break
			}
		}
		if blocked {
			break
		}
		runtime.Gosched()
	}
	if !blocked {
		m.diskMu.Unlock()
		<-done
		t.Fatal("retention worker did not reach disk gate")
	}
	// OpenArchive registers protection under mu before it waits for diskMu.
	// Reserve exactly that state while retention's candidate is already stale.
	m.mu.Lock()
	m.sessions[session.Id].exporting++
	m.mu.Unlock()
	m.diskMu.Unlock()
	<-done
	if _, err := m.GetSession(session.Id); err != nil {
		t.Fatalf("retention deleted newly protected session: %v", err)
	}
	if _, err := os.Stat(filepath.Join(m.sessionDir(session.Id), "session.json")); err != nil {
		t.Fatalf("retention removed archive files: %v", err)
	}
	m.finishExport(session.Id)
	m.maintain()
	if _, err := m.GetSession(session.Id); err != ErrNotFound {
		t.Fatalf("unprotected expired session was retained: %v", err)
	}
}

func TestSubscribeResumesAfterCacheWindowWithoutGaps(t *testing.T) {
	logs := t.TempDir()
	id, _ := writeMemoryTestJournal(t, logs, MaxCachedEvents+30, time.Now())
	m, err := NewManager(logs)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	after := uint64(MaxCachedEvents - 5)
	_, stream, err := m.Subscribe(ctx, id, after)
	if err != nil {
		t.Fatal(err)
	}
	for expected := after + 1; expected <= MaxCachedEvents+30; expected++ {
		select {
		case event := <-stream:
			if event.GetSequence() != expected {
				t.Fatalf("resume sequence=%d, want=%d", event.GetSequence(), expected)
			}
		case <-time.After(time.Second):
			t.Fatalf("resume stalled at %d", expected)
		}
	}
}

func TestJournalRemainsReadableWhenIndexAppendFails(t *testing.T) {
	m := memoryTestManager()
	m.dir = t.TempDir()
	if err := os.MkdirAll(filepath.Join(m.sessionDir("test"), "events.idx"), 0700); err != nil {
		t.Fatal(err)
	}
	event := &pb.DeepMonitorEvent{Summary: &pb.DeepMonitorEventSummary{Type: "http_exchange", Path: "/index-unavailable"}}
	if !m.Record("test", event, nil) {
		t.Fatal("record rejected")
	}
	job := <-m.queue
	m.writeJob(job)
	m.Stop("test", "manual") // Clear the in-memory offset cache, forcing sidecar fallback.
	stored, err := m.GetEvent("test", job.event.Summary.Id)
	if err != nil || stored.Summary.Path != "/index-unavailable" {
		t.Fatalf("valid journal hidden by broken sidecar: event=%v err=%v", stored, err)
	}
	session, _ := m.GetSession("test")
	if session.EventCount != 1 || session.DroppedEvents != 0 {
		t.Fatalf("committed event counted as dropped: %v", session)
	}
}

func TestStoredByteQuotaIncludesGeneratedMetadata(t *testing.T) {
	m := memoryTestManager()
	m.dir = t.TempDir()
	if err := os.MkdirAll(m.sessionDir("test"), 0700); err != nil {
		t.Fatal(err)
	}
	event := &pb.DeepMonitorEvent{Summary: &pb.DeepMonitorEventSummary{Type: "http_exchange"}}
	if !m.Record("test", event, map[string][]byte{"body": []byte("payload")}) {
		t.Fatal("record rejected")
	}
	job := <-m.queue
	m.writeJob(job)
	info, err := os.Stat(filepath.Join(m.sessionDir("test"), "events.pb"))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := m.sessions["test"].meta.BytesStored, uint64(info.Size()+int64(len("payload"))); got != want {
		t.Fatalf("stored byte accounting=%d want=%d", got, want)
	}
	limited := memoryTestManager()
	limited.sessions["test"].meta.QuotaBytes = 32 // The caller metadata fits; generated fields do not.
	if limited.Record("test", event, nil) {
		t.Fatal("generated metadata bypassed the disk quota")
	}
	if limited.BufferedBytes() != 0 || limited.queuedBytes.Load() != 0 || len(limited.queue) != 0 {
		t.Fatal("quota rejection retained a reservation")
	}
}
