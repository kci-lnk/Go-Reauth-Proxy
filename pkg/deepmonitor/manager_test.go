package deepmonitor

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go-reauth-proxy/pkg/grpc/pb"
)

func TestManagerLifecyclePersistenceAndPayload(t *testing.T) {
	logsDir := t.TempDir()
	manager, err := NewManager(logsDir)
	if err != nil {
		t.Fatal(err)
	}
	session, err := manager.Start("ABC.Example.com:443", MinDuration)
	if err != nil {
		t.Fatal(err)
	}
	if session.Host != "abc.example.com" || session.State != "active" {
		t.Fatalf("unexpected session: %#v", session)
	}
	event := &pb.DeepMonitorEvent{
		Summary:  &pb.DeepMonitorEventSummary{Type: "http_exchange", Host: session.Host, Method: "POST", Path: "/secret", Status: 201, ClientIp: "198.51.100.4", Identity: "alice"},
		Payloads: []*pb.DeepMonitorPayloadRef{{Part: "request_body", ObservedBytes: 6, CapturedBytes: 6, ContentType: "text/plain"}},
	}
	if !manager.Record(session.Id, event, map[string][]byte{"request_body": []byte("secret")}) {
		t.Fatal("record rejected")
	}
	waitForEvents(t, manager, session.Id, 1)
	items, _, more, err := manager.Query(session.Id, "", 10, "", "secret", "")
	if err != nil || more || len(items) != 1 {
		t.Fatalf("query = %#v, %v, %v", items, more, err)
	}
	filtered, _, _, err := manager.QueryFiltered(session.Id, "", 10, QueryFilter{
		Method: "post", Status: 201, Path: "secret", ClientIP: "198.51", Identity: "ali",
	})
	if err != nil || len(filtered) != 1 {
		t.Fatalf("filtered query = %#v, %v", filtered, err)
	}
	stored, err := manager.GetEvent(session.Id, items[0].Id)
	if err != nil || stored.GetSummary().GetPath() != "/secret" {
		t.Fatalf("event = %#v, %v", stored, err)
	}
	file, total, _, err := manager.OpenPayload(session.Id, items[0].Id, "request_body", 0)
	if err != nil {
		t.Fatal(err)
	}
	file.Close()
	if total != 6 {
		t.Fatalf("payload size = %d", total)
	}
	archiveStream, err := manager.OpenArchive(session.Id)
	if err != nil {
		t.Fatal(err)
	}
	archiveData, err := io.ReadAll(archiveStream)
	archiveStream.Close()
	if err != nil {
		t.Fatal(err)
	}
	archive, err := zip.NewReader(bytes.NewReader(archiveData), int64(len(archiveData)))
	if err != nil {
		t.Fatal(err)
	}
	archiveFiles := make(map[string][]byte, len(archive.File))
	for _, entry := range archive.File {
		reader, openErr := entry.Open()
		if openErr != nil {
			t.Fatal(openErr)
		}
		data, readErr := io.ReadAll(reader)
		reader.Close()
		if readErr != nil {
			t.Fatal(readErr)
		}
		archiveFiles[entry.Name] = data
	}
	if readme := string(archiveFiles["README.md"]); !strings.Contains(readme, "events.jsonl") || !strings.Contains(readme, session.Host) {
		t.Fatalf("archive README does not describe the session: %q", readme)
	}
	if !strings.Contains(string(archiveFiles["events.jsonl"]), `"path":"/secret"`) {
		t.Fatalf("archive events missing request path: %s", archiveFiles["events.jsonl"])
	}
	if !strings.Contains(string(archiveFiles["payloads.jsonl"]), `"part":"request_body"`) {
		t.Fatalf("archive payload manifest missing request body: %s", archiveFiles["payloads.jsonl"])
	}
	payloadFound := false
	for name, data := range archiveFiles {
		if strings.HasPrefix(name, "payloads/") && string(data) == "secret" {
			payloadFound = true
		}
	}
	if !payloadFound {
		t.Fatal("archive missing captured payload")
	}
	if info, err := os.Stat(filepath.Join(logsDir, "deep-monitor", session.Id, "session.json")); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("session metadata permissions = %v, %v", info, err)
	}
	manager.Close()

	reloaded, err := NewManager(logsDir)
	if err != nil {
		t.Fatal(err)
	}
	defer reloaded.Close()
	reloadedSession, err := reloaded.GetSession(session.Id)
	if err != nil || reloadedSession.State != "aborted_restart" {
		t.Fatalf("reloaded session = %#v, %v", reloadedSession, err)
	}
	if err := reloaded.Delete(session.Id); err != nil {
		t.Fatal(err)
	}
}

func TestManagerLimitsAndWatch(t *testing.T) {
	manager, err := NewManager(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	session, err := manager.Start("one.example.com", MinDuration)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Start("one.example.com", MinDuration); err != ErrHostAlreadyActive {
		t.Fatalf("duplicate host error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, watched, err := manager.Subscribe(ctx, session.Id, 0)
	if err != nil {
		t.Fatal(err)
	}
	manager.Record(session.Id, &pb.DeepMonitorEvent{Summary: &pb.DeepMonitorEventSummary{Type: "monitor_notice"}}, nil)
	select {
	case event := <-watched:
		if event.GetSequence() != 1 {
			t.Fatalf("sequence = %d", event.GetSequence())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("watch event timed out")
	}
	if _, err := manager.Stop(session.Id, "manual_stop"); err != nil {
		t.Fatal(err)
	}
	if err := manager.Delete(session.Id); err != nil {
		t.Fatal(err)
	}
}

func TestManagerActiveLimitExpiryRetentionAndQuota(t *testing.T) {
	manager, err := NewManager(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	base := time.Now().UTC()
	current := base
	manager.now = func() time.Time { return current }
	var sessions []*pb.DeepMonitorSession
	for _, host := range []string{"a.example.com", "b.example.com", "c.example.com", "d.example.com"} {
		session, err := manager.Start(host, MinDuration)
		if err != nil {
			t.Fatal(err)
		}
		sessions = append(sessions, session)
	}
	if _, err := manager.Start("e.example.com", MinDuration); err != ErrTooManyActive {
		t.Fatalf("active limit error = %v", err)
	}
	manager.mu.Lock()
	manager.sessions[sessions[0].Id].meta.QuotaBytes = 1
	manager.mu.Unlock()
	if manager.Record(sessions[0].Id, &pb.DeepMonitorEvent{Summary: &pb.DeepMonitorEventSummary{Type: "monitor_notice"}}, nil) {
		t.Fatal("quota-exceeding event was accepted")
	}
	quotaSession, _ := manager.GetSession(sessions[0].Id)
	if quotaSession.State != "quota_exceeded" {
		t.Fatalf("quota state = %s", quotaSession.State)
	}
	current = base.Add(MinDuration + time.Second)
	manager.maintain()
	expired, _ := manager.GetSession(sessions[1].Id)
	if expired.State != "expired" {
		t.Fatalf("expired state = %s", expired.State)
	}
	current = base.Add(MinDuration + Retention + 2*time.Second)
	manager.maintain()
	if _, err := manager.GetSession(sessions[1].Id); err != ErrNotFound {
		t.Fatalf("retention lookup error = %v", err)
	}
}

func TestManagerRejectsRecordsAfterClose(t *testing.T) {
	manager, err := NewManager(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	session, err := manager.Start("closed.example.com", MinDuration)
	if err != nil {
		t.Fatal(err)
	}
	manager.Close()
	if manager.Record(session.Id, &pb.DeepMonitorEvent{Summary: &pb.DeepMonitorEventSummary{Type: "monitor_notice"}}, nil) {
		t.Fatal("record was accepted after manager close")
	}
	if _, err := manager.Start("late.example.com", MinDuration); err == nil {
		t.Fatal("session was started after manager close")
	}
}

func TestRecordDoesNotWaitForMetadataDiskIO(t *testing.T) {
	var blockMetadata atomic.Bool
	metadataEntered := make(chan struct{}, 1)
	releaseMetadata := make(chan struct{})
	manager, err := newManager(t.TempDir(), func(root string, meta sessionMeta) error {
		if blockMetadata.Load() {
			select {
			case metadataEntered <- struct{}{}:
			default:
			}
			<-releaseMetadata
		}
		return writeSessionMeta(root, meta)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	defer close(releaseMetadata)

	session, err := manager.Start("async.example.com", MinDuration)
	if err != nil {
		t.Fatal(err)
	}
	blockMetadata.Store(true)
	if !manager.Record(session.Id, &pb.DeepMonitorEvent{Summary: &pb.DeepMonitorEventSummary{Type: "monitor_notice"}}, nil) {
		t.Fatal("first record was rejected")
	}
	select {
	case <-metadataEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("metadata writer did not block")
	}

	recorded := make(chan bool, 1)
	go func() {
		recorded <- manager.Record(session.Id, &pb.DeepMonitorEvent{Summary: &pb.DeepMonitorEventSummary{Type: "monitor_notice"}}, nil)
	}()
	select {
	case accepted := <-recorded:
		if !accepted {
			t.Fatal("second record was rejected")
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("Record waited for metadata disk I/O")
	}
}

func TestQuotaFailureDoesNotWriteMetadataSynchronously(t *testing.T) {
	var blockMetadata atomic.Bool
	metadataEntered := make(chan struct{}, 1)
	releaseMetadata := make(chan struct{})
	manager, err := newManager(t.TempDir(), func(root string, meta sessionMeta) error {
		if blockMetadata.Load() {
			select {
			case metadataEntered <- struct{}{}:
			default:
			}
			<-releaseMetadata
		}
		return writeSessionMeta(root, meta)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	defer close(releaseMetadata)

	session, err := manager.Start("quota-async.example.com", MinDuration)
	if err != nil {
		t.Fatal(err)
	}
	manager.mu.Lock()
	manager.sessions[session.Id].meta.QuotaBytes = 1
	manager.mu.Unlock()
	blockMetadata.Store(true)

	recorded := make(chan bool, 1)
	go func() {
		recorded <- manager.Record(session.Id, &pb.DeepMonitorEvent{Summary: &pb.DeepMonitorEventSummary{Type: "monitor_notice"}}, nil)
	}()
	select {
	case accepted := <-recorded:
		if accepted {
			t.Fatal("quota-exceeding record was accepted")
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("quota failure waited for metadata disk I/O")
	}
	select {
	case <-metadataEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("asynchronous metadata writer was not notified")
	}
}

func waitForEvents(t *testing.T, manager *Manager, sessionID string, count uint64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		session, err := manager.GetSession(sessionID)
		if err == nil && session.EventCount >= count {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("session %s did not reach %d events", sessionID, count)
}
