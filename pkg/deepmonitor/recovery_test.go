package deepmonitor

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go-reauth-proxy/pkg/grpc/pb"
)

func TestRestartReconcilesJournalAndPayloadStatistics(t *testing.T) {
	for _, scenario := range []string{"metadata_behind", "metadata_ahead", "missing_payload", "unreferenced_payload", "orphan_payload", "many_payloads", "partial_header", "partial_body", "invalid_tail_frame", "stopped_session"} {
		t.Run(scenario, func(t *testing.T) {
			logs := t.TempDir()
			m := memoryTestManager()
			m.dir = filepath.Join(logs, "deep-monitor")
			if err := os.MkdirAll(m.sessionDir("test"), 0700); err != nil {
				t.Fatal(err)
			}
			event := &pb.DeepMonitorEvent{Summary: &pb.DeepMonitorEventSummary{Type: "http_exchange", Path: "/committed"}}
			if scenario != "unreferenced_payload" {
				event.Payloads = []*pb.DeepMonitorPayloadRef{{Part: "body", CapturedBytes: 7}}
			}
			if !m.Record("test", event, map[string][]byte{"body": []byte("payload")}) {
				t.Fatal("record rejected")
			}
			job := <-m.queue
			m.writeJob(job)
			journal := filepath.Join(m.sessionDir("test"), "events.pb")
			payloadBytes := uint64(7)
			var tail []byte
			switch scenario {
			case "missing_payload":
				if err := os.Remove(m.payloadPath("test", job.event.Summary.Id, "body")); err != nil {
					t.Fatal(err)
				}
				payloadBytes = 0
			case "orphan_payload":
				if err := os.WriteFile(m.payloadPath("test", "uncommitted", "body"), []byte("orphan"), 0600); err != nil {
					t.Fatal(err)
				}
				payloadBytes += 6
			case "many_payloads":
				for i := 0; i < 257; i++ {
					if err := os.WriteFile(m.payloadPath("test", fmt.Sprint(i), "body"), []byte("x"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				payloadBytes += 257
			case "partial_header":
				tail = []byte{0, 0, 0}
			case "partial_body":
				tail = binary.BigEndian.AppendUint32(nil, 10)
				tail = append(tail, 1, 2, 3)
			case "invalid_tail_frame":
				tail = make([]byte, 4)
			}
			if len(tail) != 0 {
				if err := appendSecureFile(journal, tail); err != nil {
					t.Fatal(err)
				}
			}
			info, err := os.Stat(journal)
			if err != nil {
				t.Fatal(err)
			}
			wantBytes := uint64(info.Size()) + payloadBytes
			meta := m.sessions["test"].meta
			meta.EventCount, meta.BytesStored, meta.NextSequence = 99, 999999, 100
			meta.DeadlineAt = time.Now().Add(MinDuration)
			wantNext := uint64(100)
			if scenario == "metadata_behind" {
				meta.EventCount, meta.BytesStored, meta.NextSequence = 0, 0, 0
				wantNext = 2
			}
			wantState := "aborted_restart"
			if scenario == "stopped_session" {
				meta.State, meta.StopReason, meta.StoppedAt = "stopped", "manual", time.Now().UTC()
				wantState = "stopped"
			}
			if err := writeSessionMeta(m.dir, meta); err != nil {
				t.Fatal(err)
			}
			restored, err := NewManager(logs)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(restored.Close)
			got, err := restored.GetSession("test")
			if err != nil || got.EventCount != 1 || got.BytesStored != wantBytes || got.State != wantState {
				t.Fatalf("recovered session=%v err=%v; want events=1 bytes=%d state=%s", got, err, wantBytes, wantState)
			}
			items, _, _, err := restored.Query("test", "", 10, "", "", "")
			if err != nil || len(items) != 1 || items[0].Path != "/committed" {
				t.Fatalf("committed prefix unavailable: items=%v err=%v", items, err)
			}
			state := restored.sessions["test"]
			if state.meta.NextSequence != wantNext || state.lastSequence != 1 || len(state.events) != 0 || len(state.byID) != 0 {
				t.Fatalf("recovery changed sequence/cache semantics: next=%d last=%d cache=%d index=%d", state.meta.NextSequence, state.lastSequence, len(state.events), len(state.byID))
			}
			data, err := os.ReadFile(filepath.Join(m.sessionDir("test"), "session.json"))
			if err != nil {
				t.Fatal(err)
			}
			var persisted sessionMeta
			if err := json.Unmarshal(data, &persisted); err != nil || persisted.EventCount != 1 || persisted.BytesStored != wantBytes {
				t.Fatalf("reconciled counters were not persisted: %v err=%v", persisted, err)
			}
		})
	}
}

func TestLoadEventsDistinguishesEmptyJournalFromReadFailure(t *testing.T) {
	for _, scenario := range []string{"missing", "empty", "truncated_first_frame", "unreadable_journal", "unreadable_directory"} {
		t.Run(scenario, func(t *testing.T) {
			m := memoryTestManager()
			m.dir = t.TempDir()
			if err := os.Mkdir(m.sessionDir("test"), 0700); err != nil {
				t.Fatal(err)
			}
			s := m.sessions["test"]
			s.meta.EventCount, s.meta.BytesStored = 7, 777
			journal := filepath.Join(m.sessionDir("test"), "events.pb")
			wantEvents, wantBytes := uint64(0), uint64(0)
			switch scenario {
			case "empty":
				if err := os.WriteFile(journal, nil, 0600); err != nil {
					t.Fatal(err)
				}
			case "truncated_first_frame":
				if err := os.WriteFile(journal, binary.BigEndian.AppendUint32(nil, 10), 0600); err != nil {
					t.Fatal(err)
				}
				wantBytes = 4
			case "unreadable_journal":
				// Portable I/O failure even when tests run with elevated rights.
				// The same filesystem-error branch preserves prior statistics
				// regardless of how many frames were readable before the error.
				if err := os.Mkdir(journal, 0700); err != nil {
					t.Fatal(err)
				}
				wantEvents, wantBytes = 7, 777
			case "unreadable_directory":
				if err := os.Remove(m.sessionDir("test")); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(m.sessionDir("test"), nil, 0600); err != nil {
					t.Fatal(err)
				}
				wantEvents, wantBytes = 7, 777
			}
			err := m.loadEvents(s)
			if scenario == "unreadable_journal" || scenario == "unreadable_directory" {
				if err == nil {
					t.Fatal("I/O failure was hidden")
				}
			}
			if s.meta.EventCount != wantEvents || s.meta.BytesStored != wantBytes {
				t.Fatalf("recovered events=%d bytes=%d err=%v; want events=%d bytes=%d", s.meta.EventCount, s.meta.BytesStored, err, wantEvents, wantBytes)
			}
		})
	}
}
