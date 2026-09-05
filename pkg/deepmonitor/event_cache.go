package deepmonitor

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"go-reauth-proxy/pkg/grpc/pb"
	"google.golang.org/protobuf/proto"
)

// Only a recent summary/offset window lives in memory. Older pages, payload
// lookups and exports remain available from the append-only journal and index.
func (s *sessionState) cacheEvent(summary *pb.DeepMonitorEventSummary, location eventLocation) {
	s.lastSequence = summary.Sequence
	if s.meta.State != "active" {
		return
	}
	size := proto.Size(summary) + 256
	for len(s.events) > 0 && (len(s.events) >= MaxCachedEvents || s.cachedBytes+size > MaxCachedSummaryBytes) {
		remove := max(1, len(s.events)/2)
		for _, old := range s.events[:remove] {
			delete(s.byID, old.Id)
			s.cachedBytes -= proto.Size(old) + 256
		}
		copy(s.events, s.events[remove:])
		clear(s.events[len(s.events)-remove:])
		s.events = s.events[:len(s.events)-remove]
	}
	if size > MaxCachedSummaryBytes {
		return
	}
	summary = cloneOwnedSummary(summary)
	s.events = append(s.events, summary)
	s.byID[summary.Id] = location
	s.cachedBytes += size
}

func (m *Manager) findEventLocation(sessionID, eventID string, through uint64) (eventLocation, error) {
	if through == 0 {
		return eventLocation{}, ErrEventNotFound
	}
	file, err := os.Open(filepath.Join(m.sessionDir(sessionID), "events.idx"))
	if err == nil {
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			parts := strings.Split(scanner.Text(), "\t")
			if len(parts) != 4 || parts[3] != eventID {
				continue
			}
			sequence, e0 := strconv.ParseUint(parts[0], 10, 64)
			if e0 != nil || sequence > through {
				continue
			}
			offset, e1 := strconv.ParseInt(parts[1], 10, 64)
			length, e2 := strconv.ParseUint(parts[2], 10, 32)
			if e1 == nil && e2 == nil && offset >= 0 && length > 4 && length <= 64<<20 {
				return eventLocation{offset: offset, length: uint32(length) - 4}, nil
			}
		}
	}
	// The sidecar is optional; missing, unreadable or incomplete indices fall
	// back to the committed journal rather than hiding otherwise valid events.
	var location eventLocation
	var found bool
	err = m.scanJournal(sessionID, func(event *pb.DeepMonitorEvent, at eventLocation) bool {
		if event.Summary.Sequence > through {
			return false
		}
		if event.Summary.Id == eventID {
			location, found = at, true
			return false
		}
		return event.Summary.Sequence < through
	})
	if err != nil {
		return eventLocation{}, err
	}
	if !found {
		return eventLocation{}, ErrEventNotFound
	}
	return location, nil
}

func (m *Manager) scanEvents(sessionID string, through uint64, visit func(*pb.DeepMonitorEvent) bool) error {
	if through == 0 {
		return nil
	}
	return m.scanJournal(sessionID, func(event *pb.DeepMonitorEvent, _ eventLocation) bool {
		if event.Summary.Sequence > through {
			return false
		}
		return visit(event) && event.Summary.Sequence < through
	})
}

func (m *Manager) scanJournal(sessionID string, visit func(*pb.DeepMonitorEvent, eventLocation) bool) error {
	file, err := os.Open(filepath.Join(m.sessionDir(sessionID), "events.pb"))
	if err != nil {
		return err
	}
	defer file.Close()
	reader := bufio.NewReader(file)
	var offset int64
	for {
		var header [4]byte
		if _, err := io.ReadFull(reader, header[:]); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil
			}
			return err
		}
		length := binary.BigEndian.Uint32(header[:])
		if length == 0 || length > 64<<20 {
			return errors.New("invalid deep monitor journal frame")
		}
		data := make([]byte, length)
		if _, err := io.ReadFull(reader, data); err != nil {
			return err
		}
		event := &pb.DeepMonitorEvent{}
		if err := proto.Unmarshal(data, event); err != nil {
			return err
		}
		if event.Summary == nil {
			return errors.New("deep monitor event has no summary")
		}
		if !visit(event, eventLocation{offset: offset, length: length}) {
			return nil
		}
		offset += int64(length) + 4
	}
}

func (s *sessionState) clearEventCache() {
	s.events = nil
	s.byID = nil
	s.cachedBytes = 0
}

// Generated protobuf cloning does not detach immutable strings. Cached paths
// and other substrings must not keep an entire request URI or header alive.
func cloneOwnedSummary(summary *pb.DeepMonitorEventSummary) *pb.DeepMonitorEventSummary {
	return cloneOwnedProto(summary).(*pb.DeepMonitorEventSummary)
}
