package deepmonitor

import (
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"strings"
	"sync"

	"go-reauth-proxy/pkg/grpc/pb"
)

// Capture retains a prefix while hashing the entire observed stream. Captures
// and queued writes share a manager-wide budget; exhaustion truncates capture,
// never blocks or fails the proxied stream. Release or RecordCaptured must be
// called when the exchange ends.
type Capture struct {
	mu        sync.Mutex
	manager   *Manager
	sessionID string
	data      []byte
	observed  uint64
	hash      hash.Hash
	truncated bool
	done      bool
}

func (m *Manager) NewCapture(sessionIDs ...string) *Capture {
	capture := &Capture{manager: m, hash: sha256.New()}
	if m == nil || len(sessionIDs) == 0 {
		return capture
	}
	capture.sessionID = strings.Clone(sessionIDs[0])
	m.captureMu.Lock()
	defer m.captureMu.Unlock()
	// Stop publishes its inactive snapshot before detaching this registry.
	// Checking under captureMu makes admission atomic with that detachment.
	if !m.IsActive(capture.sessionID) {
		capture.done = true
		return capture
	}
	if m.captures == nil {
		m.captures = make(map[string]map[*Capture]struct{})
	}
	captures := m.captures[capture.sessionID]
	if captures == nil {
		captures = make(map[*Capture]struct{})
		m.captures[capture.sessionID] = captures
	}
	captures[capture] = struct{}{}
	return capture
}

func (c *Capture) Write(data []byte) (int, error) {
	if c == nil || len(data) == 0 {
		return len(data), nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.done {
		return len(data), nil
	}
	c.observed += uint64(len(data))
	_, _ = c.hash.Write(data)
	allowed := min(len(data), int(PayloadLimitBytes)-len(c.data))
	if c.truncated {
		allowed = 0
	}
	if allowed > 0 {
		needed := len(c.data) + allowed
		if needed > cap(c.data) {
			capacity := min(int(PayloadLimitBytes), max(needed, max(4096, cap(c.data)*2)))
			// Account for both arrays during growth, then release the old capacity.
			if c.manager == nil || reserveBytes(&c.manager.bufferedBytes, int64(capacity), MaxQueuedBytes) {
				next := make([]byte, len(c.data), capacity)
				copy(next, c.data)
				if c.manager != nil {
					c.manager.bufferedBytes.Add(-int64(cap(c.data)))
				}
				c.data = next
			} else {
				allowed = min(allowed, cap(c.data)-len(c.data))
			}
		}
		c.data = append(c.data, data[:allowed]...)
	}
	if uint64(len(c.data)) < c.observed {
		c.truncated = true
	}
	return len(data), nil
}

// Reference returns metadata without duplicating the captured payload.
func (c *Capture) Reference(part, contentType string) *pb.DeepMonitorPayloadRef {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.referenceLocked(part, contentType)
}

// Seal freezes a completed capture before creating its payload metadata, so
// late transport writes cannot change the bytes handed to RecordCaptured.
func (c *Capture) Seal(part, contentType string) *pb.DeepMonitorPayloadRef {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.done = true
	return c.referenceLocked(part, contentType)
}

func (c *Capture) referenceLocked(part, contentType string) *pb.DeepMonitorPayloadRef {
	if c.observed == 0 {
		return nil
	}
	return &pb.DeepMonitorPayloadRef{Part: part, ObservedBytes: c.observed,
		CapturedBytes: uint64(len(c.data)), Truncated: c.truncated,
		Sha256: hex.EncodeToString(c.hash.Sum(nil)), ContentType: contentType}
}

// Snapshot is for callers that need an independent copy. The traffic path uses
// Reference followed by RecordCaptured to avoid this allocation.
func (c *Capture) Snapshot() []byte {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.data...)
}

func (c *Capture) takeBuffer() ([]byte, int64) {
	if c == nil {
		return nil, 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	data := c.data
	c.data = nil
	c.done = true
	return data, int64(cap(data))
}

func (c *Capture) take() ([]byte, int64) {
	data, size := c.takeBuffer()
	if c != nil && c.manager != nil && c.sessionID != "" {
		c.manager.captureMu.Lock()
		captures := c.manager.captures[c.sessionID]
		delete(captures, c)
		if len(captures) == 0 {
			delete(c.manager.captures, c.sessionID)
		}
		c.manager.captureMu.Unlock()
	}
	return data, size
}

// releaseCaptures is called after the active snapshot changes. Detach before
// locking any Capture: take/Release never hold Capture.mu while unregistering.
// An empty session ID releases all captures during Manager.Close.
func (m *Manager) releaseCaptures(sessionID string) {
	m.captureMu.Lock()
	var groups map[string]map[*Capture]struct{}
	if sessionID == "" {
		groups = m.captures
		m.captures = nil
	} else {
		groups = map[string]map[*Capture]struct{}{sessionID: m.captures[sessionID]}
		delete(m.captures, sessionID)
	}
	m.captureMu.Unlock()
	for _, captures := range groups {
		for capture := range captures {
			_, size := capture.takeBuffer()
			m.bufferedBytes.Add(-size)
		}
	}
}

func (c *Capture) Release() {
	if c == nil {
		return
	}
	_, size := c.take()
	if c.manager != nil {
		c.manager.bufferedBytes.Add(-size)
	}
}

// BufferedBytes includes active capture capacities and queued/writing jobs.
func (m *Manager) BufferedBytes() int64 {
	if m == nil {
		return 0
	}
	return m.bufferedBytes.Load()
}
