package deepmonitor

import (
	"archive/zip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go-reauth-proxy/pkg/grpc/pb"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

const (
	DefaultDuration   = 30 * time.Minute
	MinDuration       = 5 * time.Minute
	MaxDuration       = 2 * time.Hour
	PayloadLimitBytes = uint64(16 << 20)
	SessionQuotaBytes = uint64(2 << 30)
	Retention         = 24 * time.Hour
	MaxActiveSessions = 4
	// A single exchange can contain a capped request body plus distinct
	// upstream and downstream response bodies. This remains globally bounded
	// while accepting that worst-case event.
	MaxCachedEvents       = 1024
	MaxCachedSummaryBytes = 1 << 20
	MaxQueuedBytes        = int64(64 << 20)
	PayloadChunkBytes     = 512 << 10
)

var (
	ErrNotFound          = errors.New("deep monitor session not found")
	ErrEventNotFound     = errors.New("deep monitor event not found")
	ErrPayloadNotFound   = errors.New("deep monitor payload not found")
	ErrSessionActive     = errors.New("deep monitor session is active")
	ErrSessionExporting  = errors.New("deep monitor session is being exported")
	ErrSessionNotActive  = errors.New("deep monitor session is not active")
	ErrHostAlreadyActive = errors.New("deep monitor session is already active for host")
	ErrTooManyActive     = errors.New("too many active deep monitor sessions")
	ErrInvalidDuration   = errors.New("duration must be between 5 minutes and 2 hours")
)

type sessionMeta struct {
	ID            string    `json:"id"`
	Host          string    `json:"host"`
	State         string    `json:"state"`
	StartedAt     time.Time `json:"started_at"`
	DeadlineAt    time.Time `json:"deadline_at"`
	StoppedAt     time.Time `json:"stopped_at,omitempty"`
	StopReason    string    `json:"stop_reason,omitempty"`
	BytesStored   uint64    `json:"bytes_stored"`
	EventCount    uint64    `json:"event_count"`
	DroppedEvents uint64    `json:"dropped_events"`
	QuotaBytes    uint64    `json:"quota_bytes"`
	PayloadLimit  uint64    `json:"payload_limit_bytes"`
	NextSequence  uint64    `json:"next_sequence"`
	QueuedBytes   uint64    `json:"queued_bytes,omitempty"`
}

type sessionState struct {
	meta         sessionMeta
	metaDirty    bool
	metaRevision uint64
	exporting    uint32
	cachedBytes  int
	lastSequence uint64
	events       []*pb.DeepMonitorEventSummary
	byID         map[string]eventLocation
	watchers     map[uint64]chan *pb.DeepMonitorEventSummary
}

type eventLocation struct {
	offset int64
	length uint32
}

type writeJob struct {
	sessionID    string
	event        *pb.DeepMonitorEvent
	payloads     map[string][]byte
	bytes        int64
	storageBytes int64
}

type activeSessionSnapshot struct {
	byHost map[string]string
	byID   map[string]struct{}
}

type Manager struct {
	dir string
	mu  sync.RWMutex
	// diskMu is never acquired by Record. It only serializes writer and
	// control-plane cleanup operations that touch a session directory.
	diskMu         sync.Mutex
	sessions       map[string]*sessionState
	activeByHost   map[string]string
	startingByHost map[string]struct{}
	active         atomic.Value
	queue          chan writeJob
	metaWake       chan struct{}
	queuedBytes    atomic.Int64
	bufferedBytes  atomic.Int64
	captureMu      sync.Mutex
	captures       map[string]map[*Capture]struct{}
	closed         chan struct{}
	closeOnce      sync.Once
	closing        bool
	wg             sync.WaitGroup
	nextWatcher    uint64
	now            func() time.Time
	writeMeta      func(string, sessionMeta) error
}

func NewManager(logsDir string) (*Manager, error) {
	return newManager(logsDir, writeSessionMeta)
}

func newManager(logsDir string, metaWriter func(string, sessionMeta) error) (*Manager, error) {
	dir := filepath.Join(filepath.Clean(logsDir), "deep-monitor")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create deep monitor directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("secure deep monitor directory: %w", err)
	}
	m := &Manager{
		dir:            dir,
		sessions:       make(map[string]*sessionState),
		activeByHost:   make(map[string]string),
		startingByHost: make(map[string]struct{}),
		queue:          make(chan writeJob, 128),
		metaWake:       make(chan struct{}, 1),
		closed:         make(chan struct{}),
		now:            time.Now,
		writeMeta:      metaWriter,
	}
	m.active.Store(activeSessionSnapshot{byHost: map[string]string{}, byID: map[string]struct{}{}})
	if err := m.load(); err != nil {
		return nil, err
	}
	m.wg.Add(2)
	go m.writerLoop()
	go m.maintenanceLoop()
	return m, nil
}

func (m *Manager) Close() {
	if m == nil {
		return
	}
	m.closeOnce.Do(func() {
		m.mu.Lock()
		m.closing = true
		for _, s := range m.sessions {
			s.clearEventCache()
		}
		m.active.Store(activeSessionSnapshot{byHost: map[string]string{}, byID: map[string]struct{}{}})
		m.releaseCaptures("")
		m.mu.Unlock()
		close(m.closed)
		m.wg.Wait()
	})
}

func NormalizeHost(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.TrimSuffix(value, ".")
	if host, port, ok := strings.Cut(value, ":"); ok && port != "" && !strings.Contains(host, ":") {
		value = host
	}
	return value
}

func (m *Manager) ActiveSession(host string) (string, bool) {
	if m == nil {
		return "", false
	}
	active, _ := m.active.Load().(activeSessionSnapshot)
	id, ok := active.byHost[NormalizeHost(host)]
	return id, ok
}

func (m *Manager) IsActive(sessionID string) bool {
	if m == nil {
		return false
	}
	active, _ := m.active.Load().(activeSessionSnapshot)
	_, ok := active.byID[sessionID]
	return ok
}

func (m *Manager) Start(host string, duration time.Duration) (*pb.DeepMonitorSession, error) {
	host = NormalizeHost(host)
	if duration == 0 {
		duration = DefaultDuration
	}
	if duration < MinDuration || duration > MaxDuration {
		return nil, ErrInvalidDuration
	}
	now := m.now().UTC()
	id := newID()
	state := &sessionState{
		meta: sessionMeta{
			ID: id, Host: host, State: "active", StartedAt: now,
			DeadlineAt: now.Add(duration), QuotaBytes: SessionQuotaBytes,
			PayloadLimit: PayloadLimitBytes, NextSequence: 1,
		},
		byID:     make(map[string]eventLocation),
		watchers: make(map[uint64]chan *pb.DeepMonitorEventSummary),
	}

	m.mu.Lock()
	if m.closing {
		m.mu.Unlock()
		return nil, errors.New("deep monitor manager is closed")
	}
	if _, exists := m.activeByHost[host]; exists {
		m.mu.Unlock()
		return nil, ErrHostAlreadyActive
	}
	if _, exists := m.startingByHost[host]; exists {
		m.mu.Unlock()
		return nil, ErrHostAlreadyActive
	}
	if len(m.activeByHost)+len(m.startingByHost) >= MaxActiveSessions {
		m.mu.Unlock()
		return nil, ErrTooManyActive
	}
	m.startingByHost[host] = struct{}{}
	m.mu.Unlock()

	dir := m.sessionDir(id)
	if err := os.Mkdir(dir, 0o700); err != nil {
		m.cancelStart(host)
		return nil, fmt.Errorf("create session directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		_ = os.RemoveAll(dir)
		m.cancelStart(host)
		return nil, fmt.Errorf("secure session directory: %w", err)
	}
	if err := m.writeMeta(m.dir, state.meta); err != nil {
		_ = os.RemoveAll(dir)
		m.cancelStart(host)
		return nil, err
	}

	m.mu.Lock()
	delete(m.startingByHost, host)
	if m.closing {
		m.mu.Unlock()
		_ = os.RemoveAll(dir)
		return nil, errors.New("deep monitor manager is closed")
	}
	m.sessions[id] = state
	m.activeByHost[host] = id
	m.publishActiveHostsLocked()
	result := toProtoSession(state.meta)
	m.mu.Unlock()
	return result, nil
}

func (m *Manager) Extend(id string, duration time.Duration) (*pb.DeepMonitorSession, error) {
	if duration < MinDuration || duration > MaxDuration {
		return nil, ErrInvalidDuration
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.sessions[id]
	if s == nil {
		return nil, ErrNotFound
	}
	if s.meta.State != "active" {
		return nil, ErrSessionNotActive
	}
	deadline := s.meta.DeadlineAt.Add(duration)
	absolute := s.meta.StartedAt.Add(MaxDuration)
	if deadline.After(absolute) {
		deadline = absolute
	}
	if !deadline.After(m.now()) {
		return nil, ErrInvalidDuration
	}
	s.meta.DeadlineAt = deadline
	m.markMetaDirtyLocked(s)
	return toProtoSession(s.meta), nil
}

func (m *Manager) Stop(id, reason string) (*pb.DeepMonitorSession, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.sessions[id]
	if s == nil {
		return nil, ErrNotFound
	}
	if s.meta.State == "active" {
		m.stopLocked(s, "stopped", reason)
	}
	return toProtoSession(s.meta), nil
}

func (m *Manager) Delete(id string) error {
	m.mu.Lock()
	s := m.sessions[id]
	if s == nil {
		m.mu.Unlock()
		return ErrNotFound
	}
	if s.meta.State == "active" {
		m.mu.Unlock()
		return ErrSessionActive
	}
	if s.exporting > 0 {
		m.mu.Unlock()
		return ErrSessionExporting
	}
	delete(m.sessions, id)
	for _, ch := range s.watchers {
		close(ch)
	}
	s.watchers = make(map[uint64]chan *pb.DeepMonitorEventSummary)
	m.mu.Unlock()
	m.diskMu.Lock()
	if err := os.RemoveAll(m.sessionDir(id)); err != nil {
		m.diskMu.Unlock()
		m.mu.Lock()
		if _, exists := m.sessions[id]; !exists {
			m.sessions[id] = s
		}
		m.mu.Unlock()
		return err
	}
	m.diskMu.Unlock()
	return nil
}

func (m *Manager) List(includeExpired bool) []*pb.DeepMonitorSession {
	m.mu.RLock()
	items := make([]*pb.DeepMonitorSession, 0, len(m.sessions))
	for _, s := range m.sessions {
		if !includeExpired && s.meta.State != "active" && !s.meta.StoppedAt.IsZero() && m.now().Sub(s.meta.StoppedAt) >= Retention {
			continue
		}
		items = append(items, toProtoSession(s.meta))
	}
	m.mu.RUnlock()
	sort.Slice(items, func(i, j int) bool { return items[i].StartedAt > items[j].StartedAt })
	return items
}

func (m *Manager) GetSession(id string) (*pb.DeepMonitorSession, error) {
	m.mu.RLock()
	s := m.sessions[id]
	if s == nil {
		m.mu.RUnlock()
		return nil, ErrNotFound
	}
	result := toProtoSession(s.meta)
	m.mu.RUnlock()
	return result, nil
}

// Record is the data-plane entry point. It only copies into a bounded queue;
// all filesystem I/O caused by captured traffic runs in writerLoop.
func (m *Manager) Record(sessionID string, event *pb.DeepMonitorEvent, payloads map[string][]byte) bool {
	return m.record(sessionID, event, payloads, 0, false)
}

// RecordCaptured consumes captures, including on rejection. Their allocated
// capacities remain charged until the writer completes, without a payload copy.
func (m *Manager) RecordCaptured(sessionID string, event *pb.DeepMonitorEvent, captures map[string]*Capture) bool {
	payloads := make(map[string][]byte, len(captures))
	var reserved int64
	for _, capture := range captures {
		if capture == nil {
			continue
		}
		if capture.manager != m { // Only transfer this manager's reservations.
			for _, c := range captures {
				c.Release()
			}
			return false
		}
	}
	for part, capture := range captures {
		data, size := capture.take()
		payloads[part] = data
		reserved += size
	}
	return m.record(sessionID, event, payloads, reserved, true)
}

func reserveBytes(counter *atomic.Int64, size, limit int64) bool {
	if size < 0 || size > limit {
		return false
	}
	for {
		current := counter.Load()
		if current > limit-size {
			return false
		}
		if counter.CompareAndSwap(current, current+size) {
			return true
		}
	}
}

func (m *Manager) record(sessionID string, event *pb.DeepMonitorEvent, payloads map[string][]byte, ownedBytes int64, owned bool) bool {
	if m == nil {
		return false
	}
	accepted := false
	reservedBytes := ownedBytes
	defer func() {
		if !accepted {
			m.bufferedBytes.Add(-reservedBytes)
		}
	}()
	if event == nil || event.Summary == nil || !m.IsActive(sessionID) {
		return false
	}
	// Include protobuf objects, their serialization buffer, and generated IDs.
	// Reserve before cloning either metadata or caller-owned payloads.
	storageBytes := int64(proto.Size(event)) + 4
	jobBytes := int64(proto.Size(event))*2 + 1024
	for part, data := range payloads {
		jobBytes += int64(len(part)) + 32
		storageBytes += int64(len(data))
		if owned {
			jobBytes += int64(cap(data))
		} else {
			jobBytes += int64(len(data))
		}
	}
	if !reserveBytes(&m.queuedBytes, jobBytes, MaxQueuedBytes) {
		m.stopForFailure(sessionID, "overload")
		return false
	}
	defer func() {
		if !accepted {
			m.queuedBytes.Add(-jobBytes)
		}
	}()
	if !reserveBytes(&m.bufferedBytes, jobBytes-ownedBytes, MaxQueuedBytes) {
		m.stopForFailure(sessionID, "overload")
		return false
	}
	reservedBytes = jobBytes
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.sessions[sessionID]
	if m.closing || s == nil || s.meta.State != "active" {
		return false
	}
	if s.meta.BytesStored+s.meta.QueuedBytes+uint64(storageBytes) > s.meta.QuotaBytes {
		s.meta.DroppedEvents++
		m.stopLocked(s, "quota_exceeded", "quota_exceeded")
		return false
	}
	// Check the slot before allocating. The manager lock serializes producers;
	// the sole consumer can only make additional room while we copy.
	if len(m.queue) == cap(m.queue) {
		s.meta.DroppedEvents++
		m.stopLocked(s, "overload", "queue_full")
		return false
	}
	copyEvent := cloneOwnedProto(event).(*pb.DeepMonitorEvent)
	copyPayloads := make(map[string][]byte, len(payloads))
	for part, data := range payloads {
		if !owned {
			data = append([]byte(nil), data...)
		}
		copyPayloads[strings.Clone(part)] = data
	}
	sessionID = s.meta.ID
	copyEvent.Summary.SessionId = sessionID
	copyEvent.Summary.Sequence = s.meta.NextSequence
	copyEvent.Summary.Id = newID()
	if copyEvent.Summary.Time == "" {
		copyEvent.Summary.Time = m.now().UTC().Format(time.RFC3339Nano)
	}
	// Generated IDs, sequence and timestamp are part of the stored frame too.
	// Recheck the quota with the final metadata size before committing the job.
	storageBytes = int64(proto.Size(copyEvent)) + 4
	for _, data := range copyPayloads {
		storageBytes += int64(len(data))
	}
	if s.meta.BytesStored+s.meta.QueuedBytes+uint64(storageBytes) > s.meta.QuotaBytes {
		s.meta.DroppedEvents++
		m.stopLocked(s, "quota_exceeded", "quota_exceeded")
		return false
	}
	s.meta.NextSequence++
	s.meta.QueuedBytes += uint64(storageBytes)
	m.queue <- writeJob{sessionID: sessionID, event: copyEvent, payloads: copyPayloads, bytes: jobBytes, storageBytes: storageBytes}
	accepted = true
	return true
}

type QueryFilter struct {
	Type      string
	Search    string
	Direction string
	Method    string
	Status    int32
	ClientIP  string
	Identity  string
	Path      string
}

func (m *Manager) Query(sessionID, cursor string, limit int, eventType, search, direction string) ([]*pb.DeepMonitorEventSummary, string, bool, error) {
	return m.QueryFiltered(sessionID, cursor, limit, QueryFilter{Type: eventType, Search: search, Direction: direction})
}

func (m *Manager) QueryFiltered(sessionID, cursor string, limit int, filter QueryFilter) ([]*pb.DeepMonitorEventSummary, string, bool, error) {
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	after, _ := strconv.ParseUint(cursor, 10, 64)
	filter.Type = strings.TrimSpace(filter.Type)
	filter.Search = strings.ToLower(strings.TrimSpace(filter.Search))
	filter.Direction = strings.TrimSpace(filter.Direction)
	filter.Method = strings.ToUpper(strings.TrimSpace(filter.Method))
	filter.ClientIP = strings.ToLower(strings.TrimSpace(filter.ClientIP))
	filter.Identity = strings.ToLower(strings.TrimSpace(filter.Identity))
	filter.Path = strings.ToLower(strings.TrimSpace(filter.Path))
	m.mu.RLock()
	s := m.sessions[sessionID]
	if s == nil {
		m.mu.RUnlock()
		return nil, "", false, ErrNotFound
	}
	items := make([]*pb.DeepMonitorEventSummary, 0, limit+1)
	matches := func(summary *pb.DeepMonitorEventSummary) bool {
		if summary.GetSequence() <= after ||
			(filter.Type != "" && summary.GetType() != filter.Type) ||
			(filter.Direction != "" && summary.GetDirection() != filter.Direction) ||
			(filter.Method != "" && strings.ToUpper(summary.GetMethod()) != filter.Method) ||
			(filter.Status != 0 && summary.GetStatus() != filter.Status) ||
			(filter.ClientIP != "" && !strings.Contains(strings.ToLower(summary.GetClientIp()), filter.ClientIP)) ||
			(filter.Identity != "" && !strings.Contains(strings.ToLower(summary.GetIdentity()), filter.Identity)) ||
			(filter.Path != "" && !strings.Contains(strings.ToLower(summary.GetPath()), filter.Path)) {
			return false
		}
		if filter.Search != "" && !strings.Contains(strings.ToLower(summary.GetHost()+" "+summary.GetMethod()+" "+summary.GetPath()+" "+summary.GetClientIp()+" "+summary.GetIdentity()+" "+summary.GetNotice()), filter.Search) {
			return false
		}
		return true
	}
	cached := after >= s.lastSequence || (len(s.events) > 0 && after >= s.events[0].Sequence-1)
	lastSequence := s.lastSequence
	if cached {
		for _, summary := range s.events {
			if matches(summary) {
				items = append(items, proto.Clone(summary).(*pb.DeepMonitorEventSummary))
				if len(items) > limit {
					break
				}
			}
		}
	}
	m.mu.RUnlock()
	if !cached {
		err := m.scanEvents(sessionID, lastSequence, func(event *pb.DeepMonitorEvent) bool {
			if matches(event.Summary) {
				items = append(items, event.Summary)
			}
			return len(items) <= limit
		})
		if err != nil {
			return nil, "", false, err
		}
	}
	hasMore := len(items) > limit
	if hasMore {
		items = items[:limit]
	}
	next := cursor
	if len(items) > 0 {
		next = strconv.FormatUint(items[len(items)-1].GetSequence(), 10)
	}
	return items, next, hasMore, nil
}

func (m *Manager) GetEvent(sessionID, eventID string) (*pb.DeepMonitorEvent, error) {
	m.mu.RLock()
	s := m.sessions[sessionID]
	if s == nil {
		m.mu.RUnlock()
		return nil, ErrNotFound
	}
	location, ok := s.byID[eventID]
	through := s.lastSequence
	m.mu.RUnlock()
	if !ok {
		var err error
		location, err = m.findEventLocation(sessionID, eventID, through)
		if err != nil {
			return nil, err
		}
	}
	file, err := os.Open(filepath.Join(m.sessionDir(sessionID), "events.pb"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrEventNotFound
		}
		return nil, err
	}
	defer file.Close()
	data := make([]byte, location.length)
	if _, err := file.ReadAt(data, location.offset+4); err != nil {
		return nil, err
	}
	result := &pb.DeepMonitorEvent{}
	if err := proto.Unmarshal(data, result); err != nil {
		return nil, err
	}
	if result.GetSummary().GetId() != eventID || result.GetSummary().GetSequence() > through {
		return nil, ErrEventNotFound
	}
	return result, nil
}

func (m *Manager) OpenPayload(sessionID, eventID, part string, offset uint64) (*os.File, uint64, string, error) {
	event, err := m.GetEvent(sessionID, eventID)
	if err != nil {
		return nil, 0, "", err
	}
	contentType := "application/octet-stream"
	found := false
	for _, ref := range event.GetPayloads() {
		if ref.GetPart() == part {
			contentType = ref.GetContentType()
			found = true
			break
		}
	}
	if !found {
		return nil, 0, "", ErrPayloadNotFound
	}
	file, err := os.Open(m.payloadPath(sessionID, eventID, part))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, 0, "", ErrPayloadNotFound
		}
		return nil, 0, "", err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, 0, "", err
	}
	total := uint64(info.Size())
	if offset > total {
		file.Close()
		return nil, total, contentType, io.EOF
	}
	if _, err := file.Seek(int64(offset), io.SeekStart); err != nil {
		file.Close()
		return nil, total, contentType, err
	}
	return file, total, contentType, nil
}

type archiveFile struct {
	path     string
	name     string
	size     int64
	modified time.Time
}

// OpenArchive returns a point-in-time ZIP stream without staging another copy
// on disk. Captured traffic may continue to be written while the snapshot is
// downloaded; deletion and retention cleanup wait until the stream closes.
func (m *Manager) OpenArchive(sessionID string) (io.ReadCloser, error) {
	m.mu.Lock()
	s := m.sessions[sessionID]
	if s == nil {
		m.mu.Unlock()
		return nil, ErrNotFound
	}
	s.exporting++
	m.mu.Unlock()

	m.diskMu.Lock()
	m.mu.RLock()
	s = m.sessions[sessionID]
	if s == nil {
		m.mu.RUnlock()
		m.diskMu.Unlock()
		m.finishExport(sessionID)
		return nil, ErrNotFound
	}
	meta := s.meta
	lastSequence := s.lastSequence
	m.mu.RUnlock()

	entries, err := os.ReadDir(m.sessionDir(sessionID))
	files := make([]archiveFile, 0, len(entries))
	if err == nil {
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || (name != "events.pb" && name != "events.idx" && !strings.HasSuffix(name, ".payload")) {
				continue
			}
			info, infoErr := entry.Info()
			if infoErr != nil {
				err = infoErr
				break
			}
			archiveName := name
			if strings.HasSuffix(name, ".payload") {
				archiveName = "payloads/" + name
			}
			files = append(files, archiveFile{
				path: filepath.Join(m.sessionDir(sessionID), name), name: archiveName,
				size: info.Size(), modified: info.ModTime(),
			})
		}
	}
	m.diskMu.Unlock()
	if err != nil {
		m.finishExport(sessionID)
		return nil, err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].name < files[j].name })

	reader, writer := io.Pipe()
	go func() {
		writeErr := writeArchive(writer, meta, files, func(visit func(*pb.DeepMonitorEvent) error) error {
			var visitErr error
			err := m.scanEvents(sessionID, lastSequence, func(event *pb.DeepMonitorEvent) bool { visitErr = visit(event); return visitErr == nil })
			if err != nil {
				return err
			}
			return visitErr
		})
		m.finishExport(sessionID)
		if writeErr != nil {
			_ = writer.CloseWithError(writeErr)
			return
		}
		_ = writer.Close()
	}()
	return reader, nil
}

func (m *Manager) finishExport(sessionID string) {
	m.mu.Lock()
	if s := m.sessions[sessionID]; s != nil && s.exporting > 0 {
		s.exporting--
	}
	m.mu.Unlock()
}

func writeArchive(output io.Writer, meta sessionMeta, files []archiveFile, scan func(func(*pb.DeepMonitorEvent) error) error) error {
	archive := zip.NewWriter(output)
	closeWithError := func(err error) error {
		_ = archive.Close()
		return err
	}
	if err := writeZipBytes(archive, "README.md", archiveReadme(meta), meta.StartedAt); err != nil {
		return closeWithError(err)
	}
	metadata, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return closeWithError(err)
	}
	metadata = append(metadata, '\n')
	if err := writeZipBytes(archive, "session.json", metadata, meta.StartedAt); err != nil {
		return closeWithError(err)
	}

	eventHeader := &zip.FileHeader{Name: "events.jsonl", Method: zip.Store}
	eventHeader.SetModTime(meta.StartedAt)
	eventWriter, err := archive.CreateHeader(eventHeader)
	if err != nil {
		return closeWithError(err)
	}
	jsonOptions := protojson.MarshalOptions{UseProtoNames: true}
	if err := scan(func(event *pb.DeepMonitorEvent) error {
		data, err := jsonOptions.Marshal(event)
		if err != nil {
			return err
		}
		_, err = eventWriter.Write(append(data, '\n'))
		return err
	}); err != nil {
		return closeWithError(err)
	}

	manifestHeader := &zip.FileHeader{Name: "payloads.jsonl", Method: zip.Store}
	manifestHeader.SetModTime(meta.StartedAt)
	manifestWriter, err := archive.CreateHeader(manifestHeader)
	if err != nil {
		return closeWithError(err)
	}
	if err := scan(func(event *pb.DeepMonitorEvent) error {
		for _, ref := range event.GetPayloads() {
			hash := sha256.Sum256([]byte(ref.GetPart()))
			filename := event.GetSummary().GetId() + "-" + hex.EncodeToString(hash[:8]) + ".payload"
			entry := map[string]any{
				"event_id": event.GetSummary().GetId(), "sequence": event.GetSummary().GetSequence(),
				"part": ref.GetPart(), "file": "payloads/" + filename,
				"content_type": ref.GetContentType(), "observed_bytes": ref.GetObservedBytes(),
				"captured_bytes": ref.GetCapturedBytes(), "sha256": ref.GetSha256(),
				"truncated": ref.GetTruncated(),
			}
			data, marshalErr := json.Marshal(entry)
			if marshalErr != nil {
				return marshalErr
			}
			if _, err := manifestWriter.Write(append(data, '\n')); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return closeWithError(err)
	}

	for _, file := range files {
		header := &zip.FileHeader{Name: file.name, Method: zip.Store}
		header.SetModTime(file.modified)
		entryWriter, createErr := archive.CreateHeader(header)
		if createErr != nil {
			return closeWithError(createErr)
		}
		input, openErr := os.Open(file.path)
		if openErr != nil {
			return closeWithError(openErr)
		}
		_, copyErr := io.CopyN(entryWriter, input, file.size)
		closeErr := input.Close()
		if copyErr != nil {
			return closeWithError(copyErr)
		}
		if closeErr != nil {
			return closeWithError(closeErr)
		}
	}
	return archive.Close()
}

func archiveReadme(meta sessionMeta) []byte {
	return []byte(fmt.Sprintf(`# fn-knock 深度监控日志包

本压缩包是主机 **%s** 的深度监控离线日志，不是 PCAP 网络抓包。

## 快速使用

1. 优先分析 events.jsonl：每行是一个完整的 HTTP 或 WebSocket 事件，可使用 jq、DuckDB、VS Code 或脚本逐行读取。
2. 通过 payloads.jsonl 查找事件正文对应的文件名，再读取 payloads/*.payload 中的原始请求、响应或 WebSocket 帧载荷。
3. session.json 保存监控主机、开始/停止时间、状态、事件数量及存储配额。
4. events.pb 与 events.idx 是供程序高速读取的长度分帧 protobuf journal 和偏移索引；日常分析通常不需要直接使用。

## 示例

	# 查看 HTTP 交互
	jq 'select(.summary.type == "http_exchange")' events.jsonl

	# 输出时间、IP、方法、路径、状态码和总耗时
	jq -r 'select(.summary.type == "http_exchange") | [.summary.time, .summary.client_ip, .summary.method, .summary.path, .summary.status, .timing.total_ms] | @tsv' events.jsonl

	# 查看 WebSocket 帧
	jq 'select(.summary.type == "ws_frame")' events.jsonl

## 注意

- HTTP 内容是网关解析后的语义数据，不保留原始报文的 Header 大小写、顺序或传输分块格式。
- 压缩的 HTTP 正文及 WebSocket permessage-deflate 帧可能仍保持压缩状态。
- 日志可能包含 Cookie、Authorization、密码、令牌及个人数据，请妥善保管并在使用后删除。

Session ID: %s

Started at: %s
`, meta.Host, meta.ID, meta.StartedAt.Format(time.RFC3339Nano)))
}

func writeZipBytes(archive *zip.Writer, name string, data []byte, modified time.Time) error {
	header := &zip.FileHeader{Name: name, Method: zip.Store}
	header.SetModTime(modified)
	entry, err := archive.CreateHeader(header)
	if err != nil {
		return err
	}
	_, err = entry.Write(data)
	return err
}

// Subscribe streams historical replay through the same bounded channel as live
// updates. Register live delivery before reading the journal to avoid gaps; if
// replay is too slow, the live queue closes and callers can resume by sequence.
func (m *Manager) Subscribe(ctx context.Context, sessionID string, after uint64) ([]*pb.DeepMonitorEventSummary, <-chan *pb.DeepMonitorEventSummary, error) {
	m.mu.Lock()
	if m.closing {
		m.mu.Unlock()
		return nil, nil, errors.New("deep monitor manager is closed")
	}
	s := m.sessions[sessionID]
	if s == nil {
		m.mu.Unlock()
		return nil, nil, ErrNotFound
	}
	cached := after >= s.lastSequence || (len(s.events) > 0 && after >= s.events[0].Sequence-1)
	through := s.lastSequence
	var recent []*pb.DeepMonitorEventSummary
	if cached {
		for _, summary := range s.events {
			if summary.Sequence > after {
				recent = append(recent, summary)
			}
		}
	}
	m.nextWatcher++
	id := m.nextWatcher
	live := make(chan *pb.DeepMonitorEventSummary, 128)
	s.watchers[id] = live
	m.wg.Add(1)
	m.mu.Unlock()
	output := make(chan *pb.DeepMonitorEventSummary, 128)
	go func() {
		defer m.wg.Done()
		defer close(output)
		defer func() {
			m.mu.Lock()
			if current := m.sessions[sessionID]; current != nil {
				if existing, ok := current.watchers[id]; ok {
					delete(current.watchers, id)
					close(existing)
				}
			}
			m.mu.Unlock()
		}()
		send := func(summary *pb.DeepMonitorEventSummary) bool {
			select {
			case <-m.closed:
				return false
			default:
			}
			select {
			case output <- summary:
				return true
			case <-ctx.Done():
				return false
			case <-m.closed:
				return false
			}
		}
		if cached {
			for _, summary := range recent {
				if !send(proto.Clone(summary).(*pb.DeepMonitorEventSummary)) {
					return
				}
			}
			recent = nil
		} else {
			err := m.scanEvents(sessionID, through, func(event *pb.DeepMonitorEvent) bool {
				if ctx.Err() != nil {
					return false
				}
				select {
				case <-m.closed:
					return false
				default:
				}
				return event.Summary.Sequence <= after || send(event.Summary)
			})
			if err != nil || ctx.Err() != nil {
				return
			}
		}
		for {
			select {
			case summary, ok := <-live:
				if !ok || !send(summary) {
					return
				}
			case <-ctx.Done():
				return
			case <-m.closed:
				return
			}
		}
	}()
	return nil, output, nil
}

func (m *Manager) writerLoop() {
	defer m.wg.Done()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case job := <-m.queue:
			m.writeJob(job)
		case <-m.metaWake:
			m.flushDirtyMetadata()
		case <-ticker.C:
			m.flushDirtyMetadata()
		case <-m.closed:
			for {
				select {
				case job := <-m.queue:
					m.writeJob(job)
				default:
					m.flushDirtyMetadata()
					return
				}
			}
		}
	}
}

func (m *Manager) writeJob(job writeJob) {
	defer m.queuedBytes.Add(-job.bytes)
	defer m.bufferedBytes.Add(-job.bytes)
	var location eventLocation
	m.diskMu.Lock()
	data, err := proto.Marshal(job.event)
	// Payloads must exist before the event becomes part of the readable journal.
	// A failed payload must not appear later merely because another queued event
	// succeeded and advanced the session's committed sequence.
	var payloadPaths []string
	if err == nil {
		for part, payload := range job.payloads {
			path := m.payloadPath(job.sessionID, job.event.GetSummary().GetId(), part)
			payloadPaths = append(payloadPaths, path)
			if err = os.WriteFile(path, payload, 0o600); err != nil {
				break
			}
			_ = os.Chmod(path, 0o600)
		}
	}
	if err == nil {
		eventsPath := filepath.Join(m.sessionDir(job.sessionID), "events.pb")
		file, openErr := os.OpenFile(eventsPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if openErr != nil {
			err = openErr
		} else {
			_ = os.Chmod(eventsPath, 0o600)
			offset, seekErr := file.Seek(0, io.SeekEnd)
			err = seekErr
			if err == nil {
				location = eventLocation{offset: offset, length: uint32(len(data))}
				var header [4]byte
				binary.BigEndian.PutUint32(header[:], uint32(len(data)))
				if _, err = file.Write(header[:]); err == nil {
					_, err = file.Write(data)
				}
				if err != nil {
					_ = file.Truncate(offset)
				}
			}
			_ = file.Close()
			if err == nil {
				index := fmt.Sprintf("%d\t%d\t%d\t%s\n", job.event.GetSummary().GetSequence(), offset, len(data)+4, job.event.GetSummary().GetId())
				// The sidecar is an acceleration index. A committed journal event stays
				// readable through scan fallback even if updating the index fails.
				_ = appendSecureFile(filepath.Join(m.sessionDir(job.sessionID), "events.idx"), []byte(index))
			}
		}
	}
	if err != nil {
		for _, path := range payloadPaths {
			_ = os.Remove(path)
		}
	}
	m.diskMu.Unlock()
	m.mu.Lock()
	s := m.sessions[job.sessionID]
	if s != nil {
		if s.meta.QueuedBytes >= uint64(job.storageBytes) {
			s.meta.QueuedBytes -= uint64(job.storageBytes)
		}
		if err != nil {
			s.meta.DroppedEvents++
			if s.meta.State == "active" {
				m.stopLocked(s, "io_error", "storage_write_failed")
			} else {
				m.markMetaDirtyLocked(s)
			}
		} else {
			s.meta.BytesStored += uint64(job.storageBytes)
			s.meta.EventCount++
			if m.closing {
				s.lastSequence = job.event.Summary.Sequence
			} else {
				s.cacheEvent(job.event.Summary, location)
			}
			for id, watcher := range s.watchers {
				select {
				case watcher <- cloneOwnedSummary(job.event.GetSummary()):
				default:
					close(watcher)
					delete(s.watchers, id)
				}
			}
			m.markMetaDirtyLocked(s)
		}
	}
	m.mu.Unlock()
}

type metadataSnapshot struct {
	id       string
	revision uint64
	meta     sessionMeta
}

func (m *Manager) flushDirtyMetadata() {
	m.mu.Lock()
	snapshots := make([]metadataSnapshot, 0)
	for id, s := range m.sessions {
		if !s.metaDirty {
			continue
		}
		s.metaDirty = false
		snapshots = append(snapshots, metadataSnapshot{id: id, revision: s.metaRevision, meta: s.meta})
	}
	m.mu.Unlock()

	for _, snapshot := range snapshots {
		m.diskMu.Lock()
		err := m.writeMeta(m.dir, snapshot.meta)
		m.diskMu.Unlock()
		wakeAgain := false
		m.mu.Lock()
		s := m.sessions[snapshot.id]
		if s != nil {
			switch {
			case err != nil:
				// A metadata failure is terminal for an active session, but it is
				// deliberately handled only by the writer. Do not retry in a hot
				// loop when the storage is unavailable.
				if s.meta.State == "active" {
					s.meta.DroppedEvents++
					m.stopWithoutMetadataWakeLocked(s, "io_error", "metadata_write_failed")
				}
				s.metaDirty = false
			case s.metaRevision != snapshot.revision:
				s.metaDirty = true
				wakeAgain = true
			}
		}
		m.mu.Unlock()
		if wakeAgain {
			m.wakeMetadataWriter()
		}
	}
}

func (m *Manager) maintenanceLoop() {
	defer m.wg.Done()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			m.maintain()
		case <-m.closed:
			return
		}
	}
}

func (m *Manager) maintain() {
	now := m.now()
	var remove []string
	m.mu.Lock()
	for id, s := range m.sessions {
		if s.meta.State == "active" && !now.Before(s.meta.DeadlineAt) {
			m.stopLocked(s, "expired", "deadline_reached")
		}
		if s.meta.State != "active" && s.exporting == 0 && !s.meta.StoppedAt.IsZero() && now.Sub(s.meta.StoppedAt) >= Retention {
			remove = append(remove, id)
		}
	}
	m.mu.Unlock()
	for _, id := range remove {
		m.diskMu.Lock()
		// An archive may have registered protection after the candidate scan but
		// before diskMu was available. Recheck and remove atomically with respect
		// to OpenArchive's registration before touching the directory.
		m.mu.Lock()
		state := m.sessions[id]
		if state == nil || state.meta.State == "active" || state.exporting != 0 || state.meta.StoppedAt.IsZero() || now.Sub(state.meta.StoppedAt) < Retention {
			m.mu.Unlock()
			m.diskMu.Unlock()
			continue
		}
		delete(m.sessions, id)
		for _, watcher := range state.watchers {
			close(watcher)
		}
		state.watchers = make(map[uint64]chan *pb.DeepMonitorEventSummary)
		m.mu.Unlock()
		err := os.RemoveAll(m.sessionDir(id))
		m.diskMu.Unlock()
		if err != nil {
			m.mu.Lock()
			if _, exists := m.sessions[id]; !exists {
				m.sessions[id] = state
			}
			m.mu.Unlock()
		}
	}
}

func (m *Manager) stopForFailure(id, state string) {
	m.mu.Lock()
	if s := m.sessions[id]; s != nil && s.meta.State == "active" {
		s.meta.DroppedEvents++
		m.stopLocked(s, state, state)
	}
	m.mu.Unlock()
}

func (m *Manager) stopLocked(s *sessionState, state, reason string) {
	if s.meta.State != "active" {
		return
	}
	s.meta.State = state
	s.clearEventCache()
	s.meta.StopReason = reason
	s.meta.StoppedAt = m.now().UTC()
	delete(m.activeByHost, s.meta.Host)
	m.publishActiveHostsLocked()
	m.releaseCaptures(s.meta.ID)
	m.markMetaDirtyLocked(s)
}

func (m *Manager) stopWithoutMetadataWakeLocked(s *sessionState, state, reason string) {
	if s.meta.State != "active" {
		return
	}
	s.meta.State = state
	s.clearEventCache()
	s.meta.StopReason = reason
	s.meta.StoppedAt = m.now().UTC()
	delete(m.activeByHost, s.meta.Host)
	m.publishActiveHostsLocked()
	m.releaseCaptures(s.meta.ID)
	s.metaRevision++
}

func (m *Manager) markMetaDirtyLocked(s *sessionState) {
	s.metaRevision++
	s.metaDirty = true
	m.wakeMetadataWriter()
}

func (m *Manager) wakeMetadataWriter() {
	select {
	case m.metaWake <- struct{}{}:
	default:
	}
}

func (m *Manager) cancelStart(host string) {
	m.mu.Lock()
	delete(m.startingByHost, host)
	m.mu.Unlock()
}

func (m *Manager) publishActiveHostsLocked() {
	byHost := make(map[string]string, len(m.activeByHost))
	byID := make(map[string]struct{}, len(m.activeByHost))
	for host, id := range m.activeByHost {
		byHost[host] = id
		byID[id] = struct{}{}
	}
	m.active.Store(activeSessionSnapshot{byHost: byHost, byID: byID})
}

func (m *Manager) load() error {
	entries, err := os.ReadDir(m.dir)
	if err != nil {
		return fmt.Errorf("read deep monitor directory: %w", err)
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(m.dir, entry.Name(), "session.json"))
		if err != nil {
			continue
		}
		var meta sessionMeta
		if json.Unmarshal(data, &meta) != nil || meta.ID != entry.Name() {
			continue
		}
		if meta.State != "active" && !meta.StoppedAt.IsZero() && m.now().Sub(meta.StoppedAt) >= Retention {
			if err := os.RemoveAll(m.sessionDir(meta.ID)); err != nil {
				// Keep only metadata so maintenance can retry removal without
				// retaining expired event contents or disabling other sessions.
				m.sessions[meta.ID] = &sessionState{meta: meta, watchers: make(map[uint64]chan *pb.DeepMonitorEventSummary)}
			}
			continue
		}
		meta.QueuedBytes = 0
		state := &sessionState{meta: meta, byID: make(map[string]eventLocation), watchers: make(map[uint64]chan *pb.DeepMonitorEventSummary)}
		if state.meta.State == "active" {
			state.meta.State = "aborted_restart"
			state.meta.StopReason = "gateway_restart"
			state.meta.StoppedAt = m.now().UTC()
		}
		_ = m.loadEvents(state)
		if state.meta.NextSequence == 0 {
			state.meta.NextSequence = state.lastSequence + 1
		}
		m.sessions[meta.ID] = state
		_ = m.writeMeta(m.dir, state.meta)
	}
	m.publishActiveHostsLocked()
	return nil
}

func (m *Manager) loadEvents(s *sessionState) error {
	return m.scanJournal(s.meta.ID, func(event *pb.DeepMonitorEvent, location eventLocation) bool {
		s.cacheEvent(event.Summary, location)
		s.meta.NextSequence = max(s.meta.NextSequence, event.Summary.Sequence+1)
		return true
	})
}

func writeSessionMeta(root string, meta sessionMeta) error {
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(root, meta.ID, "session.json")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	_ = os.Chmod(tmp, 0o600)
	return os.Rename(tmp, path)
}

func (m *Manager) sessionDir(id string) string { return filepath.Join(m.dir, id) }

func (m *Manager) payloadPath(sessionID, eventID, part string) string {
	hash := sha256.Sum256([]byte(part))
	return filepath.Join(m.sessionDir(sessionID), eventID+"-"+hex.EncodeToString(hash[:8])+".payload")
}

func appendSecureFile(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	_ = os.Chmod(path, 0o600)
	_, err = file.Write(data)
	return err
}

func toProtoSession(meta sessionMeta) *pb.DeepMonitorSession {
	result := &pb.DeepMonitorSession{
		Id: meta.ID, Host: meta.Host, State: meta.State,
		StartedAt:  meta.StartedAt.Format(time.RFC3339Nano),
		DeadlineAt: meta.DeadlineAt.Format(time.RFC3339Nano),
		StopReason: meta.StopReason, BytesStored: meta.BytesStored,
		EventCount: meta.EventCount, DroppedEvents: meta.DroppedEvents,
		QuotaBytes: meta.QuotaBytes, PayloadLimitBytes: meta.PayloadLimit,
	}
	if !meta.StoppedAt.IsZero() {
		result.StoppedAt = meta.StoppedAt.Format(time.RFC3339Nano)
	}
	return result
}

func newID() string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err == nil {
		value[6] = (value[6] & 0x0f) | 0x40
		value[8] = (value[8] & 0x3f) | 0x80
		return hex.EncodeToString(value[:])
	}
	return fmt.Sprintf("%x", time.Now().UnixNano())
}
