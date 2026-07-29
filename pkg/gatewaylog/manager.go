package gatewaylog

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go-reauth-proxy/pkg/diagnostics"
	"go-reauth-proxy/pkg/models"

	"github.com/rs/zerolog"
)

const (
	DefaultMaxDays                = 7
	dateLayout                    = "2006-01-02"
	fileExtension                 = ".log"
	maxScanToken                  = 8 * 1024 * 1024
	cursorChunkSize               = 64 * 1024
	pageQueryTailWindowMaxEntries = 10000
	unrecordedCredentialFilter    = "__unrecorded__"
	asyncLogQueueSize             = 13200
	asyncLogDropWarnInterval      = 30 * time.Second
	asyncLogFlushInterval         = 50 * time.Millisecond
	asyncLogWriterBufferSize      = 64 * 1024
)

var errStopScan = errors.New("stop scan")

type Entry struct {
	Time                    string `json:"time,omitempty"`
	Level                   string `json:"level,omitempty"`
	Method                  string `json:"method,omitempty"`
	Scheme                  string `json:"scheme,omitempty"`
	Host                    string `json:"host,omitempty"`
	Path                    string `json:"path,omitempty"`
	Query                   string `json:"query,omitempty"`
	RequestURI              string `json:"request_uri,omitempty"`
	Protocol                string `json:"protocol,omitempty"`
	Status                  int    `json:"status"`
	DurationMs              int64  `json:"duration_ms"`
	RemoteIP                string `json:"remote_ip,omitempty"`
	RemoteAddr              string `json:"remote_addr,omitempty"`
	UserAgent               string `json:"user_agent,omitempty"`
	Referer                 string `json:"referer,omitempty"`
	LoggedIn                bool   `json:"logged_in"`
	AuthRequired            bool   `json:"auth_required"`
	AuthDecision            string `json:"auth_decision,omitempty"`
	AuthCredentialID        string `json:"auth_credential_id,omitempty"`
	AuthCredentialName      string `json:"auth_credential_name,omitempty"`
	AuthCredentialMethod    string `json:"auth_credential_method,omitempty"`
	AuthLinkedTOTPID        string `json:"auth_linked_totp_id,omitempty"`
	AuthLinkedTOTPName      string `json:"auth_linked_totp_name,omitempty"`
	AccessMode              string `json:"access_mode,omitempty"`
	RouteType               string `json:"route_type,omitempty"`
	RouteKey                string `json:"route_key,omitempty"`
	Upstream                string `json:"upstream,omitempty"`
	Matched                 bool   `json:"matched"`
	BytesIn                 uint64 `json:"bytes_in"`
	BytesOut                uint64 `json:"bytes_out"`
	TLS                     bool   `json:"tls"`
	WebSocket               bool   `json:"websocket"`
	AliRealClientIP         string `json:"ali_real_client_ip,omitempty"`
	EOConnectingIP          string `json:"eo_connecting_ip,omitempty"`
	XForwardedFor           string `json:"x_forwarded_for,omitempty"`
	XRealIP                 string `json:"x_real_ip,omitempty"`
	WAFBlocked              bool   `json:"waf_blocked,omitempty"`
	WAFTraceID              string `json:"waf_trace_id,omitempty"`
	WAFMode                 string `json:"waf_mode,omitempty"`
	WAFRuleIDs              []int  `json:"waf_rule_ids,omitempty"`
	WAFAction               string `json:"waf_action,omitempty"`
	WAFBundle               string `json:"waf_bundle,omitempty"`
	GeneralBlacklistBlocked bool   `json:"general_blacklist_blocked,omitempty"`
	AuthRuleGroupID         string `json:"auth_rule_group_id,omitempty"`
	AuthGrantState          string `json:"auth_grant_state,omitempty"`
}

type ConfigInfo struct {
	Enabled         bool   `json:"enabled"`
	RecordLocalhost bool   `json:"record_localhost"`
	MaxDays         int    `json:"max_days"`
	LogsDir         string `json:"logs_dir"`
	DroppedEntries  uint64 `json:"dropped_entries"`
	QueueSize       int    `json:"queue_size"`
	QueueDepth      int    `json:"queue_depth"`
}

type DirectoryInfo struct {
	LogsDir string `json:"logs_dir"`
}

type DatesResult struct {
	Today   string   `json:"today"`
	LogsDir string   `json:"logs_dir"`
	Dates   []string `json:"dates"`
}

type QueryResult struct {
	Date           string   `json:"date"`
	LogsDir        string   `json:"logs_dir"`
	AvailableDates []string `json:"available_dates"`
	Pagination     string   `json:"pagination"`
	Page           int      `json:"page"`
	Limit          int      `json:"limit"`
	Total          int      `json:"total"`
	Cursor         string   `json:"cursor,omitempty"`
	NextCursor     string   `json:"next_cursor,omitempty"`
	HasMore        bool     `json:"has_more"`
	Items          []Entry  `json:"items"`
}

type queryFilter struct {
	search        string
	searchASCII   bool
	exactStatuses map[int]struct{}
	statusClasses map[int]struct{}
	loggedIn      *bool
	credential    string
}

type DeleteResult struct {
	Date           string   `json:"date"`
	LogsDir        string   `json:"logs_dir"`
	Deleted        bool     `json:"deleted"`
	AvailableDates []string `json:"available_dates"`
}

type DailyFileWriter struct {
	baseDir       string
	mu            sync.Mutex
	retentionDays int
	currentDate   string
	currentFile   *os.File
	currentBuffer *bufio.Writer
	lastCleanup   string
	dirReady      bool
}

func NewDailyFileWriter(baseDir string, retentionDays int) *DailyFileWriter {
	return &DailyFileWriter{
		baseDir:       baseDir,
		retentionDays: normalizeMaxDays(retentionDays),
	}
}

func (w *DailyFileWriter) SetRetentionDays(days int) {
	w.mu.Lock()
	w.retentionDays = normalizeMaxDays(days)
	w.mu.Unlock()
}

func (w *DailyFileWriter) Cleanup() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.cleanupLocked(time.Now())
}

func (w *DailyFileWriter) DeleteDate(date string) (bool, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.currentDate == date && w.currentFile != nil {
		if w.currentBuffer != nil {
			_ = w.currentBuffer.Flush()
			w.currentBuffer = nil
		}
		_ = w.currentFile.Close()
		w.currentFile = nil
		w.currentDate = ""
	}

	logPath := w.pathForDate(date)
	if err := os.Remove(logPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (w *DailyFileWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	now := time.Now()
	if err := w.ensureDirLocked(); err != nil {
		return 0, err
	}
	if err := w.rotateLocked(now); err != nil {
		return 0, err
	}
	if err := w.maybeCleanupLocked(now); err != nil {
		return 0, err
	}
	if w.currentFile == nil || w.currentBuffer == nil {
		return 0, fmt.Errorf("log file is not open")
	}
	return w.currentBuffer.Write(p)
}

func (w *DailyFileWriter) Flush() error {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.currentBuffer == nil {
		return nil
	}
	return w.currentBuffer.Flush()
}

func (w *DailyFileWriter) Close() error {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	var flushErr error
	if w.currentBuffer != nil {
		flushErr = w.currentBuffer.Flush()
		w.currentBuffer = nil
	}
	if w.currentFile == nil {
		return flushErr
	}
	closeErr := w.currentFile.Close()
	w.currentFile = nil
	w.currentDate = ""
	if flushErr != nil {
		return flushErr
	}
	return closeErr
}

func (w *DailyFileWriter) ensureDirLocked() error {
	if w.dirReady {
		return nil
	}
	if err := os.MkdirAll(w.baseDir, 0o755); err != nil {
		return err
	}
	w.dirReady = true
	return nil
}

func (w *DailyFileWriter) maybeCleanupLocked(now time.Time) error {
	date := now.Format(dateLayout)
	if w.lastCleanup == date {
		return nil
	}
	if err := w.cleanupLocked(now); err != nil {
		return err
	}
	w.lastCleanup = date
	return nil
}

func (w *DailyFileWriter) rotateLocked(now time.Time) error {
	date := now.Format(dateLayout)
	if w.currentDate == date && w.currentFile != nil {
		return nil
	}

	if w.currentFile != nil {
		if w.currentBuffer != nil {
			if err := w.currentBuffer.Flush(); err != nil {
				return err
			}
			w.currentBuffer = nil
		}
		_ = w.currentFile.Close()
		w.currentFile = nil
	}

	file, err := os.OpenFile(w.pathForDate(date), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}

	w.currentDate = date
	w.currentFile = file
	w.currentBuffer = bufio.NewWriterSize(file, asyncLogWriterBufferSize)
	return nil
}

func (w *DailyFileWriter) cleanupLocked(now time.Time) error {
	entries, err := os.ReadDir(w.baseDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}

	retentionDays := normalizeMaxDays(w.retentionDays)
	cutoff := dayStart(now).AddDate(0, 0, -(retentionDays - 1))

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		date, ok := parseFileDate(entry.Name())
		if !ok {
			continue
		}
		if date.Before(cutoff) {
			if err := os.Remove(filepath.Join(w.baseDir, entry.Name())); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
	}
	return nil
}

func (w *DailyFileWriter) pathForDate(date string) string {
	return filepath.Join(w.baseDir, date+fileExtension)
}

type logQueueState struct {
	entries chan *Entry
	stopped chan struct{}
}

type Manager struct {
	mu                sync.RWMutex
	workerMu          sync.Mutex
	config            models.LoggingConfig
	logsDir           string
	writer            *DailyFileWriter
	logger            zerolog.Logger
	logQueue          atomic.Pointer[logQueueState]
	flushQueue        chan chan struct{}
	done              chan struct{}
	closeOnce         sync.Once
	closed            atomic.Bool
	enabled           atomic.Bool
	recordLocalhost   atomic.Bool
	droppedLogEntries atomic.Uint64
	lastDropWarnNano  atomic.Int64
	entryPool         sync.Pool
}

func NormalizeConfig(cfg models.LoggingConfig) models.LoggingConfig {
	cfg.MaxDays = normalizeMaxDays(cfg.MaxDays)
	return cfg
}

func DefaultLogsDir(runtimeDir string) string {
	return filepath.Join(runtimeDir, "logs")
}

func NewManager(logsDir string, cfg models.LoggingConfig) *Manager {
	normalized := NormalizeConfig(cfg)
	writer := NewDailyFileWriter(logsDir, normalized.MaxDays)
	logger := zerolog.New(writer).With().Timestamp().Logger()

	m := &Manager{
		config:     normalized,
		logsDir:    logsDir,
		writer:     writer,
		logger:     logger,
		flushQueue: make(chan chan struct{}),
		done:       make(chan struct{}),
	}
	m.entryPool.New = func() any { return new(Entry) }
	m.recordLocalhost.Store(normalized.RecordLocalhost)
	if normalized.Enabled {
		m.ensureLogWorker()
		m.enabled.Store(true)
	}
	return m
}

func (m *Manager) GetConfigInfo() ConfigInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	queueSize := 0
	queueDepth := 0
	if queue := m.logQueue.Load(); queue != nil {
		queueSize = cap(queue.entries)
		queueDepth = len(queue.entries)
	}
	return ConfigInfo{
		Enabled:         m.config.Enabled,
		RecordLocalhost: m.config.RecordLocalhost,
		MaxDays:         m.config.MaxDays,
		LogsDir:         m.logsDir,
		DroppedEntries:  m.droppedLogEntries.Load(),
		QueueSize:       queueSize,
		QueueDepth:      queueDepth,
	}
}

func (m *Manager) UpdateConfig(cfg models.LoggingConfig) ConfigInfo {
	normalized := NormalizeConfig(cfg)
	if !normalized.Enabled {
		m.enabled.Store(false)
	}
	m.Flush()
	if normalized.Enabled {
		m.ensureLogWorker()
	}

	m.mu.Lock()
	m.config = normalized
	m.writer.SetRetentionDays(normalized.MaxDays)
	m.mu.Unlock()
	m.recordLocalhost.Store(normalized.RecordLocalhost)
	m.enabled.Store(normalized.Enabled)

	_ = m.writer.Cleanup()
	return m.GetConfigInfo()
}

func (m *Manager) LogsDir() string {
	return m.logsDir
}

func (m *Manager) Enabled() bool {
	return m != nil && !m.closed.Load() && m.enabled.Load()
}

func (m *Manager) Log(entry Entry) {
	if m == nil || m.closed.Load() || !m.enabled.Load() {
		return
	}
	if !m.recordLocalhost.Load() && isLocalhostIPv4Entry(entry) {
		return
	}
	queue := m.logQueue.Load()
	if queue == nil || m.closed.Load() || !m.enabled.Load() {
		return
	}
	queued := m.entryPool.Get().(*Entry)
	*queued = cloneLogEntry(entry)
	select {
	case queue.entries <- queued:
	default:
		m.releaseLogEntry(queued)
		dropped := m.droppedLogEntries.Add(1)
		diagnostics.RecordGatewayLogDrop()
		m.warnDroppedLogEntry(dropped)
	}
}

func isLocalhostIPv4Entry(entry Entry) bool {
	// Protocol mappings are data-plane traffic. Keep their access records even
	// when the client connects through loopback (for example via a local tunnel).
	// Unmatched-route resets are security-relevant and must remain observable
	// during local diagnostics as well.
	if entry.RouteType == "stream_rule" || entry.RouteType == "unmatched_route_blocked" {
		return false
	}
	if remoteIP := strings.TrimSpace(entry.RemoteIP); remoteIP != "" {
		return isLocalhostIPv4(remoteIP)
	}
	return isLocalhostIPv4(entry.RemoteAddr)
}

func isLocalhostIPv4(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}

	if addr, err := netip.ParseAddr(value); err == nil {
		return addr.Unmap() == netip.AddrFrom4([4]byte{127, 0, 0, 1})
	}
	if addrPort, err := netip.ParseAddrPort(value); err == nil {
		return addrPort.Addr().Unmap() == netip.AddrFrom4([4]byte{127, 0, 0, 1})
	}
	return false
}

func (m *Manager) warnDroppedLogEntry(dropped uint64) {
	if m == nil {
		return
	}
	now := time.Now().UnixNano()
	last := m.lastDropWarnNano.Load()
	if last > 0 && now-last < int64(asyncLogDropWarnInterval) {
		return
	}
	if !m.lastDropWarnNano.CompareAndSwap(last, now) {
		return
	}
	_, _ = fmt.Fprintf(os.Stderr, "gateway access log queue full; dropped %d entries\n", dropped)
}

func (m *Manager) Flush() {
	if m == nil || m.flushQueue == nil || m.logQueue.Load() == nil {
		return
	}
	ack := make(chan struct{})
	select {
	case m.flushQueue <- ack:
		<-ack
	case <-m.done:
	}
}

func (m *Manager) Close() {
	if m == nil {
		return
	}
	m.closeOnce.Do(func() {
		m.closed.Store(true)
		m.enabled.Store(false)
		m.Flush()
		close(m.done)
		if queue := m.logQueue.Load(); queue != nil {
			<-queue.stopped
		}
		_ = m.writer.Close()
	})
}

func (m *Manager) DroppedLogEntries() uint64 {
	if m == nil {
		return 0
	}
	return m.droppedLogEntries.Load()
}

func (m *Manager) ensureLogWorker() {
	if m == nil || m.closed.Load() || m.logQueue.Load() != nil {
		return
	}
	m.workerMu.Lock()
	defer m.workerMu.Unlock()
	if m.closed.Load() || m.logQueue.Load() != nil {
		return
	}
	queue := &logQueueState{
		entries: make(chan *Entry, asyncLogQueueSize),
		stopped: make(chan struct{}),
	}
	m.logQueue.Store(queue)
	go m.runLogWorker(queue)
}

func (m *Manager) runLogWorker(queue *logQueueState) {
	defer close(queue.stopped)
	ticker := time.NewTicker(asyncLogFlushInterval)
	defer ticker.Stop()
	for {
		select {
		case entry := <-queue.entries:
			m.writeLogEntry(entry)
		case ack := <-m.flushQueue:
			m.drainLogQueue(queue)
			_ = m.writer.Flush()
			close(ack)
		case <-ticker.C:
			_ = m.writer.Flush()
		case <-m.done:
			m.drainLogQueue(queue)
			_ = m.writer.Flush()
			return
		}
	}
}

func (m *Manager) drainLogQueue(queue *logQueueState) {
	for {
		select {
		case entry := <-queue.entries:
			m.writeLogEntry(entry)
		default:
			return
		}
	}
}

func cloneLogEntry(entry Entry) Entry {
	if len(entry.WAFRuleIDs) > 0 {
		entry.WAFRuleIDs = append([]int(nil), entry.WAFRuleIDs...)
	}
	return entry
}

func (m *Manager) releaseLogEntry(entry *Entry) {
	if entry == nil {
		return
	}
	*entry = Entry{}
	m.entryPool.Put(entry)
}

func (m *Manager) writeLogEntry(entry *Entry) {
	if entry == nil {
		return
	}
	defer m.releaseLogEntry(entry)
	m.mu.RLock()
	logger := m.logger
	m.mu.RUnlock()

	event := logger.Info()
	event.Str("method", entry.Method).
		Str("scheme", entry.Scheme).
		Str("host", entry.Host).
		Str("path", entry.Path).
		Str("query", entry.Query).
		Str("request_uri", entry.RequestURI).
		Str("protocol", entry.Protocol).
		Int("status", entry.Status).
		Int64("duration_ms", entry.DurationMs).
		Str("remote_ip", entry.RemoteIP).
		Str("remote_addr", entry.RemoteAddr).
		Str("user_agent", entry.UserAgent).
		Str("referer", entry.Referer).
		Bool("logged_in", entry.LoggedIn).
		Bool("auth_required", entry.AuthRequired).
		Str("auth_decision", entry.AuthDecision).
		Str("auth_credential_id", entry.AuthCredentialID).
		Str("auth_credential_name", entry.AuthCredentialName).
		Str("auth_credential_method", entry.AuthCredentialMethod).
		Str("auth_linked_totp_id", entry.AuthLinkedTOTPID).
		Str("auth_linked_totp_name", entry.AuthLinkedTOTPName).
		Str("access_mode", entry.AccessMode).
		Str("route_type", entry.RouteType).
		Str("route_key", entry.RouteKey).
		Str("upstream", entry.Upstream).
		Bool("matched", entry.Matched).
		Uint64("bytes_in", entry.BytesIn).
		Uint64("bytes_out", entry.BytesOut).
		Bool("tls", entry.TLS).
		Bool("websocket", entry.WebSocket).
		Str("ali_real_client_ip", entry.AliRealClientIP).
		Str("eo_connecting_ip", entry.EOConnectingIP).
		Str("x_forwarded_for", entry.XForwardedFor).
		Str("x_real_ip", entry.XRealIP).
		Bool("waf_blocked", entry.WAFBlocked).
		Str("waf_trace_id", entry.WAFTraceID).
		Str("waf_mode", entry.WAFMode).
		Ints("waf_rule_ids", entry.WAFRuleIDs).
		Str("waf_action", entry.WAFAction).
		Str("waf_bundle", entry.WAFBundle).
		Bool("general_blacklist_blocked", entry.GeneralBlacklistBlocked).
		Str("auth_rule_group_id", entry.AuthRuleGroupID).
		Str("auth_grant_state", entry.AuthGrantState).
		Send()
}

func (m *Manager) GetDates() (DatesResult, error) {
	m.Flush()
	dates, err := m.listDates(true)
	if err != nil {
		return DatesResult{}, err
	}

	return DatesResult{
		Today:   time.Now().Format(dateLayout),
		LogsDir: m.logsDir,
		Dates:   dates,
	}, nil
}

func (m *Manager) Query(date string, page int, limit int, search string, status string, loggedIn string, credential string, cursor string, pagination string) (QueryResult, error) {
	m.Flush()
	selectedDate, err := normalizeDate(date)
	if err != nil {
		return QueryResult{}, err
	}

	if page <= 0 {
		page = 1
	}
	if limit <= 0 {
		limit = 20
	}
	if limit > 200 {
		limit = 200
	}

	logPath := filepath.Join(m.logsDir, selectedDate+fileExtension)
	filter, err := newQueryFilter(search, status, loggedIn, credential)
	if err != nil {
		return QueryResult{}, err
	}

	dates, err := m.listDates(true)
	if err != nil {
		return QueryResult{}, err
	}

	mode := normalizePaginationMode(pagination)
	if mode == "cursor" {
		items, nextCursor, hasMore, resolvedCursor, err := queryEntriesByCursor(logPath, filter, cursor, limit)
		if err != nil {
			return QueryResult{}, err
		}

		return QueryResult{
			Date:           selectedDate,
			LogsDir:        m.logsDir,
			AvailableDates: dates,
			Pagination:     mode,
			Page:           1,
			Limit:          limit,
			Total:          0,
			Cursor:         resolvedCursor,
			NextCursor:     nextCursor,
			HasMore:        hasMore,
			Items:          items,
		}, nil
	}

	items, total, hasMore, err := queryEntries(logPath, filter, page, limit)
	if err != nil {
		return QueryResult{}, err
	}

	return QueryResult{
		Date:           selectedDate,
		LogsDir:        m.logsDir,
		AvailableDates: dates,
		Pagination:     mode,
		Page:           page,
		Limit:          limit,
		Total:          total,
		HasMore:        hasMore,
		Items:          items,
	}, nil
}

func (m *Manager) DeleteDate(date string) (DeleteResult, error) {
	m.Flush()
	selectedDate, err := normalizeDate(date)
	if err != nil {
		return DeleteResult{}, err
	}

	deleted, err := m.writer.DeleteDate(selectedDate)
	if err != nil {
		return DeleteResult{}, err
	}

	dates, err := m.listDates(true)
	if err != nil {
		return DeleteResult{}, err
	}

	return DeleteResult{
		Date:           selectedDate,
		LogsDir:        m.logsDir,
		Deleted:        deleted,
		AvailableDates: dates,
	}, nil
}

func (m *Manager) listDates(includeToday bool) ([]string, error) {
	entries, err := os.ReadDir(m.logsDir)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		entries = nil
	}

	dateSet := make(map[string]struct{})
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		date, ok := parseFileDate(entry.Name())
		if !ok {
			continue
		}
		dateSet[date.Format(dateLayout)] = struct{}{}
	}

	if includeToday {
		dateSet[time.Now().Format(dateLayout)] = struct{}{}
	}

	dates := make([]string, 0, len(dateSet))
	for date := range dateSet {
		dates = append(dates, date)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(dates)))
	return dates, nil
}

func normalizeMaxDays(days int) int {
	if days <= 0 {
		return DefaultMaxDays
	}
	return days
}

func dayStart(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, t.Location())
}

func parseFileDate(fileName string) (time.Time, bool) {
	if filepath.Ext(fileName) != fileExtension {
		return time.Time{}, false
	}

	base := strings.TrimSuffix(fileName, fileExtension)
	parsed, err := time.Parse(dateLayout, base)
	if err != nil {
		return time.Time{}, false
	}
	return parsed, true
}

func normalizeDate(raw string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return time.Now().Format(dateLayout), nil
	}

	parsed, err := time.Parse(dateLayout, raw)
	if err != nil {
		return "", fmt.Errorf("invalid date, expected format YYYY-MM-DD")
	}
	return parsed.Format(dateLayout), nil
}

func normalizePaginationMode(raw string) string {
	if strings.EqualFold(strings.TrimSpace(raw), "cursor") {
		return "cursor"
	}
	return "page"
}

func reverseEntries(items []Entry) {
	for left, right := 0, len(items)-1; left < right; left, right = left+1, right-1 {
		items[left], items[right] = items[right], items[left]
	}
}

func newQueryFilter(search string, status string, loggedIn string, credential string) (queryFilter, error) {
	filter := queryFilter{
		search:     strings.ToLower(strings.TrimSpace(search)),
		credential: normalizeCredentialFilter(credential),
	}
	filter.searchASCII = isASCIIString(filter.search)

	rawStatus := strings.TrimSpace(status)
	if rawStatus != "" && !strings.EqualFold(rawStatus, "all") {
		filter.exactStatuses = make(map[int]struct{})
		filter.statusClasses = make(map[int]struct{})

		for _, token := range strings.Split(rawStatus, ",") {
			value := strings.ToLower(strings.TrimSpace(token))
			if value == "" || value == "all" {
				continue
			}

			if len(value) == 3 && strings.HasSuffix(value, "xx") {
				class := int(value[0] - '0')
				if class < 1 || class > 5 {
					return queryFilter{}, fmt.Errorf("invalid status filter: %s", token)
				}
				filter.statusClasses[class] = struct{}{}
				continue
			}

			code, err := strconv.Atoi(value)
			if err != nil || code < 100 || code > 599 {
				return queryFilter{}, fmt.Errorf("invalid status filter: %s", token)
			}
			filter.exactStatuses[code] = struct{}{}
		}
	}

	if loggedInFilter, err := parseLoggedInFilter(loggedIn); err != nil {
		return queryFilter{}, err
	} else {
		filter.loggedIn = loggedInFilter
	}

	return filter, nil
}

func normalizeCredentialFilter(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" || strings.EqualFold(value, "all") {
		return ""
	}
	switch strings.ToLower(value) {
	case unrecordedCredentialFilter, "unrecorded", "unknown", "missing":
		return unrecordedCredentialFilter
	}
	return value
}

func (f queryFilter) matchLine(line string) bool {
	if f.search == "" {
		return true
	}
	if f.searchASCII {
		return containsFoldASCIIString(line, f.search)
	}
	return strings.Contains(strings.ToLower(line), f.search)
}

func (f queryFilter) matchLineBytes(line []byte) bool {
	if f.search == "" {
		return true
	}
	if f.searchASCII {
		return containsFoldASCIIBytes(line, f.search)
	}
	return f.matchLine(string(line))
}

func isASCIIString(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] >= 0x80 {
			return false
		}
	}
	return true
}

func containsFoldASCIIString(value string, search string) bool {
	if search == "" {
		return true
	}
	if len(search) > len(value) {
		return false
	}
	first := search[0]
	last := len(value) - len(search)
	for i := 0; i <= last; i++ {
		if lowerASCIIByte(value[i]) != first {
			continue
		}
		if hasFoldASCIIPrefixString(value[i:], search) {
			return true
		}
	}
	return false
}

func hasFoldASCIIPrefixString(value string, search string) bool {
	if len(search) > len(value) {
		return false
	}
	for i := 1; i < len(search); i++ {
		if lowerASCIIByte(value[i]) != search[i] {
			return false
		}
	}
	return true
}

func containsFoldASCIIBytes(value []byte, search string) bool {
	if search == "" {
		return true
	}
	if len(search) > len(value) {
		return false
	}
	first := search[0]
	last := len(value) - len(search)
	for i := 0; i <= last; i++ {
		if lowerASCIIByte(value[i]) != first {
			continue
		}
		if hasFoldASCIIPrefixBytes(value[i:], search) {
			return true
		}
	}
	return false
}

func hasFoldASCIIPrefixBytes(value []byte, search string) bool {
	if len(search) > len(value) {
		return false
	}
	for i := 1; i < len(search); i++ {
		if lowerASCIIByte(value[i]) != search[i] {
			return false
		}
	}
	return true
}

func lowerASCIIByte(value byte) byte {
	if value >= 'A' && value <= 'Z' {
		return value + ('a' - 'A')
	}
	return value
}

func (f queryFilter) matchStatus(status int) bool {
	if len(f.exactStatuses) == 0 && len(f.statusClasses) == 0 {
		return true
	}
	if _, ok := f.exactStatuses[status]; ok {
		return true
	}
	_, ok := f.statusClasses[status/100]
	return ok
}

func (f queryFilter) matchLoggedIn(loggedIn bool) bool {
	if f.loggedIn == nil {
		return true
	}
	return *f.loggedIn == loggedIn
}

func (f queryFilter) matchCredential(entry Entry) bool {
	if f.credential == "" {
		return true
	}
	if f.credential == unrecordedCredentialFilter {
		return !entryHasRecordedCredential(entry) && entryNeedsCredentialContext(entry)
	}
	for _, value := range []string{entry.AuthCredentialID, entry.AuthLinkedTOTPID} {
		if strings.EqualFold(strings.TrimSpace(value), f.credential) {
			return true
		}
	}
	return false
}

func entryHasRecordedCredential(entry Entry) bool {
	return strings.TrimSpace(entry.AuthCredentialID) != "" ||
		strings.TrimSpace(entry.AuthLinkedTOTPID) != ""
}

func entryNeedsCredentialContext(entry Entry) bool {
	if entry.LoggedIn {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(entry.AuthDecision), "access_denied")
}

func (f queryFilter) matchEntry(entry Entry) bool {
	return f.matchStatus(entry.Status) &&
		f.matchLoggedIn(entry.LoggedIn) &&
		f.matchCredential(entry)
}

func (f queryFilter) needsDecodedEntryFilter() bool {
	return f.credential != ""
}

var (
	jsonStatusFieldName   = []byte("status")
	jsonLoggedInFieldName = []byte("logged_in")
)

func (f queryFilter) matchRawEntryFields(line []byte) bool {
	if len(f.exactStatuses) > 0 || len(f.statusClasses) > 0 {
		status, _ := rawJSONIntField(line, jsonStatusFieldName)
		if !f.matchStatus(status) {
			return false
		}
	}
	if f.loggedIn != nil {
		loggedIn, _ := rawJSONBoolField(line, jsonLoggedInFieldName)
		if !f.matchLoggedIn(loggedIn) {
			return false
		}
	}
	return true
}

func rawJSONIntField(line []byte, field []byte) (int, bool) {
	value, ok := rawJSONFieldValue(line, field)
	if !ok {
		return 0, false
	}
	n := 0
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c < '0' || c > '9' {
			return n, i > 0
		}
		n = n*10 + int(c-'0')
	}
	return n, len(value) > 0
}

func rawJSONBoolField(line []byte, field []byte) (bool, bool) {
	value, ok := rawJSONFieldValue(line, field)
	if !ok {
		return false, false
	}
	if len(value) >= len("true") &&
		value[0] == 't' && value[1] == 'r' && value[2] == 'u' && value[3] == 'e' {
		return true, true
	}
	if len(value) >= len("false") &&
		value[0] == 'f' && value[1] == 'a' && value[2] == 'l' && value[3] == 's' && value[4] == 'e' {
		return false, true
	}
	return false, false
}

func rawJSONFieldValue(line []byte, field []byte) ([]byte, bool) {
	depth := 0
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '"':
			if depth == 1 {
				if value, ok := rawJSONTopLevelFieldValueAt(line, field, i); ok {
					return value, true
				}
			}
			end, ok := skipJSONString(line, i)
			if !ok {
				return nil, false
			}
			i = end
		case '{', '[':
			depth++
		case '}', ']':
			if depth == 0 {
				return nil, false
			}
			depth--
		}
	}
	return nil, false
}

func rawJSONTopLevelFieldValueAt(line []byte, field []byte, quote int) ([]byte, bool) {
	nameStart := quote + 1
	nameEnd := nameStart + len(field)
	if nameEnd >= len(line) || line[nameEnd] != '"' || !bytes.Equal(line[nameStart:nameEnd], field) {
		return nil, false
	}
	j := nameEnd + 1
	for j < len(line) && isJSONSpace(line[j]) {
		j++
	}
	if j >= len(line) || line[j] != ':' {
		return nil, false
	}
	j++
	for j < len(line) && isJSONSpace(line[j]) {
		j++
	}
	if j >= len(line) {
		return nil, false
	}
	return line[j:], true
}

func skipJSONString(line []byte, quote int) (int, bool) {
	for i := quote + 1; i < len(line); i++ {
		switch line[i] {
		case '\\':
			i++
		case '"':
			return i, true
		}
	}
	return len(line), false
}

func isJSONSpace(c byte) bool {
	switch c {
	case ' ', '\n', '\r', '\t':
		return true
	default:
		return false
	}
}

func parseLoggedInFilter(raw string) (*bool, error) {
	value := strings.ToLower(strings.TrimSpace(raw))
	switch value {
	case "", "all":
		return nil, nil
	case "true", "1", "yes", "logged_in":
		loggedIn := true
		return &loggedIn, nil
	case "false", "0", "no", "logged_out":
		loggedIn := false
		return &loggedIn, nil
	default:
		return nil, fmt.Errorf("invalid logged_in filter: %s", raw)
	}
}

func queryEntries(logPath string, filter queryFilter, page int, limit int) ([]Entry, int, bool, error) {
	return queryEntriesStreaming(logPath, filter, page, limit)
}

func queryEntriesStreaming(logPath string, filter queryFilter, page int, limit int) ([]Entry, int, bool, error) {
	if page <= 0 {
		page = 1
	}
	if limit <= 0 {
		limit = 20
	}
	if page > (int(^uint(0)>>1))/limit {
		return queryEntriesStreamingTwoPass(logPath, filter, page, limit)
	}

	windowSize := page * limit
	if windowSize > pageQueryTailWindowMaxEntries {
		return queryEntriesStreamingTwoPass(logPath, filter, page, limit)
	}

	return queryEntriesStreamingRawTail(logPath, filter, page, limit, windowSize)
}

func queryEntriesStreamingRawTail(logPath string, filter queryFilter, page int, limit int, windowSize int) ([]Entry, int, bool, error) {
	tail := newRawLineTailWindow(windowSize)
	total, err := scanMatchingRawLinesToTail(logPath, filter, tail)
	if err != nil {
		return nil, 0, false, err
	}

	forwardStart, forwardEnd := resolveForwardWindow(total, page, limit)
	if forwardStart == forwardEnd {
		return []Entry{}, total, false, nil
	}

	tailStart := total - tail.Len()
	if forwardStart < tailStart {
		return queryEntriesStreamingTwoPass(logPath, filter, page, limit)
	}

	items, ok := tail.DecodeEntriesDescending(forwardStart-tailStart, forwardEnd-tailStart)
	if !ok {
		return queryEntriesStreamingTwoPass(logPath, filter, page, limit)
	}
	return items, total, forwardStart > 0, nil
}

func queryEntriesStreamingTwoPass(logPath string, filter queryFilter, page int, limit int) ([]Entry, int, bool, error) {
	total, err := scanMatchingEntries(logPath, filter, nil)
	if err != nil {
		return nil, 0, false, err
	}

	forwardStart, forwardEnd := resolveForwardWindow(total, page, limit)
	if forwardStart == forwardEnd {
		return []Entry{}, total, false, nil
	}

	items := make([]Entry, 0, forwardEnd-forwardStart)
	err = collectMatchingEntries(logPath, filter, forwardStart, forwardEnd, func(entry Entry) {
		items = append(items, entry)
	})
	if err != nil {
		return nil, 0, false, err
	}

	reverseEntries(items)
	return items, total, forwardStart > 0, nil
}

type rawLineTailWindow struct {
	lines [][]byte
	start int
	count int
}

func newRawLineTailWindow(capacity int) *rawLineTailWindow {
	if capacity <= 0 {
		return &rawLineTailWindow{}
	}
	return &rawLineTailWindow{lines: make([][]byte, capacity)}
}

func (w *rawLineTailWindow) Add(line []byte) {
	if w == nil || len(w.lines) == 0 {
		return
	}
	index := (w.start + w.count) % len(w.lines)
	if w.count == len(w.lines) {
		index = w.start
		w.start = (w.start + 1) % len(w.lines)
	} else {
		w.count++
	}
	w.lines[index] = append(w.lines[index][:0], line...)
}

func (w *rawLineTailWindow) Len() int {
	if w == nil {
		return 0
	}
	return w.count
}

func (w *rawLineTailWindow) DecodeEntriesDescending(start int, end int) ([]Entry, bool) {
	if w == nil || len(w.lines) == 0 || start < 0 || end < start || end > w.count {
		return []Entry{}, true
	}
	items := make([]Entry, end-start)
	for i := start; i < end; i++ {
		var entry Entry
		if err := json.Unmarshal(w.lines[(w.start+i)%len(w.lines)], &entry); err != nil {
			return nil, false
		}
		items[end-i-1] = entry
	}
	return items, true
}

func queryEntriesByCursor(logPath string, filter queryFilter, cursor string, limit int) ([]Entry, string, bool, string, error) {
	file, err := os.Open(logPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []Entry{}, "", false, "", nil
		}
		return nil, "", false, "", err
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return nil, "", false, "", err
	}

	endOffset, resolvedCursor, err := resolveCursorOffset(stat.Size(), cursor)
	if err != nil {
		return nil, "", false, "", err
	}
	if endOffset == 0 {
		return []Entry{}, "", false, resolvedCursor, nil
	}

	items := make([]Entry, 0, limit)
	oldestReturnedStart := int64(0)
	hasMore := false

	err = scanLinesBackward(file, endOffset, func(line []byte, lineStart int64) (bool, error) {
		if !filter.matchLineBytes(line) {
			return true, nil
		}
		if !jsonLogLineLooksLikeEntryObject(line) || !filter.matchRawEntryFields(line) {
			return true, nil
		}

		var entry Entry
		if err := json.Unmarshal(line, &entry); err != nil {
			return true, nil
		}
		if !filter.matchEntry(entry) {
			return true, nil
		}

		if len(items) == limit {
			hasMore = true
			return false, nil
		}

		items = append(items, entry)
		oldestReturnedStart = lineStart
		return true, nil
	})
	if err != nil {
		return nil, "", false, "", err
	}

	nextCursor := ""
	if hasMore && oldestReturnedStart > 0 {
		nextCursor = strconv.FormatInt(oldestReturnedStart, 10)
	}

	return items, nextCursor, hasMore, resolvedCursor, nil
}

func resolveForwardWindow(total int, page int, limit int) (int, int) {
	startDesc := (page - 1) * limit
	if startDesc >= total {
		return total, total
	}

	endDesc := startDesc + limit
	if endDesc > total {
		endDesc = total
	}

	return total - endDesc, total - startDesc
}

func scanMatchingRawLinesToTail(logPath string, filter queryFilter, tail *rawLineTailWindow) (int, error) {
	file, err := os.Open(logPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), maxScanToken)

	total := 0
	for scanner.Scan() {
		line := scanner.Bytes()
		if !filter.matchLineBytes(line) {
			continue
		}
		if !jsonLogLineLooksLikeEntryObject(line) || !filter.matchRawEntryFields(line) {
			continue
		}
		if filter.needsDecodedEntryFilter() {
			var entry Entry
			if err := json.Unmarshal(line, &entry); err != nil {
				continue
			}
			if !filter.matchEntry(entry) {
				continue
			}
		} else if !json.Valid(line) {
			continue
		}

		tail.Add(line)
		total++
	}

	if err := scanner.Err(); err != nil {
		return 0, err
	}
	return total, nil
}

func jsonLogLineLooksLikeEntryObject(line []byte) bool {
	line = bytes.TrimLeft(line, " \t\r\n")
	return len(line) > 0 && line[0] == '{'
}

func scanMatchingEntries(logPath string, filter queryFilter, onMatch func(entry Entry, matchIndex int) error) (int, error) {
	file, err := os.Open(logPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), maxScanToken)

	total := 0
	for scanner.Scan() {
		line := scanner.Bytes()
		if !filter.matchLineBytes(line) {
			continue
		}
		if !jsonLogLineLooksLikeEntryObject(line) || !filter.matchRawEntryFields(line) {
			continue
		}

		var entry Entry
		if err := json.Unmarshal(line, &entry); err != nil {
			continue
		}
		if !filter.matchEntry(entry) {
			continue
		}

		if onMatch != nil {
			if err := onMatch(entry, total); err != nil {
				return total, err
			}
		}
		total++
	}

	if err := scanner.Err(); err != nil {
		return 0, err
	}
	return total, nil
}

func collectMatchingEntries(logPath string, filter queryFilter, start int, end int, onCollect func(entry Entry)) error {
	_, err := scanMatchingEntries(logPath, filter, func(entry Entry, matchIndex int) error {
		if matchIndex < start {
			return nil
		}
		if matchIndex >= end {
			return errStopScan
		}
		onCollect(entry)
		return nil
	})
	if err != nil && !errors.Is(err, errStopScan) {
		return err
	}
	return nil
}

func resolveCursorOffset(fileSize int64, cursor string) (int64, string, error) {
	trimmed := strings.TrimSpace(cursor)
	if trimmed == "" {
		return fileSize, "", nil
	}

	offset, err := strconv.ParseInt(trimmed, 10, 64)
	if err != nil {
		return 0, "", fmt.Errorf("invalid cursor")
	}
	if offset < 0 || offset > fileSize {
		return 0, "", fmt.Errorf("cursor out of range")
	}
	return offset, trimmed, nil
}

func scanLinesBackward(file *os.File, endOffset int64, onLine func(line []byte, lineStart int64) (bool, error)) error {
	position := endOffset
	var remainder []byte
	readBufferSize := cursorChunkSize
	if endOffset > 0 && endOffset < int64(readBufferSize) {
		readBufferSize = int(endOffset)
	}
	readBuffer := make([]byte, readBufferSize)
	var combinedBuffer []byte
	firstPass := true

	for position > 0 {
		readSize := int64(cursorChunkSize)
		if readSize > position {
			readSize = position
		}

		start := position - readSize
		buffer := readBuffer[:readSize]
		n, err := file.ReadAt(buffer, start)
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		buffer = buffer[:n]

		combined := buffer
		if len(remainder) > 0 {
			needed := len(buffer) + len(remainder)
			if cap(combinedBuffer) < needed {
				combinedBuffer = make([]byte, needed)
			}
			combined = combinedBuffer[:needed]
			copy(combined, buffer)
			copy(combined[len(buffer):], remainder)
		}
		scanEnd := len(combined)
		if firstPass {
			scanEnd = len(bytes.TrimRight(combined[:scanEnd], "\r\n"))
			firstPass = false
		}

		for scanEnd > 0 {
			index := bytes.LastIndexByte(combined[:scanEnd], '\n')
			if index == -1 {
				break
			}

			line := bytes.TrimRight(combined[index+1:scanEnd], "\r")
			lineStart := start + int64(index+1)
			scanEnd = index

			if len(line) == 0 {
				continue
			}

			keepScanning, err := onLine(line, lineStart)
			if err != nil {
				return err
			}
			if !keepScanning {
				return nil
			}
		}

		remainder = append(remainder[:0], combined[:scanEnd]...)
		position = start
	}

	line := bytes.TrimRight(remainder, "\r\n")
	if len(line) == 0 {
		return nil
	}

	_, err := onLine(line, 0)
	return err
}
