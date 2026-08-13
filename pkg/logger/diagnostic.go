package logger

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	DiagnosticLogDirEnv = "FN_KNOCK_DIAGNOSTIC_LOG_DIR"
	DataDirEnv          = "FN_KNOCK_DATA_DIR"

	diagnosticLogMaxBytes  = int64(1 << 20)
	diagnosticCrashMax     = int64(512 << 10)
	diagnosticQueueSize    = 1024
	diagnosticHighSize     = 256
	diagnosticRepeatWindow = 60 * time.Second
	diagnosticRepeatTTL    = 5 * time.Minute
	diagnosticRepeatMax    = 1024
)

var diagnosticFields = map[string]struct{}{
	"commit": {}, "count": {}, "dropped": {}, "duration_ms": {},
	"exit_code": {}, "gc_percent": {}, "generation": {}, "heap_alloc_bytes": {},
	"heap_sys_bytes": {}, "instance_id": {}, "listener": {}, "pid": {},
	"previous_status": {}, "protocol_version": {}, "queue_depth": {}, "result": {},
	"rss_bytes": {}, "signal": {}, "status": {}, "version": {},
}

type diagnosticRecord struct {
	Time       string         `json:"time"`
	Level      string         `json:"level"`
	Component  string         `json:"component"`
	Event      string         `json:"event"`
	ReasonCode string         `json:"reason_code,omitempty"`
	Fields     map[string]any `json:"fields,omitempty"`
}

type repeatState struct {
	last       time.Time
	suppressed uint64
}

type diagnosticRuntime struct {
	writer      *rotatingDiagnosticWriter
	info        chan []byte
	high        chan []byte
	flush       chan chan struct{}
	done        chan struct{}
	stopped     chan struct{}
	closed      atomic.Bool
	droppedInfo atomic.Uint64
	repeatMu    sync.Mutex
	repeats     map[string]repeatState
	crash       *os.File
}

var (
	diagnosticMu    sync.Mutex
	diagnosticState atomic.Pointer[diagnosticRuntime]
)

func configureDiagnosticLoggerFromEnv() {
	dir := strings.TrimSpace(os.Getenv(DiagnosticLogDirEnv))
	if dir == "" {
		if dataDir := strings.TrimSpace(os.Getenv(DataDirEnv)); dataDir != "" {
			dir = filepath.Join(dataDir, "runtime", "logs")
		} else {
			dir = filepath.Join(os.TempDir(), "fn-knock", "runtime", "logs")
		}
	}

	runtime, err := newDiagnosticRuntime(dir)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "diagnostic logger unavailable: %v\n", err)
		return
	}
	diagnosticMu.Lock()
	old := diagnosticState.Swap(runtime)
	diagnosticMu.Unlock()
	if old != nil {
		old.close()
	}
}

func newDiagnosticRuntime(dir string) (*diagnosticRuntime, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	writer, err := newRotatingDiagnosticWriter(filepath.Join(dir, "gateway.jsonl"), diagnosticLogMaxBytes)
	if err != nil {
		return nil, err
	}
	crashPath := filepath.Join(dir, "gateway-crash.log")
	if err := capCrashFile(crashPath, diagnosticCrashMax); err != nil {
		_ = writer.Close()
		return nil, err
	}
	crash, err := os.OpenFile(crashPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		_ = writer.Close()
		return nil, err
	}
	_ = crash.Chmod(0o600)
	if err := debug.SetCrashOutput(crash, debug.CrashOptions{}); err != nil {
		_ = crash.Close()
		_ = writer.Close()
		return nil, err
	}
	runtime := &diagnosticRuntime{
		writer:  writer,
		info:    make(chan []byte, diagnosticQueueSize-diagnosticHighSize),
		high:    make(chan []byte, diagnosticHighSize),
		flush:   make(chan chan struct{}),
		done:    make(chan struct{}),
		stopped: make(chan struct{}),
		repeats: make(map[string]repeatState),
		crash:   crash,
	}
	go runtime.run()
	return runtime, nil
}

// Diagnostic writes one allow-listed operational event. It must never be used
// from a request hot path or for request, authentication, WAF, or config data.
func Diagnostic(level, component, event, reasonCode string, fields map[string]any) {
	runtime := diagnosticState.Load()
	if runtime == nil || runtime.closed.Load() {
		return
	}
	now := time.Now()
	component = cleanDiagnosticIdentifier(component)
	event = cleanDiagnosticIdentifier(event)
	reasonCode = cleanDiagnosticIdentifier(reasonCode)
	if component == "" || event == "" {
		return
	}

	key := component + "\x00" + event + "\x00" + reasonCode
	count, emit := runtime.aggregateRepeat(now, key)
	if !emit {
		return
	}

	cleanFields := cleanDiagnosticFields(fields)
	if count > 1 {
		if cleanFields == nil {
			cleanFields = make(map[string]any)
		}
		cleanFields["count"] = count
	}
	record := diagnosticRecord{
		Time: now.UTC().Format(time.RFC3339Nano), Level: normalizeDiagnosticLevel(level),
		Component: component, Event: event, ReasonCode: reasonCode, Fields: cleanFields,
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return
	}
	encoded = append(encoded, '\n')
	runtime.enqueue(record.Level, encoded)
}

func (r *diagnosticRuntime) aggregateRepeat(now time.Time, key string) (uint64, bool) {
	r.repeatMu.Lock()
	defer r.repeatMu.Unlock()
	r.pruneRepeatsLocked(now)
	previous, exists := r.repeats[key]
	if exists && now.Sub(previous.last) < diagnosticRepeatWindow {
		previous.suppressed++
		r.repeats[key] = previous
		return 0, false
	}
	count := uint64(1)
	if exists {
		count += previous.suppressed
	}
	if !exists && len(r.repeats) >= diagnosticRepeatMax {
		var oldestKey string
		var oldest time.Time
		for repeatKey, state := range r.repeats {
			if oldestKey == "" || state.last.Before(oldest) {
				oldestKey, oldest = repeatKey, state.last
			}
		}
		delete(r.repeats, oldestKey)
	}
	r.repeats[key] = repeatState{last: now}
	return count, true
}

func (r *diagnosticRuntime) pruneRepeats(now time.Time) {
	r.repeatMu.Lock()
	defer r.repeatMu.Unlock()
	r.pruneRepeatsLocked(now)
}

func (r *diagnosticRuntime) pruneRepeatsLocked(now time.Time) {
	for repeatKey, state := range r.repeats {
		if now.Sub(state.last) > diagnosticRepeatTTL {
			delete(r.repeats, repeatKey)
		}
	}
}

func DiagnosticDroppedInfo() uint64 {
	if runtime := diagnosticState.Load(); runtime != nil {
		return runtime.droppedInfo.Load()
	}
	return 0
}

func FlushDiagnosticLogger() {
	if runtime := diagnosticState.Load(); runtime != nil {
		runtime.flushPending()
	}
}

func CloseDiagnosticLogger() {
	diagnosticMu.Lock()
	runtime := diagnosticState.Swap(nil)
	diagnosticMu.Unlock()
	if runtime != nil {
		runtime.close()
	}
}

func (r *diagnosticRuntime) enqueue(level string, data []byte) {
	if level == "WARN" || level == "ERROR" {
		select {
		case r.high <- data:
			return
		default:
		}
		// Keep the newest warning/error without blocking the service. INFO has a
		// separate queue, so high-priority events always retain reserved capacity.
		select {
		case <-r.high:
		default:
		}
		select {
		case r.high <- data:
		default:
			// Do not block the service when the filesystem is unavailable.
		}
		return
	}
	select {
	case r.info <- data:
	default:
		r.droppedInfo.Add(1)
	}
}

func (r *diagnosticRuntime) run() {
	defer close(r.stopped)
	repeatCleanup := time.NewTicker(time.Minute)
	defer repeatCleanup.Stop()
	for {
		// Drain high priority first without starving the control channels.
		select {
		case data := <-r.high:
			r.write(data)
			continue
		default:
		}
		select {
		case data := <-r.high:
			r.write(data)
		case data := <-r.info:
			r.write(data)
		case ack := <-r.flush:
			r.drain()
			close(ack)
		case now := <-repeatCleanup.C:
			r.pruneRepeats(now)
		case <-r.done:
			r.drain()
			return
		}
	}
}

func (r *diagnosticRuntime) drain() {
	for {
		select {
		case data := <-r.high:
			r.write(data)
		default:
			for {
				select {
				case data := <-r.info:
					r.write(data)
				default:
					return
				}
			}
		}
	}
}

func (r *diagnosticRuntime) write(data []byte) {
	if len(data) > 8<<10 {
		data = append(append([]byte(nil), data[:8<<10-1]...), '\n')
	}
	_, _ = r.writer.Write(data)
}

func (r *diagnosticRuntime) flushPending() {
	if r == nil || r.closed.Load() {
		return
	}
	ack := make(chan struct{})
	select {
	case r.flush <- ack:
		<-ack
	case <-r.done:
	}
}

func (r *diagnosticRuntime) close() {
	if r == nil || !r.closed.CompareAndSwap(false, true) {
		return
	}
	ack := make(chan struct{})
	select {
	case r.flush <- ack:
		<-ack
	case <-r.done:
	}
	close(r.done)
	<-r.stopped
	_ = r.writer.Close()
	_ = r.crash.Sync()
	_ = r.crash.Close()
}

type rotatingDiagnosticWriter struct {
	path     string
	maxBytes int64
	mu       sync.Mutex
	file     *os.File
	size     int64
}

func newRotatingDiagnosticWriter(path string, maxBytes int64) (*rotatingDiagnosticWriter, error) {
	if err := capCrashFile(path, maxBytes); err != nil {
		return nil, err
	}
	if err := capCrashFile(path+".1", maxBytes); err != nil {
		return nil, err
	}
	writer := &rotatingDiagnosticWriter{path: path, maxBytes: maxBytes}
	if err := writer.open(); err != nil {
		return nil, err
	}
	return writer, nil
}

func (w *rotatingDiagnosticWriter) open() error {
	file, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	_ = file.Chmod(0o600)
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return err
	}
	w.file = file
	w.size = info.Size()
	return nil
}

func (w *rotatingDiagnosticWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	// The management service may clear this fixed operational log in place.
	// Refresh the observed size so an external truncate cannot leave the
	// writer's rotation accounting stale on Linux, Windows, or packaged hosts.
	if info, err := w.file.Stat(); err == nil {
		w.size = info.Size()
	}
	if int64(len(data)) > w.maxBytes {
		data = data[int64(len(data))-w.maxBytes:]
	}
	if w.size+int64(len(data)) > w.maxBytes {
		if err := w.rotate(); err != nil {
			return 0, err
		}
	}
	n, err := w.file.Write(data)
	w.size += int64(n)
	return n, err
}

func (w *rotatingDiagnosticWriter) rotate() error {
	if w.file != nil {
		_ = w.file.Close()
		w.file = nil
	}
	previous := w.path + ".1"
	_ = os.Remove(previous)
	if err := os.Rename(w.path, previous); err != nil && !os.IsNotExist(err) {
		return err
	}
	return w.open()
}

func (w *rotatingDiagnosticWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return nil
	}
	err := w.file.Close()
	w.file = nil
	return err
}

func capCrashFile(path string, maxBytes int64) error {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil || info.Size() < maxBytes {
		return err
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	start := info.Size() - maxBytes
	if _, err := file.Seek(start, io.SeekStart); err != nil {
		_ = file.Close()
		return err
	}
	tail, err := io.ReadAll(io.LimitReader(file, maxBytes))
	_ = file.Close()
	if err != nil {
		return err
	}
	if start > 0 {
		if newline := strings.IndexByte(string(tail), '\n'); newline >= 0 && newline+1 < len(tail) {
			tail = tail[newline+1:]
		}
	}
	if err := os.WriteFile(path, tail, 0o600); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

func cleanDiagnosticIdentifier(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 128 {
		value = value[:128]
	}
	for _, char := range value {
		if !(char == '_' || char == '-' || char == '.' || char >= '0' && char <= '9' || char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z') {
			return ""
		}
	}
	return value
}

func cleanDiagnosticFields(fields map[string]any) map[string]any {
	if len(fields) == 0 {
		return nil
	}
	clean := make(map[string]any)
	for key, value := range fields {
		if _, allowed := diagnosticFields[key]; !allowed || IsSensitiveName(key) {
			continue
		}
		switch typed := value.(type) {
		case string:
			clean[key] = cleanDiagnosticString(typed)
		case bool, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64:
			clean[key] = typed
		}
	}
	if len(clean) == 0 {
		return nil
	}
	return clean
}

func cleanDiagnosticString(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if filepath.IsAbs(value) {
		value = filepath.Base(value)
	}
	if parsed, err := url.Parse(value); err == nil && parsed.IsAbs() {
		parsed.User = nil
		parsed.Host = "[host]"
		parsed.RawQuery = ""
		parsed.Fragment = ""
		value = parsed.String()
	} else if host, port, err := net.SplitHostPort(value); err == nil {
		if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil && !ip.IsLoopback() {
			value = net.JoinHostPort("[ip]", port)
		}
	} else if ip := net.ParseIP(value); ip != nil && !ip.IsLoopback() {
		value = "[ip]"
	}
	value = SanitizeLogString(value)
	if len(value) > 512 {
		value = value[:512]
	}
	return value
}

func normalizeDiagnosticLevel(level string) string {
	switch strings.ToUpper(strings.TrimSpace(level)) {
	case "WARN", "WARNING":
		return "WARN"
	case "ERROR":
		return "ERROR"
	default:
		return "INFO"
	}
}

var _ io.Writer = (*rotatingDiagnosticWriter)(nil)
