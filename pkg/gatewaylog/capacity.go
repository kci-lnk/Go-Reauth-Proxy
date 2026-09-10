package gatewaylog

import (
	"bufio"
	"errors"
	"fmt"
	"go-reauth-proxy/pkg/models"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// All catalog and writer mutations hold DailyFileWriter.mu. Sizes include buffered bytes.
type logSegment struct {
	path, date string
	size       int64
}
type logStorageStatus struct {
	today, total int64
	error        string
}

func (w *DailyFileWriter) setCapacityLocked(cfg models.LoggingConfig) {
	w.dailyLimit = cfg.MaxDailySizeMB << 20
	w.totalLimit = cfg.MaxTotalSizeMB << 20
	w.segmentLimit = min(int64(16<<20), w.dailyLimit, w.totalLimit)
}

func listLogSegments(dir string) ([]logSegment, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	result := make([]logSegment, 0, len(entries))
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			continue
		}
		date, ok := parseFileDate(entry.Name())
		if !ok {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return nil, err
		}
		result = append(result, logSegment{filepath.Join(dir, entry.Name()), date.Format(dateLayout), info.Size()})
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].date != result[j].date {
			return result[i].date < result[j].date
		}
		// Legacy date.log precedes numbered segments.
		a, b := filepath.Base(result[i].path), filepath.Base(result[j].path)
		if len(a) == 14 || len(b) == 14 {
			return len(a) < len(b)
		}
		return a < b
	})
	return result, nil
}

func (w *DailyFileWriter) indexLocked() error {
	if w.indexed {
		return nil
	}
	if w.currentBuffer != nil {
		if err := w.currentBuffer.Flush(); err != nil {
			return err
		}
	}
	files, err := listLogSegments(w.baseDir)
	if err != nil {
		return err
	}
	w.segments = files
	// Interrupted compaction never replaces the source until its temporary
	// file is complete. Stale temporary files can therefore be removed safely.
	entries, err := os.ReadDir(w.baseDir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, entry := range entries {
		if entry.Type().IsRegular() && strings.HasPrefix(entry.Name(), ".gateway-log-compact-") {
			if err := os.Remove(filepath.Join(w.baseDir, entry.Name())); err != nil {
				return err
			}
		}
	}
	for _, file := range files {
		name := filepath.Base(file.path)
		if len(name) > 14 {
			if ordinal, err := strconv.ParseInt(name[11:31], 10, 64); err == nil {
				w.sequence = max(w.sequence, ordinal)
			}
		}
	}
	w.segments = files
	w.indexed = true
	return nil
}

func (w *DailyFileWriter) closeSegmentLocked() error {
	if w.currentBuffer != nil {
		if err := w.currentBuffer.Flush(); err != nil {
			return err
		}
		w.currentBuffer = nil
	}
	if w.currentFile != nil {
		if err := w.currentFile.Close(); err != nil {
			return err
		}
		w.currentFile = nil
	}
	return nil
}

func (w *DailyFileWriter) openSegmentLocked(now time.Time, force bool) error {
	if err := w.ensureDirLocked(); err != nil {
		return err
	}
	if err := w.indexLocked(); err != nil {
		return err
	}
	date := now.Format(dateLayout)
	if !force && w.currentFile != nil && w.currentDate == date {
		return nil
	}
	if err := w.closeSegmentLocked(); err != nil {
		return err
	}
	path := ""
	if !force && len(w.segments) > 0 {
		last := w.segments[len(w.segments)-1]
		if last.date == date && last.size < w.segmentLimit && len(filepath.Base(last.path)) > 14 {
			path = last.path
		}
	}
	if path == "" {
		w.sequence = max(w.sequence+1, now.UnixNano())
		path = filepath.Join(w.baseDir, fmt.Sprintf("%s.%020d.log", date, w.sequence))
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		w.currentFile = file
		w.segments = append(w.segments, logSegment{path, date, 0})
		sort.SliceStable(w.segments, func(i, j int) bool { return w.segments[i].date < w.segments[j].date })
	} else {
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return err
		}
		w.currentFile = file
	}
	w.currentBuffer = bufio.NewWriterSize(w.currentFile, asyncLogWriterBufferSize)
	w.currentDate = date
	w.currentDay = dayStart(now)
	w.nextDay = w.currentDay.AddDate(0, 0, 1)
	return nil
}

func (w *DailyFileWriter) removeSegmentLocked(i int) error {
	segment := w.segments[i]
	if w.currentFile != nil && w.currentFile.Name() == segment.path {
		// These records are being intentionally evicted. Flushing them first
		// requires free disk space precisely when eviction is meant to free it.
		w.currentBuffer = nil
		file := w.currentFile
		w.currentFile = nil
		if err := file.Close(); err != nil {
			return err
		}
	}
	if err := os.Remove(segment.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	w.segments = append(w.segments[:i], w.segments[i+1:]...)
	return nil
}

// Old monolithic files and segments larger than a reduced quota are compacted
// to their latest complete records. Temporary disk and memory stay <= one segment.
func (w *DailyFileWriter) compactSegmentLocked(i int) error {
	segment := &w.segments[i]
	if w.currentFile != nil && w.currentFile.Name() == segment.path {
		if err := w.closeSegmentLocked(); err != nil {
			return err
		}
	}
	file, err := os.Open(segment.path)
	if err != nil {
		return err
	}
	defer file.Close()
	start := max(int64(0), segment.size-w.segmentLimit)
	reader := bufio.NewReader(io.NewSectionReader(file, start, segment.size-start))
	if start > 0 {
		var previous [1]byte
		if _, err := file.ReadAt(previous[:], start-1); err != nil {
			return err
		}
		if previous[0] != '\n' {
			for {
				_, err := reader.ReadSlice('\n')
				if err == bufio.ErrBufferFull {
					continue
				}
				if err != nil && err != io.EOF {
					return err
				}
				break
			}
		}
	}
	tmp, err := os.CreateTemp(w.baseDir, ".gateway-log-compact-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	if err := tmp.Chmod(0o644); err != nil {
		return err
	}
	// Copy only complete lines, without allocating a potentially huge record.
	n, err := io.Copy(tmp, reader)
	if err != nil {
		return err
	}
	if n > 0 {
		end := n
		buffer := make([]byte, 64*1024)
		found := false
		for end > 0 && !found {
			count := min(int64(len(buffer)), end)
			if _, err := tmp.ReadAt(buffer[:count], end-count); err != nil {
				return err
			}
			for j := int(count) - 1; j >= 0; j-- {
				if buffer[j] == '\n' {
					n = end - count + int64(j) + 1
					found = true
					break
				}
			}
			end -= count
		}
		if !found {
			n = 0
		}
		if err := tmp.Truncate(n); err != nil {
			return err
		}
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	// Use a fresh identity: existing cursors must not address replacement bytes.
	w.sequence = max(w.sequence+1, time.Now().UnixNano())
	ordinal := "00000000000000000000"
	if name := filepath.Base(segment.path); len(name) > 14 {
		ordinal = name[11:31]
	}
	target := filepath.Join(w.baseDir, fmt.Sprintf("%s.%s-%020d.log", segment.date, ordinal, w.sequence))
	if err := os.Rename(tmp.Name(), segment.path); err != nil {
		return err
	}
	if err := os.Rename(segment.path, target); err != nil {
		w.indexed = false
		return err
	}
	segment.path = target
	segment.size = n
	return nil
}

func (w *DailyFileWriter) enforceCapacityLocked(now time.Time, date string, incoming int64) error {
	if err := w.indexLocked(); err != nil {
		return err
	}
	cutoff := dayStart(now).AddDate(0, 0, -(normalizeMaxDays(w.retentionDays) - 1)).Format(dateLayout)
	for i := 0; i < len(w.segments); {
		if w.segments[i].date < cutoff {
			if err := w.removeSegmentLocked(i); err != nil {
				return err
			}
			continue
		}
		// Compact old large files only when they violate a quota. Regular rotation
		// does not rewrite historical records merely because they exceed shard size.
		if w.segments[i].size > min(w.dailyLimit, w.totalLimit) {
			if err := w.compactSegmentLocked(i); err != nil {
				return err
			}
		}
		i++
	}
	totals := map[string]int64{}
	total := incoming
	for _, s := range w.segments {
		totals[s.date] += s.size
		total += s.size
	}
	totals[date] += incoming
	// First enforce each day's quota, then the overall quota. A busy day
	// must not evict unrelated days unnecessarily.
	for i := 0; i < len(w.segments); {
		s := w.segments[i]
		if totals[s.date] > w.dailyLimit {
			if err := w.removeSegmentLocked(i); err != nil {
				return err
			}
			totals[s.date] -= s.size
			total -= s.size
		} else {
			i++
		}
	}
	for total > w.totalLimit && len(w.segments) > 0 {
		size := w.segments[0].size
		if err := w.removeSegmentLocked(0); err != nil {
			return err
		}
		total -= size
	}
	return nil
}

func (w *DailyFileWriter) prepareWriteLocked(now time.Time, incoming int64) error {
	if incoming > w.segmentLimit || incoming >= maxScanToken {
		return fmt.Errorf("request log entry exceeds segment capacity")
	}
	if err := w.enforceCapacityLocked(now, now.Format(dateLayout), incoming); err != nil {
		return err
	}
	if err := w.openSegmentLocked(now, false); err != nil {
		return err
	}
	for _, s := range w.segments {
		if s.path == w.currentFile.Name() && s.size+incoming > w.segmentLimit {
			return w.openSegmentLocked(now, true)
		}
	}
	return nil
}

func (w *DailyFileWriter) publishStorageStatus(err error) {
	status := &logStorageStatus{}
	today := time.Now().Format(dateLayout)
	for _, s := range w.segments {
		status.total += s.size
		if s.date == today {
			status.today += s.size
		}
	}
	if err != nil {
		status.error = err.Error()
	}
	w.storageStatus.Store(status)
}
