package gatewaylog

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func segmentsForDate(dir, date string) ([]logSegment, error) {
	all, err := listLogSegments(dir)
	if err != nil {
		return nil, err
	}
	result := make([]logSegment, 0)
	for _, s := range all {
		if s.date == date {
			result = append(result, s)
		}
	}
	return result, nil
}

// Cursor identity is an immutable segment name plus a byte offset. No user
// supplied name is ever opened: it must match the enumerated day catalog.
func querySegmentEntries(dir, date string, filter queryFilter, cursor string, page, limit int, mode string) ([]Entry, int, string, bool, error) {
	files, err := segmentsForDate(dir, date)
	if err != nil {
		return nil, 0, "", false, err
	}
	start := len(files) - 1
	offset := int64(-1)
	if mode == "cursor" && cursor != "" {
		name, raw, ok := strings.Cut(cursor, ":")
		if !ok {
			name = date + fileExtension
			raw = cursor
		}
		start = -1
		for i, s := range files {
			if filepath.Base(s.path) == name {
				start = i
				break
			}
		}
		if start < 0 {
			return nil, 0, "", false, fmt.Errorf("log cursor expired; refresh the log list")
		}
		offset, err = strconv.ParseInt(raw, 10, 64)
		if err != nil || offset < 0 || offset > files[start].size {
			return nil, 0, "", false, fmt.Errorf("log cursor expired; refresh the log list")
		}
	}
	items := make([]Entry, 0, limit)
	total := 0
	size := 0
	next := ""
	hasMore := false
	skip := int64(0)
	if mode != "cursor" {
		if page > 0 && int64(page-1) <= int64(^uint64(0)>>1)/int64(limit) {
			skip = int64(page-1) * int64(limit)
		} else {
			skip = int64(^uint64(0) >> 1)
		}
	}
	for i := start; i >= 0; i-- {
		s := files[i]
		file, err := os.Open(s.path)
		if err != nil {
			return nil, 0, "", false, err
		}
		end := s.size
		if i == start && offset >= 0 {
			end = offset
		}
		err = scanLinesBackwardContext(filter.ctx, file, end, func(line []byte, pos int64) (bool, error) {
			if !filter.matchLineBytes(line) || !jsonLogLineLooksLikeEntryObject(line) || !filter.matchRawEntryFields(line) {
				return true, nil
			}
			var entry Entry
			if json.Unmarshal(line, &entry) != nil || !filter.matchEntry(entry) {
				return true, nil
			}
			total++
			if mode == "cursor" && len(items) == limit {
				hasMore = true
				return false, errStopScan
			}
			if int64(total) <= skip || len(items) == limit {
				return true, nil
			}
			size += queryEntryFootprint(entry, len(line))
			if size > queryResultMaxBytes {
				return false, ErrQueryResultTooLarge
			}
			items = append(items, entry)
			next = filepath.Base(s.path) + ":" + strconv.FormatInt(pos, 10)
			return true, nil
		})
		_ = file.Close()
		if err == errStopScan {
			break
		}
		if err != nil {
			return nil, 0, "", false, err
		}
	}
	if mode != "cursor" {
		hasMore = int64(total) > skip+int64(len(items))
		next = ""
	} else if !hasMore {
		next = ""
	}
	return items, total, next, hasMore, nil
}

func (m *Manager) analyticsForSegments(ctx context.Context, date string) (*dailyAnalytics, error) {
	select {
	case m.analyticsScan <- struct{}{}:
		defer func() { <-m.analyticsScan }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	// Hold the writer lock for a consistent file set. This is off the proxy path;
	// the bounded async queue continues to protect forwarding from slow disks.
	if err := m.writer.lockContext(ctx); err != nil {
		return nil, err
	}
	defer m.writer.mu.Unlock()
	if m.writer.currentBuffer != nil {
		if err := m.writer.flushLocked(); err != nil {
			return nil, err
		}
	}
	files, err := segmentsForDate(m.logsDir, date)
	if err != nil {
		return nil, err
	}
	fingerprint := ""
	var totalSize int64
	modified := make([]int64, 0, len(files))
	for _, s := range files {
		info, err := os.Stat(s.path)
		if err != nil {
			return nil, err
		}
		totalSize += info.Size()
		modified = append(modified, info.ModTime().UnixNano())
		fingerprint += fmt.Sprintf("%s:%d:%d;", filepath.Base(s.path), info.Size(), info.ModTime().UnixNano())
	}
	m.analyticsMu.Lock()
	cached, ok := m.analyticsCache[date]
	m.analyticsMu.Unlock()
	if ok && cached.fingerprint == fingerprint && cached.data != nil {
		return cached.data, nil
	}
	data := &dailyAnalytics{analyticsCounter: newAnalyticsCounter()}
	incremental := ok && cached.data != nil && len(cached.segments) > 0 && len(files) >= len(cached.segments)
	if incremental {
		for i, old := range cached.segments {
			if old.path != files[i].path || old.size > files[i].size || (i < len(cached.segments)-1 && (old.size != files[i].size || cached.modified[i] != modified[i])) || (old.size == files[i].size && cached.modified[i] != modified[i]) {
				incremental = false
				break
			}
		}
	}
	if incremental {
		data = cloneDailyAnalytics(cached.data)
	}
	for i, s := range files {
		start := int64(0)
		if incremental && i < len(cached.segments) {
			start = cached.segments[i].size
		}
		if start == s.size {
			continue
		}
		if err := scanDailyAnalyticsRange(ctx, s.path, date, start, s.size, data); err != nil {
			return nil, err
		}
	}
	m.analyticsMu.Lock()
	m.analyticsCache[date] = cachedDailyAnalytics{data: data, fingerprint: fingerprint, size: totalSize, segments: files, modified: modified}
	m.enforceAnalyticsCacheLimitLocked(date)
	m.analyticsMu.Unlock()
	return data, nil
}
