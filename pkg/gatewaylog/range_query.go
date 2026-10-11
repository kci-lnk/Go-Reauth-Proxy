package gatewaylog

import (
	"container/heap"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// RangeQuery opts into timestamp ordering. Legacy single-day queries retain
// their segment-order cursor and do not need to scan the entire date range.
type RangeQuery struct {
	Date, From, To, Sort, Order                               string
	Search, Status, LoggedIn, Credential, ClientIP, WAFStatus string
	Cursor, Pagination                                        string
	Page, Limit                                               int
}
type rangeFile struct {
	Name     string
	Size     int64
	Boundary string
}
type rangePosition struct {
	Valid   bool
	Seconds int64
	Nanos   int
	Name    string
	Offset  int64
	Length  int
}
type rangeCursor struct {
	Version int
	Query   string
	Files   []rangeFile
	After   *rangePosition
}

func expiredRangeCursor() error { return fmt.Errorf("log cursor expired; refresh the log list") }

func normalizeRangeQuery(q RangeQuery) (RangeQuery, error) {
	if q.From != "" || q.To != "" {
		if q.Date != "" || q.From == "" || q.To == "" {
			return q, fmt.Errorf("from and to must be supplied together without date")
		}
	} else {
		date, err := normalizeDate(q.Date)
		if err != nil {
			return q, err
		}
		q.From, q.To = date, date
	}
	from, err := time.Parse(dateLayout, q.From)
	if err != nil {
		return q, fmt.Errorf("invalid from date")
	}
	to, err := time.Parse(dateLayout, q.To)
	if err != nil {
		return q, fmt.Errorf("invalid to date")
	}
	if to.Before(from) || to.Sub(from) >= 30*24*time.Hour {
		return q, fmt.Errorf("date range must contain 1 to 30 days")
	}
	if q.Sort != "" && q.Sort != "time" {
		return q, fmt.Errorf("invalid sort")
	}
	q.Sort = "time"
	if q.Order == "" {
		q.Order = "desc"
	}
	if q.Order != "asc" && q.Order != "desc" {
		return q, fmt.Errorf("invalid order")
	}
	if q.ClientIP != "" && q.ClientIP != "unknown" {
		if _, err := netip.ParseAddr(q.ClientIP); err != nil {
			return q, fmt.Errorf("invalid client_ip")
		}
	}
	if q.WAFStatus != "" && q.WAFStatus != "has_waf" && q.WAFStatus != "none" {
		return q, fmt.Errorf("invalid waf_status")
	}

	if q.Limit <= 0 {
		q.Limit = 20
	}
	if q.Limit > 200 {
		q.Limit = 200
	}
	// Timestamp queries use cursors; page 1 is accepted for old API consumers.
	if q.Page > 1 && q.Cursor == "" {
		return q, fmt.Errorf("timestamp queries require cursor pagination")
	}
	return q, nil
}

// The administration API treats IPv6 loopback as the IPv4 loopback identity.
func canonicalRangeIP(value string) string {
	ip := normalizeAnalyticsIP(value)
	if ip == "::1" {
		return "127.0.0.1"
	}
	return ip
}

// Apply IP and WAF filters before selecting the page; otherwise sparse matches
// would require repeated full-range scans in the administration service.
func matchesRangeFilters(entry Entry, q RangeQuery) bool {
	if q.ClientIP != "" {
		actual := canonicalRangeIP(EffectiveClientIP(entry))
		if q.ClientIP == "unknown" {
			if actual != "" {
				return false
			}
		} else if actual != canonicalRangeIP(q.ClientIP) {
			return false
		}
	}
	waf := entry.WAFTraceID != "" || entry.WAFBundle != "" || entry.WAFAction != "" || entry.WAFBlocked || len(entry.WAFRuleIDs) > 0
	return q.WAFStatus == "" || q.WAFStatus == "has_waf" && waf || q.WAFStatus == "none" && !waf
}

func rangeQueryKey(q RangeQuery) string {
	data, _ := json.Marshal([]string{q.From, q.To, q.Sort, q.Order, q.Search, q.Status, q.LoggedIn, q.Credential, q.ClientIP, q.WAFStatus})
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
func encodeRangeCursor(c rangeCursor) string {
	data, _ := json.Marshal(c)
	return "r1." + base64.RawURLEncoding.EncodeToString(data)
}
func decodeRangeCursor(value, key string) (rangeCursor, error) {
	var c rangeCursor
	if len(value) > 256*1024 || len(value) < 3 || value[:3] != "r1." {
		return c, expiredRangeCursor()
	}
	data, err := base64.RawURLEncoding.DecodeString(value[3:])
	if err != nil {
		return c, expiredRangeCursor()
	}
	if json.Unmarshal(data, &c) != nil || c.Version != 1 || c.Query != key {
		return c, expiredRangeCursor()
	}
	return c, nil
}

// Only metadata is kept in the heap, not potentially large request bodies.
// Invalid timestamps always follow valid timestamps in either direction.
func rangeBefore(a, b rangePosition, asc bool) bool {
	if a.Valid != b.Valid {
		return a.Valid
	}
	cmp := 0
	switch {
	case a.Seconds < b.Seconds:
		cmp = -1
	case a.Seconds > b.Seconds:
		cmp = 1
	case a.Nanos < b.Nanos:
		cmp = -1
	case a.Nanos > b.Nanos:
		cmp = 1
	case a.Name < b.Name:
		cmp = -1
	case a.Name > b.Name:
		cmp = 1
	case a.Offset < b.Offset:
		cmp = -1
	case a.Offset > b.Offset:
		cmp = 1
	}
	if asc {
		return cmp < 0
	}
	return cmp > 0
}

type rangeHeap struct {
	items []rangePosition
	asc   bool
}

func (h rangeHeap) Len() int           { return len(h.items) }
func (h rangeHeap) Less(i, j int) bool { return rangeBefore(h.items[j], h.items[i], h.asc) }
func (h rangeHeap) Swap(i, j int)      { h.items[i], h.items[j] = h.items[j], h.items[i] }
func (h *rangeHeap) Push(v any)        { h.items = append(h.items, v.(rangePosition)) }
func (h *rangeHeap) Pop() any {
	n := len(h.items)
	v := h.items[n-1]
	h.items = h.items[:n-1]
	return v
}

func rangeBoundary(file *os.File, size int64) (string, error) {
	start := size - 256
	if start < 0 {
		start = 0
	}
	data := make([]byte, size-start)
	if _, err := file.ReadAt(data, start); err != nil && err != io.EOF {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// Snapshot under the writer lock, then release it before the expensive scan.
// Each later access is restricted to enumerated segments and the captured size.
func (m *Manager) rangeSnapshot(ctx context.Context, q RangeQuery) (rangeCursor, []string, error) {
	if err := m.writer.lockContext(ctx); err != nil {
		return rangeCursor{}, nil, err
	}
	defer m.writer.mu.Unlock()
	if m.writer.currentBuffer != nil {
		if err := m.writer.flushLocked(); err != nil {
			return rangeCursor{}, nil, err
		}
	}
	dates, err := m.listDates(true)
	if err != nil {
		return rangeCursor{}, nil, err
	}
	segments, err := listLogSegments(m.logsDir)
	if err != nil {
		return rangeCursor{}, nil, err
	}
	c := rangeCursor{Version: 1, Query: rangeQueryKey(q), Files: []rangeFile{}}
	catalog := map[string]logSegment{}
	for _, s := range segments {
		if s.date >= q.From && s.date <= q.To {
			catalog[filepath.Base(s.path)] = s
		}
	}
	if q.Cursor != "" {
		c, err = decodeRangeCursor(q.Cursor, c.Query)
		if err != nil {
			return c, nil, err
		}
	} else {
		for _, s := range segments {
			if _, ok := catalog[filepath.Base(s.path)]; ok {
				c.Files = append(c.Files, rangeFile{Name: filepath.Base(s.path), Size: s.size})
			}
		}
	}
	seen := map[string]bool{}
	for i := range c.Files {
		f := &c.Files[i]
		s, ok := catalog[f.Name]
		if !ok || seen[f.Name] || f.Size < 0 {
			return c, nil, expiredRangeCursor()
		}
		seen[f.Name] = true
		file, err := os.Open(s.path)
		if err != nil {
			return c, nil, expiredRangeCursor()
		}
		info, statErr := file.Stat()
		if statErr != nil || info.Size() < f.Size {
			file.Close()
			return c, nil, expiredRangeCursor()
		}
		boundary, err := rangeBoundary(file, f.Size)
		file.Close()
		if err != nil {
			return c, nil, err
		}
		if q.Cursor != "" && boundary != f.Boundary {
			return c, nil, expiredRangeCursor()
		}
		f.Boundary = boundary
	}
	return c, dates, nil
}
func (m *Manager) QueryRangeContext(ctx context.Context, query RangeQuery) (QueryResult, error) {
	q, err := normalizeRangeQuery(query)
	if err != nil {
		return QueryResult{}, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err = m.directoryMu.RLockContext(ctx); err != nil {
		return QueryResult{}, err
	}
	defer m.directoryMu.RUnlock()
	release, err := m.acquireQuery(ctx)
	if err != nil {
		return QueryResult{}, err
	}
	defer release()
	if err = m.FlushContext(ctx); err != nil {
		return QueryResult{}, err
	}
	c, dates, err := m.rangeSnapshot(ctx, q)
	if err != nil {
		return QueryResult{}, err
	}
	initial := encodeRangeCursor(c)
	filter, err := newQueryFilter(q.Search, q.Status, q.LoggedIn, q.Credential)
	if err != nil {
		return QueryResult{}, err
	}
	filter.ctx = ctx
	candidates := &rangeHeap{asc: q.Order == "asc"}
	for _, s := range c.Files {
		file, err := os.Open(filepath.Join(m.logsDir, s.Name))
		if err != nil {
			return QueryResult{}, expiredRangeCursor()
		}
		err = scanLinesBackwardContext(ctx, file, s.Size, func(line []byte, pos int64) (bool, error) {
			if !filter.matchLineBytes(line) || !jsonLogLineLooksLikeEntryObject(line) || !filter.matchRawEntryFields(line) {
				return true, nil
			}
			var entry Entry
			if json.Unmarshal(line, &entry) != nil || !filter.matchEntry(entry) || !matchesRangeFilters(entry, q) {
				return true, nil
			}
			p := rangePosition{Name: s.Name, Offset: pos, Length: len(line)}
			if parsed, e := time.Parse(time.RFC3339Nano, entry.Time); e == nil {
				p.Valid = true
				p.Seconds = parsed.Unix()
				p.Nanos = parsed.Nanosecond()
			}
			if c.After != nil && !rangeBefore(*c.After, p, candidates.asc) {
				return true, nil
			}
			if candidates.Len() < q.Limit+1 {
				heap.Push(candidates, p)
			} else if rangeBefore(p, candidates.items[0], candidates.asc) {
				heap.Pop(candidates)
				heap.Push(candidates, p)
			}
			return true, nil
		})
		file.Close()
		if err != nil {
			return QueryResult{}, err
		}
	}
	sort.Slice(candidates.items, func(i, j int) bool { return rangeBefore(candidates.items[i], candidates.items[j], candidates.asc) })
	more := candidates.Len() > q.Limit
	if more {
		candidates.items = candidates.items[:q.Limit]
	}
	items := make([]Entry, 0, len(candidates.items))
	size := 0
	for _, p := range candidates.items {
		if err := ctx.Err(); err != nil {
			return QueryResult{}, err
		}
		file, err := os.Open(filepath.Join(m.logsDir, p.Name))
		if err != nil {
			return QueryResult{}, expiredRangeCursor()
		}
		line := make([]byte, p.Length)
		_, err = file.ReadAt(line, p.Offset)
		file.Close()
		if err != nil {
			return QueryResult{}, expiredRangeCursor()
		}
		var entry Entry
		if json.Unmarshal(line, &entry) != nil {
			return QueryResult{}, expiredRangeCursor()
		}
		size += queryEntryFootprint(entry, len(line))
		if size > queryResultMaxBytes {
			return QueryResult{}, ErrQueryResultTooLarge
		}
		items = append(items, entry)
	}
	// Revalidate the snapshot after scanning, so concurrent retention/deletion
	// cannot turn a complete response into silently missing records.
	verify := q
	verify.Cursor = initial
	if _, _, err = m.rangeSnapshot(ctx, verify); err != nil {
		return QueryResult{}, err
	}
	next := ""
	if more {
		last := candidates.items[len(candidates.items)-1]
		c.After = &last
		next = encodeRangeCursor(c)
	}
	date := ""
	if q.From == q.To {
		date = q.From
	}
	return QueryResult{From: q.From, To: q.To, Date: date, LogsDir: m.logsDir, AvailableDates: dates, Pagination: "cursor", Page: 1, Limit: q.Limit, Cursor: initial, NextCursor: next, HasMore: more, Items: items}, nil
}
