package proxy

import (
	"fmt"
	"go-reauth-proxy/pkg/config"
	"go-reauth-proxy/pkg/logger"
	"go-reauth-proxy/pkg/models"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

type generalBlacklistRuntime struct {
	mu      sync.RWMutex
	config  models.GeneralBlacklistConfig
	records map[string]models.GeneralBlacklistRecord
}

func newGeneralBlacklistRuntime(cfg models.GeneralBlacklistConfig) *generalBlacklistRuntime {
	runtime := &generalBlacklistRuntime{
		records: make(map[string]models.GeneralBlacklistRecord),
	}
	runtime.updateConfig(cfg)
	return runtime
}

func (r *generalBlacklistRuntime) getConfig() models.GeneralBlacklistConfig {
	if r == nil {
		return models.GeneralBlacklistConfig{Items: []models.GeneralBlacklistRecord{}}
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	items := make([]models.GeneralBlacklistRecord, len(r.config.Items))
	copy(items, r.config.Items)
	return models.GeneralBlacklistConfig{Items: items}
}

func (r *generalBlacklistRuntime) updateConfig(cfg models.GeneralBlacklistConfig) models.GeneralBlacklistConfig {
	normalized, records := normalizeGeneralBlacklistConfig(cfg)

	r.mu.Lock()
	r.config = normalized
	r.records = records
	r.mu.Unlock()

	return normalized
}

func (r *generalBlacklistRuntime) contains(clientIP string) (models.GeneralBlacklistRecord, bool) {
	normalizedIP, _, ok := normalizeGeneralBlacklistIP(clientIP)
	if !ok || r == nil {
		return models.GeneralBlacklistRecord{}, false
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	record, exists := r.records[normalizedIP]
	return record, exists
}

func (r *generalBlacklistRuntime) list(page int, limit int, search string) models.GeneralBlacklistList {
	if r == nil {
		return models.GeneralBlacklistList{Items: []models.GeneralBlacklistRecord{}}
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

	needle := strings.TrimSpace(search)
	r.mu.RLock()
	items := make([]models.GeneralBlacklistRecord, 0, len(r.config.Items))
	for _, item := range r.config.Items {
		if needle == "" || generalBlacklistRecordMatches(item, needle) {
			items = append(items, item)
		}
	}
	r.mu.RUnlock()

	sortGeneralBlacklistRecords(items)
	total := len(items)
	start := (page - 1) * limit
	if start >= total {
		return models.GeneralBlacklistList{Total: total, Items: []models.GeneralBlacklistRecord{}}
	}
	end := start + limit
	if end > total {
		end = total
	}

	pageItems := make([]models.GeneralBlacklistRecord, end-start)
	copy(pageItems, items[start:end])
	return models.GeneralBlacklistList{Total: total, Items: pageItems}
}

func (r *generalBlacklistRuntime) status(ips []string) (models.GeneralBlacklistStatus, error) {
	normalizedIPs := normalizeGeneralBlacklistIPListForStatus(ips)
	status := models.GeneralBlacklistStatus{
		Records: make(map[string]models.GeneralBlacklistRecord),
	}
	if len(normalizedIPs) == 0 || r == nil {
		return status, nil
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, ip := range normalizedIPs {
		if record, exists := r.records[ip]; exists {
			status.Records[ip] = record
		}
	}
	return status, nil
}

func (r *generalBlacklistRuntime) addMany(ips []string, source string, comment string, now time.Time) (models.GeneralBlacklistConfig, models.GeneralBlacklistMutationResult, error) {
	normalizedIPs, err := normalizeGeneralBlacklistIPList(ips)
	if err != nil {
		return models.GeneralBlacklistConfig{}, models.GeneralBlacklistMutationResult{}, err
	}
	if len(normalizedIPs) == 0 {
		return models.GeneralBlacklistConfig{}, models.GeneralBlacklistMutationResult{}, fmt.Errorf("at least one IP is required")
	}
	if now.IsZero() {
		now = time.Now()
	}

	nextSource := normalizeGeneralBlacklistSource(source)
	nextComment := strings.TrimSpace(comment)
	nowText := now.UTC().Format(time.RFC3339Nano)

	r.mu.Lock()
	defer r.mu.Unlock()

	current := make(map[string]models.GeneralBlacklistRecord, len(r.records)+len(normalizedIPs))
	for ip, record := range r.records {
		current[ip] = record
	}

	added := 0
	updated := 0
	for _, ip := range normalizedIPs {
		record, exists := current[ip]
		if !exists {
			record = models.GeneralBlacklistRecord{
				IP:        ip,
				CreatedAt: nowText,
			}
			added++
		} else {
			updated++
		}
		record.IP = ip
		record.Source = nextSource
		record.Comment = nextComment
		if strings.TrimSpace(record.CreatedAt) == "" {
			record.CreatedAt = nowText
		}
		record.UpdatedAt = nowText
		current[ip] = record
	}

	items := recordsMapToSortedGeneralBlacklistItems(current)
	normalized := models.GeneralBlacklistConfig{Items: items}
	r.config = normalized
	r.records = current

	resultItems := make([]models.GeneralBlacklistRecord, 0, len(normalizedIPs))
	for _, ip := range normalizedIPs {
		if record, exists := current[ip]; exists {
			resultItems = append(resultItems, record)
		}
	}
	sortGeneralBlacklistRecords(resultItems)

	return normalized, models.GeneralBlacklistMutationResult{
		Added:   added,
		Updated: updated,
		Total:   len(items),
		Items:   resultItems,
	}, nil
}

func (r *generalBlacklistRuntime) removeMany(ips []string) (models.GeneralBlacklistConfig, models.GeneralBlacklistMutationResult, error) {
	normalizedIPs, err := normalizeGeneralBlacklistIPList(ips)
	if err != nil {
		return models.GeneralBlacklistConfig{}, models.GeneralBlacklistMutationResult{}, err
	}
	if len(normalizedIPs) == 0 {
		return models.GeneralBlacklistConfig{}, models.GeneralBlacklistMutationResult{}, fmt.Errorf("at least one IP is required")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	current := make(map[string]models.GeneralBlacklistRecord, len(r.records))
	for ip, record := range r.records {
		current[ip] = record
	}

	removed := 0
	for _, ip := range normalizedIPs {
		if _, exists := current[ip]; exists {
			delete(current, ip)
			removed++
		}
	}

	items := recordsMapToSortedGeneralBlacklistItems(current)
	normalized := models.GeneralBlacklistConfig{Items: items}
	r.config = normalized
	r.records = current

	return normalized, models.GeneralBlacklistMutationResult{
		Removed: removed,
		Total:   len(items),
		Items:   []models.GeneralBlacklistRecord{},
	}, nil
}

func normalizeGeneralBlacklistConfig(cfg models.GeneralBlacklistConfig) (models.GeneralBlacklistConfig, map[string]models.GeneralBlacklistRecord) {
	records := make(map[string]models.GeneralBlacklistRecord, len(cfg.Items))
	for _, raw := range cfg.Items {
		ip, _, ok := normalizeGeneralBlacklistIP(raw.IP)
		if !ok {
			continue
		}
		record := models.GeneralBlacklistRecord{
			IP:        ip,
			Source:    normalizeGeneralBlacklistSource(raw.Source),
			Comment:   strings.TrimSpace(raw.Comment),
			CreatedAt: strings.TrimSpace(raw.CreatedAt),
			UpdatedAt: strings.TrimSpace(raw.UpdatedAt),
		}
		if record.CreatedAt == "" {
			record.CreatedAt = record.UpdatedAt
		}
		if record.UpdatedAt == "" {
			record.UpdatedAt = record.CreatedAt
		}
		records[ip] = record
	}

	return models.GeneralBlacklistConfig{
		Items: recordsMapToSortedGeneralBlacklistItems(records),
	}, records
}

func normalizeGeneralBlacklistIPListForStatus(ips []string) []string {
	seen := make(map[string]struct{}, len(ips))
	normalized := make([]string, 0, len(ips))
	for _, raw := range ips {
		ip, _, ok := normalizeGeneralBlacklistIP(raw)
		if !ok {
			continue
		}
		if _, exists := seen[ip]; exists {
			continue
		}
		seen[ip] = struct{}{}
		normalized = append(normalized, ip)
	}
	return normalized
}

func normalizeGeneralBlacklistIPList(ips []string) ([]string, error) {
	seen := make(map[string]struct{}, len(ips))
	normalized := make([]string, 0, len(ips))
	for _, raw := range ips {
		ip, _, ok := normalizeGeneralBlacklistIP(raw)
		if !ok {
			return nil, fmt.Errorf("invalid blacklist IP: %s", strings.TrimSpace(raw))
		}
		if _, exists := seen[ip]; exists {
			continue
		}
		seen[ip] = struct{}{}
		normalized = append(normalized, ip)
	}
	return normalized, nil
}

func normalizeGeneralBlacklistIP(value string) (string, netip.Addr, bool) {
	normalizedIP := normalizeIPAddress(value)
	if normalizedIP == "" {
		return "", netip.Addr{}, false
	}

	addr, err := netip.ParseAddr(normalizedIP)
	if err != nil || !addr.IsValid() || addr.IsLoopback() || addr.IsUnspecified() {
		return "", netip.Addr{}, false
	}

	return normalizedIP, addr, true
}

func normalizeGeneralBlacklistSource(value string) string {
	switch strings.TrimSpace(value) {
	case models.GeneralBlacklistSourceRequestLog:
		return models.GeneralBlacklistSourceRequestLog
	case models.GeneralBlacklistSourceActiveIP:
		return models.GeneralBlacklistSourceActiveIP
	case models.GeneralBlacklistSourceWAFRateLimit:
		return models.GeneralBlacklistSourceWAFRateLimit
	case models.GeneralBlacklistSourceWAFLog:
		return models.GeneralBlacklistSourceWAFLog
	default:
		return models.GeneralBlacklistSourceManual
	}
}

func recordsMapToSortedGeneralBlacklistItems(records map[string]models.GeneralBlacklistRecord) []models.GeneralBlacklistRecord {
	items := make([]models.GeneralBlacklistRecord, 0, len(records))
	for _, record := range records {
		items = append(items, record)
	}
	sortGeneralBlacklistRecords(items)
	return items
}

func sortGeneralBlacklistRecords(items []models.GeneralBlacklistRecord) {
	sort.SliceStable(items, func(i, j int) bool {
		leftTime := parseGeneralBlacklistTime(items[i].CreatedAt)
		rightTime := parseGeneralBlacklistTime(items[j].CreatedAt)
		if !leftTime.Equal(rightTime) {
			return leftTime.After(rightTime)
		}
		return items[i].IP < items[j].IP
	})
}

func parseGeneralBlacklistTime(value string) time.Time {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return time.Time{}
	}
	if parsed, err := time.Parse(time.RFC3339Nano, trimmed); err == nil {
		return parsed
	}
	if parsed, err := time.Parse(time.RFC3339, trimmed); err == nil {
		return parsed
	}
	return time.Time{}
}

func generalBlacklistRecordMatches(record models.GeneralBlacklistRecord, needle string) bool {
	return containsFoldString(record.IP, needle) ||
		containsFoldString(record.Source, needle) ||
		containsFoldString(record.Comment, needle)
}

func (h *Handler) ListGeneralBlacklist(page int, limit int, search string) models.GeneralBlacklistList {
	h.mu.RLock()
	runtime := h.generalBlacklist
	h.mu.RUnlock()

	if runtime == nil {
		return models.GeneralBlacklistList{Items: []models.GeneralBlacklistRecord{}}
	}
	return runtime.list(page, limit, search)
}

func (h *Handler) CheckGeneralBlacklist(ips []string) (models.GeneralBlacklistStatus, error) {
	h.mu.RLock()
	runtime := h.generalBlacklist
	h.mu.RUnlock()

	if runtime == nil {
		runtime = newGeneralBlacklistRuntime(models.GeneralBlacklistConfig{})
	}
	return runtime.status(ips)
}

func (h *Handler) GetGeneralBlacklist() models.GeneralBlacklistConfig {
	h.mu.RLock()
	runtime := h.generalBlacklist
	h.mu.RUnlock()

	if runtime == nil {
		return models.GeneralBlacklistConfig{Items: []models.GeneralBlacklistRecord{}}
	}
	return runtime.getConfig()
}

func (h *Handler) AddGeneralBlacklist(ips []string, source string, comment string) (models.GeneralBlacklistMutationResult, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.addGeneralBlacklistLocked(ips, source, comment)
}

func (h *Handler) addGeneralBlacklistLocked(ips []string, source string, comment string) (models.GeneralBlacklistMutationResult, error) {
	runtime := h.generalBlacklist
	if runtime == nil {
		runtime = newGeneralBlacklistRuntime(models.GeneralBlacklistConfig{})
		h.generalBlacklist = runtime
	}
	previousRuntime := runtime.getConfig()
	previousConfigured := h.GeneralBlacklist
	normalized, result, err := runtime.addMany(ips, source, comment, time.Now())
	if err != nil {
		return models.GeneralBlacklistMutationResult{}, err
	}

	h.GeneralBlacklist = normalized
	if err := h.saveConfigMutationLocked(func(conf *config.AppConfig) {
		conf.GeneralBlacklist = h.GeneralBlacklist
	}); err != nil {
		runtime.updateConfig(previousRuntime)
		h.GeneralBlacklist = previousConfigured
		return models.GeneralBlacklistMutationResult{}, err
	}

	if event := debugProxyEvent("general_blacklist_added", ""); event != nil {
		event.Int("added", result.Added).
			Int("updated", result.Updated).
			Int("total", result.Total).
			Str("source", logger.SanitizeLogString(normalizeGeneralBlacklistSource(source))).
			Send()
	}
	return result, nil
}

func (h *Handler) RemoveGeneralBlacklist(ips []string) (models.GeneralBlacklistMutationResult, error) {
	h.mu.Lock()
	runtime := h.generalBlacklist
	if runtime == nil {
		runtime = newGeneralBlacklistRuntime(models.GeneralBlacklistConfig{})
		h.generalBlacklist = runtime
	}
	previousRuntime := runtime.getConfig()
	previousConfigured := h.GeneralBlacklist
	normalized, result, err := runtime.removeMany(ips)
	if err != nil {
		h.mu.Unlock()
		return models.GeneralBlacklistMutationResult{}, err
	}

	h.GeneralBlacklist = normalized
	if err := h.saveConfigMutationLocked(func(conf *config.AppConfig) {
		conf.GeneralBlacklist = h.GeneralBlacklist
	}); err != nil {
		runtime.updateConfig(previousRuntime)
		h.GeneralBlacklist = previousConfigured
		h.mu.Unlock()
		return models.GeneralBlacklistMutationResult{}, err
	}
	h.wafViolationEpoch.Add(1)
	if h.wafViolationLimiter != nil {
		for _, raw := range ips {
			if ip, _, ok := normalizeGeneralBlacklistIP(raw); ok {
				h.wafViolationLimiter.remove(ip)
			}
		}
	}
	h.mu.Unlock()

	if event := debugProxyEvent("general_blacklist_removed", ""); event != nil {
		event.Int("removed", result.Removed).
			Int("total", result.Total).
			Send()
	}
	return result, nil
}
