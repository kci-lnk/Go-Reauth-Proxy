package waf

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	goruntime "runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/corazawaf/coraza/v3/types"

	"go-reauth-proxy/pkg/logger"
	"go-reauth-proxy/pkg/models"
)

var (
	traceFallbackCounter        atomic.Uint64
	runtimeMemoryReleasePending atomic.Bool
)

type Runtime struct {
	state           atomic.Pointer[runtimeState]
	lastError       atomic.Value
	events          *EventStore
	defaultRulesDir string
}

type runtimeState struct {
	config     models.WAFConfig
	compiled   *CompiledRuntime
	exclusions exclusionConfig
}

type exclusionConfig struct {
	disabledHosts        map[string]struct{}
	disabledPathPrefixes []string
}

// PreparedState is an immutable WAF candidate built without publishing it.
// CommitPrepared publishes the candidate after its owning configuration has
// been durably stored.
type PreparedState struct {
	config          models.WAFConfig
	compiled        *CompiledRuntime
	replaceCompiled bool
}

func (prepared PreparedState) Config() models.WAFConfig {
	return CopyConfig(prepared.config)
}

func NewRuntime(cfg models.WAFConfig, runtimeDir string) *Runtime {
	defaultRulesDir := DefaultRulesDir(runtimeDir)
	rt := &Runtime{
		events:          NewEventStore(DefaultMaxEvents, DefaultEventTTL),
		defaultRulesDir: defaultRulesDir,
	}
	rt.state.Store(newRuntimeState(NormalizeConfig(cfg, defaultRulesDir), nil))
	rt.lastError.Store("")
	return rt
}

func (rt *Runtime) Config() models.WAFConfig {
	if rt == nil {
		return NormalizeConfig(models.WAFConfig{}, DefaultRulesDir("."))
	}
	return CopyConfig(rt.snapshot().config)
}

func newRuntimeState(cfg models.WAFConfig, compiled *CompiledRuntime) *runtimeState {
	cfg = CopyConfig(cfg)
	return &runtimeState{
		config:     cfg,
		compiled:   compiled,
		exclusions: buildExclusionConfig(cfg),
	}
}

func (rt *Runtime) snapshot() *runtimeState {
	if rt == nil {
		return &runtimeState{}
	}
	if state := rt.state.Load(); state != nil {
		return state
	}
	return &runtimeState{}
}

func buildExclusionConfig(cfg models.WAFConfig) exclusionConfig {
	exclusions := exclusionConfig{
		disabledHosts:        make(map[string]struct{}, len(cfg.DisabledHosts)),
		disabledPathPrefixes: append([]string(nil), cfg.DisabledPathPrefixes...),
	}
	for _, disabledHost := range cfg.DisabledHosts {
		host := normalizeHost(disabledHost)
		if host != "" {
			exclusions.disabledHosts[host] = struct{}{}
		}
	}
	return exclusions
}

func (rt *Runtime) PrepareConfig(cfg models.WAFConfig) (PreparedState, error) {
	if rt == nil {
		return PreparedState{config: cfg}, nil
	}
	cfg = NormalizeConfig(cfg, rt.defaultRulesDir)
	if !IsActive(cfg) {
		return PreparedState{
			config:          cfg,
			replaceCompiled: true,
		}, nil
	}
	if rt.snapshot().compiled == nil {
		return PreparedState{config: cfg}, nil
	}
	compiled, err := buildCompiledRuntime(cfg, rt.defaultRulesDir, "", "")
	if err != nil {
		rt.lastError.Store(err.Error())
		return PreparedState{}, err
	}
	return PreparedState{
		config:          cfg,
		compiled:        compiled,
		replaceCompiled: true,
	}, nil
}

func (rt *Runtime) PrepareReload(
	cfg models.WAFConfig,
	bundleID string,
	bundlePath string,
) (PreparedState, error) {
	if rt == nil {
		return PreparedState{}, fmt.Errorf("WAF runtime is not initialized")
	}
	cfg = NormalizeConfig(cfg, rt.defaultRulesDir)
	if !IsActive(cfg) {
		return PreparedState{
			config:          cfg,
			replaceCompiled: true,
		}, nil
	}
	compiled, err := buildCompiledRuntime(cfg, rt.defaultRulesDir, bundleID, bundlePath)
	if err != nil {
		rt.lastError.Store(err.Error())
		return PreparedState{}, err
	}
	return PreparedState{
		config:          compiled.Config,
		compiled:        compiled,
		replaceCompiled: true,
	}, nil
}

func (rt *Runtime) CommitPrepared(prepared PreparedState) Status {
	if rt == nil {
		return Status{}
	}
	previous := rt.snapshot()
	compiled := previous.compiled
	if prepared.replaceCompiled {
		compiled = prepared.compiled
	}
	rt.state.Store(newRuntimeState(prepared.config, compiled))
	rt.lastError.Store("")
	if prepared.replaceCompiled && previous.compiled != nil {
		releaseRuntimeMemorySoon()
	}
	return rt.Status()
}

func (rt *Runtime) Status() Status {
	if rt == nil {
		return Status{}
	}
	snapshot := rt.snapshot()
	cfg := snapshot.config
	status := Status{
		Enabled:       cfg.Enabled,
		Mode:          cfg.Mode,
		RulesDir:      cfg.RulesDir,
		PendingEvents: rt.events.Pending(),
	}
	if lastError, _ := rt.lastError.Load().(string); lastError != "" {
		status.LastError = lastError
	}
	if current := snapshot.compiled; current != nil {
		status.Loaded = true
		status.BundleID = current.BundleID
		status.BundleHash = current.BundleHash
		status.LoadedAt = current.LoadedAt.Format(time.RFC3339Nano)
	}
	return status
}

func (rt *Runtime) Active() bool {
	if rt == nil {
		return false
	}
	return IsActive(rt.snapshot().config)
}

func (rt *Runtime) SetConfig(cfg models.WAFConfig) (models.WAFConfig, error) {
	if rt == nil {
		return cfg, nil
	}
	cfg = NormalizeConfig(cfg, rt.defaultRulesDir)
	if event := logger.DebugEvent("waf", "config_set_start"); event != nil {
		event.Bool("enabled", cfg.Enabled).
			Str("mode", logger.SanitizeLogString(cfg.Mode)).
			Str("rules_dir", logger.SanitizeLogString(cfg.RulesDir)).
			Int("disabled_host_count", len(cfg.DisabledHosts)).
			Int("disabled_path_prefix_count", len(cfg.DisabledPathPrefixes)).
			Send()
	}
	prepared, err := rt.PrepareConfig(cfg)
	if err != nil {
		if event := logger.DebugEvent("waf", "config_set_failed"); event != nil {
			event.Str("error", logger.SanitizeLogString(err.Error())).
				Str("rules_dir", logger.SanitizeLogString(cfg.RulesDir)).
				Send()
		}
		return cfg, err
	}
	status := rt.CommitPrepared(prepared)
	if event := logger.DebugEvent("waf", "config_set_end"); event != nil {
		event.Bool("active", status.Enabled && status.Mode != ModeOff).Send()
	}
	return prepared.Config(), nil
}

func (rt *Runtime) Validate(cfg models.WAFConfig, bundleID string, bundlePath string) (ValidationResult, error) {
	if rt == nil {
		return ValidationResult{OK: false, Error: "WAF runtime is not initialized"}, fmt.Errorf("WAF runtime is not initialized")
	}
	start := time.Now()
	if event := logger.DebugEvent("waf", "validate_start"); event != nil {
		event.Bool("enabled", cfg.Enabled).
			Str("mode", logger.SanitizeLogString(cfg.Mode)).
			Str("bundle_id", logger.SanitizeLogString(bundleID)).
			Str("bundle_path", logger.SanitizeLogString(bundlePath)).
			Send()
	}
	compiled, err := buildCompiledRuntime(cfg, rt.defaultRulesDir, bundleID, bundlePath)
	releaseRuntimeMemorySoon()
	if err != nil {
		result := ValidationResult{
			OK:         false,
			BundleID:   strings.TrimSpace(bundleID),
			BundlePath: strings.TrimSpace(bundlePath),
			Error:      err.Error(),
		}
		if event := logger.DebugEvent("waf", "validate_end"); event != nil {
			event.Bool("ok", false).
				Str("bundle_id", logger.SanitizeLogString(result.BundleID)).
				Str("bundle_path", logger.SanitizeLogString(result.BundlePath)).
				Str("error", logger.SanitizeLogString(result.Error)).
				Int64("duration_ms", time.Since(start).Milliseconds()).
				Send()
		}
		return result, err
	}
	result := ValidationResult{
		OK:         true,
		BundleID:   compiled.BundleID,
		BundlePath: compiled.BundlePath,
		BundleHash: compiled.BundleHash,
	}
	if event := logger.DebugEvent("waf", "validate_end"); event != nil {
		event.Bool("ok", true).
			Str("bundle_id", logger.SanitizeLogString(result.BundleID)).
			Str("bundle_path", logger.SanitizeLogString(result.BundlePath)).
			Str("bundle_hash", logger.SanitizeLogString(result.BundleHash)).
			Int64("duration_ms", time.Since(start).Milliseconds()).
			Send()
	}
	return result, nil
}

func (rt *Runtime) Reload(cfg models.WAFConfig, bundleID string, bundlePath string) (Status, error) {
	if rt == nil {
		return Status{}, fmt.Errorf("WAF runtime is not initialized")
	}
	cfg = NormalizeConfig(cfg, rt.defaultRulesDir)
	start := time.Now()
	if event := logger.DebugEvent("waf", "reload_start"); event != nil {
		event.Bool("enabled", cfg.Enabled).
			Str("mode", logger.SanitizeLogString(cfg.Mode)).
			Str("rules_dir", logger.SanitizeLogString(cfg.RulesDir)).
			Str("bundle_id", logger.SanitizeLogString(bundleID)).
			Str("bundle_path", logger.SanitizeLogString(bundlePath)).
			Send()
	}
	prepared, err := rt.PrepareReload(cfg, bundleID, bundlePath)
	if err != nil {
		if event := logger.DebugEvent("waf", "reload_failed"); event != nil {
			event.Str("error", logger.SanitizeLogString(err.Error())).
				Str("bundle_id", logger.SanitizeLogString(bundleID)).
				Str("bundle_path", logger.SanitizeLogString(bundlePath)).
				Int64("duration_ms", time.Since(start).Milliseconds()).
				Send()
		}
		return rt.Status(), err
	}
	status := rt.CommitPrepared(prepared)
	if event := logger.DebugEvent("waf", "reload_end"); event != nil {
		event.Bool("enabled", status.Enabled).
			Bool("loaded", status.Loaded).
			Str("mode", logger.SanitizeLogString(status.Mode)).
			Str("bundle_id", logger.SanitizeLogString(status.BundleID)).
			Str("bundle_hash", logger.SanitizeLogString(status.BundleHash)).
			Int("pending_events", status.PendingEvents).
			Int64("duration_ms", time.Since(start).Milliseconds()).
			Send()
	}
	return status, nil
}

func (rt *Runtime) Drain(limit int) DrainResult {
	if rt == nil || rt.events == nil {
		return DrainResult{Events: []Event{}}
	}
	return rt.events.Drain(limit)
}

func (rt *Runtime) Evaluate(r *http.Request, ctx EvaluateContext) Decision {
	decision := Decision{Allowed: true}
	if rt == nil || r == nil {
		return decision
	}
	start := time.Now()
	snapshot := rt.snapshot()
	cfg := snapshot.config
	decision.Enabled = IsActive(cfg)
	decision.Mode = cfg.Mode
	decision.DetectionOnly = cfg.Mode == ModeDetection
	if !decision.Enabled || isExcludedByConfig(snapshot.exclusions, r) {
		if event := logger.DebugEvent("waf", "evaluate_skipped"); event != nil {
			event.Bool("enabled", decision.Enabled).
				Bool("excluded", decision.Enabled).
				Str("method", r.Method).
				Str("host", logger.SanitizeLogString(r.Host)).
				Str("path", logger.SanitizeLogString(r.URL.Path)).
				Str("route_type", logger.SanitizeLogString(ctx.RouteType)).
				Str("route_key", logger.SanitizeLogString(ctx.RouteKey)).
				Send()
		}
		return decision
	}
	compiled := snapshot.compiled
	if compiled == nil || compiled.WAF == nil {
		if event := logger.DebugEvent("waf", "evaluate_skipped"); event != nil {
			event.Bool("enabled", decision.Enabled).
				Bool("loaded", false).
				Str("method", r.Method).
				Str("host", logger.SanitizeLogString(r.Host)).
				Str("path", logger.SanitizeLogString(r.URL.Path)).
				Str("route_type", logger.SanitizeLogString(ctx.RouteType)).
				Str("route_key", logger.SanitizeLogString(ctx.RouteKey)).
				Send()
		}
		return decision
	}

	tx := compiled.WAF.NewTransaction()
	defer func() {
		tx.ProcessLogging()
		_ = tx.Close()
	}()
	clientIP, clientPort := splitAddress(ctx.ClientIP, r.RemoteAddr)
	tx.ProcessConnection(clientIP, clientPort, "", 0)
	tx.ProcessURI(r.URL.RequestURI(), r.Method, r.Proto)
	if r.Host != "" {
		tx.AddRequestHeader("Host", r.Host)
		tx.SetServerName(r.Host)
	}
	for key, values := range r.Header {
		for _, value := range values {
			tx.AddRequestHeader(key, value)
		}
	}
	for _, te := range r.TransferEncoding {
		tx.AddRequestHeader("Transfer-Encoding", te)
	}
	addInternalHeader(tx, "X-Fn-Knock-Route-Type", ctx.RouteType)
	addInternalHeader(tx, "X-Fn-Knock-Route-Key", ctx.RouteKey)
	addInternalHeader(tx, "X-Fn-Knock-Upstream", ctx.Upstream)

	var interruption *types.Interruption
	if it := tx.ProcessRequestHeaders(); it != nil {
		interruption = it
	} else if tx.IsRequestBodyAccessible() && r.Body != nil && r.Body != http.NoBody {
		if it, err := readAndRestoreRequestBody(tx, r, int64(cfg.RequestBodyLimitBytes)); err != nil {
			decision.Err = err
		} else if it != nil {
			interruption = it
		}
		if interruption == nil {
			if it, err := tx.ProcessRequestBody(); err != nil {
				decision.Err = err
			} else if it != nil {
				interruption = it
			}
		}
	} else if it, err := tx.ProcessRequestBody(); err != nil {
		decision.Err = err
	} else if it != nil {
		interruption = it
	}
	if interruption == nil && decision.DetectionOnly {
		interruption = detectionOnlyInterruption(tx)
	}

	rules := collectRuleMatches(tx.MatchedRules(), interruption)
	ruleIDs := uniqueRuleIDs(rules, interruption)
	if len(rules) == 0 && interruption == nil && decision.Err == nil {
		if event := logger.DebugEvent("waf", "evaluate_end"); event != nil {
			event.Bool("allowed", true).
				Str("mode", logger.SanitizeLogString(cfg.Mode)).
				Str("method", r.Method).
				Str("host", logger.SanitizeLogString(r.Host)).
				Str("path", logger.SanitizeLogString(r.URL.Path)).
				Str("query", logger.SanitizeURL("?"+r.URL.RawQuery)).
				Str("route_type", logger.SanitizeLogString(ctx.RouteType)).
				Str("route_key", logger.SanitizeLogString(ctx.RouteKey)).
				Str("upstream", logger.SanitizeURL(ctx.Upstream)).
				Int("rule_match_count", 0).
				Int64("duration_ms", time.Since(start).Milliseconds()).
				Send()
		}
		return decision
	}

	traceID := newTraceID()
	decision.TraceID = traceID
	decision.BundleID = compiled.BundleID

	action := "log"
	status := 0
	if interruption != nil {
		status = normalizeStatus(interruption.Status)
		if decision.DetectionOnly {
			action = "detect"
		} else {
			action = strings.TrimSpace(interruption.Action)
			if action == "" {
				action = "deny"
			}
			decision.Allowed = false
			decision.Status = status
		}
	} else if decision.DetectionOnly {
		action = "detect"
	}
	decision.Action = action
	decision.RuleIDs = ruleIDs

	event := buildEvent(r, ctx, compiled, traceID, cfg.Mode, action, status, ruleIDs, rules, interruption, decision.Err)
	rt.events.Add(event)
	decision.Event = &event
	if debugEvent := logger.DebugEvent("waf", "evaluate_end"); debugEvent != nil {
		debugEvent.Bool("allowed", decision.Allowed).
			Str("mode", logger.SanitizeLogString(cfg.Mode)).
			Str("action", logger.SanitizeLogString(action)).
			Int("status", status).
			Str("trace_id", logger.SanitizeLogString(traceID)).
			Str("bundle_id", logger.SanitizeLogString(compiled.BundleID)).
			Str("method", r.Method).
			Str("host", logger.SanitizeLogString(r.Host)).
			Str("path", logger.SanitizeLogString(r.URL.Path)).
			Str("query", logger.SanitizeURL("?"+r.URL.RawQuery)).
			Str("route_type", logger.SanitizeLogString(ctx.RouteType)).
			Str("route_key", logger.SanitizeLogString(ctx.RouteKey)).
			Str("upstream", logger.SanitizeURL(ctx.Upstream)).
			Ints("rule_ids", ruleIDs).
			Int("rule_match_count", len(rules)).
			Bool("interrupted", interruption != nil).
			Str("error", func() string {
				if decision.Err == nil {
					return ""
				}
				return logger.SanitizeLogString(decision.Err.Error())
			}()).
			Int64("duration_ms", time.Since(start).Milliseconds()).
			Send()
	}
	return decision
}

func (rt *Runtime) compiled() *CompiledRuntime {
	if rt == nil {
		return nil
	}
	return rt.snapshot().compiled
}

func releaseRuntimeMemorySoon() {
	if !runtimeMemoryReleasePending.CompareAndSwap(false, true) {
		return
	}
	time.AfterFunc(500*time.Millisecond, func() {
		defer runtimeMemoryReleasePending.Store(false)
		goruntime.GC()
		debug.FreeOSMemory()
	})
}

func (rt *Runtime) isExcluded(r *http.Request) bool {
	return isExcludedByConfig(rt.snapshot().exclusions, r)
}

func isExcludedByConfig(exclusions exclusionConfig, r *http.Request) bool {
	hasDisabledHosts := len(exclusions.disabledHosts) > 0
	hasDisabledPathPrefixes := len(exclusions.disabledPathPrefixes) > 0
	if !hasDisabledHosts && !hasDisabledPathPrefixes {
		return false
	}

	if hasDisabledHosts {
		host := normalizeHost(r.Host)
		if _, ok := exclusions.disabledHosts[host]; ok {
			return true
		}
	}

	if !hasDisabledPathPrefixes {
		return false
	}
	requestPath := filepath.ToSlash(filepath.Clean(r.URL.Path))
	if !strings.HasPrefix(requestPath, "/") {
		requestPath = "/" + requestPath
	}
	for _, prefix := range exclusions.disabledPathPrefixes {
		if prefix == "/" || requestPath == prefix || strings.HasPrefix(requestPath, strings.TrimRight(prefix, "/")+"/") {
			return true
		}
	}
	return false
}

type requestBodyReadCloser struct {
	io.Reader
	closer io.Closer
}

func (r requestBodyReadCloser) Close() error {
	if r.closer == nil {
		return nil
	}
	return r.closer.Close()
}

var errRequestBodyInspectionBufferLimit = errors.New("request body inspection buffer limit exceeded")

type requestBodyInspectionBuffer struct {
	bytes.Buffer
	limit int64
}

func (b *requestBodyInspectionBuffer) Write(p []byte) (int, error) {
	if b.limit >= 0 && int64(b.Len()+len(p)) > b.limit {
		allowed := int(b.limit) - b.Len()
		if allowed > 0 {
			_, _ = b.Buffer.Write(p[:allowed])
		}
		return allowed, errRequestBodyInspectionBufferLimit
	}
	return b.Buffer.Write(p)
}

func readAndRestoreRequestBody(tx interface {
	ReadRequestBodyFrom(io.Reader) (*types.Interruption, int, error)
}, r *http.Request, limit int64) (*types.Interruption, error) {
	originalBody := r.Body
	buffered := &requestBodyInspectionBuffer{limit: limit}
	tee := io.TeeReader(originalBody, buffered)
	it, _, err := tx.ReadRequestBodyFrom(tee)
	r.Body = requestBodyReadCloser{
		Reader: io.MultiReader(bytes.NewReader(buffered.Bytes()), originalBody),
		closer: originalBody,
	}
	if err != nil {
		return nil, fmt.Errorf("failed to append request body: %w", err)
	}
	return it, nil
}

func addInternalHeader(tx interface{ AddRequestHeader(string, string) }, key string, value string) {
	value = strings.TrimSpace(value)
	if value != "" {
		tx.AddRequestHeader(key, value)
	}
}

func detectionOnlyInterruption(tx any) *types.Interruption {
	withDetectionOnly, ok := tx.(interface {
		DetectionOnlyInterruption() *types.Interruption
	})
	if !ok {
		return nil
	}
	return withDetectionOnly.DetectionOnlyInterruption()
}

func buildEvent(r *http.Request, ctx EvaluateContext, compiled *CompiledRuntime, traceID string, mode string, action string, status int, ruleIDs []int, rules []RuleMatch, interruption *types.Interruption, evalErr error) Event {
	event := Event{
		TraceID:       traceID,
		TransactionID: traceID,
		Time:          time.Now().UTC().Format(time.RFC3339Nano),
		Mode:          mode,
		Action:        action,
		Status:        status,
		ClientIP:      ctx.ClientIP,
		RemoteAddr:    r.RemoteAddr,
		Method:        r.Method,
		Scheme:        ctx.Scheme,
		Host:          r.Host,
		Path:          r.URL.Path,
		Query:         redactRawQuery(r.URL.RawQuery),
		RequestURI:    redactRequestURI(r.URL),
		UserAgent:     r.UserAgent(),
		Referer:       r.Referer(),
		RouteType:     ctx.RouteType,
		RouteKey:      ctx.RouteKey,
		Upstream:      ctx.Upstream,
		BundleID:      compiled.BundleID,
		BundleHash:    compiled.BundleHash,
		RuleIDs:       ruleIDs,
		Rules:         rules,
	}
	if event.Scheme == "" {
		event.Scheme = "http"
		if r.TLS != nil {
			event.Scheme = "https"
		}
	}
	if interruption != nil {
		event.Interruption = &InterruptionInfo{
			RuleID: interruption.RuleID,
			Action: interruption.Action,
			Status: normalizeStatus(interruption.Status),
		}
	}
	if evalErr != nil {
		event.Error = evalErr.Error()
	}
	return event
}

func collectRuleMatches(matches []types.MatchedRule, interruption *types.Interruption) []RuleMatch {
	out := make([]RuleMatch, 0, len(matches))
	for _, match := range matches {
		if match == nil || match.Rule() == nil {
			continue
		}
		rule := match.Rule()
		if isInternalRule(rule) {
			continue
		}
		if !shouldRecordRuleMatch(match, interruption) {
			continue
		}
		out = append(out, RuleMatch{
			ID:               rule.ID(),
			Message:          truncate(match.Message(), 512),
			Data:             truncate(match.Data(), 512),
			Severity:         fmt.Sprint(rule.Severity()),
			Phase:            int(rule.Phase()),
			File:             rule.File(),
			Line:             rule.Line(),
			Tags:             append([]string{}, rule.Tags()...),
			Disruptive:       match.Disruptive(),
			MatchedVariables: collectMatchedVariables(match.MatchedDatas()),
		})
	}
	return out
}

func isInternalRule(rule types.RuleMetadata) bool {
	if rule == nil {
		return true
	}
	return rule.ID() == internalSetupRuleID ||
		strings.EqualFold(filepath.Base(rule.File()), initializationRuleFilename)
}

func shouldRecordRuleMatch(match types.MatchedRule, interruption *types.Interruption) bool {
	if match == nil || match.Rule() == nil {
		return false
	}
	if interruption != nil && match.Rule().ID() == interruption.RuleID {
		return true
	}
	if strings.TrimSpace(match.Message()) != "" || strings.TrimSpace(match.Data()) != "" {
		return true
	}
	for _, data := range match.MatchedDatas() {
		if data == nil {
			continue
		}
		if strings.TrimSpace(data.Message()) != "" || strings.TrimSpace(data.Data()) != "" {
			return true
		}
	}
	if withLog, ok := match.(interface{ Log() bool }); ok && withLog.Log() {
		return true
	}
	if withAudit, ok := match.(interface{ Audit() bool }); ok && withAudit.Audit() {
		return true
	}
	return false
}

func collectMatchedVariables(matches []types.MatchData) []MatchedVariable {
	out := make([]MatchedVariable, 0, len(matches))
	for _, match := range matches {
		if match == nil {
			continue
		}
		key := match.Key()
		value := match.Value()
		if isSensitiveName(key) || isSensitiveName(fmt.Sprint(match.Variable())) {
			value = "[redacted]"
		}
		out = append(out, MatchedVariable{
			Variable:     fmt.Sprint(match.Variable()),
			Key:          key,
			ValuePreview: truncate(value, 256),
		})
	}
	return out
}

func uniqueRuleIDs(rules []RuleMatch, interruption *types.Interruption) []int {
	seen := make(map[int]struct{}, len(rules)+1)
	out := make([]int, 0, len(rules)+1)
	for _, rule := range rules {
		if rule.ID <= 0 {
			continue
		}
		if _, ok := seen[rule.ID]; ok {
			continue
		}
		seen[rule.ID] = struct{}{}
		out = append(out, rule.ID)
	}
	if interruption != nil && interruption.RuleID > 0 {
		if _, ok := seen[interruption.RuleID]; !ok {
			out = append(out, interruption.RuleID)
		}
	}
	return out
}

func splitAddress(clientIP string, remoteAddr string) (string, int) {
	clientIP = strings.TrimSpace(clientIP)
	if clientIP != "" {
		return clientIP, 0
	}
	host, port, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return strings.TrimSpace(remoteAddr), 0
	}
	portNum, _ := strconv.Atoi(port)
	return host, portNum
}

func normalizeHost(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	if strings.HasPrefix(host, "[") {
		if idx := strings.LastIndex(host, "]"); idx >= 0 {
			return lowerASCIIString(host[:idx+1])
		}
	}
	if idx := strings.LastIndexByte(host, ':'); idx != -1 && strings.IndexByte(host[:idx], ':') == -1 {
		return lowerASCIIString(strings.TrimSpace(host[:idx]))
	}
	return lowerASCIIString(host)
}

func normalizeStatus(status int) int {
	if status < 400 || status > 599 {
		return http.StatusForbidden
	}
	return status
}

func newTraceID() string {
	var uuid [16]byte
	if _, err := rand.Read(uuid[:]); err != nil {
		binary.BigEndian.PutUint64(uuid[0:8], uint64(time.Now().UnixNano()))
		binary.BigEndian.PutUint64(uuid[8:16], traceFallbackCounter.Add(1))
	}
	uuid[6] = (uuid[6] & 0x0f) | 0x40
	uuid[8] = (uuid[8] & 0x3f) | 0x80
	return formatTraceID(uuid)
}

func formatTraceID(uuid [16]byte) string {
	var buf [40]byte
	copy(buf[:], "waf_")
	hex.Encode(buf[4:12], uuid[0:4])
	buf[12] = '-'
	hex.Encode(buf[13:17], uuid[4:6])
	buf[17] = '-'
	hex.Encode(buf[18:22], uuid[6:8])
	buf[22] = '-'
	hex.Encode(buf[23:27], uuid[8:10])
	buf[27] = '-'
	hex.Encode(buf[28:40], uuid[10:16])
	return string(buf[:])
}

func truncate(value string, limit int) string {
	if limit <= 0 || len(value) <= limit {
		return value
	}
	return value[:limit]
}
