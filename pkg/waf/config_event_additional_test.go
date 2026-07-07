package waf

import (
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go-reauth-proxy/pkg/models"
)

func TestDefaultRulesDirUsesCurrentDirectoryWhenBlank(t *testing.T) {
	if got := DefaultRulesDir("   "); got != "waf" {
		t.Fatalf("default rules dir = %q", got)
	}
}

func TestDefaultRulesDirTrimsRuntimeDirectory(t *testing.T) {
	got := DefaultRulesDir("  /tmp/runtime  ")

	if got != filepath.Join("/tmp/runtime", "waf") {
		t.Fatalf("default rules dir = %q", got)
	}
}

func TestNormalizeConfigLowercasesMode(t *testing.T) {
	cfg := NormalizeConfig(models.WAFConfig{Mode: " DETECTION "}, "/rules")

	if cfg.Mode != ModeDetection {
		t.Fatalf("mode = %q", cfg.Mode)
	}
}

func TestNormalizeConfigInvalidModeDefaultsToBlocking(t *testing.T) {
	cfg := NormalizeConfig(models.WAFConfig{Mode: "invalid"}, "/rules")

	if cfg.Mode != ModeBlocking {
		t.Fatalf("mode = %q", cfg.Mode)
	}
}

func TestNormalizeConfigBlankModeEnablesRequestBodyAccess(t *testing.T) {
	cfg := NormalizeConfig(models.WAFConfig{}, "/rules")

	if !cfg.RequestBodyAccess {
		t.Fatalf("blank mode should default request body access on: %#v", cfg)
	}
}

func TestNormalizeConfigExplicitModeKeepsRequestBodyAccess(t *testing.T) {
	cfg := NormalizeConfig(models.WAFConfig{Mode: ModeBlocking}, "/rules")

	if cfg.RequestBodyAccess {
		t.Fatalf("explicit mode should not force request body access: %#v", cfg)
	}
}

func TestNormalizeConfigUsesProvidedDefaultRulesDir(t *testing.T) {
	cfg := NormalizeConfig(models.WAFConfig{Mode: ModeBlocking}, "/default-rules")

	if cfg.RulesDir != "/default-rules" {
		t.Fatalf("rules dir = %q", cfg.RulesDir)
	}
}

func TestNormalizeConfigCleansRelativeRulesDir(t *testing.T) {
	cfg := NormalizeConfig(models.WAFConfig{RulesDir: " rules/../crs "}, "")

	if cfg.RulesDir != "crs" {
		t.Fatalf("rules dir = %q", cfg.RulesDir)
	}
}

func TestNormalizeConfigTrimsActiveBundleID(t *testing.T) {
	cfg := NormalizeConfig(models.WAFConfig{ActiveBundleID: " bundle-1 "}, "/rules")

	if cfg.ActiveBundleID != "bundle-1" {
		t.Fatalf("active bundle ID = %q", cfg.ActiveBundleID)
	}
}

func TestNormalizeConfigDefaultsParanoiaLevel(t *testing.T) {
	cfg := NormalizeConfig(models.WAFConfig{ParanoiaLevel: 9}, "/rules")

	if cfg.ParanoiaLevel != defaultParanoiaLevel {
		t.Fatalf("paranoia level = %d", cfg.ParanoiaLevel)
	}
}

func TestNormalizeConfigDefaultsExecutingParanoiaLevel(t *testing.T) {
	cfg := NormalizeConfig(models.WAFConfig{ParanoiaLevel: 2}, "/rules")

	if cfg.ExecutingParanoiaLevel != 2 {
		t.Fatalf("executing paranoia level = %d", cfg.ExecutingParanoiaLevel)
	}
}

func TestNormalizeConfigRaisesExecutingParanoiaLevelToParanoia(t *testing.T) {
	cfg := NormalizeConfig(models.WAFConfig{ParanoiaLevel: 3, ExecutingParanoiaLevel: 1}, "/rules")

	if cfg.ExecutingParanoiaLevel != 3 {
		t.Fatalf("executing paranoia level = %d", cfg.ExecutingParanoiaLevel)
	}
}

func TestNormalizeConfigPreservesValidThresholds(t *testing.T) {
	cfg := NormalizeConfig(models.WAFConfig{InboundAnomalyThreshold: 7, OutboundAnomalyThreshold: 8}, "/rules")

	if cfg.InboundAnomalyThreshold != 7 || cfg.OutboundAnomalyThreshold != 8 {
		t.Fatalf("thresholds not preserved: %#v", cfg)
	}
}

func TestNormalizeConfigDefaultsThresholds(t *testing.T) {
	cfg := NormalizeConfig(models.WAFConfig{}, "/rules")

	if cfg.InboundAnomalyThreshold != defaultInboundThreshold || cfg.OutboundAnomalyThreshold != defaultOutboundThreshold {
		t.Fatalf("thresholds not defaulted: %#v", cfg)
	}
}

func TestNormalizeConfigClampsRequestBodyMemoryLimit(t *testing.T) {
	cfg := NormalizeConfig(models.WAFConfig{RequestBodyLimitBytes: 10, RequestBodyInMemoryLimitBytes: 100}, "/rules")

	if cfg.RequestBodyInMemoryLimitBytes != 10 {
		t.Fatalf("memory limit = %d", cfg.RequestBodyInMemoryLimitBytes)
	}
}

func TestNormalizeConfigDisablesResponseBodyAccess(t *testing.T) {
	cfg := NormalizeConfig(models.WAFConfig{ResponseBodyAccess: true}, "/rules")

	if cfg.ResponseBodyAccess {
		t.Fatalf("response body access should be disabled: %#v", cfg)
	}
}

func TestNormalizeConfigNormalizesDisabledHosts(t *testing.T) {
	cfg := NormalizeConfig(models.WAFConfig{DisabledHosts: []string{" App.Example.COM ", "app.example.com", ""}}, "/rules")

	if len(cfg.DisabledHosts) != 1 || cfg.DisabledHosts[0] != "app.example.com" {
		t.Fatalf("disabled hosts = %#v", cfg.DisabledHosts)
	}
}

func TestNormalizeConfigNormalizesDisabledPathPrefixes(t *testing.T) {
	cfg := NormalizeConfig(models.WAFConfig{DisabledPathPrefixes: []string{" api//v1 ", "/api/v1", ""}}, "/rules")

	if len(cfg.DisabledPathPrefixes) != 1 || cfg.DisabledPathPrefixes[0] != "/api/v1" {
		t.Fatalf("disabled path prefixes = %#v", cfg.DisabledPathPrefixes)
	}
}

func TestNormalizeConfigTrimsUpdatedAt(t *testing.T) {
	cfg := NormalizeConfig(models.WAFConfig{UpdatedAt: " 2026-07-08T00:00:00Z "}, "/rules")

	if cfg.UpdatedAt != "2026-07-08T00:00:00Z" {
		t.Fatalf("updated_at = %q", cfg.UpdatedAt)
	}
}

func TestIsActiveFalseWhenDisabled(t *testing.T) {
	if IsActive(models.WAFConfig{Enabled: false, Mode: ModeBlocking}) {
		t.Fatal("disabled WAF should not be active")
	}
}

func TestIsActiveFalseWhenModeOff(t *testing.T) {
	if IsActive(models.WAFConfig{Enabled: true, Mode: ModeOff}) {
		t.Fatal("off WAF should not be active")
	}
}

func TestIsActiveTrueWhenEnabledAndBlocking(t *testing.T) {
	if !IsActive(models.WAFConfig{Enabled: true, Mode: ModeBlocking}) {
		t.Fatal("enabled blocking WAF should be active")
	}
}

func TestNormalizeStringListPreservesCaseWhenRequested(t *testing.T) {
	got := normalizeStringList([]string{" App ", "App", "api"}, false)

	if len(got) != 2 || got[0] != "App" || got[1] != "api" {
		t.Fatalf("string list = %#v", got)
	}
}

func TestNormalizePathPrefixesEmptyReturnsEmptySlice(t *testing.T) {
	got := normalizePathPrefixes(nil)

	if got == nil || len(got) != 0 {
		t.Fatalf("path prefixes = %#v", got)
	}
}

func TestRedactRequestURINil(t *testing.T) {
	if got := redactRequestURI(nil); got != "" {
		t.Fatalf("nil request URI = %q", got)
	}
}

func TestRedactRequestURIRedactsSensitiveQuery(t *testing.T) {
	u, err := url.Parse("https://example.com/search?q=ok&token=secret")
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	got := redactRequestURI(u)

	if strings.Contains(got, "secret") || !strings.Contains(got, "/search?q=ok") {
		t.Fatalf("request URI not redacted correctly: %q", got)
	}
}

func TestRedactRawQueryFastRefusesEscapedInput(t *testing.T) {
	if _, ok := redactRawQueryFast("to%6ben=secret"); ok {
		t.Fatal("fast redaction should refuse escaped input")
	}
}

func TestRedactRawQueryFastRedactsAPIKey(t *testing.T) {
	got, ok := redactRawQueryFast("api_key=secret&ok=1")

	if !ok || strings.Contains(got, "secret") || !strings.Contains(got, "api_key=%5Bredacted%5D") {
		t.Fatalf("fast redaction failed: got=%q ok=%v", got, ok)
	}
}

func TestWAFContainsFoldASCIIStringEmptySearch(t *testing.T) {
	if !containsFoldASCIIString("abc", "") {
		t.Fatal("empty search should match")
	}
}

func TestWAFHasFoldASCIIPrefixLongPrefixFalse(t *testing.T) {
	if hasFoldASCIIPrefix("abc", "abcd") {
		t.Fatal("longer prefix should not match")
	}
}

func TestWAFLowerASCIIByteLowercasesUppercase(t *testing.T) {
	if lowerASCIIByte('Z') != 'z' {
		t.Fatal("uppercase ASCII byte not lowercased")
	}
}

func TestEventStoreNilAddDoesNotPanic(t *testing.T) {
	var store *EventStore

	store.Add(Event{TraceID: "trace"})
}

func TestEventStoreIgnoresEmptyTraceID(t *testing.T) {
	store := NewEventStore(10, time.Minute)

	store.Add(Event{})

	if pending := store.Pending(); pending != 0 {
		t.Fatalf("pending = %d", pending)
	}
}

func TestEventStoreDuplicateTraceUpdatesEventWithoutGrowing(t *testing.T) {
	store := NewEventStore(10, time.Minute)
	store.Add(Event{TraceID: "trace", Action: "old"})
	store.Add(Event{TraceID: "trace", Action: "new"})

	result := store.Drain(10)

	if result.Drained != 1 || result.Events[0].Action != "new" {
		t.Fatalf("unexpected duplicate trace drain: %#v", result)
	}
}

func TestEventStoreNilPendingIsZero(t *testing.T) {
	var store *EventStore

	if pending := store.Pending(); pending != 0 {
		t.Fatalf("pending = %d", pending)
	}
}

func TestEventStoreNilDrainReturnsEmptyEvents(t *testing.T) {
	var store *EventStore

	result := store.Drain(10)

	if result.Drained != 0 || result.Remaining != 0 || len(result.Events) != 0 {
		t.Fatalf("nil drain result = %#v", result)
	}
}

func TestEventStoreDrainZeroLimitUsesMaxEntries(t *testing.T) {
	store := NewEventStore(2, time.Minute)
	store.Add(Event{TraceID: "a"})
	store.Add(Event{TraceID: "b"})

	result := store.Drain(0)

	if result.Drained != 2 || result.Remaining != 0 {
		t.Fatalf("zero-limit drain result = %#v", result)
	}
}

func TestEventStoreExpiresOldEvents(t *testing.T) {
	store := NewEventStore(10, time.Nanosecond)
	store.Add(Event{TraceID: "expired"})
	time.Sleep(time.Millisecond)

	if pending := store.Pending(); pending != 0 {
		t.Fatalf("expired event still pending: %d", pending)
	}
}

func TestEventStoreEvictsOldestWhenMaxEntriesExceeded(t *testing.T) {
	store := NewEventStore(2, time.Minute)
	store.Add(Event{TraceID: "a"})
	store.Add(Event{TraceID: "b"})
	store.Add(Event{TraceID: "c"})

	result := store.Drain(10)

	if result.Drained != 2 || result.Events[0].TraceID != "b" || result.Events[1].TraceID != "c" {
		t.Fatalf("unexpected eviction order: %#v", result)
	}
}
