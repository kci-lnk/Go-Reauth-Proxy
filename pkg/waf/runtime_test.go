package waf

import (
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/corazawaf/coraza/v3/types"

	"go-reauth-proxy/pkg/models"
)

var (
	benchmarkWAFBoolSink   bool
	benchmarkWAFStringSink string
)

type recordingRequestBodyTx struct {
	body string
}

func (tx *recordingRequestBodyTx) ReadRequestBodyFrom(reader io.Reader) (*types.Interruption, int, error) {
	body, err := io.ReadAll(reader)
	tx.body = string(body)
	return nil, len(body), err
}

type recordingLimitedRequestBodyTx struct {
	limit int64
	body  string
}

func (tx *recordingLimitedRequestBodyTx) ReadRequestBodyFrom(reader io.Reader) (*types.Interruption, int, error) {
	body, err := io.ReadAll(io.LimitReader(reader, tx.limit))
	tx.body = string(body)
	return nil, len(body), err
}

func writeTestRule(t *testing.T, rulesDir string, customRule string) {
	t.Helper()
	customDir := filepath.Join(rulesDir, "custom")
	if err := os.MkdirAll(customDir, 0o755); err != nil {
		t.Fatalf("create custom dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(customDir, "1001-test.conf"), []byte(customRule+"\n"), 0o644); err != nil {
		t.Fatalf("write custom rule: %v", err)
	}
}

func writeSystemTestRule(t *testing.T, rulesDir string, filename string, content string) {
	t.Helper()
	systemDir := filepath.Join(rulesDir, "system")
	if err := os.MkdirAll(systemDir, 0o755); err != nil {
		t.Fatalf("create system dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(systemDir, filename), []byte(content+"\n"), 0o644); err != nil {
		t.Fatalf("write system rule: %v", err)
	}
}

func writeRulesState(t *testing.T, rulesDir string, state string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(rulesDir, rulesStateFilename), []byte(state), 0o644); err != nil {
		t.Fatalf("write rules state: %v", err)
	}
}

func testConfig(rulesDir string, mode string) models.WAFConfig {
	return models.WAFConfig{
		Enabled:           true,
		Mode:              mode,
		RulesDir:          rulesDir,
		RequestBodyAccess: true,
	}
}

func TestPrepareConfigDoesNotPublishBeforeCommit(t *testing.T) {
	runtime := NewRuntime(models.WAFConfig{}, t.TempDir())
	beforeConfig := runtime.Config()
	beforeStatus := runtime.Status()

	prepared, err := runtime.PrepareConfig(models.WAFConfig{
		Enabled: true,
		Mode:    ModeBlocking,
	})
	if err != nil {
		t.Fatalf("PrepareConfig() returned error: %v", err)
	}
	if got := runtime.Config(); got.Enabled != beforeConfig.Enabled || got.Mode != beforeConfig.Mode {
		t.Fatalf("runtime config changed before commit: %#v", got)
	}
	if got := runtime.Status(); got.Enabled != beforeStatus.Enabled || got.Loaded != beforeStatus.Loaded {
		t.Fatalf("runtime status changed before commit: %#v", got)
	}

	status := runtime.CommitPrepared(prepared)
	if !runtime.Config().Enabled || !status.Enabled {
		t.Fatalf("prepared config was not published: config=%#v status=%#v", runtime.Config(), status)
	}
}

func TestRuntimeConfigReturnsDefensiveCopies(t *testing.T) {
	runtime := NewRuntime(models.WAFConfig{
		DisabledHosts:        []string{"app.example.test"},
		DisabledPathPrefixes: []string{"/private"},
	}, t.TempDir())

	copy := runtime.Config()
	copy.DisabledHosts[0] = "changed.example.test"
	copy.DisabledPathPrefixes[0] = "/changed"

	stored := runtime.Config()
	if stored.DisabledHosts[0] != "app.example.test" ||
		stored.DisabledPathPrefixes[0] != "/private" {
		t.Fatalf("stored WAF config was mutated through a returned copy: %#v", stored)
	}
}

func TestCommitPreparedPublishesOneRuntimeGeneration(t *testing.T) {
	runtime := NewRuntime(models.WAFConfig{}, t.TempDir())
	prepared := func(id string) PreparedState {
		return PreparedState{
			config: models.WAFConfig{
				Enabled:        true,
				Mode:           ModeBlocking,
				ActiveBundleID: id,
				DisabledHosts:  []string{id + ".example.test"},
			},
			compiled:        &CompiledRuntime{BundleID: id},
			replaceCompiled: true,
		}
	}
	first := prepared("first")
	second := prepared("second")
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 10_000 {
			runtime.CommitPrepared(first)
			runtime.CommitPrepared(second)
		}
	}()

	for {
		select {
		case <-done:
			return
		default:
			snapshot := runtime.snapshot()
			id := snapshot.config.ActiveBundleID
			if id == "" {
				continue
			}
			if snapshot.compiled == nil || snapshot.compiled.BundleID != id {
				t.Fatalf(
					"mixed WAF generation: config=%q compiled=%#v",
					id,
					snapshot.compiled,
				)
			}
			if _, ok := snapshot.exclusions.disabledHosts[id+".example.test"]; !ok {
				t.Fatalf(
					"mixed WAF generation: config=%q exclusions=%#v",
					id,
					snapshot.exclusions.disabledHosts,
				)
			}
		}
	}
}

func TestRuntimeExclusionConfigMatchesDisabledHostAndPath(t *testing.T) {
	rt := NewRuntime(models.WAFConfig{
		Enabled:              true,
		Mode:                 ModeBlocking,
		DisabledHosts:        []string{"App.Example.TEST:443"},
		DisabledPathPrefixes: []string{"admin", "/internal/"},
	}, t.TempDir())

	hostReq := httptest.NewRequest("GET", "https://app.example.test/dashboard", nil)
	if !rt.isExcluded(hostReq) {
		t.Fatalf("expected disabled host to be excluded")
	}

	pathReq := httptest.NewRequest("GET", "https://other.example.test/admin/users", nil)
	if !rt.isExcluded(pathReq) {
		t.Fatalf("expected disabled path prefix to be excluded")
	}

	nestedPathReq := httptest.NewRequest("GET", "https://other.example.test/internal/status", nil)
	if !rt.isExcluded(nestedPathReq) {
		t.Fatalf("expected disabled slash-suffixed path prefix to be excluded")
	}

	allowedReq := httptest.NewRequest("GET", "https://other.example.test/public", nil)
	if rt.isExcluded(allowedReq) {
		t.Fatalf("expected unrelated request not to be excluded")
	}
}

func TestRuntimeSetConfigUpdatesDisabledHostsWhileLoaded(t *testing.T) {
	rulesDir := t.TempDir()
	writeTestRule(t, rulesDir, `SecRule ARGS:test "@streq attack" "id:1002,phase:2,deny,status:403,msg:'test block',log"`)

	cfg := testConfig(rulesDir, ModeBlocking)
	cfg.DisabledHosts = []string{"app.example.test"}
	rt := NewRuntime(cfg, t.TempDir())
	if _, err := rt.Reload(rt.Config(), "", ""); err != nil {
		t.Fatalf("reload WAF: %v", err)
	}

	excluded := httptest.NewRequest("GET", "https://app.example.test/search?test=attack", nil)
	if decision := rt.Evaluate(excluded, EvaluateContext{}); !decision.Allowed {
		t.Fatalf("expected disabled host to skip WAF, got %#v", decision)
	}

	next := rt.Config()
	next.DisabledHosts = []string{}
	if _, err := rt.SetConfig(next); err != nil {
		t.Fatalf("clear disabled hosts: %v", err)
	}

	checked := httptest.NewRequest("GET", "https://app.example.test/search?test=attack", nil)
	if decision := rt.Evaluate(checked, EvaluateContext{}); decision.Allowed {
		t.Fatalf("expected host to return to WAF evaluation, got %#v", decision)
	}
}

func TestNormalizeHostMatchesLegacyBehavior(t *testing.T) {
	cases := []string{
		"",
		" App.Example.TEST ",
		"App.Example.TEST:443",
		"app.example.test:",
		":8080",
		"app.example.test:abc",
		"2001:db8::1",
		"[2001:db8::1]:443",
		"[2001:db8::1]",
		"[2001:db8::1]trailing",
		"[2001:db8::1",
		"app.example.test:443:extra",
	}

	for _, tc := range cases {
		if got, want := normalizeHost(tc), legacyNormalizeHost(tc); got != want {
			t.Fatalf("normalizeHost(%q) = %q, want legacy %q", tc, got, want)
		}
	}
}

func TestDynamicDirectivesInitializeCRSSetup(t *testing.T) {
	directives := dynamicDirectives(models.WAFConfig{
		Mode:                          ModeBlocking,
		RequestBodyAccess:             true,
		RequestBodyLimitBytes:         1024,
		RequestBodyInMemoryLimitBytes: 512,
		ParanoiaLevel:                 2,
		ExecutingParanoiaLevel:        3,
		InboundAnomalyThreshold:       7,
		OutboundAnomalyThreshold:      6,
	})

	expected := []string{
		"id:1000000",
		"setvar:tx.crs_setup_version=4250",
		"setvar:tx.blocking_paranoia_level=2",
		"setvar:tx.detection_paranoia_level=3",
		"setvar:tx.paranoia_level=2",
		"setvar:tx.executing_paranoia_level=3",
	}
	for _, item := range expected {
		if !strings.Contains(directives, item) {
			t.Fatalf("expected dynamic directives to include %q, got %s", item, directives)
		}
	}
}

func TestRuntimeSkipsUpdateTargetForDisabledSystemRule(t *testing.T) {
	rulesDir := t.TempDir()
	writeSystemTestRule(t, rulesDir, "REQUEST-930-APPLICATION-ATTACK-LFI.conf", `SecRule ARGS:test "@streq attack" "id:930120,phase:2,deny,status:403,msg:'lfi block',log"`)
	writeSystemTestRule(t, rulesDir, "REQUEST-999-COMMON-EXCEPTIONS-AFTER.conf", `SecRuleUpdateTargetById 930120 "!ARGS_NAMES:json.profile"`)
	writeRulesState(t, rulesDir, `{
  "system_enabled": {
    "REQUEST-930-APPLICATION-ATTACK-LFI.conf": false,
    "REQUEST-999-COMMON-EXCEPTIONS-AFTER.conf": true
  },
  "custom_enabled": {}
}`)

	rt := NewRuntime(testConfig(rulesDir, ModeBlocking), t.TempDir())
	if _, err := rt.Reload(rt.Config(), "", ""); err != nil {
		t.Fatalf("reload WAF with disabled update target: %v", err)
	}

	req := httptest.NewRequest("GET", "https://app.example.test/search?test=attack", nil)
	decision := rt.Evaluate(req, EvaluateContext{ClientIP: "203.0.113.10"})
	if !decision.Allowed {
		t.Fatalf("expected disabled system rule to allow request, got %#v", decision)
	}
}

func TestRuntimeUsesAdminDefaultDisabledSystemRules(t *testing.T) {
	rulesDir := t.TempDir()
	writeSystemTestRule(t, rulesDir, "REQUEST-930-APPLICATION-ATTACK-LFI.conf", `SecRule ARGS:test "@streq attack" "id:930120,phase:2,deny,status:403,msg:'lfi block',log"`)
	writeRulesState(t, rulesDir, `{"system_enabled": {}, "custom_enabled": {}}`)

	rt := NewRuntime(testConfig(rulesDir, ModeBlocking), t.TempDir())
	if _, err := rt.Reload(rt.Config(), "", ""); err != nil {
		t.Fatalf("reload WAF: %v", err)
	}

	req := httptest.NewRequest("GET", "https://app.example.test/search?test=attack", nil)
	decision := rt.Evaluate(req, EvaluateContext{ClientIP: "203.0.113.10"})
	if !decision.Allowed {
		t.Fatalf("expected omitted default-disabled system rule to be inactive, got %#v", decision)
	}
}

func TestRuntimeLoadsSystemDataFilesFromRuleDirectory(t *testing.T) {
	rulesDir := t.TempDir()
	systemDir := filepath.Join(rulesDir, "system")
	if err := os.MkdirAll(systemDir, 0o755); err != nil {
		t.Fatalf("create system dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(systemDir, "test-patterns.data"), []byte("attack\n"), 0o644); err != nil {
		t.Fatalf("write data file: %v", err)
	}
	writeSystemTestRule(t, rulesDir, "REQUEST-913-SCANNER-DETECTION.conf", `SecRule ARGS:test "@pmFromFile test-patterns.data" "id:913120,phase:2,deny,status:403,msg:'data file block',log"`)
	writeRulesState(t, rulesDir, `{
  "system_enabled": {
    "REQUEST-913-SCANNER-DETECTION.conf": true
  },
  "custom_enabled": {}
}`)

	rt := NewRuntime(testConfig(rulesDir, ModeBlocking), t.TempDir())
	if _, err := rt.Reload(rt.Config(), "", ""); err != nil {
		t.Fatalf("reload WAF: %v", err)
	}

	req := httptest.NewRequest("GET", "https://app.example.test/search?test=attack", nil)
	decision := rt.Evaluate(req, EvaluateContext{ClientIP: "203.0.113.10"})
	if decision.Allowed {
		t.Fatalf("expected rule using @pmFromFile to block request")
	}
	if !slices.Contains(decision.RuleIDs, 913120) {
		t.Fatalf("expected data-file rule id, got %#v", decision.RuleIDs)
	}
}

func TestRuntimeEvaluateBlocksAndDrainsEvent(t *testing.T) {
	rulesDir := t.TempDir()
	writeTestRule(t, rulesDir, `SecRule ARGS:test "@streq attack" "id:1001,phase:2,deny,status:403,msg:'test block',log"`)

	rt := NewRuntime(testConfig(rulesDir, ModeBlocking), t.TempDir())
	if _, err := rt.Reload(rt.Config(), "", ""); err != nil {
		t.Fatalf("reload WAF: %v", err)
	}

	req := httptest.NewRequest("GET", "https://app.example.test/search?test=attack", nil)
	req.RemoteAddr = "203.0.113.10:12345"

	decision := rt.Evaluate(req, EvaluateContext{
		ClientIP:  "203.0.113.10",
		RouteType: "host_rule",
		RouteKey:  "app.example.test",
		Upstream:  "http://127.0.0.1:8080",
		Scheme:    "https",
	})
	if decision.Allowed {
		t.Fatalf("expected WAF to block request")
	}
	if decision.Status != 403 {
		t.Fatalf("expected status 403, got %d", decision.Status)
	}
	if !slices.Contains(decision.RuleIDs, 1001) {
		t.Fatalf("expected rule id 1001, got %#v", decision.RuleIDs)
	}
	if slices.Contains(decision.RuleIDs, internalSetupRuleID) {
		t.Fatalf("did not expect internal setup rule id in event, got %#v", decision.RuleIDs)
	}
	if decision.TraceID == "" {
		t.Fatalf("expected trace id")
	}

	drained := rt.Drain(10)
	if drained.Drained != 1 || drained.Remaining != 0 {
		t.Fatalf("unexpected drain result: %#v", drained)
	}
	if drained.Events[0].TraceID != decision.TraceID {
		t.Fatalf("expected drained event trace %q, got %q", decision.TraceID, drained.Events[0].TraceID)
	}
	if drained.Events[0].Interruption == nil || drained.Events[0].Interruption.RuleID != 1001 {
		t.Fatalf("expected interruption for rule 1001, got %#v", drained.Events[0].Interruption)
	}
	if second := rt.Drain(10); second.Drained != 0 {
		t.Fatalf("expected second drain to be empty, got %#v", second)
	}
}

func TestRuntimeFiltersUnloggedControlMatches(t *testing.T) {
	rulesDir := t.TempDir()
	writeTestRule(t, rulesDir, `
SecAction "id:2000,phase:1,pass,nolog,setvar:tx.test_control=1"
SecRule REQUEST_URI "@contains /blocked" "id:2001,phase:1,deny,status:403,msg:'real block',log"
`)

	rt := NewRuntime(testConfig(rulesDir, ModeBlocking), t.TempDir())
	if _, err := rt.Reload(rt.Config(), "", ""); err != nil {
		t.Fatalf("reload WAF: %v", err)
	}

	req := httptest.NewRequest("GET", "https://app.example.test/blocked", nil)
	req.RemoteAddr = "203.0.113.10:12345"

	decision := rt.Evaluate(req, EvaluateContext{ClientIP: "203.0.113.10"})
	if decision.Allowed {
		t.Fatalf("expected WAF to block request")
	}

	drained := rt.Drain(10)
	if drained.Drained != 1 {
		t.Fatalf("expected one event, got %#v", drained)
	}
	if slices.Contains(drained.Events[0].RuleIDs, 2000) {
		t.Fatalf("did not expect unlogged control rule in ids, got %#v", drained.Events[0].RuleIDs)
	}
	if !slices.Contains(drained.Events[0].RuleIDs, 2001) {
		t.Fatalf("expected blocking rule id in ids, got %#v", drained.Events[0].RuleIDs)
	}
	if len(drained.Events[0].Rules) != 1 || drained.Events[0].Rules[0].ID != 2001 {
		t.Fatalf("expected only recorded block rule, got %#v", drained.Events[0].Rules)
	}
}

func TestRuntimeDisableClearsLoadedWAF(t *testing.T) {
	rulesDir := t.TempDir()
	writeTestRule(t, rulesDir, `SecRule ARGS:test "@streq attack" "id:1001,phase:2,deny,status:403,msg:'test block',log"`)

	rt := NewRuntime(testConfig(rulesDir, ModeBlocking), t.TempDir())
	if _, err := rt.Reload(rt.Config(), "", ""); err != nil {
		t.Fatalf("reload WAF: %v", err)
	}
	if status := rt.Status(); !status.Loaded || !status.Enabled {
		t.Fatalf("expected WAF to be loaded and enabled, got %#v", status)
	}

	cfg := rt.Config()
	cfg.Enabled = false
	if _, err := rt.SetConfig(cfg); err != nil {
		t.Fatalf("disable WAF: %v", err)
	}
	status := rt.Status()
	if status.Loaded || status.Enabled {
		t.Fatalf("expected disabled WAF to clear loaded status, got %#v", status)
	}

	req := httptest.NewRequest("GET", "https://app.example.test/search?test=attack", nil)
	decision := rt.Evaluate(req, EvaluateContext{ClientIP: "203.0.113.10"})
	if !decision.Allowed || decision.Enabled {
		t.Fatalf("expected disabled WAF to allow request without evaluation, got %#v", decision)
	}
}

func TestRuntimeDetectionOnlyAllowsAndRecordsEvent(t *testing.T) {
	rulesDir := t.TempDir()
	writeTestRule(t, rulesDir, `SecRule ARGS:test "@streq attack" "id:1001,phase:2,deny,status:403,msg:'test block',log"`)

	rt := NewRuntime(testConfig(rulesDir, ModeDetection), t.TempDir())
	if _, err := rt.Reload(rt.Config(), "", ""); err != nil {
		t.Fatalf("reload WAF: %v", err)
	}

	req := httptest.NewRequest("GET", "http://app.example.test/search?test=attack", nil)
	decision := rt.Evaluate(req, EvaluateContext{ClientIP: "203.0.113.10", RouteType: "path_rule", RouteKey: "/app"})
	if !decision.Allowed {
		t.Fatalf("expected DetectionOnly mode to allow request")
	}
	if decision.Action != "detect" {
		t.Fatalf("expected detect action, got %q", decision.Action)
	}

	drained := rt.Drain(10)
	if drained.Drained != 1 {
		t.Fatalf("expected one event, got %#v", drained)
	}
	if drained.Events[0].Action != "detect" || drained.Events[0].Mode != ModeDetection {
		t.Fatalf("unexpected event mode/action: %#v", drained.Events[0])
	}
}

func TestRuntimeRestoresRequestBodyAfterInspection(t *testing.T) {
	rulesDir := t.TempDir()
	writeTestRule(t, rulesDir, `SecRule ARGS:test "@streq attack" "id:1001,phase:2,deny,status:403,msg:'form block',log"`)

	rt := NewRuntime(testConfig(rulesDir, ModeDetection), t.TempDir())
	if _, err := rt.Reload(rt.Config(), "", ""); err != nil {
		t.Fatalf("reload WAF: %v", err)
	}

	body := "test=attack&keep=1"
	req := httptest.NewRequest("POST", "http://app.example.test/submit", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.ContentLength = int64(len(body))

	decision := rt.Evaluate(req, EvaluateContext{ClientIP: "203.0.113.10", RouteType: "path_rule", RouteKey: "/submit"})
	if !decision.Allowed {
		t.Fatalf("expected DetectionOnly mode to allow request")
	}
	restored, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read restored body: %v", err)
	}
	if string(restored) != body {
		t.Fatalf("body was not restored, got %q", string(restored))
	}
}

func TestRuntimePreservesRequestBodyLimitInterruptionAndRestoresBody(t *testing.T) {
	rulesDir := t.TempDir()
	writeTestRule(t, rulesDir, `SecRule INBOUND_DATA_ERROR "@eq 1" "id:1002,phase:2,deny,status:413,msg:'body limit',log"`)

	cfg := testConfig(rulesDir, ModeBlocking)
	cfg.RequestBodyLimitBytes = 5
	cfg.RequestBodyInMemoryLimitBytes = 5
	rt := NewRuntime(cfg, t.TempDir())
	if _, err := rt.Reload(rt.Config(), "", ""); err != nil {
		t.Fatalf("reload WAF: %v", err)
	}

	body := "0123456789abcdef"
	req := httptest.NewRequest("POST", "http://app.example.test/submit", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.ContentLength = int64(len(body))

	decision := rt.Evaluate(req, EvaluateContext{ClientIP: "203.0.113.10", RouteType: "path_rule", RouteKey: "/submit"})
	if decision.Allowed {
		t.Fatalf("expected request body limit rule to block request")
	}
	if decision.Status != 413 {
		t.Fatalf("status = %d, want 413", decision.Status)
	}
	if !slices.Contains(decision.RuleIDs, 1002) {
		t.Fatalf("expected body limit rule id, got %#v", decision.RuleIDs)
	}
	restored, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read restored body: %v", err)
	}
	if string(restored) != body {
		t.Fatalf("restored body = %q, want %q", string(restored), body)
	}
}

func TestReadAndRestoreRequestBodyLimitsInspectionBuffer(t *testing.T) {
	body := "0123456789abcdef"
	req := httptest.NewRequest("POST", "http://app.example.test/submit", strings.NewReader(body))
	tx := &recordingLimitedRequestBodyTx{limit: 5}

	if _, err := readAndRestoreRequestBody(tx, req, 5); err != nil {
		t.Fatalf("readAndRestoreRequestBody returned error: %v", err)
	}
	if tx.body != "01234" {
		t.Fatalf("inspected body = %q, want first 5 bytes", tx.body)
	}
	restored, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read restored body: %v", err)
	}
	if string(restored) != body {
		t.Fatalf("restored body = %q, want %q", string(restored), body)
	}
}

func TestValidateRejectsBundlePath(t *testing.T) {
	rulesDir := t.TempDir()
	rt := NewRuntime(testConfig(rulesDir, ModeBlocking), t.TempDir())

	result, err := rt.Validate(rt.Config(), "", "../outside")
	if err == nil {
		t.Fatalf("expected validation error")
	}
	if result.OK {
		t.Fatalf("expected validation result to be unsuccessful")
	}
}

func TestEventStoreDrainRemovesItems(t *testing.T) {
	store := NewEventStore(2, time.Minute)
	store.Add(Event{TraceID: "a"})
	store.Add(Event{TraceID: "b"})
	store.Add(Event{TraceID: "c"})

	first := store.Drain(1)
	if first.Drained != 1 || first.Events[0].TraceID != "b" || first.Remaining != 1 {
		t.Fatalf("unexpected first drain: %#v", first)
	}
	second := store.Drain(10)
	if second.Drained != 1 || second.Events[0].TraceID != "c" || second.Remaining != 0 {
		t.Fatalf("unexpected second drain: %#v", second)
	}
}

func TestEventStoreDefaultLimitIsBounded(t *testing.T) {
	store := NewEventStore(0, time.Minute)
	for i := 0; i < DefaultMaxEvents+5; i++ {
		store.Add(Event{TraceID: "trace-" + strconv.Itoa(i)})
	}

	if pending := store.Pending(); pending != DefaultMaxEvents {
		t.Fatalf("expected default event limit %d, got %d", DefaultMaxEvents, pending)
	}
}

func TestNewTraceIDUsesUUIDFormat(t *testing.T) {
	traceID := newTraceID()
	pattern := regexp.MustCompile(`^waf_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	if !pattern.MatchString(traceID) {
		t.Fatalf("expected waf UUID trace id, got %q", traceID)
	}
}

func formatTraceIDLegacyForBenchmark(uuid [16]byte) string {
	return fmt.Sprintf("waf_%x-%x-%x-%x-%x", uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:16])
}

func legacyNormalizeHost(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" {
		return ""
	}
	if strings.HasPrefix(host, "[") {
		if idx := strings.LastIndex(host, "]"); idx >= 0 {
			return host[:idx+1]
		}
	}
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		return strings.TrimSpace(strings.ToLower(parsedHost))
	}
	return host
}

func BenchmarkNormalizeHostNoPort(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		benchmarkWAFStringSink = normalizeHost("app.example.test")
	}
}

func BenchmarkNormalizeHostWithPort(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		benchmarkWAFStringSink = normalizeHost("App.Example.TEST:443")
	}
}

func BenchmarkNormalizeHostLowercaseWithPort(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		benchmarkWAFStringSink = normalizeHost("app.example.test:443")
	}
}

func BenchmarkFormatTraceID(b *testing.B) {
	uuid := [16]byte{0x7a, 0xfe, 0x10, 0x02, 0xc0, 0xff, 0x4e, 0xee, 0xaa, 0xbb, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab}
	b.ReportAllocs()
	for b.Loop() {
		benchmarkWAFStringSink = formatTraceID(uuid)
	}
}

func BenchmarkFormatTraceIDOld(b *testing.B) {
	uuid := [16]byte{0x7a, 0xfe, 0x10, 0x02, 0xc0, 0xff, 0x4e, 0xee, 0xaa, 0xbb, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab}
	b.ReportAllocs()
	for b.Loop() {
		benchmarkWAFStringSink = formatTraceIDLegacyForBenchmark(uuid)
	}
}

func BenchmarkRuntimeIsExcludedHost(b *testing.B) {
	rt := NewRuntime(models.WAFConfig{
		Enabled:       true,
		Mode:          ModeBlocking,
		DisabledHosts: []string{"app.example.test"},
	}, b.TempDir())
	req := httptest.NewRequest("GET", "https://app.example.test/dashboard", nil)

	b.ReportAllocs()
	for b.Loop() {
		benchmarkWAFBoolSink = rt.isExcluded(req)
	}
}

func BenchmarkRuntimeIsExcludedPath(b *testing.B) {
	rt := NewRuntime(models.WAFConfig{
		Enabled:              true,
		Mode:                 ModeBlocking,
		DisabledPathPrefixes: []string{"/admin"},
	}, b.TempDir())
	req := httptest.NewRequest("GET", "https://app.example.test/admin/dashboard", nil)

	b.ReportAllocs()
	for b.Loop() {
		benchmarkWAFBoolSink = rt.isExcluded(req)
	}
}

func BenchmarkRuntimeIsExcludedNoExclusions(b *testing.B) {
	rt := NewRuntime(models.WAFConfig{
		Enabled: true,
		Mode:    ModeBlocking,
	}, b.TempDir())
	req := httptest.NewRequest("GET", "https://app.example.test/dashboard", nil)

	b.ReportAllocs()
	for b.Loop() {
		benchmarkWAFBoolSink = rt.isExcluded(req)
	}
}

func BenchmarkRuntimeEvaluateDisabled(b *testing.B) {
	rt := NewRuntime(models.WAFConfig{Enabled: false, Mode: ModeOff}, b.TempDir())
	req := httptest.NewRequest("GET", "https://app.example.test/dashboard", nil)

	b.ReportAllocs()
	for b.Loop() {
		benchmarkWAFBoolSink = rt.Evaluate(req, EvaluateContext{}).Allowed
	}
}
