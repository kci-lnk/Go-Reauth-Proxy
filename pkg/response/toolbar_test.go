package response

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"go-reauth-proxy/pkg/i18n"
	"go-reauth-proxy/pkg/models"
)

var (
	toolbarBenchmarkSink          string
	toolbarBenchmarkBoolSink      bool
	toolbarBenchmarkRulesSink     []models.Rule
	toolbarBenchmarkHostRulesSink []models.HostRule
)

func disabledGatewayPortalConfigForToolbarTest(t *testing.T) models.GatewayPortalConfig {
	t.Helper()

	var cfg models.GatewayPortalConfig
	if err := json.Unmarshal([]byte(`{"enabled":false}`), &cfg); err != nil {
		t.Fatalf("unmarshal disabled gateway portal config: %v", err)
	}
	return cfg
}

func TestGenerateToolbarWithHostsEscapesDynamicRouteData(t *testing.T) {
	toolbar := GenerateToolbarWithHosts(
		[]models.Rule{{Path: `/app</script><script>alert("path")</script>`}},
		[]models.HostRule{{
			Host:    `evil.example</script><script>alert("host")</script>`,
			Title:   `Evil</script><script>alert("title")</script>`,
			Favicon: `data:image/png;base64,AAA</script><script>alert("icon")</script>`,
		}},
		`/app</script><script>alert("current")</script>`,
		`evil.example</script><script>alert("current-host")</script>`,
		"",
		models.GatewayPortalConfig{DisplayStyle: models.GatewayPortalDisplayStyleTitle, ShowAppIcon: true},
	)

	if count := strings.Count(toolbar, "</script>"); count != 1 {
		t.Fatalf("toolbar contains %d raw closing script tags, want only wrapper close: %s", count, toolbar)
	}
	for _, forbidden := range []string{
		`<script>alert("path")</script>`,
		`<script>alert("host")</script>`,
		`<script>alert("title")</script>`,
		`<script>alert("icon")</script>`,
		`<script>alert("current")</script>`,
		`<script>alert("current-host")</script>`,
	} {
		if strings.Contains(toolbar, forbidden) {
			t.Fatalf("toolbar contains unescaped dynamic script fragment %q: %s", forbidden, toolbar)
		}
	}
	if !strings.Contains(toolbar, `\u003c/script\u003e`) {
		t.Fatalf("toolbar does not contain JSON-escaped dynamic script delimiters: %s", toolbar)
	}
}

func TestGenerateToolbarPayloadIsValidJSON(t *testing.T) {
	toolbar := GenerateToolbarWithHosts(
		[]models.Rule{{Path: `/app "quoted"`}},
		[]models.HostRule{{
			Host:    `app.example.com`,
			Title:   `App <Portal>`,
			Favicon: `data:image/png;base64,AAAA`,
		}},
		`/app "quoted"`,
		`app.example.com`,
		"",
		models.GatewayPortalConfig{DisplayStyle: models.GatewayPortalDisplayStyleTitle, ShowAppIcon: true},
	)

	var payload struct {
		Rules []struct {
			Path string `json:"path"`
		} `json:"rules"`
		HostRules []struct {
			Host    string `json:"host"`
			Label   string `json:"label"`
			Favicon string `json:"favicon"`
		} `json:"host_rules"`
		CurrentPath  string        `json:"current_path"`
		CurrentHost  string        `json:"current_host"`
		IconDragMode string        `json:"icon_drag_mode"`
		ShowAppIcon  bool          `json:"show_app_icon"`
		Labels       toolbarLabels `json:"labels"`
	}
	if err := json.Unmarshal([]byte(extractToolbarPayloadForTest(t, toolbar)), &payload); err != nil {
		t.Fatalf("toolbar payload is not valid JSON: %v\n%s", err, toolbar)
	}
	if len(payload.Rules) != 1 || payload.Rules[0].Path != `/app "quoted"` {
		t.Fatalf("unexpected rules payload: %#v", payload.Rules)
	}
	if len(payload.HostRules) != 1 ||
		payload.HostRules[0].Host != "app.example.com" ||
		payload.HostRules[0].Label != "App <Portal>" ||
		payload.HostRules[0].Favicon != "data:image/png;base64,AAAA" {
		t.Fatalf("unexpected host rules payload: %#v", payload.HostRules)
	}
	if payload.CurrentPath != `/app "quoted"` || payload.CurrentHost != "app.example.com" || !payload.ShowAppIcon {
		t.Fatalf("unexpected current payload fields: %#v", payload)
	}
	if payload.IconDragMode != models.GatewayPortalIconDragModeCorners {
		t.Fatalf("icon drag mode = %q, want corners", payload.IconDragMode)
	}
}

func TestGenerateToolbarPayloadIncludesFreeIconDragMode(t *testing.T) {
	toolbar := GenerateToolbarWithHosts(
		[]models.Rule{{Path: `/app</script>`}},
		nil,
		`/app</script>`,
		"",
		"",
		models.GatewayPortalConfig{IconDragMode: models.GatewayPortalIconDragModeFree},
	)

	var payload struct {
		IconDragMode string `json:"icon_drag_mode"`
		Rules        []struct {
			Path string `json:"path"`
		} `json:"rules"`
	}
	if err := json.Unmarshal([]byte(extractToolbarPayloadForTest(t, toolbar)), &payload); err != nil {
		t.Fatalf("toolbar payload is not valid JSON: %v\n%s", err, toolbar)
	}
	if payload.IconDragMode != models.GatewayPortalIconDragModeFree {
		t.Fatalf("icon drag mode = %q, want free", payload.IconDragMode)
	}
	if len(payload.Rules) != 1 || payload.Rules[0].Path != `/app</script>` {
		t.Fatalf("unexpected escaped rule payload: %#v", payload.Rules)
	}
}

func extractToolbarPayloadForTest(t *testing.T, toolbar string) string {
	t.Helper()
	if !strings.HasPrefix(toolbar, toolbarTemplatePrefix) || !strings.HasSuffix(toolbar, toolbarTemplateSuffix) {
		t.Fatalf("toolbar does not use expected template wrapper: %s", toolbar)
	}
	return toolbar[len(toolbarTemplatePrefix) : len(toolbar)-len(toolbarTemplateSuffix)]
}

func TestGenerateToolbarWithHostsReturnsEmptyWhenPortalDisabled(t *testing.T) {
	toolbar := GenerateToolbarWithHosts(
		nil,
		[]models.HostRule{{Host: "app.example.com", Title: "App Portal"}},
		"",
		"",
		"",
		disabledGatewayPortalConfigForToolbarTest(t),
	)

	if toolbar != "" {
		t.Fatalf("toolbar = %q, want empty when portal is disabled", toolbar)
	}
}

func TestGenerateToolbarWithHostsFiltersWebSocketTargets(t *testing.T) {
	toolbar := GenerateToolbarWithHosts(
		[]models.Rule{
			{Path: "/app", Target: "http://127.0.0.1:3000"},
			{Path: "/socket", Target: "ws://127.0.0.1:3001"},
		},
		[]models.HostRule{
			{Host: "app.example.com", Target: "https://127.0.0.1:3000"},
			{Host: "socket.example.com", Target: "wss://127.0.0.1:3001"},
		},
		"",
		"",
		"",
		models.GatewayPortalConfig{DisplayStyle: models.GatewayPortalDisplayStyleTitle},
	)

	for _, want := range []string{`"path":"/app"`, `"host":"app.example.com"`} {
		if !strings.Contains(toolbar, want) {
			t.Fatalf("toolbar missing HTTP(S) route %q: %s", want, toolbar)
		}
	}
	for _, forbidden := range []string{`/socket`, `socket.example.com`} {
		if strings.Contains(toolbar, forbidden) {
			t.Fatalf("toolbar included WebSocket route %q: %s", forbidden, toolbar)
		}
	}
}

func TestIsToolbarNavigableTargetMatchesLegacyBehavior(t *testing.T) {
	cases := []string{
		"",
		" http://127.0.0.1:3000 ",
		" HTTPS://app.example.com/path?x=1 ",
		"https://app.example.com/path?x=1",
		"ws://127.0.0.1:3001",
		"wss://127.0.0.1:3001",
		"ftp://example.com",
		"http://",
		"http://:80",
		"http://[::1]:8080",
		"http://[]:8080",
		"http://exa mple.com",
		"http:example.com",
		"://example.com",
	}

	for _, tc := range cases {
		if got, want := isToolbarNavigableTarget(tc), legacyIsToolbarNavigableTarget(tc); got != want {
			t.Fatalf("isToolbarNavigableTarget(%q) = %v, want legacy %v", tc, got, want)
		}
	}
}

func TestGenerateToolbarWithHostsIncludesFaviconOnlyWhenEnabled(t *testing.T) {
	icon := "DATA:IMAGE/png;base64,AAAA"
	hostRules := []models.HostRule{{Host: "app.example.com", Title: "App Portal", Favicon: icon}}

	disabled := GenerateToolbarWithHosts(
		nil,
		hostRules,
		"",
		"",
		"",
		models.GatewayPortalConfig{DisplayStyle: models.GatewayPortalDisplayStyleTitle},
	)
	if strings.Contains(disabled, icon) {
		t.Fatalf("toolbar included favicon while app icon display disabled: %s", disabled)
	}

	enabled := GenerateToolbarWithHosts(
		nil,
		hostRules,
		"",
		"",
		"",
		models.GatewayPortalConfig{DisplayStyle: models.GatewayPortalDisplayStyleTitle, ShowAppIcon: true},
	)
	if !strings.Contains(enabled, `"favicon":"`+icon+`"`) {
		t.Fatalf("toolbar did not include favicon while app icon display enabled: %s", enabled)
	}
	if !strings.Contains(enabled, `"show_app_icon":true`) {
		t.Fatalf("toolbar did not mark app icon display as enabled: %s", enabled)
	}
}

func TestGenerateToolbarWithHostsIncludesLargeFaviconUnderLimit(t *testing.T) {
	icon := "data:image/x-icon;base64," + strings.Repeat("A", 90*1024)
	toolbar := GenerateToolbarWithHosts(
		nil,
		[]models.HostRule{{Host: "app.example.com", Title: "App Portal", Favicon: icon}},
		"",
		"",
		"",
		models.GatewayPortalConfig{DisplayStyle: models.GatewayPortalDisplayStyleTitle, ShowAppIcon: true},
	)

	if !strings.Contains(toolbar, `"favicon":"`+icon+`"`) {
		t.Fatalf("toolbar did not include large favicon under limit: %s", toolbar)
	}
}

func TestGenerateToolbarWithHostsOmitsOversizedFavicon(t *testing.T) {
	icon := "data:image/png;base64," + strings.Repeat("A", toolbarFaviconMaxBytes)
	toolbar := GenerateToolbarWithHosts(
		nil,
		[]models.HostRule{{Host: "app.example.com", Title: "App Portal", Favicon: icon}},
		"",
		"",
		"",
		models.GatewayPortalConfig{DisplayStyle: models.GatewayPortalDisplayStyleTitle, ShowAppIcon: true},
	)

	if strings.Contains(toolbar, `"favicon":`) {
		t.Fatalf("toolbar included oversized favicon field: %s", toolbar)
	}
}

func TestShouldSuppressToolbarForUserAgentCaseInsensitive(t *testing.T) {
	if !ShouldSuppressToolbarForUserAgent("Mozilla COM.TRIM.APP") {
		t.Fatal("ShouldSuppressToolbarForUserAgent() = false, want true for FN App user agent")
	}
	if !ShouldSuppressToolbarForUserAgent("FNOS Browser") {
		t.Fatal("ShouldSuppressToolbarForUserAgent() = false, want true for FNOS user agent")
	}
	if ShouldSuppressToolbarForUserAgent("Mozilla/5.0") {
		t.Fatal("ShouldSuppressToolbarForUserAgent() = true, want false for generic user agent")
	}
}

func TestGenerateToolbarWithHostsOmitsEmptyFavicon(t *testing.T) {
	toolbar := GenerateToolbarWithHosts(
		nil,
		[]models.HostRule{{Host: "app.example.com", Title: "App Portal", Favicon: "   "}},
		"",
		"",
		"",
		models.GatewayPortalConfig{DisplayStyle: models.GatewayPortalDisplayStyleTitle, ShowAppIcon: true},
	)

	if strings.Contains(toolbar, `"favicon":`) {
		t.Fatalf("toolbar included empty favicon field: %s", toolbar)
	}
}

func TestGenerateToolbarWithHostsRejectsNonDataImageFavicon(t *testing.T) {
	toolbar := GenerateToolbarWithHosts(
		nil,
		[]models.HostRule{{Host: "app.example.com", Title: "App Portal", Favicon: "xata:image/png;base64,AAAA"}},
		"",
		"",
		"",
		models.GatewayPortalConfig{DisplayStyle: models.GatewayPortalDisplayStyleTitle, ShowAppIcon: true},
	)

	if strings.Contains(toolbar, `"favicon":`) {
		t.Fatalf("toolbar included non-data-image favicon field: %s", toolbar)
	}
}

func TestGenerateToolbarWithHostsUsesPortalTitleDisplay(t *testing.T) {
	toolbar := GenerateToolbarWithHosts(
		nil,
		[]models.HostRule{{Host: "app.example.com", Title: "App Portal"}},
		"",
		"",
		"",
		models.GatewayPortalConfig{DisplayStyle: models.GatewayPortalDisplayStyleTitle},
	)

	if !strings.Contains(toolbar, `"host":"app.example.com"`) {
		t.Fatalf("toolbar did not retain host for navigation: %s", toolbar)
	}
	if !strings.Contains(toolbar, `"label":"App Portal"`) {
		t.Fatalf("toolbar did not use title label: %s", toolbar)
	}
}

func TestGenerateToolbarWithHostsFallsBackToHostWhenTitleEmpty(t *testing.T) {
	toolbar := GenerateToolbarWithHosts(
		nil,
		[]models.HostRule{{Host: "app.example.com", Title: "   "}},
		"",
		"",
		"",
		models.GatewayPortalConfig{DisplayStyle: models.GatewayPortalDisplayStyleTitle},
	)

	if !strings.Contains(toolbar, `"label":"app.example.com"`) {
		t.Fatalf("toolbar did not fall back to host label: %s", toolbar)
	}
}

func TestGenerateToolbarWithPrefilteredHostsExcludesCurrentHost(t *testing.T) {
	toolbar := GenerateToolbarWithPrefilteredHostsForLocale(
		"en",
		[]models.Rule{{Path: "/app", Target: "http://127.0.0.1:3000"}},
		[]models.HostRule{
			{Host: "app.example.com", Target: "https://127.0.0.1:3000"},
			{Host: "auth.example.com", Target: "https://127.0.0.1:3001"},
		},
		"/app",
		"app.example.com",
		"auth.example.com",
		models.GatewayPortalConfig{DisplayStyle: models.GatewayPortalDisplayStyleTitle},
	)

	if !strings.Contains(toolbar, `"host":"app.example.com"`) {
		t.Fatalf("toolbar missing included host rule: %s", toolbar)
	}
	if strings.Contains(toolbar, "auth.example.com") {
		t.Fatalf("toolbar included excluded host rule: %s", toolbar)
	}
}

func TestGenerateToolbarWithPrefilteredHostsExcludesCurrentHostCaseInsensitive(t *testing.T) {
	toolbar := GenerateToolbarWithPrefilteredHostsForLocale(
		"en",
		nil,
		[]models.HostRule{
			{Host: " App.Example.Com. ", Target: "https://127.0.0.1:3000"},
			{Host: "auth.example.com", Target: "https://127.0.0.1:3001"},
		},
		"",
		"app.example.com",
		"app.example.com",
		models.GatewayPortalConfig{DisplayStyle: models.GatewayPortalDisplayStyleTitle},
	)

	if strings.Contains(toolbar, "App.Example.Com") {
		t.Fatalf("toolbar included mixed-case excluded host rule: %s", toolbar)
	}
	if !strings.Contains(toolbar, `"host":"auth.example.com"`) {
		t.Fatalf("toolbar missing non-excluded host rule: %s", toolbar)
	}
}

func TestFilterToolbarRulesReusesAllNavigableSlice(t *testing.T) {
	rules := []models.Rule{
		{Path: "/app", Target: "https://127.0.0.1:3000"},
		{Path: "/api", Target: "http://127.0.0.1:3001"},
	}

	filtered := filterToolbarRules(rules)
	if len(filtered) != len(rules) {
		t.Fatalf("filtered length = %d, want %d", len(filtered), len(rules))
	}
	if &filtered[0] != &rules[0] {
		t.Fatalf("expected all-navigable rules to reuse original slice")
	}
}

func TestFilterToolbarRulesDropsNonNavigableTarget(t *testing.T) {
	rules := []models.Rule{
		{Path: "/app", Target: "https://127.0.0.1:3000"},
		{Path: "/socket", Target: "ws://127.0.0.1:3001"},
		{Path: "/api", Target: "http://127.0.0.1:3002"},
	}

	filtered := filterToolbarRules(rules)
	if len(filtered) != 2 || filtered[0].Path != "/app" || filtered[1].Path != "/api" {
		t.Fatalf("unexpected filtered rules: %#v", filtered)
	}
	if &filtered[0] == &rules[0] {
		t.Fatalf("expected filtered rules to allocate only after dropping an item")
	}
}

func TestFilterToolbarHostRulesReusesAllNavigableSlice(t *testing.T) {
	hostRules := []models.HostRule{
		{Host: "app.example.com", Target: "https://127.0.0.1:3000"},
		{Host: "api.example.com", Target: "http://127.0.0.1:3001"},
	}

	filtered := filterToolbarHostRules(hostRules, "")
	if len(filtered) != len(hostRules) {
		t.Fatalf("filtered length = %d, want %d", len(filtered), len(hostRules))
	}
	if &filtered[0] != &hostRules[0] {
		t.Fatalf("expected all-navigable host rules to reuse original slice")
	}
}

func TestFilterToolbarHostRulesDropsExcludedAndNonNavigableTargets(t *testing.T) {
	hostRules := []models.HostRule{
		{Host: "app.example.com", Target: "https://127.0.0.1:3000"},
		{Host: "socket.example.com", Target: "ws://127.0.0.1:3001"},
		{Host: "api.example.com", Target: "http://127.0.0.1:3002"},
	}

	filtered := filterToolbarHostRules(hostRules, "app.example.com")
	if len(filtered) != 1 || filtered[0].Host != "api.example.com" {
		t.Fatalf("unexpected filtered host rules: %#v", filtered)
	}
	if &filtered[0] == &hostRules[0] {
		t.Fatalf("expected filtered host rules to allocate only after dropping an item")
	}
}

func legacyIsToolbarNavigableTarget(rawTarget string) bool {
	target := strings.TrimSpace(rawTarget)
	if target == "" {
		return true
	}

	parsed, err := url.Parse(target)
	if err != nil || parsed.Hostname() == "" {
		return false
	}

	switch strings.ToLower(parsed.Scheme) {
	case "http", "https":
		return true
	default:
		return false
	}
}

func filterToolbarRulesOldForBenchmark(rules []models.Rule) []models.Rule {
	filtered := make([]models.Rule, 0, len(rules))
	for _, rule := range rules {
		if !isToolbarNavigableTarget(rule.Target) {
			continue
		}
		filtered = append(filtered, rule)
	}
	return filtered
}

func filterToolbarHostRulesOldForBenchmark(hostRules []models.HostRule, excludedHost string) []models.HostRule {
	normalizedExcludedHost := normalizeToolbarHost(excludedHost)
	filtered := make([]models.HostRule, 0, len(hostRules))
	for _, rule := range hostRules {
		if normalizedExcludedHost != "" && toolbarHostMatchesNormalized(rule.Host, normalizedExcludedHost) {
			continue
		}
		if !isToolbarNavigableTarget(rule.Target) {
			continue
		}
		filtered = append(filtered, rule)
	}
	return filtered
}

func generateToolbarWithPrefilteredHostsForLocaleOldForBenchmark(locale string, filteredRules []models.Rule, filteredHostRules []models.HostRule, currentPath string, currentHost string, excludedHost string, portalConfig models.GatewayPortalConfig) string {
	normalizedPortal := models.NormalizeGatewayPortalConfig(portalConfig)
	if !normalizedPortal.Enabled {
		return ""
	}
	filteredHostRules = filterToolbarHostRulesByHost(filteredHostRules, excludedHost)

	labels := toolbarLabels{
		Logout:             i18n.T(locale, "gateway.logout"),
		LogoutTitle:        i18n.T(locale, "gateway.logoutConfirmTitle"),
		LogoutMessage:      i18n.T(locale, "gateway.logoutConfirmMessage"),
		Cancel:             i18n.T(locale, "gateway.cancel"),
		Confirm:            i18n.T(locale, "gateway.confirm"),
		Go:                 i18n.T(locale, "gateway.go"),
		NoRoutesConfigured: i18n.T(locale, "gateway.noRoutesConfigured"),
	}
	return renderToolbarTemplateData(filteredRules, filteredHostRules, currentPath, currentHost, "", normalizedPortal, labels)
}

func toolbarBenchmarkRoutes(count int) ([]models.Rule, []models.HostRule) {
	rules := make([]models.Rule, 0, count)
	hostRules := make([]models.HostRule, 0, count)
	for i := 0; i < count; i++ {
		scheme := "http"
		if i%3 == 0 {
			scheme = "ws"
		}
		rules = append(rules, models.Rule{
			Path:   fmt.Sprintf("/app-%03d", i),
			Target: fmt.Sprintf("%s://127.0.0.1:%d", scheme, 3000+i),
		})

		hostScheme := "https"
		if i%3 == 0 {
			hostScheme = "wss"
		}
		hostRules = append(hostRules, models.HostRule{
			Host:   fmt.Sprintf("app-%03d.example.com", i),
			Title:  fmt.Sprintf("App %03d", i),
			Target: fmt.Sprintf("%s://127.0.0.1:%d", hostScheme, 4000+i),
		})
	}
	return rules, hostRules
}

func toolbarBenchmarkNavigableRoutes(count int) ([]models.Rule, []models.HostRule) {
	rules := make([]models.Rule, 0, count)
	hostRules := make([]models.HostRule, 0, count)
	for i := 0; i < count; i++ {
		rules = append(rules, models.Rule{
			Path:   fmt.Sprintf("/app-%03d", i),
			Target: fmt.Sprintf("https://127.0.0.1:%d", 3000+i),
		})
		hostRules = append(hostRules, models.HostRule{
			Host:   fmt.Sprintf("app-%03d.example.com", i),
			Title:  fmt.Sprintf("App %03d", i),
			Target: fmt.Sprintf("https://127.0.0.1:%d", 4000+i),
		})
	}
	return rules, hostRules
}

func BenchmarkGenerateToolbarWithHostsForLocale(b *testing.B) {
	rules, hostRules := toolbarBenchmarkRoutes(128)
	portal := models.GatewayPortalConfig{DisplayStyle: models.GatewayPortalDisplayStyleTitle}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		toolbarBenchmarkSink = GenerateToolbarWithHostsForLocale("en", rules, hostRules, "/app-001", "app-001.example.com", "app-002.example.com", portal)
	}
}

func BenchmarkGenerateToolbarWithNavigableHostsForLocale(b *testing.B) {
	rules, hostRules := toolbarBenchmarkNavigableRoutes(128)
	portal := models.GatewayPortalConfig{DisplayStyle: models.GatewayPortalDisplayStyleTitle}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		toolbarBenchmarkSink = GenerateToolbarWithHostsForLocale("en", rules, hostRules, "/app-001", "app-001.example.com", "", portal)
	}
}

func BenchmarkFilterToolbarRulesAllNavigable(b *testing.B) {
	rules, _ := toolbarBenchmarkNavigableRoutes(128)

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		toolbarBenchmarkRulesSink = filterToolbarRules(rules)
	}
}

func BenchmarkFilterToolbarRulesAllNavigableOld(b *testing.B) {
	rules, _ := toolbarBenchmarkNavigableRoutes(128)

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		toolbarBenchmarkRulesSink = filterToolbarRulesOldForBenchmark(rules)
	}
}

func BenchmarkFilterToolbarHostRulesAllNavigable(b *testing.B) {
	_, hostRules := toolbarBenchmarkNavigableRoutes(128)

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		toolbarBenchmarkHostRulesSink = filterToolbarHostRules(hostRules, "")
	}
}

func BenchmarkFilterToolbarHostRulesAllNavigableOld(b *testing.B) {
	_, hostRules := toolbarBenchmarkNavigableRoutes(128)

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		toolbarBenchmarkHostRulesSink = filterToolbarHostRulesOldForBenchmark(hostRules, "")
	}
}

func BenchmarkGenerateToolbarWithPrefilteredHostsForLocale(b *testing.B) {
	rules, hostRules := toolbarBenchmarkRoutes(128)
	filteredRules := filterToolbarRules(rules)
	filteredHostRules := filterToolbarHostRules(hostRules, "")
	portal := models.GatewayPortalConfig{DisplayStyle: models.GatewayPortalDisplayStyleTitle}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		toolbarBenchmarkSink = GenerateToolbarWithPrefilteredHostsForLocale("en", filteredRules, filteredHostRules, "/app-001", "app-001.example.com", "app-002.example.com", portal)
	}
}

func BenchmarkGenerateToolbarWithPrefilteredHostsForLocaleOld(b *testing.B) {
	rules, hostRules := toolbarBenchmarkRoutes(128)
	filteredRules := filterToolbarRules(rules)
	filteredHostRules := filterToolbarHostRules(hostRules, "")
	portal := models.GatewayPortalConfig{DisplayStyle: models.GatewayPortalDisplayStyleTitle}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		toolbarBenchmarkSink = generateToolbarWithPrefilteredHostsForLocaleOldForBenchmark("en", filteredRules, filteredHostRules, "/app-001", "app-001.example.com", "app-002.example.com", portal)
	}
}

func BenchmarkShouldSuppressToolbarForUserAgent(b *testing.B) {
	userAgent := "Mozilla COM.TRIM.APP"

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		toolbarBenchmarkBoolSink = ShouldSuppressToolbarForUserAgent(userAgent)
	}
}

func BenchmarkShouldSuppressToolbarForUserAgentOld(b *testing.B) {
	userAgent := "Mozilla COM.TRIM.APP"

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		normalized := strings.ToLower(strings.TrimSpace(userAgent))
		toolbarBenchmarkBoolSink = strings.Contains(normalized, "com.trim.app") ||
			strings.Contains(normalized, "com.trim.media") ||
			strings.Contains(normalized, "fnos")
	}
}

func BenchmarkGatewayPortalHostFavicon(b *testing.B) {
	rule := models.HostRule{Favicon: "DATA:IMAGE/png;base64,AAAA"}
	portal := models.GatewayPortalConfig{ShowAppIcon: true}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		toolbarBenchmarkSink = GatewayPortalHostFavicon(rule, portal)
	}
}

func BenchmarkGatewayPortalHostFaviconOld(b *testing.B) {
	rule := models.HostRule{Favicon: "DATA:IMAGE/png;base64,AAAA"}
	portal := models.GatewayPortalConfig{ShowAppIcon: true}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		favicon := strings.TrimSpace(rule.Favicon)
		if !models.NormalizeGatewayPortalConfig(portal).ShowAppIcon || !strings.HasPrefix(strings.ToLower(favicon), "data:image/") {
			toolbarBenchmarkSink = ""
			continue
		}
		toolbarBenchmarkSink = favicon
	}
}

func BenchmarkNormalizeToolbarHostMixedCase(b *testing.B) {
	host := " App-001.EXAMPLE.Com. "

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		toolbarBenchmarkSink = normalizeToolbarHost(host)
	}
}

func BenchmarkNormalizeToolbarHostMixedCaseOld(b *testing.B) {
	host := " App-001.EXAMPLE.Com. "

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		toolbarBenchmarkSink = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	}
}

func BenchmarkFilterToolbarHostRulesByHostMixedCaseNoMatch(b *testing.B) {
	_, hostRules := toolbarBenchmarkRoutes(128)
	for i := range hostRules {
		hostRules[i].Host = strings.ToUpper(hostRules[i].Host) + "."
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		toolbarBenchmarkHostRulesSink = filterToolbarHostRulesByHost(hostRules, "auth.example.com")
	}
}

func BenchmarkFilterToolbarHostRulesByHostMixedCaseNoMatchOld(b *testing.B) {
	_, hostRules := toolbarBenchmarkRoutes(128)
	for i := range hostRules {
		hostRules[i].Host = strings.ToUpper(hostRules[i].Host) + "."
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		toolbarBenchmarkHostRulesSink = legacyFilterToolbarHostRulesByHost(hostRules, "auth.example.com")
	}
}

func legacyNormalizeToolbarHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}

func legacyFilterToolbarHostRulesByHost(hostRules []models.HostRule, excludedHost string) []models.HostRule {
	normalizedExcludedHost := legacyNormalizeToolbarHost(excludedHost)
	if normalizedExcludedHost == "" {
		return hostRules
	}

	for i, rule := range hostRules {
		if legacyNormalizeToolbarHost(rule.Host) == normalizedExcludedHost {
			filtered := make([]models.HostRule, 0, len(hostRules)-1)
			filtered = append(filtered, hostRules[:i]...)
			filtered = append(filtered, hostRules[i+1:]...)
			return filtered
		}
	}
	return hostRules
}
