package proxy

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"go-reauth-proxy/pkg/config"
	"go-reauth-proxy/pkg/gatewaylog"
	"go-reauth-proxy/pkg/models"
)

func TestSetProxyProtocolForceInvokesHookWhenChanged(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	calls := 0
	handler.SetProxyProtocolForceChangeHook(func() { calls++ })
	if err := handler.SetProxyProtocolForce(true); err != nil {
		t.Fatalf("SetProxyProtocolForce() returned error: %v", err)
	}
	if calls != 1 || !handler.GetProxyProtocolForce() {
		t.Fatalf("calls=%d force=%v, want one hook and enabled", calls, handler.GetProxyProtocolForce())
	}
}

func TestSetProxyProtocolForceSkipsHookWhenUnchanged(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	if err := handler.SetProxyProtocolForce(false); err != nil {
		t.Fatalf("SetProxyProtocolForce() returned error: %v", err)
	}
	calls := 0
	handler.SetProxyProtocolForceChangeHook(func() { calls++ })
	if err := handler.SetProxyProtocolForce(false); err != nil {
		t.Fatalf("SetProxyProtocolForce() returned error: %v", err)
	}
	if calls != 0 {
		t.Fatalf("hook calls = %d, want 0", calls)
	}
}

func TestSetGatewayListenerConfigDoesNotPersistWhenRuntimeApplyFails(t *testing.T) {
	handler, manager := newAdditionalProxyTestHandler(t)
	previous := handler.GetGatewayListenerConfig()
	nextScope := models.GatewayListenerScopeLoopback
	if previous.Scope == nextScope {
		nextScope = models.GatewayListenerScopeAll
	}

	var applied models.GatewayListenerConfig
	handler.SetGatewayListenerConfigChangeHook(func(candidate models.GatewayListenerConfig) error {
		applied = candidate
		if got := handler.GetGatewayListenerConfig(); got != previous {
			t.Fatalf("runtime hook observed listener config %#v, want previous %#v", got, previous)
		}
		return errors.New("listener port is unavailable")
	})

	err := handler.SetGatewayListenerConfig(models.GatewayListenerConfig{Scope: nextScope})
	if err == nil {
		t.Fatal("SetGatewayListenerConfig() succeeded after a failed runtime apply")
	}
	if applied.Scope != nextScope {
		t.Fatalf("runtime hook candidate = %#v, want scope %q", applied, nextScope)
	}
	if got := handler.GetGatewayListenerConfig(); got != previous {
		t.Fatalf("listener config after failed runtime apply = %#v, want %#v", got, previous)
	}
	stored, loadErr := manager.Load()
	if loadErr != nil {
		t.Fatalf("Load() returned error: %v", loadErr)
	}
	if got := stored.GatewayListener; got != previous {
		t.Fatalf("persisted listener config after failed runtime apply = %#v, want %#v", got, previous)
	}
}

func TestSetGatewayListenerConfigPersistsOnlyAfterRuntimeApplySucceeds(t *testing.T) {
	handler, manager := newAdditionalProxyTestHandler(t)
	previous := handler.GetGatewayListenerConfig()
	nextScope := models.GatewayListenerScopeLoopback
	if previous.Scope == nextScope {
		nextScope = models.GatewayListenerScopeAll
	}

	calls := 0
	handler.SetGatewayListenerConfigChangeHook(func(candidate models.GatewayListenerConfig) error {
		calls++
		if candidate.Scope != nextScope {
			t.Fatalf("runtime hook candidate = %#v, want scope %q", candidate, nextScope)
		}
		if got := handler.GetGatewayListenerConfig(); got != previous {
			t.Fatalf("runtime hook observed listener config %#v, want previous %#v", got, previous)
		}
		return nil
	})

	if err := handler.SetGatewayListenerConfig(models.GatewayListenerConfig{Scope: nextScope}); err != nil {
		t.Fatalf("SetGatewayListenerConfig() returned error: %v", err)
	}
	if calls != 1 {
		t.Fatalf("runtime hook calls = %d, want 1", calls)
	}
	if got := handler.GetGatewayListenerConfig().Scope; got != nextScope {
		t.Fatalf("listener scope = %q, want %q", got, nextScope)
	}
	stored, loadErr := manager.Load()
	if loadErr != nil {
		t.Fatalf("Load() returned error: %v", loadErr)
	}
	if got := stored.GatewayListener.Scope; got != nextScope {
		t.Fatalf("persisted listener scope = %q, want %q", got, nextScope)
	}
}

func TestSetDefaultRouteEmptyResetsToSelect(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	if err := handler.SetDefaultRoute(""); err != nil {
		t.Fatalf("SetDefaultRoute() returned error: %v", err)
	}
	if got := handler.GetDefaultRoute(); got != "/__select__" {
		t.Fatalf("DefaultRoute = %q", got)
	}
}

func TestSetDefaultRoutePersistsToConfig(t *testing.T) {
	handler, manager := newAdditionalProxyTestHandler(t)
	if err := handler.SetRules([]models.Rule{{Path: "/app", Target: "http://127.0.0.1:8080"}}); err != nil {
		t.Fatalf("SetRules() returned error: %v", err)
	}
	if err := handler.SetDefaultRoute("/app"); err != nil {
		t.Fatalf("SetDefaultRoute() returned error: %v", err)
	}
	cfg, err := manager.Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if cfg.DefaultRoute != "/app" {
		t.Fatalf("persisted DefaultRoute = %q", cfg.DefaultRoute)
	}
}

func TestSetAuthConfigNormalizesDefaultsAndTrimmedFields(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	err := handler.SetAuthConfig(models.AuthConfig{
		PublicAuthBaseURL:     " https://auth.example.test/// ",
		AuthHost:              " App.Example.Test:443 ",
		AuthCacheTTL:          -1,
		AuthCacheFailTTL:      -1,
		PublicHTTPPort:        -80,
		PublicHTTPSPort:       -443,
		EdgeClientIPEnabled:   true,
		AliyunESAEnabled:      true,
		TencentEdgeOneEnabled: true,
	})
	if err != nil {
		t.Fatalf("SetAuthConfig() returned error: %v", err)
	}
	got := handler.GetAuthConfig()
	if got.AuthPort != 7997 || got.AuthURL != "/api/auth/verify" || got.LoginURL != "/login" || got.PreflightURL != "/api/auth/preflight" {
		t.Fatalf("auth defaults not applied: %#v", got)
	}
	if got.PublicAuthBaseURL != "https://auth.example.test///" || got.AuthHost != "app.example.test" {
		t.Fatalf("auth fields not normalized: %#v", got)
	}
	if got.AuthCacheTTL != 0 || got.AuthCacheFailTTL != 0 || got.PublicHTTPPort != 0 || got.PublicHTTPSPort != 0 {
		t.Fatalf("negative auth values not clamped: %#v", got)
	}
	if got.AliyunESAEnabled || !got.TencentEdgeOneEnabled {
		t.Fatalf("edge vendor mutual exclusion not applied: %#v", got)
	}
}

func TestSetReverseProxyThrottleNormalizesInvalidEnabledValues(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	err := handler.SetReverseProxyThrottle(models.ReverseProxyThrottleConfig{Enabled: true})
	if err != nil {
		t.Fatalf("SetReverseProxyThrottle() returned error: %v", err)
	}
	got := handler.GetReverseProxyThrottle()
	if !got.Enabled || got.RequestsPerSecond <= 0 || got.Burst <= 0 || got.BlockSeconds <= 0 {
		t.Fatalf("throttle config = %#v", got)
	}
}

func TestSetGatewayVisibilityStoresCopy(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	if err := handler.SetGatewayVisibility(models.GatewayVisibilityConfig{Enabled: true, CIDRs: []string{"192.168.0.0/16"}}); err != nil {
		t.Fatalf("SetGatewayVisibility() returned error: %v", err)
	}
	got := handler.GetGatewayVisibility()
	got.CIDRs[0] = "10.0.0.0/8"
	if handler.GetGatewayVisibility().CIDRs[0] != "192.168.0.0/16" {
		t.Fatal("GetGatewayVisibility() did not return a defensive copy")
	}
}

func TestSetForwardedHeadersConfigStoresCopy(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	if err := handler.SetForwardedHeadersConfig(models.ForwardedHeadersConfig{Enabled: true, OmitTargets: []string{"http://127.0.0.1:8080"}}); err != nil {
		t.Fatalf("SetForwardedHeadersConfig() returned error: %v", err)
	}
	got := handler.GetForwardedHeadersConfig()
	got.OmitTargets[0] = "http://127.0.0.1:9090"
	if handler.GetForwardedHeadersConfig().OmitTargets[0] == "http://127.0.0.1:9090" {
		t.Fatal("GetForwardedHeadersConfig() did not return a defensive copy")
	}
}

func TestSetPreserveHostConfigStoresCopy(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	if err := handler.SetPreserveHostConfig(models.PreserveHostConfig{Enabled: true, OmitTargets: []string{"http://127.0.0.1:8080"}}); err != nil {
		t.Fatalf("SetPreserveHostConfig() returned error: %v", err)
	}
	got := handler.GetPreserveHostConfig()
	got.OmitTargets[0] = "http://127.0.0.1:9090"
	if handler.GetPreserveHostConfig().OmitTargets[0] == "http://127.0.0.1:9090" {
		t.Fatal("GetPreserveHostConfig() did not return a defensive copy")
	}
}

func TestSetCrawlerBlockerConfigTrimsUpdatedAt(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	got, err := handler.SetCrawlerBlockerConfig(models.CrawlerBlockerConfig{Enabled: true, UpdatedAt: " now "})
	if err != nil {
		t.Fatalf("SetCrawlerBlockerConfig() returned error: %v", err)
	}
	if !got.Enabled || got.UpdatedAt != "now" {
		t.Fatalf("crawler blocker config = %#v", got)
	}
}

func TestSetGatewayPortalConfigNormalizesInvalidValues(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	got, err := handler.SetGatewayPortalConfig(models.GatewayPortalConfig{DisplayStyle: "bad", IconDragMode: "bad"})
	if err != nil {
		t.Fatalf("SetGatewayPortalConfig() returned error: %v", err)
	}
	if !got.Enabled || got.DisplayStyle != models.GatewayPortalDisplayStyleDomain || got.IconDragMode != models.GatewayPortalIconDragModeCorners {
		t.Fatalf("gateway portal config = %#v", got)
	}
}

func TestSetFnosPortIconHijackConfigTrimsUpdatedAt(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	got, err := handler.SetFnosPortIconHijackConfig(models.FnosPortIconHijackConfig{Enabled: true, UpdatedAt: " t "})
	if err != nil {
		t.Fatalf("SetFnosPortIconHijackConfig() returned error: %v", err)
	}
	if !got.Enabled || got.UpdatedAt != "t" {
		t.Fatalf("fnos hijack config = %#v", got)
	}
}

func TestSetReverseProxyThrottleExemptIPsNormalizesRuntime(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	handler.SetReverseProxyThrottleExemptIPs(models.ReverseProxyThrottleExemptIPsRuntime{
		Enabled: true,
		IPs:     []string{" 198.51.100.7 ", "bad"},
		CIDRs:   []string{"192.168.0.0/16"},
	})
	got := handler.GetReverseProxyThrottleExemptIPs()
	if !got.Enabled || len(got.IPs) != 1 || got.IPs[0] != "198.51.100.7" || len(got.CIDRs) != 1 {
		t.Fatalf("exempt IP runtime = %#v", got)
	}
}

func TestSetCommonLocationExemptionsNormalizesRuntime(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	handler.SetCommonLocationExemptions(models.CommonLocationExemptionsRuntime{
		Enabled: true,
		CIDRs:   []string{"192.168.0.0/16", "bad"},
	})
	got := handler.GetCommonLocationExemptions()
	if !got.Enabled || len(got.CIDRs) != 1 || got.CIDRs[0] != "192.168.0.0/16" {
		t.Fatalf("common location exemptions = %#v", got)
	}
}

func TestAddRuleAppendsPathRule(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	if err := handler.AddRule(models.Rule{Path: "/app", Target: "http://127.0.0.1:8080"}); err != nil {
		t.Fatalf("AddRule() returned error: %v", err)
	}
	rules := handler.GetRules()
	if len(rules) != 1 || rules[0].Path != "/app" {
		t.Fatalf("rules = %#v", rules)
	}
}

func TestAddRuleUpdatesExistingPathRule(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	if err := handler.AddRule(models.Rule{Path: "/app", Target: "http://127.0.0.1:8080"}); err != nil {
		t.Fatalf("AddRule() returned error: %v", err)
	}
	if err := handler.AddRule(models.Rule{Path: "/app", Target: "http://127.0.0.1:8081"}); err != nil {
		t.Fatalf("AddRule(update) returned error: %v", err)
	}
	rules := handler.GetRules()
	if len(rules) != 1 || rules[0].Target != "http://127.0.0.1:8081" {
		t.Fatalf("rules = %#v", rules)
	}
}

func TestSetRulesDeduplicatesByPathKeepingLast(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	err := handler.SetRules([]models.Rule{
		{Path: "/app", Target: "http://127.0.0.1:8080"},
		{Path: "/app", Target: "http://127.0.0.1:8081"},
	})
	if err != nil {
		t.Fatalf("SetRules() returned error: %v", err)
	}
	rules := handler.GetRules()
	if len(rules) != 1 || rules[0].Target != "http://127.0.0.1:8081" {
		t.Fatalf("rules = %#v", rules)
	}
}

func TestRemoveRuleDeletesMatchingPath(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	if err := handler.SetRules([]models.Rule{{Path: "/app", Target: "http://127.0.0.1:8080"}}); err != nil {
		t.Fatalf("SetRules() returned error: %v", err)
	}
	handler.RemoveRule("/app")
	if got := handler.GetRules(); len(got) != 0 {
		t.Fatalf("rules after remove = %#v", got)
	}
}

func TestFlushRulesClearsPathRules(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	if err := handler.SetRules([]models.Rule{{Path: "/app", Target: "http://127.0.0.1:8080"}}); err != nil {
		t.Fatalf("SetRules() returned error: %v", err)
	}
	if err := handler.FlushRules(); err != nil {
		t.Fatalf("FlushRules() returned error: %v", err)
	}
	if got := handler.GetRules(); len(got) != 0 {
		t.Fatalf("rules after flush = %#v", got)
	}
}

func TestAddHostRuleNormalizesHostAndAppends(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	err := handler.AddHostRule(models.HostRule{Host: " App.Example.Test:443 ", Target: "http://127.0.0.1:8080"})
	if err != nil {
		t.Fatalf("AddHostRule() returned error: %v", err)
	}
	rules := handler.GetHostRules()
	if len(rules) != 1 || rules[0].Host != "app.example.test" {
		t.Fatalf("host rules = %#v", rules)
	}
}

func TestSetHostRulesKeepsOnlyFirstDefault(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	err := handler.SetHostRules([]models.HostRule{
		{Host: "a.example.test", Target: "http://127.0.0.1:8080", IsDefault: true},
		{Host: "b.example.test", Target: "http://127.0.0.1:8081", IsDefault: true},
	})
	if err != nil {
		t.Fatalf("SetHostRules() returned error: %v", err)
	}
	rules := handler.GetHostRules()
	if len(rules) != 2 || !rules[0].IsDefault || rules[1].IsDefault {
		t.Fatalf("host rules = %#v", rules)
	}
}

func TestGetHostRulesDeepCopiesLocations(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	err := handler.SetHostRules([]models.HostRule{{
		Host:   "app.example.test",
		Target: "http://127.0.0.1:8080",
		Locations: []models.HostLocation{{
			Path: "/api", Action: models.HostLocationActionResponse, Response: models.HostLocationResponse{Status: 200, Headers: map[string]string{"X-Test": "a"}},
		}},
	}})
	if err != nil {
		t.Fatalf("SetHostRules() returned error: %v", err)
	}
	got := handler.GetHostRules()
	got[0].Locations[0].Response.Headers["X-Test"] = "b"
	if handler.GetHostRules()[0].Locations[0].Response.Headers["X-Test"] != "a" {
		t.Fatal("GetHostRules() did not deep-copy location response headers")
	}
}

func TestFlushHostRulesClearsHostRules(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	if err := handler.SetHostRules([]models.HostRule{{Host: "app.example.test", Target: "http://127.0.0.1:8080"}}); err != nil {
		t.Fatalf("SetHostRules() returned error: %v", err)
	}
	if err := handler.FlushHostRules(); err != nil {
		t.Fatalf("FlushHostRules() returned error: %v", err)
	}
	if got := handler.GetHostRules(); len(got) != 0 {
		t.Fatalf("host rules after flush = %#v", got)
	}
}

func TestValidateStreamRulesDefaultsProtocolToTCP(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	rules, err := handler.ValidateStreamRules([]models.StreamRule{{ListenPort: 3306, Target: "127.0.0.1:3307"}})
	if err != nil {
		t.Fatalf("ValidateStreamRules() returned error: %v", err)
	}
	if rules[0].Protocol != models.StreamProtocolTCP {
		t.Fatalf("protocol = %q", rules[0].Protocol)
	}
}

func TestValidateStreamRulesRejectsReservedAdminPort(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	_, err := handler.ValidateStreamRules([]models.StreamRule{{Protocol: "tcp", ListenPort: 7996, Target: "127.0.0.1:3307"}})
	if err == nil {
		t.Fatal("ValidateStreamRules() accepted admin port")
	}
}

func TestValidateStreamRulesRejectsSameLocalTargetPort(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	_, err := handler.ValidateStreamRules([]models.StreamRule{{Protocol: "tcp", ListenPort: 3306, Target: "127.0.0.1:3306"}})
	if err == nil {
		t.Fatal("ValidateStreamRules() accepted same local target port")
	}
}

func TestSetStreamRulesPersistsNormalizedRules(t *testing.T) {
	handler, manager := newAdditionalProxyTestHandler(t)
	err := handler.SetStreamRules([]models.StreamRule{{ListenPort: 3306, Target: "127.0.0.1:3307"}})
	if err != nil {
		t.Fatalf("SetStreamRules() returned error: %v", err)
	}
	cfg, err := manager.Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if len(cfg.StreamRules) != 1 || cfg.StreamRules[0].Protocol != models.StreamProtocolTCP {
		t.Fatalf("persisted stream rules = %#v", cfg.StreamRules)
	}
}

func TestFlushStreamRulesClearsStreamRules(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	if err := handler.SetStreamRules([]models.StreamRule{{Protocol: "udp", ListenPort: 5353, Target: "127.0.0.1:5354"}}); err != nil {
		t.Fatalf("SetStreamRules() returned error: %v", err)
	}
	if err := handler.FlushStreamRules(); err != nil {
		t.Fatalf("FlushStreamRules() returned error: %v", err)
	}
	if got := handler.GetStreamRules(); len(got) != 0 {
		t.Fatalf("stream rules after flush = %#v", got)
	}
}

func TestSetLoggingConfigDefaultsMaxDays(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	info, err := handler.SetLoggingConfig(models.LoggingConfig{Enabled: true})
	if err != nil {
		t.Fatalf("SetLoggingConfig() returned error: %v", err)
	}
	if !info.Enabled || info.MaxDays != gatewaylog.DefaultMaxDays {
		t.Fatalf("logging info = %#v", info)
	}
}

func TestGetLoggingDirectoryReturnsLogsDir(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	if got := handler.GetLoggingDirectory(); got.LogsDir == "" {
		t.Fatalf("GetLoggingDirectory() = %#v", got)
	}
}

func TestAddStreamTrafficUpdatesTotalsAnd5xx(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	handler.AddStreamTraffic(10, 20, 502)
	stats := handler.GetTrafficStats(time.Now())
	if stats.TotalIn != 10 || stats.TotalOut != 20 || stats.Error5xx != 1 {
		t.Fatalf("traffic stats = %#v", stats)
	}
}

func TestIsClientIPVisibleUsesGatewayVisibility(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	if err := handler.SetGatewayVisibility(models.GatewayVisibilityConfig{Enabled: true, CIDRs: []string{"198.51.100.0/24"}}); err != nil {
		t.Fatalf("SetGatewayVisibility() returned error: %v", err)
	}
	if !handler.IsClientIPVisible("198.51.100.7") || handler.IsClientIPVisible("203.0.113.7") {
		t.Fatalf("visibility mismatch")
	}
}

func TestLogGatewayEntryWritesWhenLoggingEnabled(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	if _, err := handler.SetLoggingConfig(models.LoggingConfig{Enabled: true}); err != nil {
		t.Fatalf("SetLoggingConfig() returned error: %v", err)
	}
	handler.LogGatewayEntry(gatewaylog.Entry{Method: "GET", Path: "/logged", Status: 200})
	result, err := handler.QueryLogEntries("", 1, 20, "/logged", "200", "", "", "", "page")
	if err != nil {
		t.Fatalf("QueryLogEntries() returned error: %v", err)
	}
	if result.Total != 1 {
		t.Fatalf("query result = %#v", result)
	}
}

func TestDrainWAFEventsReturnsEmptyWhenNoEvents(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	result := handler.DrainWAFEvents(10)
	if len(result.Events) != 0 {
		t.Fatalf("DrainWAFEvents() = %#v", result)
	}
}

func newAdditionalProxyTestHandler(t *testing.T) (*Handler, *config.Manager) {
	t.Helper()
	configPath := filepath.Join(t.TempDir(), "config.json")
	manager := config.NewManager(configPath)
	initialCfg, err := manager.Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	handler := NewHandler(7996, 7999, manager, initialCfg, filepath.Join(t.TempDir(), "logs"), nil)
	t.Cleanup(handler.gatewayLogManager.Close)
	return handler, manager
}
