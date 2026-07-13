package proxy

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"go-reauth-proxy/pkg/models"
)

func TestSetHostRulesNormalizesAndDeepCopiesVisibility(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	rules := []models.HostRule{{
		Host:   "app.example.test",
		Target: "http://127.0.0.1:8080",
		Visibility: models.HostRuleVisibility{
			Mode:  " CUSTOM ",
			CIDRs: []string{"1.1.1.7/24", "1.1.1.0/24"},
		},
	}}
	if err := handler.SetHostRules(rules); err != nil {
		t.Fatalf("SetHostRules() returned error: %v", err)
	}
	rules[0].Visibility.CIDRs[0] = "8.8.8.0/24"

	want := models.HostRuleVisibility{
		Mode:  models.HostVisibilityModeCustom,
		CIDRs: []string{"1.1.1.0/24"},
	}
	got := handler.GetHostRules()
	if !reflect.DeepEqual(got[0].Visibility, want) {
		t.Fatalf("visibility = %#v, want %#v", got[0].Visibility, want)
	}
	got[0].Visibility.CIDRs[0] = "9.9.9.0/24"
	if current := handler.GetHostRules()[0].Visibility; !reflect.DeepEqual(current, want) {
		t.Fatalf("GetHostRules() did not return a defensive visibility copy: %#v", current)
	}
}

func TestSetHostRulesPreservesDisabledVisibility(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	if err := handler.SetHostRules([]models.HostRule{{
		Host:       "app.example.test",
		Target:     "http://127.0.0.1:8080",
		Visibility: models.HostRuleVisibility{Mode: " DISABLED "},
	}}); err != nil {
		t.Fatalf("SetHostRules() returned error: %v", err)
	}
	if got := handler.GetHostRules()[0].Visibility.Mode; got != models.HostVisibilityModeDisabled {
		t.Fatalf("visibility mode = %q, want %q", got, models.HostVisibilityModeDisabled)
	}
}

func TestSetHostRulesRejectsInvalidCustomVisibility(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	for name, visibility := range map[string]models.HostRuleVisibility{
		"empty":   {Mode: models.HostVisibilityModeCustom},
		"invalid": {Mode: models.HostVisibilityModeCustom, CIDRs: []string{"not-a-cidr"}},
	} {
		t.Run(name, func(t *testing.T) {
			err := handler.SetHostRules([]models.HostRule{{
				Host:       "app.example.test",
				Target:     "http://127.0.0.1:8080",
				Visibility: visibility,
			}})
			if err == nil {
				t.Fatal("SetHostRules() returned nil error")
			}
		})
	}
}

func TestSetHostRulesPreservesVisibilityWhenLegacyUpdateOmitsIt(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	if err := handler.SetHostRules([]models.HostRule{{
		Host:       "app.example.test",
		Target:     "http://127.0.0.1:8080",
		Visibility: models.HostRuleVisibility{Mode: models.HostVisibilityModeCustom, CIDRs: []string{"1.1.1.0/24"}},
	}}); err != nil {
		t.Fatalf("initial SetHostRules() returned error: %v", err)
	}
	if err := handler.SetHostRules([]models.HostRule{{
		Host:   "app.example.test",
		Target: "http://127.0.0.1:8081",
	}}); err != nil {
		t.Fatalf("legacy SetHostRules() returned error: %v", err)
	}

	want := models.HostRuleVisibility{Mode: models.HostVisibilityModeCustom, CIDRs: []string{"1.1.1.0/24"}}
	if got := handler.GetHostRules()[0].Visibility; !reflect.DeepEqual(got, want) {
		t.Fatalf("visibility = %#v, want preserved %#v", got, want)
	}
}

func TestHostVisibilityCustomRulesReplaceGlobalRules(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	if err := handler.SetGatewayVisibility(models.GatewayVisibilityConfig{
		Enabled: true,
		CIDRs:   []string{"8.8.8.0/24"},
	}); err != nil {
		t.Fatalf("SetGatewayVisibility() returned error: %v", err)
	}
	if err := handler.SetHostRules([]models.HostRule{
		{
			Host:       "custom.example.test",
			Target:     "http://127.0.0.1:8080",
			Visibility: models.HostRuleVisibility{Mode: models.HostVisibilityModeCustom, CIDRs: []string{"1.1.1.0/24"}},
		},
		{
			Host:       "inherit.example.test",
			Target:     "http://127.0.0.1:8081",
			Visibility: models.HostRuleVisibility{Mode: models.HostVisibilityModeInherit},
		},
	}); err != nil {
		t.Fatalf("SetHostRules() returned error: %v", err)
	}

	snapshot := handler.snapshotForRequest()
	customRequest := httptest.NewRequest("GET", "http://custom.example.test/", nil)
	customRule := matchHostRule(customRequest, snapshot)
	if !handler.IsClientIPVisibleForHost("1.1.1.7", customRule, snapshot) {
		t.Fatal("custom host denied an IP in its own CIDR")
	}
	if handler.IsClientIPVisibleForHost("8.8.8.7", customRule, snapshot) {
		t.Fatal("custom host incorrectly merged the global CIDR")
	}
	if !handler.IsClientIPVisibleForHost("127.0.0.1", customRule, snapshot) {
		t.Fatal("custom host did not preserve the loopback exemption")
	}

	inheritRequest := httptest.NewRequest("GET", "http://inherit.example.test/", nil)
	inheritRule := matchHostRule(inheritRequest, snapshot)
	if !handler.IsClientIPVisibleForHost("8.8.8.7", inheritRule, snapshot) {
		t.Fatal("inherited host denied an IP in the global CIDR")
	}
	if handler.IsClientIPVisibleForHost("1.1.1.7", inheritRule, snapshot) {
		t.Fatal("inherited host incorrectly used another host's custom CIDR")
	}

	unmatchedRequest := httptest.NewRequest("GET", "http://missing.example.test/", nil)
	if rule := matchHostRule(unmatchedRequest, snapshot); rule != nil {
		t.Fatalf("unmatched request unexpectedly matched %#v", rule)
	}
	if !handler.IsClientIPVisibleForHost("8.8.8.7", nil, snapshot) {
		t.Fatal("unmatched host did not inherit global visibility")
	}
	if handler.IsClientIPVisibleForHost("1.1.1.7", nil, snapshot) {
		t.Fatal("unmatched host incorrectly used custom visibility")
	}

	if err := handler.SetGatewayVisibility(models.GatewayVisibilityConfig{Enabled: false}); err != nil {
		t.Fatalf("disabling gateway visibility returned error: %v", err)
	}
	if !handler.IsClientIPVisibleForHost("9.9.9.9", customRule, snapshot) {
		t.Fatal("disabled global switch did not pause custom host visibility")
	}
}

func TestEmptyEnabledGlobalVisibilityAllowsOnlyCustomHostRules(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	if err := handler.SetGatewayVisibility(models.GatewayVisibilityConfig{Enabled: true}); err != nil {
		t.Fatalf("SetGatewayVisibility() returned error: %v", err)
	}
	if err := handler.SetHostRules([]models.HostRule{
		{
			Host:       "custom.example.test",
			Target:     "http://127.0.0.1:8080",
			Visibility: models.HostRuleVisibility{Mode: models.HostVisibilityModeCustom, CIDRs: []string{"1.1.1.0/24"}},
		},
		{
			Host:       "inherit.example.test",
			Target:     "http://127.0.0.1:8081",
			Visibility: models.HostRuleVisibility{Mode: models.HostVisibilityModeInherit},
		},
	}); err != nil {
		t.Fatalf("SetHostRules() returned error: %v", err)
	}

	snapshot := handler.snapshotForRequest()
	customRule := matchHostRule(
		httptest.NewRequest("GET", "http://custom.example.test/", nil),
		snapshot,
	)
	if !handler.IsClientIPVisibleForHost("1.1.1.7", customRule, snapshot) {
		t.Fatal("custom host denied an IP in its own CIDR when global rules were empty")
	}

	inheritRule := matchHostRule(
		httptest.NewRequest("GET", "http://inherit.example.test/", nil),
		snapshot,
	)
	if handler.IsClientIPVisibleForHost("1.1.1.7", inheritRule, snapshot) {
		t.Fatal("inherited host allowed a public IP while global rules were empty")
	}
	if handler.IsClientIPVisibleForHost("1.1.1.7", nil, snapshot) {
		t.Fatal("unmatched host allowed a public IP while global rules were empty")
	}
	if !handler.IsClientIPVisibleForHost("127.0.0.1", inheritRule, snapshot) {
		t.Fatal("empty global rules did not preserve the loopback exemption")
	}
}

func TestDisabledHostVisibilityOverridesGlobalRules(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	if err := handler.SetGatewayVisibility(models.GatewayVisibilityConfig{
		Enabled: true,
		CIDRs:   []string{"8.8.8.0/24"},
	}); err != nil {
		t.Fatalf("SetGatewayVisibility() returned error: %v", err)
	}
	if err := handler.SetHostRules([]models.HostRule{{
		Host:       "disabled.example.test",
		Target:     "http://127.0.0.1:8080",
		Visibility: models.HostRuleVisibility{Mode: models.HostVisibilityModeDisabled},
	}}); err != nil {
		t.Fatalf("SetHostRules() returned error: %v", err)
	}

	snapshot := handler.snapshotForRequest()
	rule := matchHostRule(
		httptest.NewRequest("GET", "http://disabled.example.test/", nil),
		snapshot,
	)
	if !handler.IsClientIPVisibleForHost("1.1.1.7", rule, snapshot) {
		t.Fatal("disabled host visibility did not override the global deny rule")
	}
	if handler.IsClientIPVisibleForHost("1.1.1.7", nil, snapshot) {
		t.Fatal("disabled host visibility leaked into unmatched hosts")
	}
}

func TestDisabledHostVisibilityAllowsRequestDeniedByGlobalRules(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	handler, _ := newAdditionalProxyTestHandler(t)
	if err := handler.SetGatewayVisibility(models.GatewayVisibilityConfig{
		Enabled: true,
		CIDRs:   []string{"8.8.8.0/24"},
	}); err != nil {
		t.Fatalf("SetGatewayVisibility() returned error: %v", err)
	}
	if err := handler.SetHostRules([]models.HostRule{{
		Host:       "disabled.example.test",
		Target:     upstream.URL,
		Visibility: models.HostRuleVisibility{Mode: models.HostVisibilityModeDisabled},
	}}); err != nil {
		t.Fatalf("SetHostRules() returned error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://disabled.example.test/", nil)
	req.RemoteAddr = "1.1.1.7:4567"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("response status = %d, want %d", rec.Code, http.StatusNoContent)
	}
}

func TestAuthHostAlwaysUsesGlobalVisibility(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	if err := handler.SetGatewayVisibility(models.GatewayVisibilityConfig{
		Enabled: true,
		CIDRs:   []string{"8.8.8.0/24"},
	}); err != nil {
		t.Fatalf("SetGatewayVisibility() returned error: %v", err)
	}
	if err := handler.SetAuthConfig(models.AuthConfig{AuthHost: "auth.example.test"}); err != nil {
		t.Fatalf("SetAuthConfig() returned error: %v", err)
	}
	if err := handler.SetHostRules([]models.HostRule{{
		Host:       "auth.example.test",
		Target:     "http://127.0.0.1:7997",
		Visibility: models.HostRuleVisibility{Mode: models.HostVisibilityModeCustom, CIDRs: []string{"1.1.1.0/24"}},
	}}); err != nil {
		t.Fatalf("SetHostRules() returned error: %v", err)
	}

	snapshot := handler.snapshotForRequest()
	rule := matchHostRule(httptest.NewRequest("GET", "http://auth.example.test/", nil), snapshot)
	if !handler.IsClientIPVisibleForHost("8.8.8.7", rule, snapshot) {
		t.Fatal("auth host denied an IP allowed by global visibility")
	}
	if handler.IsClientIPVisibleForHost("1.1.1.7", rule, snapshot) {
		t.Fatal("auth host incorrectly used custom visibility")
	}

	if err := handler.SetHostRules([]models.HostRule{{
		Host:       "auth.example.test",
		Target:     "http://127.0.0.1:7997",
		Visibility: models.HostRuleVisibility{Mode: models.HostVisibilityModeDisabled},
	}}); err != nil {
		t.Fatalf("SetHostRules() with disabled auth visibility returned error: %v", err)
	}
	snapshot = handler.snapshotForRequest()
	rule = matchHostRule(httptest.NewRequest("GET", "http://auth.example.test/", nil), snapshot)
	if handler.IsClientIPVisibleForHost("1.1.1.7", rule, snapshot) {
		t.Fatal("auth host incorrectly disabled global visibility")
	}
}

func TestCustomHostVisibilityDenialKeeps499AndAccessLogBehavior(t *testing.T) {
	handler, _ := newAdditionalProxyTestHandler(t)
	if _, err := handler.SetLoggingConfig(models.LoggingConfig{Enabled: true, MaxDays: 1}); err != nil {
		t.Fatalf("SetLoggingConfig() returned error: %v", err)
	}
	if err := handler.SetGatewayVisibility(models.GatewayVisibilityConfig{
		Enabled: true,
		CIDRs:   []string{"8.8.8.0/24"},
	}); err != nil {
		t.Fatalf("SetGatewayVisibility() returned error: %v", err)
	}
	if err := handler.SetHostRules([]models.HostRule{{
		Host:       "custom.example.test",
		Target:     "http://127.0.0.1:8080",
		Visibility: models.HostRuleVisibility{Mode: models.HostVisibilityModeCustom, CIDRs: []string{"1.1.1.0/24"}},
	}}); err != nil {
		t.Fatalf("SetHostRules() returned error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://custom.example.test/private", nil)
	req.RemoteAddr = "8.8.8.8:4567"
	rec := newHijackableResponseRecorder()
	defer rec.Close()
	handler.ServeHTTP(rec, req)

	result, err := handler.QueryLogEntries("", 1, 20, "visibility_denied", "", "", "", "", "page")
	if err != nil {
		t.Fatalf("QueryLogEntries() returned error: %v", err)
	}
	if len(result.Items) != 1 {
		t.Fatalf("visibility log count = %d, want 1", len(result.Items))
	}
	entry := result.Items[0]
	if entry.Status != 499 || entry.RouteType != "visibility" || entry.AuthDecision != "visibility_denied" {
		t.Fatalf("visibility access log = %#v", entry)
	}
}
