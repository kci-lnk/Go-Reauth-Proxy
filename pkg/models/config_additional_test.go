package models

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAuthConfigNormalizeEdgeClientIPSelectionNil(t *testing.T) {
	var cfg *AuthConfig

	if cfg.NormalizeEdgeClientIPSelection() {
		t.Fatal("nil AuthConfig should not report changes")
	}
}

func TestAuthConfigNormalizeEdgeClientIPSelectionClearsAliyunWhenMasterDisabled(t *testing.T) {
	cfg := AuthConfig{AliyunESAEnabled: true}

	if !cfg.NormalizeEdgeClientIPSelection() {
		t.Fatal("expected disabled master switch to clear Aliyun selection")
	}
	if cfg.AliyunESAEnabled {
		t.Fatalf("Aliyun selection still enabled: %#v", cfg)
	}
}

func TestAuthConfigNormalizeEdgeClientIPSelectionClearsTencentWhenMasterDisabled(t *testing.T) {
	cfg := AuthConfig{TencentEdgeOneEnabled: true}

	if !cfg.NormalizeEdgeClientIPSelection() {
		t.Fatal("expected disabled master switch to clear Tencent selection")
	}
	if cfg.TencentEdgeOneEnabled {
		t.Fatalf("Tencent selection still enabled: %#v", cfg)
	}
}

func TestAuthConfigNormalizeEdgeClientIPSelectionClearsBothWhenMasterDisabled(t *testing.T) {
	cfg := AuthConfig{AliyunESAEnabled: true, TencentEdgeOneEnabled: true}

	if !cfg.NormalizeEdgeClientIPSelection() {
		t.Fatal("expected disabled master switch to clear both vendors")
	}
	if cfg.AliyunESAEnabled || cfg.TencentEdgeOneEnabled {
		t.Fatalf("vendor selections still enabled: %#v", cfg)
	}
}

func TestAuthConfigNormalizeEdgeClientIPSelectionPrefersTencentWhenBothEnabled(t *testing.T) {
	cfg := AuthConfig{EdgeClientIPEnabled: true, AliyunESAEnabled: true, TencentEdgeOneEnabled: true}

	if !cfg.NormalizeEdgeClientIPSelection() {
		t.Fatal("expected both vendors to normalize")
	}
	if cfg.AliyunESAEnabled || !cfg.TencentEdgeOneEnabled {
		t.Fatalf("Tencent should win over Aliyun: %#v", cfg)
	}
}

func TestAuthConfigNormalizeEdgeClientIPSelectionLeavesSingleAliyunVendor(t *testing.T) {
	cfg := AuthConfig{EdgeClientIPEnabled: true, AliyunESAEnabled: true}

	if cfg.NormalizeEdgeClientIPSelection() {
		t.Fatal("single Aliyun vendor should already be normalized")
	}
	if !cfg.AliyunESAEnabled || cfg.TencentEdgeOneEnabled {
		t.Fatalf("unexpected vendor state: %#v", cfg)
	}
}

func TestAuthConfigNormalizeEdgeClientIPSelectionLeavesSingleTencentVendor(t *testing.T) {
	cfg := AuthConfig{EdgeClientIPEnabled: true, TencentEdgeOneEnabled: true}

	if cfg.NormalizeEdgeClientIPSelection() {
		t.Fatal("single Tencent vendor should already be normalized")
	}
	if cfg.AliyunESAEnabled || !cfg.TencentEdgeOneEnabled {
		t.Fatalf("unexpected vendor state: %#v", cfg)
	}
}

func TestAuthConfigEdgeClientIPActiveForAliyun(t *testing.T) {
	cfg := AuthConfig{EdgeClientIPEnabled: true, AliyunESAEnabled: true}

	if !cfg.EdgeClientIPActive() {
		t.Fatal("Aliyun selection should activate edge client IP")
	}
}

func TestAuthConfigEdgeClientIPActiveForTencent(t *testing.T) {
	cfg := AuthConfig{EdgeClientIPEnabled: true, TencentEdgeOneEnabled: true}

	if !cfg.EdgeClientIPActive() {
		t.Fatal("Tencent selection should activate edge client IP")
	}
}

func TestAuthConfigEdgeClientIPInactiveWithoutMasterSwitch(t *testing.T) {
	cfg := AuthConfig{AliyunESAEnabled: true, TencentEdgeOneEnabled: true}

	if cfg.EdgeClientIPActive() {
		t.Fatal("vendor selection without master switch should be inactive")
	}
}

func TestAuthConfigAliyunESAActiveRequiresMasterSwitch(t *testing.T) {
	cfg := AuthConfig{AliyunESAEnabled: true}

	if cfg.AliyunESAActive() {
		t.Fatal("Aliyun should be inactive without master switch")
	}
}

func TestAuthConfigAliyunESAActiveFalseWhenTencentSelected(t *testing.T) {
	cfg := AuthConfig{EdgeClientIPEnabled: true, AliyunESAEnabled: true, TencentEdgeOneEnabled: true}

	if cfg.AliyunESAActive() {
		t.Fatal("Aliyun should not be active when Tencent is also selected")
	}
}

func TestAuthConfigTencentEdgeOneActiveRequiresMasterSwitch(t *testing.T) {
	cfg := AuthConfig{TencentEdgeOneEnabled: true}

	if cfg.TencentEdgeOneActive() {
		t.Fatal("Tencent should be inactive without master switch")
	}
}

func TestAuthConfigTencentEdgeOneActiveWinsWithBothVendors(t *testing.T) {
	cfg := AuthConfig{EdgeClientIPEnabled: true, AliyunESAEnabled: true, TencentEdgeOneEnabled: true}

	if !cfg.TencentEdgeOneActive() {
		t.Fatal("Tencent should be active when both vendors are selected")
	}
}

func TestGatewayPortalConfigZeroValueNormalizesToEnabledDomainCorners(t *testing.T) {
	normalized := NormalizeGatewayPortalConfig(GatewayPortalConfig{})

	if !normalized.Enabled ||
		normalized.DisplayStyle != GatewayPortalDisplayStyleDomain ||
		normalized.IconDragMode != GatewayPortalIconDragModeCorners ||
		normalized.Version != GatewayPortalVersionV1 {
		t.Fatalf("unexpected normalized zero portal config: %#v", normalized)
	}
}

func TestGatewayPortalConfigExplicitEnabledTrueNormalizesEnabled(t *testing.T) {
	var cfg GatewayPortalConfig
	if err := json.Unmarshal([]byte(`{"enabled":true}`), &cfg); err != nil {
		t.Fatalf("unmarshal gateway portal config: %v", err)
	}

	normalized := NormalizeGatewayPortalConfig(cfg)

	if !normalized.Enabled {
		t.Fatalf("enabled true was not preserved: %#v", normalized)
	}
}

func TestGatewayPortalConfigInvalidDisplayStyleDefaultsToDomain(t *testing.T) {
	normalized := NormalizeGatewayPortalConfig(GatewayPortalConfig{DisplayStyle: "icon-only"})

	if normalized.DisplayStyle != GatewayPortalDisplayStyleDomain {
		t.Fatalf("display style = %q", normalized.DisplayStyle)
	}
}

func TestGatewayPortalConfigTitleDisplayStylePreserved(t *testing.T) {
	normalized := NormalizeGatewayPortalConfig(GatewayPortalConfig{DisplayStyle: GatewayPortalDisplayStyleTitle})

	if normalized.DisplayStyle != GatewayPortalDisplayStyleTitle {
		t.Fatalf("display style = %q", normalized.DisplayStyle)
	}
}

func TestGatewayPortalConfigShowAppIconPreserved(t *testing.T) {
	normalized := NormalizeGatewayPortalConfig(GatewayPortalConfig{ShowAppIcon: true})

	if !normalized.ShowAppIcon {
		t.Fatalf("show app icon not preserved: %#v", normalized)
	}
}

func TestGatewayPortalConfigShowWOLPreserved(t *testing.T) {
	var cfg GatewayPortalConfig
	if err := json.Unmarshal([]byte(`{"enabled":true,"show_wol":true}`), &cfg); err != nil {
		t.Fatalf("unmarshal gateway portal config: %v", err)
	}
	if normalized := NormalizeGatewayPortalConfig(cfg); !normalized.ShowWOL {
		t.Fatal("NormalizeGatewayPortalConfig() discarded show_wol")
	}
}

func TestGatewayPortalConfigUnmarshalRejectsMalformedJSON(t *testing.T) {
	var cfg GatewayPortalConfig

	if err := json.Unmarshal([]byte(`{"enabled":`), &cfg); err == nil {
		t.Fatal("expected malformed JSON error")
	}
}

func TestGatewayPortalConfigUnmarshalDefaultsMissingEnabledBeforeNormalize(t *testing.T) {
	var cfg GatewayPortalConfig
	if err := json.Unmarshal([]byte(`{"display_style":"domain"}`), &cfg); err != nil {
		t.Fatalf("unmarshal gateway portal config: %v", err)
	}

	if !cfg.Enabled {
		t.Fatalf("missing enabled should unmarshal as true before normalize: %#v", cfg)
	}
}

func TestHostRuleJSONOmitsEmptyOptionalFields(t *testing.T) {
	payload, err := json.Marshal(HostRule{Host: "app.example.com", Target: "http://127.0.0.1:3000"})
	if err != nil {
		t.Fatalf("marshal host rule: %v", err)
	}

	for _, forbidden := range []string{"protocol_mode", "access_mode", "suppress_toolbar", "preserve_host", "locations"} {
		if strings.Contains(string(payload), forbidden) {
			t.Fatalf("host rule included empty optional field %q: %s", forbidden, payload)
		}
	}
}

func TestNormalizeHostProtocolMode(t *testing.T) {
	tests := map[string]string{
		"":           HostProtocolModeAuto,
		"auto":       HostProtocolModeAuto,
		" HTTP1 ":    HostProtocolModeHTTP1,
		"HtTp2":      HostProtocolModeHTTP2,
		"unexpected": HostProtocolModeAuto,
	}
	for input, want := range tests {
		if got := NormalizeHostProtocolMode(input); got != want {
			t.Fatalf("NormalizeHostProtocolMode(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestNormalizeHostTargetPathMode(t *testing.T) {
	tests := map[string]string{
		"":         HostTargetPathModeEntry,
		"entry":    HostTargetPathModeEntry,
		" ENTRY ":  HostTargetPathModeEntry,
		"prefix":   HostTargetPathModePrefix,
		" PREFIX ": HostTargetPathModePrefix,
		"unknown":  HostTargetPathModeEntry,
	}
	for input, want := range tests {
		if got := NormalizeHostTargetPathMode(input); got != want {
			t.Fatalf("NormalizeHostTargetPathMode(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestHostRuleJSONIncludesBasicAuthWhenConfigured(t *testing.T) {
	payload, err := json.Marshal(HostRule{
		Host:      "app.example.com",
		Target:    "http://127.0.0.1:3000",
		BasicAuth: BasicAuthConfig{Enabled: true, Username: "admin", Password: "secret"},
	})
	if err != nil {
		t.Fatalf("marshal host rule: %v", err)
	}

	if !strings.Contains(string(payload), `"basic_auth"`) || !strings.Contains(string(payload), `"username":"admin"`) {
		t.Fatalf("basic auth missing from host rule JSON: %s", payload)
	}
}

func TestHostLocationResponseRoundTripHeaders(t *testing.T) {
	original := HostLocationResponse{
		Status:      202,
		ContentType: "text/plain",
		Headers:     map[string]string{"X-Test": "ok"},
		Body:        "accepted",
	}
	payload, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal host location response: %v", err)
	}
	var got HostLocationResponse
	if err := json.Unmarshal(payload, &got); err != nil {
		t.Fatalf("unmarshal host location response: %v", err)
	}

	if got.Status != 202 || got.Headers["X-Test"] != "ok" || got.Body != "accepted" {
		t.Fatalf("unexpected response round trip: %#v", got)
	}
}

func TestStreamRuleConstantsMatchJSONProtocolValues(t *testing.T) {
	if StreamProtocolTCP != "tcp" || StreamProtocolUDP != "udp" {
		t.Fatalf("unexpected stream protocol constants: %q %q", StreamProtocolTCP, StreamProtocolUDP)
	}
}

func TestStreamRuleJSONRoundTrip(t *testing.T) {
	payload := []byte(`{"protocol":"udp","listen_port":5353,"target":"127.0.0.1:53","use_auth":true}`)
	var rule StreamRule
	if err := json.Unmarshal(payload, &rule); err != nil {
		t.Fatalf("unmarshal stream rule: %v", err)
	}
	out, err := json.Marshal(rule)
	if err != nil {
		t.Fatalf("marshal stream rule: %v", err)
	}

	if !strings.Contains(string(out), `"protocol":"udp"`) || !strings.Contains(string(out), `"use_auth":true`) {
		t.Fatalf("unexpected stream rule JSON: %s", out)
	}
}

func TestGeneralBlacklistMutationResultRoundTrip(t *testing.T) {
	original := GeneralBlacklistMutationResult{
		Added: 1,
		Total: 2,
		Items: []GeneralBlacklistRecord{{IP: "203.0.113.10", Source: GeneralBlacklistSourceManual}},
	}
	payload, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal blacklist result: %v", err)
	}
	var got GeneralBlacklistMutationResult
	if err := json.Unmarshal(payload, &got); err != nil {
		t.Fatalf("unmarshal blacklist result: %v", err)
	}

	if got.Added != 1 || got.Total != 2 || len(got.Items) != 1 || got.Items[0].Source != GeneralBlacklistSourceManual {
		t.Fatalf("unexpected blacklist result: %#v", got)
	}
}

func TestWAFConfigRoundTripDisabledHostsAndPrefixes(t *testing.T) {
	original := WAFConfig{
		Enabled:              true,
		DisabledHosts:        []string{"app.example.com"},
		DisabledPathPrefixes: []string{"/healthz"},
	}
	payload, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal waf config: %v", err)
	}
	var got WAFConfig
	if err := json.Unmarshal(payload, &got); err != nil {
		t.Fatalf("unmarshal waf config: %v", err)
	}

	if !got.Enabled || got.DisabledHosts[0] != "app.example.com" || got.DisabledPathPrefixes[0] != "/healthz" {
		t.Fatalf("unexpected waf config: %#v", got)
	}
}

func TestForwardedHeadersConfigOmitsEmptyTargets(t *testing.T) {
	payload, err := json.Marshal(ForwardedHeadersConfig{Enabled: true})
	if err != nil {
		t.Fatalf("marshal forwarded headers config: %v", err)
	}

	if strings.Contains(string(payload), "omit_targets") {
		t.Fatalf("empty omit targets should be omitted: %s", payload)
	}
}

func TestPreserveHostConfigIncludesOmitTargets(t *testing.T) {
	payload, err := json.Marshal(PreserveHostConfig{Enabled: true, OmitTargets: []string{"http://127.0.0.1:3000"}})
	if err != nil {
		t.Fatalf("marshal preserve host config: %v", err)
	}

	if !strings.Contains(string(payload), `"omit_targets":["http://127.0.0.1:3000"]`) {
		t.Fatalf("omit targets missing: %s", payload)
	}
}

func TestSSLDeploymentModeConstants(t *testing.T) {
	if SSLDeploymentModeSingleActive != "single_active" || SSLDeploymentModeMultiSNI != "multi_sni" {
		t.Fatalf("unexpected SSL deployment constants: %q %q", SSLDeploymentModeSingleActive, SSLDeploymentModeMultiSNI)
	}
}

func TestSSLDeploymentRequestSupportsLegacyCertAndKey(t *testing.T) {
	var req SSLDeploymentRequest
	if err := json.Unmarshal([]byte(`{"cert":"CERT","key":"KEY"}`), &req); err != nil {
		t.Fatalf("unmarshal ssl deployment request: %v", err)
	}

	if req.Cert != "CERT" || req.Key != "KEY" || len(req.Certificates) != 0 {
		t.Fatalf("unexpected legacy SSL request: %#v", req)
	}
}

func TestSSLInfoRoundTripCertificateMetadata(t *testing.T) {
	info := SSLInfo{
		Enabled:        true,
		DeploymentMode: SSLDeploymentModeMultiSNI,
		Certificates: []SSLDeployedCertificateInfo{{
			ID:        "cert-1",
			Domains:   []string{"app.example.com"},
			IsDefault: true,
		}},
	}
	payload, err := json.Marshal(info)
	if err != nil {
		t.Fatalf("marshal ssl info: %v", err)
	}
	var got SSLInfo
	if err := json.Unmarshal(payload, &got); err != nil {
		t.Fatalf("unmarshal ssl info: %v", err)
	}

	if !got.Enabled || got.DeploymentMode != SSLDeploymentModeMultiSNI ||
		len(got.Certificates) != 1 || got.Certificates[0].Domains[0] != "app.example.com" {
		t.Fatalf("unexpected ssl info: %#v", got)
	}
}
