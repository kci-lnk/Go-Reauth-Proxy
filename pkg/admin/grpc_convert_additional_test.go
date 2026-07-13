package admin

import (
	"reflect"
	"testing"
	"time"

	"go-reauth-proxy/pkg/gatewaylog"
	"go-reauth-proxy/pkg/grpc/pb"
	"go-reauth-proxy/pkg/iptables"
	"go-reauth-proxy/pkg/models"
	"go-reauth-proxy/pkg/proxy"
	proxywaf "go-reauth-proxy/pkg/waf"
)

func TestRpcOKUsesSuccessEnvelope(t *testing.T) {
	got := rpcOK()
	if !got.GetSuccess() || got.GetCode() != 200 || got.GetMessage() != "success" {
		t.Fatalf("rpcOK() = %#v", got)
	}
}

func TestBasicAuthProtoRoundTrip(t *testing.T) {
	input := models.BasicAuthConfig{Enabled: true, Username: "user", Password: "pass"}
	if got := protoToBasicAuth(basicAuthToProto(input)); got != input {
		t.Fatalf("round trip = %#v, want %#v", got, input)
	}
}

func TestHostLocationResponseProtoRoundTrip(t *testing.T) {
	input := models.HostLocationResponse{Status: 204, ContentType: "text/plain", Headers: map[string]string{"X-Test": "ok"}, Body: "body"}
	got := protoToHostLocationResponse(hostLocationResponseToProto(input))
	if !reflect.DeepEqual(got, input) {
		t.Fatalf("round trip = %#v, want %#v", got, input)
	}
}

func TestHostRulesProtoRoundTripPreservesLocations(t *testing.T) {
	input := []models.HostRule{{
		Host:            "app.example.test",
		Target:          "http://127.0.0.1:8080",
		ProtocolMode:    models.HostProtocolModeHTTP1,
		UseAuth:         true,
		AccessMode:      "login_first",
		SuppressToolbar: true,
		PreserveHost:    true,
		IsDefault:       true,
		Disabled:        true,
		Availability:    &models.HostRuleAvailability{Enabled: true, StartTime: "22:00", EndTime: "06:00"},
		Visibility:      models.HostRuleVisibility{Mode: models.HostVisibilityModeCustom, CIDRs: []string{"203.0.113.0/24"}},
		Title:           "App",
		Favicon:         "data:image/png;base64,AA",
		BasicAuth:       models.BasicAuthConfig{Enabled: true, Username: "u", Password: "p"},
		Locations: []models.HostLocation{{
			Path: "/api", Match: models.HostLocationMatchPrefix, Action: models.HostLocationActionResponse,
			Response: models.HostLocationResponse{Status: 200, Headers: map[string]string{"X-Test": "ok"}},
		}},
	}}
	got := protoToHostRules(hostRulesToProto(input))
	if !reflect.DeepEqual(got, input) {
		t.Fatalf("round trip = %#v, want %#v", got, input)
	}
}

func TestStreamRulesProtoRoundTrip(t *testing.T) {
	input := []models.StreamRule{{Protocol: "udp", ListenPort: 5353, Target: "127.0.0.1:5354", UseAuth: true}}
	got := protoToStreamRules(streamRulesToProto(input))
	if !reflect.DeepEqual(got, input) {
		t.Fatalf("round trip = %#v, want %#v", got, input)
	}
}

func TestAuthConfigProtoRoundTrip(t *testing.T) {
	input := models.AuthConfig{AuthPort: 7997, AuthURL: "/verify", LoginURL: "/login", LogoutURL: "/logout", PreflightURL: "/preflight", AuthCacheTTL: 1, AuthCacheFailTTL: 2, EdgeClientIPEnabled: true, TencentEdgeOneEnabled: true, PublicAuthBaseURL: "https://auth.example.test", PublicHTTPPort: 80, PublicHTTPSPort: 443, AuthHost: "auth.example.test", TrustForwardedProto: true}
	got := protoToAuthConfig(authConfigToProto(input))
	if got != input {
		t.Fatalf("round trip = %#v, want %#v", got, input)
	}
}

func TestLoggingConfigProtoRoundTrip(t *testing.T) {
	input := gatewaylog.ConfigInfo{
		Enabled:        true,
		MaxDays:        9,
		LogsDir:        "/tmp/logs",
		DroppedEntries: 12,
		QueueSize:      4096,
		QueueDepth:     7,
	}
	proto := loggingConfigToProto(input)
	if !proto.GetEnabled() ||
		proto.GetMaxDays() != 9 ||
		proto.GetLogsDir() != "/tmp/logs" ||
		proto.GetDroppedEntries() != 12 ||
		proto.GetQueueSize() != 4096 ||
		proto.GetQueueDepth() != 7 {
		t.Fatalf("logging proto = %#v", proto)
	}
	if got := protoToLoggingConfig(proto); got != (models.LoggingConfig{Enabled: true, MaxDays: 9}) {
		t.Fatalf("protoToLoggingConfig() = %#v", got)
	}
}

func TestReverseProxyThrottleProtoRoundTrip(t *testing.T) {
	input := models.ReverseProxyThrottleConfig{Enabled: true, RequestsPerSecond: 10, Burst: 20, BlockSeconds: 30}
	if got := protoToReverseProxyThrottle(reverseProxyThrottleToProto(input)); got != input {
		t.Fatalf("round trip = %#v", got)
	}
}

func TestGatewayVisibilityProtoRoundTrip(t *testing.T) {
	input := models.GatewayVisibilityConfig{Enabled: true, CIDRs: []string{"192.168.0.0/16"}, UpdatedAt: "now"}
	if got := protoToGatewayVisibility(gatewayVisibilityToProto(input)); !reflect.DeepEqual(got, input) {
		t.Fatalf("round trip = %#v", got)
	}
}

func TestForwardedHeadersProtoRoundTrip(t *testing.T) {
	input := models.ForwardedHeadersConfig{Enabled: true, OmitTargets: []string{"http://127.0.0.1:8080"}, UpdatedAt: "now"}
	if got := protoToForwardedHeaders(forwardedHeadersToProto(input)); !reflect.DeepEqual(got, input) {
		t.Fatalf("round trip = %#v", got)
	}
}

func TestPreserveHostProtoRoundTrip(t *testing.T) {
	input := models.PreserveHostConfig{Enabled: true, OmitTargets: []string{"http://127.0.0.1:8080"}, UpdatedAt: "now"}
	if got := protoToPreserveHost(preserveHostToProto(input)); !reflect.DeepEqual(got, input) {
		t.Fatalf("round trip = %#v", got)
	}
}

func TestCrawlerBlockerProtoRoundTrip(t *testing.T) {
	input := models.CrawlerBlockerConfig{Enabled: true, UpdatedAt: "now"}
	if got := protoToCrawlerBlocker(crawlerBlockerToProto(input)); got != input {
		t.Fatalf("round trip = %#v", got)
	}
}

func TestGatewayPortalProtoRoundTrip(t *testing.T) {
	input := models.GatewayPortalConfig{Enabled: true, DisplayStyle: "title", ShowAppIcon: true, IconDragMode: "free"}
	if got := protoToGatewayPortal(gatewayPortalToProto(input)); !reflect.DeepEqual(got, input) {
		t.Fatalf("round trip = %#v", got)
	}
}

func TestFnosPortIconHijackProtoRoundTrip(t *testing.T) {
	input := models.FnosPortIconHijackConfig{Enabled: true, UpdatedAt: "now"}
	if got := protoToFnosPortIconHijack(fnosPortIconHijackToProto(input)); got != input {
		t.Fatalf("round trip = %#v", got)
	}
}

func TestThrottleExemptIPsProtoRoundTrip(t *testing.T) {
	input := models.ReverseProxyThrottleExemptIPsRuntime{Enabled: true, IPs: []string{"198.51.100.7"}, CIDRs: []string{"192.168.0.0/16"}, UpdatedAt: "now"}
	if got := protoToThrottleExemptIPs(throttleExemptIPsToProto(input)); !reflect.DeepEqual(got, input) {
		t.Fatalf("round trip = %#v", got)
	}
}

func TestCommonLocationExemptionsProtoRoundTrip(t *testing.T) {
	input := models.CommonLocationExemptionsRuntime{Enabled: true, WAFEnabled: true, CIDRs: []string{"192.168.0.0/16"}, UpdatedAt: "now"}
	if got := protoToCommonLocationExemptions(commonLocationExemptionsToProto(input)); !reflect.DeepEqual(got, input) {
		t.Fatalf("round trip = %#v", got)
	}
}

func TestGeneralBlacklistListToProto(t *testing.T) {
	got := generalBlacklistListToProto(models.GeneralBlacklistList{Total: 1, Items: []models.GeneralBlacklistRecord{{IP: "198.51.100.7", Source: "manual"}}})
	if got.GetTotal() != 1 || got.GetItems()[0].GetIp() != "198.51.100.7" {
		t.Fatalf("generalBlacklistListToProto() = %#v", got)
	}
}

func TestGeneralBlacklistMutationToProto(t *testing.T) {
	got := generalBlacklistMutationToProto(models.GeneralBlacklistMutationResult{Added: 1, Updated: 2, Removed: 3, Total: 4})
	if got.GetAdded() != 1 || got.GetUpdated() != 2 || got.GetRemoved() != 3 || got.GetTotal() != 4 {
		t.Fatalf("mutation proto = %#v", got)
	}
}

func TestGeneralBlacklistStatusToProto(t *testing.T) {
	got := generalBlacklistStatusToProto(models.GeneralBlacklistStatus{Records: map[string]models.GeneralBlacklistRecord{"ip": {IP: "198.51.100.7"}}})
	if got.GetRecords()["ip"].GetIp() != "198.51.100.7" {
		t.Fatalf("status proto = %#v", got)
	}
}

func TestTrafficStatsToProtoIncludesHostBreakdown(t *testing.T) {
	got := trafficStatsToProto(proxy.TrafficStats{TotalIn: 1, TotalOut: 2, ActiveConns: 3, Error5xx: 4, ByHost: []proxy.HostTrafficStats{{Host: "app", TotalIn: 5, TotalOut: 6, Error5xx: 7, ActiveIPCount: 8}}})
	if got.GetTotalIn() != 1 || got.GetByHost()[0].GetActiveIpCount() != 8 {
		t.Fatalf("traffic proto = %#v", got)
	}
}

func TestHostActiveIPsToProtoFormatsTime(t *testing.T) {
	ts := time.Date(2024, 1, 2, 3, 4, 5, 6, time.UTC)
	got := hostActiveIPsToProto(proxy.HostActiveIPsStats{Host: "app", WindowSeconds: 120, Items: []proxy.HostActiveIPStats{{IP: "198.51.100.7", LastSeenAt: ts, ActiveConns: 2}}})
	if got.GetItems()[0].GetLastSeenAt() != ts.Format(time.RFC3339Nano) {
		t.Fatalf("host active IP proto = %#v", got)
	}
}

func TestWAFConfigProtoRoundTrip(t *testing.T) {
	input := models.WAFConfig{Enabled: true, Mode: "block", RulesDir: "/rules", ActiveBundleID: "bundle", ParanoiaLevel: 2, ExecutingParanoiaLevel: 1, InboundAnomalyThreshold: 5, OutboundAnomalyThreshold: 4, RequestBodyAccess: true, RequestBodyLimitBytes: 100, RequestBodyInMemoryLimitBytes: 50, ResponseBodyAccess: true, DisabledHosts: []string{"app"}, DisabledPathPrefixes: []string{"/health"}, UpdatedAt: "now"}
	if got := protoToWAFConfig(wafConfigToProto(input)); !reflect.DeepEqual(got, input) {
		t.Fatalf("round trip = %#v", got)
	}
}

func TestWAFEventToProtoIncludesRulesAndInterruption(t *testing.T) {
	got := wafEventToProto(proxywaf.Event{
		TraceID: "trace", RuleIDs: []int{1, 2}, Interruption: &proxywaf.InterruptionInfo{RuleID: 1, Action: "deny", Status: 403},
		Rules: []proxywaf.RuleMatch{{ID: 1, Message: "msg", MatchedVariables: []proxywaf.MatchedVariable{{Variable: "ARGS", Key: "x", ValuePreview: "y"}}}},
	})
	if got.GetTraceId() != "trace" || len(got.GetRules()) != 1 || got.GetInterruption().GetStatus() != 403 {
		t.Fatalf("waf event proto = %#v", got)
	}
}

func TestSSLConfigProtoRoundTrip(t *testing.T) {
	input := models.SSLConfig{DeploymentMode: models.SSLDeploymentModeMultiSNI, Certificates: []models.SSLDeployedCertificate{{ID: "id", Label: "label", Cert: "cert", Key: "key", IsDefault: true}}}
	if got := protoToSSLConfig(sslConfigToProto(input)); !reflect.DeepEqual(got, input) {
		t.Fatalf("round trip = %#v", got)
	}
}

func TestSSLInfoToProtoIncludesDomains(t *testing.T) {
	got := sslInfoToProto(models.SSLInfo{Enabled: true, DeploymentMode: models.SSLDeploymentModeMultiSNI, Certificates: []models.SSLDeployedCertificateInfo{{ID: "id", Domains: []string{"app.example.test"}}}})
	if !got.GetEnabled() || got.GetCertificates()[0].GetDomains()[0] != "app.example.test" {
		t.Fatalf("ssl info proto = %#v", got)
	}
}

func TestLogEntryToProtoIncludesWAFRuleIDs(t *testing.T) {
	got := logEntryToProto(gatewaylog.Entry{Path: "/app", Status: 403, WAFRuleIDs: []int{1001}})
	if got.GetPath() != "/app" || got.GetWafRuleIds()[0] != 1001 {
		t.Fatalf("log entry proto = %#v", got)
	}
}

func TestLogQueryResultToProtoIncludesItems(t *testing.T) {
	got := logQueryResultToProto(gatewaylog.QueryResult{Date: "2024-01-02", Items: []gatewaylog.Entry{{Path: "/app"}}})
	if got.GetDate() != "2024-01-02" || got.GetItems()[0].GetPath() != "/app" {
		t.Fatalf("query result proto = %#v", got)
	}
}

func TestIptablesRulesToProtoIncludesPort(t *testing.T) {
	got := iptablesRulesToProto([]iptables.Rule{{IP: "198.51.100.7", Action: "DROP", Protocol: "tcp", Port: 22}})
	if got.GetItems()[0].GetPort() != 22 || got.GetItems()[0].GetAction() != "DROP" {
		t.Fatalf("iptables proto = %#v", got)
	}
}

func TestProtoNilInputsReturnZeroModels(t *testing.T) {
	if protoToAuthConfig(nil) != (models.AuthConfig{}) {
		t.Fatal("protoToAuthConfig(nil) did not return zero value")
	}
	if protoToBasicAuth(nil) != (models.BasicAuthConfig{}) {
		t.Fatal("protoToBasicAuth(nil) did not return zero value")
	}
	if len(protoToRules((*pb.Rules)(nil))) != 0 {
		t.Fatal("protoToRules(nil) returned non-empty rules")
	}
}
