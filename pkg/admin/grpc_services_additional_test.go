package admin

import (
	"context"
	"testing"

	"go-reauth-proxy/pkg/grpc/pb"
	"go-reauth-proxy/pkg/models"
	"go-reauth-proxy/pkg/rpcbridge"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

func TestGatewayControlSetRulesRejectsNilRequest(t *testing.T) {
	server := newGatewayControlTestServer(t, "secret")
	_, err := server.SetRules(authTestContext(), nil)
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("status = %v, want invalid argument", status.Code(err))
	}
}

func TestGatewayControlFlushRulesClearsRules(t *testing.T) {
	server := newGatewayControlTestServer(t, "secret")
	ctx := authTestContext()
	if _, err := server.SetRules(ctx, &pb.Rules{Items: []*pb.Rule{{Path: "/app", Target: "http://127.0.0.1:8080"}}}); err != nil {
		t.Fatalf("SetRules() returned error: %v", err)
	}
	if _, err := server.FlushRules(ctx, &emptypb.Empty{}); err != nil {
		t.Fatalf("FlushRules() returned error: %v", err)
	}
	got, err := server.GetRules(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatalf("GetRules() returned error: %v", err)
	}
	if len(got.GetItems()) != 0 {
		t.Fatalf("rules after flush = %#v", got.GetItems())
	}
}

func TestGatewayControlHostRulesRoundTrip(t *testing.T) {
	server := newGatewayControlTestServer(t, "secret")
	ctx := authTestContext()
	_, err := server.SetHostRules(ctx, &pb.HostRules{Items: []*pb.HostRule{{
		Host:         "App.Example.Test",
		Target:       "http://127.0.0.1:8080",
		ProtocolMode: "http1",
		UseAuth:      true,
		Disabled:     true,
		Availability: &pb.HostRuleAvailability{
			Enabled:   true,
			StartTime: "22:00",
			EndTime:   "06:00",
		},
	}}})
	if err != nil {
		t.Fatalf("SetHostRules() returned error: %v", err)
	}
	got, err := server.GetHostRules(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatalf("GetHostRules() returned error: %v", err)
	}
	if len(got.GetItems()) != 1 || got.GetItems()[0].GetHost() != "app.example.test" {
		t.Fatalf("host rules = %#v", got.GetItems())
	}
	if !got.GetItems()[0].GetDisabled() ||
		got.GetItems()[0].GetProtocolMode() != "http1" ||
		got.GetItems()[0].GetAvailability().GetStartTime() != "22:00" ||
		got.GetItems()[0].GetAvailability().GetEndTime() != "06:00" {
		t.Fatalf("availability fields not preserved: %#v", got.GetItems()[0])
	}

	if _, err := server.SetHostRules(ctx, &pb.HostRules{Items: []*pb.HostRule{{
		Host:    "app.example.test",
		Target:  "http://127.0.0.1:8080",
		UseAuth: true,
	}}}); err != nil {
		t.Fatalf("legacy SetHostRules() returned error: %v", err)
	}
	got, err = server.GetHostRules(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatalf("GetHostRules() after legacy update returned error: %v", err)
	}
	if mode := got.GetItems()[0].GetProtocolMode(); mode != "http1" {
		t.Fatalf("legacy update reset protocol mode to %q, want http1", mode)
	}
}

func TestGatewayControlLegacyHostRuleUpdatePreservesGroupsAndExplicitEmptyClears(t *testing.T) {
	server := newGatewayControlTestServer(t, "secret")
	ctx := authTestContext()
	groupID := "11111111-1111-4111-8111-111111111111"
	groupName := "Media"
	baseRule := func() *pb.HostRule {
		return &pb.HostRule{
			Host:    "app.example.test",
			Target:  "http://127.0.0.1:8080",
			UseAuth: true,
		}
	}

	grouped := baseRule()
	grouped.GroupId = proto.String(groupID)
	grouped.GroupName = proto.String(groupName)
	if _, err := server.SetHostRules(ctx, &pb.HostRules{Items: []*pb.HostRule{grouped}}); err != nil {
		t.Fatalf("grouped SetHostRules() returned error: %v", err)
	}
	if _, err := server.SetHostRules(ctx, &pb.HostRules{Items: []*pb.HostRule{baseRule()}}); err != nil {
		t.Fatalf("legacy SetHostRules() returned error: %v", err)
	}
	preserved, err := server.GetHostRules(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatalf("GetHostRules() after legacy update returned error: %v", err)
	}
	if got := preserved.GetItems()[0]; got.GetGroupId() != groupID || got.GetGroupName() != groupName {
		t.Fatalf("legacy update cleared group metadata: %#v", got)
	}
	persisted, err := server.admin.ConfigManager.Load()
	if err != nil {
		t.Fatalf("Load() after legacy update returned error: %v", err)
	}
	if got := persisted.HostRules[0]; got.GroupID != groupID || got.GroupName != groupName {
		t.Fatalf("persisted group metadata = %#v", got)
	}

	flat := baseRule()
	flat.GroupId = proto.String("")
	flat.GroupName = proto.String("")
	if _, err := server.SetHostRules(ctx, &pb.HostRules{Items: []*pb.HostRule{flat}}); err != nil {
		t.Fatalf("explicit flat SetHostRules() returned error: %v", err)
	}
	cleared, err := server.GetHostRules(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatalf("GetHostRules() after explicit clear returned error: %v", err)
	}
	if got := cleared.GetItems()[0]; got.GetGroupId() != "" || got.GetGroupName() != "" {
		t.Fatalf("explicit empty group metadata was not cleared: %#v", got)
	}
}

func TestGatewayControlSetHostRulesRejectsNilRequest(t *testing.T) {
	server := newGatewayControlTestServer(t, "secret")
	_, err := server.SetHostRules(authTestContext(), nil)
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("status = %v, want invalid argument", status.Code(err))
	}
}

func TestGatewayControlFlushHostRulesClearsRules(t *testing.T) {
	server := newGatewayControlTestServer(t, "secret")
	ctx := authTestContext()
	if _, err := server.SetHostRules(ctx, &pb.HostRules{Items: []*pb.HostRule{{Host: "app.example.test", Target: "http://127.0.0.1:8080"}}}); err != nil {
		t.Fatalf("SetHostRules() returned error: %v", err)
	}
	if _, err := server.FlushHostRules(ctx, &emptypb.Empty{}); err != nil {
		t.Fatalf("FlushHostRules() returned error: %v", err)
	}
	got, _ := server.GetHostRules(ctx, &emptypb.Empty{})
	if len(got.GetItems()) != 0 {
		t.Fatalf("host rules after flush = %#v", got.GetItems())
	}
}

func TestGatewayControlStreamRulesRoundTrip(t *testing.T) {
	server := newGatewayControlTestServer(t, "secret")
	ctx := authTestContext()
	_, err := server.SetStreamRules(ctx, &pb.StreamRules{Items: []*pb.StreamRule{{Protocol: "udp", ListenPort: 5353, Target: "127.0.0.1:5354", UseAuth: true}}})
	if err != nil {
		t.Fatalf("SetStreamRules() returned error: %v", err)
	}
	got, err := server.GetStreamRules(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatalf("GetStreamRules() returned error: %v", err)
	}
	if len(got.GetItems()) != 1 || got.GetItems()[0].GetProtocol() != "udp" {
		t.Fatalf("stream rules = %#v", got.GetItems())
	}
}

func TestGatewayControlSetStreamRulesRejectsNilRequest(t *testing.T) {
	server := newGatewayControlTestServer(t, "secret")
	_, err := server.SetStreamRules(authTestContext(), nil)
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("status = %v, want invalid argument", status.Code(err))
	}
}

func TestGatewayControlFlushStreamRulesClearsRules(t *testing.T) {
	server := newGatewayControlTestServer(t, "secret")
	ctx := authTestContext()
	if _, err := server.SetStreamRules(ctx, &pb.StreamRules{Items: []*pb.StreamRule{{ListenPort: 3306, Target: "127.0.0.1:3307"}}}); err != nil {
		t.Fatalf("SetStreamRules() returned error: %v", err)
	}
	if _, err := server.FlushStreamRules(ctx, &emptypb.Empty{}); err != nil {
		t.Fatalf("FlushStreamRules() returned error: %v", err)
	}
	got, _ := server.GetStreamRules(ctx, &emptypb.Empty{})
	if len(got.GetItems()) != 0 {
		t.Fatalf("stream rules after flush = %#v", got.GetItems())
	}
}

func TestGatewayControlAuthConfigRoundTrip(t *testing.T) {
	server := newGatewayControlTestServer(t, "secret")
	ctx := authTestContext()
	if _, err := server.SetAuthConfig(ctx, &pb.AuthConfig{AuthPort: 8123, AuthUrl: "/v", LoginUrl: "/l", LogoutUrl: "/o", PreflightUrl: "/p"}); err != nil {
		t.Fatalf("SetAuthConfig() returned error: %v", err)
	}
	got, err := server.GetAuthConfig(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatalf("GetAuthConfig() returned error: %v", err)
	}
	if got.GetAuthPort() != 8123 || got.GetAuthUrl() != "/v" {
		t.Fatalf("auth config = %#v", got)
	}
}

func TestGatewayControlSetAuthConfigRejectsNilRequest(t *testing.T) {
	server := newGatewayControlTestServer(t, "secret")
	_, err := server.SetAuthConfig(authTestContext(), nil)
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("status = %v, want invalid argument", status.Code(err))
	}
}

func TestGatewayControlSetDefaultRouteRejectsNilRequest(t *testing.T) {
	server := newGatewayControlTestServer(t, "secret")
	_, err := server.SetDefaultRoute(authTestContext(), nil)
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("status = %v, want invalid argument", status.Code(err))
	}
}

func TestGatewayControlLocaleConfigRoundTrip(t *testing.T) {
	server := newGatewayControlTestServer(t, "secret")
	got, err := server.SetLocaleConfig(authTestContext(), &pb.LocaleConfig{DefaultLocale: "en-US"})
	if err != nil {
		t.Fatalf("SetLocaleConfig() returned error: %v", err)
	}
	if got.GetDefaultLocale() != "en" {
		t.Fatalf("locale = %#v", got)
	}
}

func TestGatewayControlSetReverseProxyThrottleRejectsNilRequest(t *testing.T) {
	server := newGatewayControlTestServer(t, "secret")
	_, err := server.SetReverseProxyThrottle(authTestContext(), nil)
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("status = %v, want invalid argument", status.Code(err))
	}
}

func TestGatewayControlReverseProxyThrottleRoundTrip(t *testing.T) {
	server := newGatewayControlTestServer(t, "secret")
	ctx := authTestContext()
	got, err := server.SetReverseProxyThrottle(ctx, &pb.ReverseProxyThrottleConfig{Enabled: true, RequestsPerSecond: 7, Burst: 8, BlockSeconds: 9})
	if err != nil {
		t.Fatalf("SetReverseProxyThrottle() returned error: %v", err)
	}
	if got.GetRequestsPerSecond() != 7 || got.GetBurst() != 8 || got.GetBlockSeconds() != 9 {
		t.Fatalf("throttle = %#v", got)
	}
}

func TestGatewayControlGatewayVisibilityRoundTrip(t *testing.T) {
	server := newGatewayControlTestServer(t, "secret")
	got, err := server.SetGatewayVisibility(authTestContext(), &pb.GatewayVisibilityConfig{Enabled: true, Cidrs: []string{"198.51.100.0/24"}})
	if err != nil {
		t.Fatalf("SetGatewayVisibility() returned error: %v", err)
	}
	if !got.GetEnabled() || got.GetCidrs()[0] != "198.51.100.0/24" {
		t.Fatalf("visibility = %#v", got)
	}
}

func TestGatewayControlForwardedHeadersRoundTrip(t *testing.T) {
	server := newGatewayControlTestServer(t, "secret")
	got, err := server.SetForwardedHeadersConfig(authTestContext(), &pb.OmitTargetsConfig{Enabled: true, OmitTargets: []string{"http://127.0.0.1:8080"}})
	if err != nil {
		t.Fatalf("SetForwardedHeadersConfig() returned error: %v", err)
	}
	if !got.GetEnabled() || len(got.GetOmitTargets()) != 1 {
		t.Fatalf("forwarded headers = %#v", got)
	}
}

func TestGatewayControlPreserveHostRoundTrip(t *testing.T) {
	server := newGatewayControlTestServer(t, "secret")
	got, err := server.SetPreserveHostConfig(authTestContext(), &pb.OmitTargetsConfig{Enabled: true, OmitTargets: []string{"http://127.0.0.1:8080"}})
	if err != nil {
		t.Fatalf("SetPreserveHostConfig() returned error: %v", err)
	}
	if !got.GetEnabled() || len(got.GetOmitTargets()) != 1 {
		t.Fatalf("preserve host = %#v", got)
	}
}

func TestGatewayControlCrawlerBlockerRoundTrip(t *testing.T) {
	server := newGatewayControlTestServer(t, "secret")
	got, err := server.SetCrawlerBlockerConfig(authTestContext(), &pb.CrawlerBlockerConfig{Enabled: true, UpdatedAt: "now"})
	if err != nil {
		t.Fatalf("SetCrawlerBlockerConfig() returned error: %v", err)
	}
	if !got.GetEnabled() || got.GetUpdatedAt() != "now" {
		t.Fatalf("crawler blocker = %#v", got)
	}
}

func TestGatewayControlGatewayPortalRoundTrip(t *testing.T) {
	server := newGatewayControlTestServer(t, "secret")
	got, err := server.SetGatewayPortalConfig(authTestContext(), &pb.GatewayPortalConfig{Enabled: true, DisplayStyle: models.GatewayPortalDisplayStyleTitle, IconDragMode: models.GatewayPortalIconDragModeFree, ShowAppIcon: true, Version: models.GatewayPortalVersionV2})
	if err != nil {
		t.Fatalf("SetGatewayPortalConfig() returned error: %v", err)
	}
	if got.GetDisplayStyle() != models.GatewayPortalDisplayStyleTitle || got.GetIconDragMode() != models.GatewayPortalIconDragModeFree || got.GetVersion() != models.GatewayPortalVersionV2 {
		t.Fatalf("portal = %#v", got)
	}
}

func TestGatewayControlGatewayPortalPreservesDisabled(t *testing.T) {
	server := newGatewayControlTestServer(t, "secret")
	got, err := server.SetGatewayPortalConfig(authTestContext(), &pb.GatewayPortalConfig{
		Enabled:      false,
		DisplayStyle: models.GatewayPortalDisplayStyleTitle,
		IconDragMode: models.GatewayPortalIconDragModeFree,
		ShowAppIcon:  true,
		Version:      models.GatewayPortalVersionV2,
	})
	if err != nil {
		t.Fatalf("SetGatewayPortalConfig() returned error: %v", err)
	}
	if got.GetEnabled() {
		t.Fatalf("gateway portal was re-enabled: %#v", got)
	}

	stored, err := server.GetGatewayPortalConfig(authTestContext(), &emptypb.Empty{})
	if err != nil {
		t.Fatalf("GetGatewayPortalConfig() returned error: %v", err)
	}
	if stored.GetEnabled() {
		t.Fatalf("stored gateway portal was re-enabled: %#v", stored)
	}
}

func TestGatewayControlGatewayUnmatchedRouteRoundTrip(t *testing.T) {
	server := newGatewayControlTestServer(t, "secret")
	ctx := authTestContext()
	got, err := server.SetGatewayUnmatchedRouteConfig(ctx, &pb.GatewayUnmatchedRouteConfig{
		Behavior:            models.GatewayUnmatchedRouteBehaviorResetConnection,
		UpstreamErrorDetail: models.GatewayUpstreamErrorDetailResetConnection,
	})
	if err != nil {
		t.Fatalf("SetGatewayUnmatchedRouteConfig() returned error: %v", err)
	}
	if got.GetBehavior() != models.GatewayUnmatchedRouteBehaviorResetConnection ||
		got.GetUpstreamErrorDetail() != models.GatewayUpstreamErrorDetailResetConnection {
		t.Fatalf("set response = %#v", got)
	}
	reloaded, err := server.GetGatewayUnmatchedRouteConfig(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatalf("GetGatewayUnmatchedRouteConfig() returned error: %v", err)
	}
	if reloaded.GetBehavior() != models.GatewayUnmatchedRouteBehaviorResetConnection ||
		reloaded.GetUpstreamErrorDetail() != models.GatewayUpstreamErrorDetailResetConnection {
		t.Fatalf("get response = %#v", reloaded)
	}

	normalized, err := server.SetGatewayUnmatchedRouteConfig(ctx, &pb.GatewayUnmatchedRouteConfig{
		Behavior: "invalid",
	})
	if err != nil {
		t.Fatalf("invalid-value SetGatewayUnmatchedRouteConfig() returned error: %v", err)
	}
	if normalized.GetBehavior() != models.GatewayUnmatchedRouteBehaviorErrorPage {
		t.Fatalf("invalid behavior normalized to %q", normalized.GetBehavior())
	}
	if normalized.GetUpstreamErrorDetail() != models.GatewayUpstreamErrorDetailLess {
		t.Fatalf("missing upstream error detail normalized to %q", normalized.GetUpstreamErrorDetail())
	}
}

func TestGatewayControlSetGatewayUnmatchedRouteRejectsNilRequest(t *testing.T) {
	server := newGatewayControlTestServer(t, "secret")
	_, err := server.SetGatewayUnmatchedRouteConfig(authTestContext(), nil)
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("status = %v, want invalid argument", status.Code(err))
	}
}

func TestGatewayControlFnosPortIconHijackRoundTrip(t *testing.T) {
	server := newGatewayControlTestServer(t, "secret")
	got, err := server.SetFnosPortIconHijackConfig(authTestContext(), &pb.FnosPortIconHijackConfig{Enabled: true, UpdatedAt: "now"})
	if err != nil {
		t.Fatalf("SetFnosPortIconHijackConfig() returned error: %v", err)
	}
	if !got.GetEnabled() || got.GetUpdatedAt() != "now" {
		t.Fatalf("fnos hijack = %#v", got)
	}
}

func TestGatewayControlThrottleExemptIPsRoundTrip(t *testing.T) {
	server := newGatewayControlTestServer(t, "secret")
	got, err := server.SetReverseProxyThrottleExemptIps(authTestContext(), &pb.ReverseProxyThrottleExemptIpsRuntime{Enabled: true, Ips: []string{"198.51.100.7"}})
	if err != nil {
		t.Fatalf("SetReverseProxyThrottleExemptIps() returned error: %v", err)
	}
	if !got.GetEnabled() || got.GetIps()[0] != "198.51.100.7" {
		t.Fatalf("exempt IPs = %#v", got)
	}
}

func TestGatewayControlTrustedClientIPsRoundTripAndClear(t *testing.T) {
	server := newGatewayControlTestServer(t, "secret")
	ctx := authTestContext()
	got, err := server.SetGatewayTrustedClientIps(ctx, &pb.GatewayTrustedClientIpsRuntime{
		Ips:       []string{"192.168.1.8"},
		Cidrs:     []string{"100.64.0.7/10"},
		UpdatedAt: "2026-07-31T01:00:00Z",
	})
	if err != nil {
		t.Fatalf("SetGatewayTrustedClientIps() returned error: %v", err)
	}
	if got.GetIps()[0] != "192.168.1.8" || got.GetCidrs()[0] != "100.64.0.0/10" {
		t.Fatalf("trusted client IPs = %#v", got)
	}

	read, err := server.GetGatewayTrustedClientIps(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatalf("GetGatewayTrustedClientIps() returned error: %v", err)
	}
	if !proto.Equal(got, read) {
		t.Fatalf("read trusted client IPs = %#v, want %#v", read, got)
	}

	cleared, err := server.SetGatewayTrustedClientIps(ctx, &pb.GatewayTrustedClientIpsRuntime{
		UpdatedAt: "2026-07-31T01:00:01Z",
	})
	if err != nil {
		t.Fatalf("clear GatewayTrustedClientIps() returned error: %v", err)
	}
	if len(cleared.GetIps()) != 0 || len(cleared.GetCidrs()) != 0 {
		t.Fatalf("cleared trusted client IPs = %#v", cleared)
	}
}

func TestGatewayControlCommonLocationExemptionsRoundTrip(t *testing.T) {
	server := newGatewayControlTestServer(t, "secret")
	got, err := server.SetCommonLocationExemptions(authTestContext(), &pb.CommonLocationExemptionsRuntime{Enabled: true, Cidrs: []string{"198.51.100.0/24"}})
	if err != nil {
		t.Fatalf("SetCommonLocationExemptions() returned error: %v", err)
	}
	if !got.GetEnabled() || len(got.GetCidrs()) != 1 {
		t.Fatalf("common location exemptions = %#v", got)
	}
}

func TestSecurityGeneralBlacklistAddCheckRemove(t *testing.T) {
	server := newGatewayControlTestServer(t, "secret")
	ctx := authTestContext()
	added, err := server.AddGeneralBlacklist(ctx, &pb.IpListRequest{Ips: []string{"198.51.100.7"}, Source: "manual", Comment: "test"})
	if err != nil {
		t.Fatalf("AddGeneralBlacklist() returned error: %v", err)
	}
	if added.GetAdded() != 1 {
		t.Fatalf("added = %#v", added)
	}
	statusResp, err := server.CheckGeneralBlacklist(ctx, &pb.IpListRequest{Ips: []string{"198.51.100.7"}})
	if err != nil {
		t.Fatalf("CheckGeneralBlacklist() returned error: %v", err)
	}
	if statusResp.GetRecords()["198.51.100.7"].GetIp() != "198.51.100.7" {
		t.Fatalf("status = %#v", statusResp)
	}
	removed, err := server.RemoveGeneralBlacklist(ctx, &pb.IpListRequest{Ips: []string{"198.51.100.7"}})
	if err != nil {
		t.Fatalf("RemoveGeneralBlacklist() returned error: %v", err)
	}
	if removed.GetRemoved() != 1 {
		t.Fatalf("removed = %#v", removed)
	}
}

func TestTrafficServiceGetTrafficStatsReturnsStreamTraffic(t *testing.T) {
	server := newGatewayControlTestServer(t, "secret")
	server.admin.ProxyHandler.AddStreamTraffic(3, 4, 503)
	got, err := server.GetTrafficStats(authTestContext(), &emptypb.Empty{})
	if err != nil {
		t.Fatalf("GetTrafficStats() returned error: %v", err)
	}
	if got.GetTotalIn() != 3 || got.GetTotalOut() != 4 || got.GetError_5Xx() != 1 {
		t.Fatalf("traffic = %#v", got)
	}
}

func TestWafServiceSetDisabledConfigSucceeds(t *testing.T) {
	server := newGatewayControlTestServer(t, "secret")
	got, err := server.SetWafConfig(authTestContext(), &pb.WafConfig{Enabled: false})
	if err != nil {
		t.Fatalf("SetWafConfig() returned error: %v", err)
	}
	if got.GetEnabled() {
		t.Fatalf("waf status = %#v", got)
	}
}

func TestSslServiceClearSslSucceedsWhenEmpty(t *testing.T) {
	server := newGatewayControlTestServer(t, "secret")
	if _, err := server.ClearSsl(authTestContext(), &emptypb.Empty{}); err != nil {
		t.Fatalf("ClearSsl() returned error: %v", err)
	}
}

func TestRequireIPRejectsNilRequest(t *testing.T) {
	if _, err := requireIP(nil); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("status = %v, want invalid argument", status.Code(err))
	}
}

func TestDefaultParentChainsUsesFallback(t *testing.T) {
	got := defaultParentChains(nil)
	if len(got) != 2 || got[0] != "INPUT" || got[1] != "DOCKER-USER" {
		t.Fatalf("defaultParentChains(nil) = %#v", got)
	}
}

func authTestContext() context.Context {
	return metadata.NewIncomingContext(context.Background(), metadata.Pairs(rpcbridge.InternalTokenMetadataKey, "secret"))
}
