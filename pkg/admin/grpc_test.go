package admin

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sync/atomic"
	"testing"
	"time"

	"go-reauth-proxy/pkg/config"
	"go-reauth-proxy/pkg/grpc/pb"
	"go-reauth-proxy/pkg/models"
	"go-reauth-proxy/pkg/proxy"
	"go-reauth-proxy/pkg/rpcbridge"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

func TestGatewayControlTypedProxyProtocolRequiresToken(t *testing.T) {
	server := newGatewayControlTestServer(t, "secret")

	_, err := server.GetProxyProtocolForce(context.Background(), &emptypb.Empty{})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("status = %v, want unauthenticated", status.Code(err))
	}
}

func TestWAFDrainOperations(t *testing.T) {
	server := newGatewayControlTestServer(t, "secret")
	ctx := authTestContext()

	if _, err := server.DrainWafEvents(ctx, nil); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("DrainWafEvents(nil) status = %v, want invalid argument", status.Code(err))
	}
	if _, err := server.DrainWafEvents(ctx, &pb.WafDrainRequest{
		Operation: pb.WafDrainOperation_WAF_DRAIN_OPERATION_ACKNOWLEDGE,
	}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("empty acknowledgement status = %v, want invalid argument", status.Code(err))
	}
	if _, err := server.DrainWafEvents(ctx, &pb.WafDrainRequest{
		Operation: pb.WafDrainOperation_WAF_DRAIN_OPERATION_RELEASE,
	}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("empty release status = %v, want invalid argument", status.Code(err))
	}
	if _, err := server.DrainWafEvents(ctx, &pb.WafDrainRequest{
		Operation: pb.WafDrainOperation_WAF_DRAIN_OPERATION_LEASE,
		Limit:     10,
	}); err != nil {
		t.Fatalf("leased drain returned error: %v", err)
	}
	// A legacy control plane sends UNSPECIFIED and expects an immediate drain
	// without a delivery lease; keep that path working across version skew.
	if _, err := server.DrainWafEvents(ctx, &pb.WafDrainRequest{}); err != nil {
		t.Fatalf("legacy unspecified drain returned error: %v", err)
	}
}

func TestGatewayControlTypedProxyProtocolRoundTrip(t *testing.T) {
	server := newGatewayControlTestServer(t, "secret")
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(rpcbridge.InternalTokenMetadataKey, "secret"))

	before, err := server.GetProxyProtocolForce(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatalf("GetProxyProtocolForce before set: %v", err)
	}
	if before.GetValue() {
		t.Fatalf("initial proxy protocol force = true, want false")
	}

	after, err := server.SetProxyProtocolForce(ctx, &pb.BoolValue{Value: true})
	if err != nil {
		t.Fatalf("SetProxyProtocolForce: %v", err)
	}
	if !after.GetValue() {
		t.Fatalf("set response = false, want true")
	}

	got, err := server.GetProxyProtocolForce(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatalf("GetProxyProtocolForce after set: %v", err)
	}
	if !got.GetValue() {
		t.Fatalf("stored proxy protocol force = false, want true")
	}
}

func TestGatewayControlServerInfoIncludesCompatibilityMetadata(t *testing.T) {
	server := newGatewayControlTestServer(t, "secret")
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(rpcbridge.InternalTokenMetadataKey, "secret"))
	info, err := server.GetServerInfo(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatalf("GetServerInfo: %v", err)
	}
	if info.GetVersion() == "" || info.GetOs() != runtime.GOOS || info.GetArch() != runtime.GOARCH {
		t.Fatalf("unexpected server info: %#v", info)
	}
	if info.GetControlApiVersion() != uint32(pb.ControlApiVersion_CONTROL_API_VERSION_CURRENT) || len(info.GetCapabilities()) == 0 || info.GetCommit() == "" {
		t.Fatalf("incomplete compatibility metadata: %#v", info)
	}
	hasTrustedClientIPBypass := false
	hasMemoryControl := false
	for _, capability := range info.GetCapabilities() {
		if capability == "trusted_client_ip_bypass_v1" {
			hasTrustedClientIPBypass = true
		}
		if capability == "memory_control_v1" {
			hasMemoryControl = true
		}
	}
	if !hasTrustedClientIPBypass {
		t.Fatalf("server info is missing trusted_client_ip_bypass_v1: %#v", info.GetCapabilities())
	}
	if !hasMemoryControl {
		t.Fatalf("server info is missing memory_control_v1: %#v", info.GetCapabilities())
	}
}

func TestGatewayRuntimeInfoRequiresTokenAndIsStable(t *testing.T) {
	server := newGatewayControlTestServer(t, "secret")
	if _, err := server.GetRuntimeInfo(context.Background(), &emptypb.Empty{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("unauthenticated status = %v, want unauthenticated", status.Code(err))
	}

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(rpcbridge.InternalTokenMetadataKey, "secret"))
	first, err := server.GetRuntimeInfo(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatalf("GetRuntimeInfo first: %v", err)
	}
	time.Sleep(2 * time.Millisecond)
	second, err := server.GetRuntimeInfo(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatalf("GetRuntimeInfo second: %v", err)
	}
	if first.GetInstanceId() == "" || first.GetInstanceId() != second.GetInstanceId() {
		t.Fatalf("instance id changed: %q -> %q", first.GetInstanceId(), second.GetInstanceId())
	}
	if first.GetPid() != int64(os.Getpid()) || first.GetPid() != second.GetPid() {
		t.Fatalf("unexpected pid: %d -> %d", first.GetPid(), second.GetPid())
	}
	if second.GetUptimeMs() < first.GetUptimeMs() {
		t.Fatalf("uptime moved backwards: %d -> %d", first.GetUptimeMs(), second.GetUptimeMs())
	}
	if first.GetStartedAtUnixMs() == 0 || first.GetGoVersion() == "" || first.GetGoroutines() == 0 {
		t.Fatalf("incomplete runtime info: %#v", first)
	}
	if first.GetGcPercent() != initialGCPercent() {
		t.Fatalf("GC percent = %d, want %d", first.GetGcPercent(), initialGCPercent())
	}
	if first.GetMemoryLimitBytes() <= 0 || first.GetManagedMemoryBytes() == 0 {
		t.Fatalf("memory limit/runtime-managed bytes were not reported: %#v", first)
	}
	if first.GetRssBytes() == 0 || second.GetRssBytes() == 0 {
		t.Fatalf("RSS was not reported: %d -> %d", first.GetRssBytes(), second.GetRssBytes())
	}
}

func TestInitialGCPercentHandlesGoEnvironmentValues(t *testing.T) {
	for _, test := range []struct {
		name  string
		value string
		want  int32
	}{
		{name: "unset", value: "", want: defaultGCPercent},
		{name: "numeric", value: "75", want: 75},
		{name: "off", value: "off", want: -1},
		{name: "off uppercase and padded", value: " OFF ", want: -1},
		{name: "invalid", value: "invalid", want: defaultGCPercent},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("GOGC", test.value)
			if got := initialGCPercent(); got != test.want {
				t.Fatalf("initialGCPercent() = %d, want %d", got, test.want)
			}
		})
	}
}

func TestGatewayMemoryControlRequiresTokenAndValidatesRange(t *testing.T) {
	server := newGatewayControlTestServer(t, "secret")
	if _, err := server.SetGatewayMemoryConfig(context.Background(), &pb.GatewayMemoryConfig{GcPercent: 50}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("unauthenticated set status = %v, want unauthenticated", status.Code(err))
	}
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(rpcbridge.InternalTokenMetadataKey, "secret"))
	for _, value := range []int32{24, 501} {
		if _, err := server.SetGatewayMemoryConfig(ctx, &pb.GatewayMemoryConfig{GcPercent: value}); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("gc_percent=%d status = %v, want invalid argument", value, status.Code(err))
		}
	}
	for _, value := range []int64{63 << 20, 4097 << 20} {
		if _, err := server.SetGatewayMemoryConfig(ctx, &pb.GatewayMemoryConfig{GcPercent: 100, MemoryLimitBytes: value}); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("memory_limit_bytes=%d status = %v, want invalid argument", value, status.Code(err))
		}
	}
}

func TestGatewayMemoryControlAppliesAndReclaims(t *testing.T) {
	server := newGatewayControlTestServer(t, "secret")
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(rpcbridge.InternalTokenMetadataKey, "secret"))
	previous := debug.SetGCPercent(100)
	t.Cleanup(func() { debug.SetGCPercent(previous) })
	previousLimit := debug.SetMemoryLimit(-1)
	t.Cleanup(func() { debug.SetMemoryLimit(previousLimit) })

	applied, err := server.SetGatewayMemoryConfig(ctx, &pb.GatewayMemoryConfig{GcPercent: 50, MemoryLimitBytes: 128 << 20})
	if err != nil || applied.GetGcPercent() != 50 || applied.GetMemoryLimitBytes() != 128<<20 {
		t.Fatalf("SetGatewayMemoryConfig = %#v, %v", applied, err)
	}
	info, err := server.ReclaimGatewayMemory(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatalf("ReclaimGatewayMemory: %v", err)
	}
	if info.GetGcPercent() != 50 || info.GetMemoryLimitBytes() != 128<<20 || info.GetHeapSysBytes() == 0 || info.GetRssBytes() == 0 {
		t.Fatalf("unexpected runtime info after reclaim: %#v", info)
	}
}

func TestGatewayControlListenerConfigRoundTrip(t *testing.T) {
	server := newGatewayControlTestServer(t, "secret")
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(rpcbridge.InternalTokenMetadataKey, "secret"))
	set, err := server.SetGatewayListenerConfig(ctx, &pb.GatewayListenerConfig{Scope: "loopback"})
	if err != nil || set.GetScope() != "loopback" {
		t.Fatalf("SetGatewayListenerConfig = %#v, %v", set, err)
	}
	got, err := server.GetGatewayListenerConfig(ctx, &emptypb.Empty{})
	if err != nil || got.GetScope() != "loopback" {
		t.Fatalf("GetGatewayListenerConfig = %#v, %v", got, err)
	}
	if _, err := server.SetGatewayListenerConfig(ctx, &pb.GatewayListenerConfig{Scope: "public"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("invalid scope status = %v, want invalid argument", status.Code(err))
	}
}

func TestGatewayControlListenerConfigReturnsFailureWhenRuntimeApplyFails(t *testing.T) {
	server := newGatewayControlTestServer(t, "secret")
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(rpcbridge.InternalTokenMetadataKey, "secret"))
	previous := server.admin.ProxyHandler.GetGatewayListenerConfig()
	nextScope := "loopback"
	if previous.Scope == nextScope {
		nextScope = "all"
	}
	server.admin.ProxyHandler.SetGatewayListenerConfigChangeHook(func(models.GatewayListenerConfig) error {
		return errors.New("listener port is unavailable")
	})

	if _, err := server.SetGatewayListenerConfig(ctx, &pb.GatewayListenerConfig{Scope: nextScope}); status.Code(err) != codes.Internal {
		t.Fatalf("runtime apply failure status = %v, want internal", status.Code(err))
	}
	if got := server.admin.ProxyHandler.GetGatewayListenerConfig(); got != previous {
		t.Fatalf("listener config after failed RPC = %#v, want %#v", got, previous)
	}
}

func TestGatewayControlResetAllDataClearsRuntimeAndPersistedConfig(t *testing.T) {
	server := newGatewayControlTestServer(t, "secret")
	ctx := authTestContext()
	previousGCPercent := debug.SetGCPercent(int(defaultGCPercent))
	t.Cleanup(func() { debug.SetGCPercent(previousGCPercent) })
	previousMemoryLimit := debug.SetMemoryLimit(-1)
	t.Cleanup(func() { debug.SetMemoryLimit(previousMemoryLimit) })

	if _, err := server.SetRules(ctx, &pb.Rules{Items: []*pb.Rule{{Path: "/app", Target: "http://127.0.0.1:8080"}}}); err != nil {
		t.Fatalf("SetRules: %v", err)
	}
	if _, err := server.SetHostRules(ctx, &pb.HostRules{Items: []*pb.HostRule{{Host: "app.example.test", Target: "http://127.0.0.1:8080"}}}); err != nil {
		t.Fatalf("SetHostRules: %v", err)
	}
	if _, err := server.AddGeneralBlacklist(ctx, &pb.IpListRequest{Ips: []string{"203.0.113.10"}, Source: "manual"}); err != nil {
		t.Fatalf("AddGeneralBlacklist: %v", err)
	}
	if _, err := server.SetGatewayVisibility(ctx, &pb.GatewayVisibilityConfig{Enabled: true, Cidrs: []string{"192.0.2.0/24"}}); err != nil {
		t.Fatalf("SetGatewayVisibility: %v", err)
	}
	if _, err := server.SetGatewayTrustedClientIps(ctx, &pb.GatewayTrustedClientIpsRuntime{Ips: []string{"203.0.113.11"}}); err != nil {
		t.Fatalf("SetGatewayTrustedClientIps: %v", err)
	}
	const configuredMemoryLimit = 128 << 20
	if _, err := server.SetGatewayMemoryConfig(ctx, &pb.GatewayMemoryConfig{GcPercent: 50, MemoryLimitBytes: configuredMemoryLimit}); err != nil {
		t.Fatalf("SetGatewayMemoryConfig: %v", err)
	}

	result, err := server.ResetAllData(ctx, &emptypb.Empty{})
	if err != nil || !result.GetSuccess() {
		t.Fatalf("ResetAllData = %#v, %v", result, err)
	}
	if got := server.admin.ProxyHandler.GetRules(); len(got) != 0 {
		t.Fatalf("runtime path rules after reset = %#v", got)
	}
	if got := server.admin.ProxyHandler.GetHostRules(); len(got) != 0 {
		t.Fatalf("runtime host rules after reset = %#v", got)
	}
	if got := server.admin.ProxyHandler.GetGeneralBlacklist(); len(got.Items) != 0 {
		t.Fatalf("runtime blacklist after reset = %#v", got)
	}
	if got := server.admin.ProxyHandler.GetGatewayVisibility(); got.Enabled || len(got.CIDRs) != 0 {
		t.Fatalf("runtime visibility after reset = %#v", got)
	}
	if got := server.gcPercent.Load(); got != defaultGCPercent {
		t.Fatalf("GC percent after reset = %d, want %d", got, defaultGCPercent)
	}
	if got := server.memoryLimitBytes.Load(); got != configuredMemoryLimit {
		t.Fatalf("memory limit after reset = %d, want preserved %d", got, configuredMemoryLimit)
	}
	if got := server.admin.ProxyHandler.GetGatewayTrustedClientIPs(); len(got.IPs) != 0 || len(got.CIDRs) != 0 {
		t.Fatalf("runtime trusted client IPs after reset = %#v", got)
	}

	persisted, err := server.admin.ConfigManager.Load()
	if err != nil {
		t.Fatalf("Load config after reset: %v", err)
	}
	if len(persisted.Rules) != 0 || len(persisted.HostRules) != 0 || len(persisted.StreamRules) != 0 {
		t.Fatalf("persisted rules after reset = %#v, %#v, %#v", persisted.Rules, persisted.HostRules, persisted.StreamRules)
	}
	if len(persisted.GeneralBlacklist.Items) != 0 || len(persisted.SSL.Certificates) != 0 || persisted.SSLCert != "" || persisted.SSLKey != "" {
		t.Fatalf("persisted security data was not cleared")
	}
}

func TestGatewayControlRequestShutdownIsIdempotent(t *testing.T) {
	server := newGatewayControlTestServer(t, "secret")
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(rpcbridge.InternalTokenMetadataKey, "secret"))
	var calls atomic.Int32
	done := make(chan struct{})
	server.SetShutdownRequest(func() {
		calls.Add(1)
		close(done)
	})
	for i := 0; i < 3; i++ {
		if response, err := server.RequestShutdown(ctx, &emptypb.Empty{}); err != nil || !response.GetSuccess() {
			t.Fatalf("RequestShutdown[%d] = %#v, %v", i, response, err)
		}
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("shutdown callback was not invoked")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("shutdown callback calls = %d, want 1", got)
	}
}

func TestGatewayControlSetRulesIsAtomicOnValidationError(t *testing.T) {
	server := newGatewayControlTestServer(t, "secret")
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(rpcbridge.InternalTokenMetadataKey, "secret"))

	_, err := server.SetRules(ctx, &pb.Rules{Items: []*pb.Rule{
		{Path: "/ok", Target: "http://127.0.0.1:8080", StripPath: true, RewriteHtml: true},
	}})
	if err != nil {
		t.Fatalf("SetRules initial: %v", err)
	}

	_, err = server.SetRules(ctx, &pb.Rules{Items: []*pb.Rule{
		{Path: "/next", Target: "http://127.0.0.1:8081", StripPath: true, RewriteHtml: true},
		{Path: "/", Target: "http://127.0.0.1:8082", StripPath: true, RewriteHtml: true},
	}})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("status = %v, want invalid argument", status.Code(err))
	}

	got, err := server.GetRules(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatalf("GetRules after failed set: %v", err)
	}
	if len(got.GetItems()) != 1 || got.GetItems()[0].GetPath() != "/ok" {
		t.Fatalf("rules after failed set = %#v, want original /ok rule", got.GetItems())
	}
}

func TestGatewayControlSaveErrorPropagates(t *testing.T) {
	tempDir := t.TempDir()
	goodConfig := config.NewManager(filepath.Join(tempDir, "good", "config.json"))
	initialCfg, err := goodConfig.Load()
	if err != nil {
		t.Fatalf("load default config: %v", err)
	}

	blocker := filepath.Join(tempDir, "not-a-dir")
	if err := os.WriteFile(blocker, []byte("block"), 0644); err != nil {
		t.Fatalf("write blocker file: %v", err)
	}
	badConfig := config.NewManager(filepath.Join(blocker, "config.json"))
	proxyHandler := proxy.NewHandler(7996, 7999, badConfig, initialCfg, filepath.Join(t.TempDir(), "logs"), nil)
	server := NewGRPCServer(NewServer(proxyHandler, 7996, badConfig, initialCfg, nil), "secret")
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(rpcbridge.InternalTokenMetadataKey, "secret"))

	_, err = server.SetDefaultRoute(ctx, &pb.StringValue{Value: "/next"})
	if status.Code(err) != codes.Internal {
		t.Fatalf("status = %v, want internal; err=%v", status.Code(err), err)
	}
}

func TestGatewayControlHostRulesDistinguishesPersistenceAndValidationErrors(t *testing.T) {
	tempDir := t.TempDir()
	goodConfig := config.NewManager(filepath.Join(tempDir, "good", "config.json"))
	initialCfg, err := goodConfig.Load()
	if err != nil {
		t.Fatalf("load default config: %v", err)
	}

	blocker := filepath.Join(tempDir, "not-a-dir")
	if err := os.WriteFile(blocker, []byte("block"), 0644); err != nil {
		t.Fatalf("write blocker file: %v", err)
	}
	badConfig := config.NewManager(filepath.Join(blocker, "config.json"))
	proxyHandler := proxy.NewHandler(7996, 7999, badConfig, initialCfg, filepath.Join(t.TempDir(), "logs"), nil)
	server := NewGRPCServer(NewServer(proxyHandler, 7996, badConfig, initialCfg, nil), "secret")
	ctx := authTestContext()

	_, err = server.SetHostRules(ctx, &pb.HostRules{Items: []*pb.HostRule{{
		Host:   "app.example.test",
		Target: "http://127.0.0.1:8080",
	}}})
	if status.Code(err) != codes.Internal {
		t.Fatalf("persistence status = %v, want internal; err=%v", status.Code(err), err)
	}

	_, err = server.SetHostRules(ctx, &pb.HostRules{Items: []*pb.HostRule{{
		Host:   "app.example.test",
		Target: "not-a-valid-target",
	}}})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("validation status = %v, want invalid argument; err=%v", status.Code(err), err)
	}
}

func TestGatewayControlUnchangedHostRulesDoNotRequirePersistence(t *testing.T) {
	tempDir := t.TempDir()
	goodConfig := config.NewManager(filepath.Join(tempDir, "good", "config.json"))
	initialCfg, err := goodConfig.Load()
	if err != nil {
		t.Fatalf("load default config: %v", err)
	}
	initialCfg.HostRules = []models.HostRule{{
		Host:           "app.example.test",
		Target:         "http://127.0.0.1:8080",
		TargetPathMode: models.HostTargetPathModeEntry,
		ProtocolMode:   models.HostProtocolModeAuto,
		AccessMode:     "login_first",
		Visibility: models.HostRuleVisibility{
			Mode: models.HostVisibilityModeInherit,
		},
	}}

	blocker := filepath.Join(tempDir, "not-a-dir")
	if err := os.WriteFile(blocker, []byte("block"), 0644); err != nil {
		t.Fatalf("write blocker file: %v", err)
	}
	badConfig := config.NewManager(filepath.Join(blocker, "config.json"))
	proxyHandler := proxy.NewHandler(7996, 7999, badConfig, initialCfg, filepath.Join(t.TempDir(), "logs"), nil)
	server := NewGRPCServer(NewServer(proxyHandler, 7996, badConfig, initialCfg, nil), "secret")
	ctx := authTestContext()
	emptyGroup := ""

	if _, err := server.SetHostRules(ctx, &pb.HostRules{Items: []*pb.HostRule{{
		Host:         "app.example.test",
		Target:       "http://127.0.0.1:8080",
		GroupId:      &emptyGroup,
		GroupName:    &emptyGroup,
		AdvancedAuth: &pb.AdvancedAuthConfig{},
	}}}); err != nil {
		t.Fatalf("unchanged host rules required persistence: %v", err)
	}

	if _, err := server.SetHostRules(ctx, &pb.HostRules{Items: []*pb.HostRule{{
		Host:   "app.example.test",
		Target: "http://127.0.0.1:8081",
	}}}); status.Code(err) != codes.Internal {
		t.Fatalf("changed host rules status = %v, want internal; err=%v", status.Code(err), err)
	}

	emptyHandler := proxy.NewHandler(7996, 7999, badConfig, &config.AppConfig{}, filepath.Join(t.TempDir(), "logs"), nil)
	emptyServer := NewGRPCServer(NewServer(emptyHandler, 7996, badConfig, &config.AppConfig{}, nil), "secret")
	if _, err := emptyServer.FlushHostRules(ctx, &emptypb.Empty{}); err != nil {
		t.Fatalf("unchanged empty host rules required persistence: %v", err)
	}
}

func TestGatewayControlFnosConnectIngressIsAuthenticatedAndValidatesPorts(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.json")
	cfgManager := config.NewManager(configPath)
	initialCfg, err := cfgManager.Load()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	proxyHandler := proxy.NewHandler(7996, 7999, cfgManager, initialCfg, filepath.Join(t.TempDir(), "logs"), nil)
	ingress := proxy.NewFnosConnectIngress(proxyHandler)
	defer ingress.Close()
	server := NewGRPCServer(
		NewServer(proxyHandler, 7996, cfgManager, initialCfg, nil, ingress),
		"secret",
	)

	if _, err := server.GetFnosConnectIngressStatus(context.Background(), &emptypb.Empty{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("unauthenticated status = %v, want unauthenticated", status.Code(err))
	}
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(rpcbridge.InternalTokenMetadataKey, "secret"))
	if _, err := server.SetFnosConnectIngressConfig(ctx, &pb.FnosConnectIngressConfig{Enabled: true}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("invalid port status = %v, want invalid argument", status.Code(err))
	}
	got, err := server.SetFnosConnectIngressConfig(ctx, &pb.FnosConnectIngressConfig{
		Enabled:          true,
		UpstreamHttpPort: 19122,
	})
	if err != nil {
		t.Fatalf("enable ingress: %v", err)
	}
	if !got.GetListenerActive() || !got.GetIpv4Active() || !got.GetIpv6Active() || got.GetListenPort() == 0 {
		t.Fatalf("unexpected ingress status: %#v", got)
	}
	disabled, err := server.SetFnosConnectIngressConfig(ctx, &pb.FnosConnectIngressConfig{})
	if err != nil {
		t.Fatalf("disable ingress: %v", err)
	}
	if disabled.GetEnabled() || disabled.GetListenerActive() {
		t.Fatalf("ingress remained active: %#v", disabled)
	}
}

func newGatewayControlTestServer(t *testing.T, token string) *GRPCServer {
	t.Helper()
	configPath := filepath.Join(t.TempDir(), "config.json")
	cfgManager := config.NewManager(configPath)
	initialCfg, err := cfgManager.Load()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	proxyHandler := proxy.NewHandler(7996, 7999, cfgManager, initialCfg, filepath.Join(t.TempDir(), "logs"), nil)
	return NewGRPCServer(NewServer(proxyHandler, 7996, cfgManager, initialCfg, nil), token)
}
