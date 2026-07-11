package admin

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
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
	if info.GetControlApiVersion() != 1 || len(info.GetCapabilities()) == 0 || info.GetCommit() == "" {
		t.Fatalf("incomplete compatibility metadata: %#v", info)
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
