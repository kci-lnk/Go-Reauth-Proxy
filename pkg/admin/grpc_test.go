package admin

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"go-reauth-proxy/pkg/config"
	"go-reauth-proxy/pkg/grpc/pb"
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
