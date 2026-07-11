package main

import (
	"context"
	"testing"
	"time"

	"go-reauth-proxy/pkg/grpc/pb"
	"go-reauth-proxy/pkg/rpcbridge"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type internalGRPCTestControl struct {
	pb.UnimplementedGatewayControlServiceServer
}

func TestInternalGRPCHealthIsNamedAndTokenProtected(t *testing.T) {
	server, err := startInternalGRPCServer(
		0,
		"secret",
		&internalGRPCTestControl{},
		rpcbridge.NewAuthBridgeManager("secret"),
	)
	if err != nil {
		t.Fatalf("startInternalGRPCServer: %v", err)
	}
	stopCtx, stopCancel := context.WithTimeout(context.Background(), time.Second)
	defer stopCancel()
	defer server.Stop(stopCtx)

	conn, err := grpc.NewClient(server.listeners[0].Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial internal gRPC: %v", err)
	}
	defer conn.Close()
	client := healthpb.NewHealthClient(conn)
	if _, err := client.Check(context.Background(), &healthpb.HealthCheckRequest{Service: healthGatewayProcess}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("health without token status = %v, want unauthenticated", status.Code(err))
	}
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs(rpcbridge.InternalTokenMetadataKey, "secret"))
	response, err := client.Check(ctx, &healthpb.HealthCheckRequest{Service: healthGatewayProcess})
	if err != nil || response.GetStatus() != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("process health = %#v, %v", response, err)
	}
	response, err = client.Check(ctx, &healthpb.HealthCheckRequest{Service: healthGatewayDataplane})
	if err != nil || response.GetStatus() != healthpb.HealthCheckResponse_NOT_SERVING {
		t.Fatalf("initial dataplane health = %#v, %v", response, err)
	}
	server.SetServingStatus(healthGatewayDataplane, true)
	response, err = client.Check(ctx, &healthpb.HealthCheckRequest{Service: healthGatewayDataplane})
	if err != nil || response.GetStatus() != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("updated dataplane health = %#v, %v", response, err)
	}
}
