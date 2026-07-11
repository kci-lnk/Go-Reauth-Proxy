//go:build !linux

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
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

func TestInternalGRPCFirewallIsUnimplementedOutsideLinux(t *testing.T) {
	server, err := startInternalGRPCServer(0, "secret", &internalGRPCTestControl{}, rpcbridge.NewAuthBridgeManager("secret"))
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
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs(rpcbridge.InternalTokenMetadataKey, "secret"))
	_, err = pb.NewFirewallServiceClient(conn).FlushIptables(ctx, &emptypb.Empty{})
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("firewall status = %v, want unimplemented", status.Code(err))
	}
}
