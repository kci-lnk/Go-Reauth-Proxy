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

func TestInternalGRPCMutationGateDropsCancelledQueuedRetry(t *testing.T) {
	interceptor := newInternalUnaryInterceptor("secret")
	authContext := func(ctx context.Context) context.Context {
		return metadata.NewIncomingContext(
			ctx,
			metadata.Pairs(rpcbridge.InternalTokenMetadataKey, "secret"),
		)
	}
	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	defer func() {
		select {
		case <-releaseFirst:
		default:
			close(releaseFirst)
		}
	}()
	firstResult := make(chan error, 1)
	go func() {
		_, err := interceptor(
			authContext(context.Background()),
			nil,
			&grpc.UnaryServerInfo{FullMethod: pb.GatewayControlService_SetAuthConfig_FullMethodName},
			func(context.Context, any) (any, error) {
				close(firstStarted)
				<-releaseFirst
				return nil, nil
			},
		)
		firstResult <- err
	}()
	<-firstStarted

	ctx, cancel := context.WithCancel(authContext(context.Background()))
	cancel()
	queuedHandlerCalled := false
	_, err := interceptor(
		ctx,
		nil,
		&grpc.UnaryServerInfo{FullMethod: pb.GatewayControlService_SetRules_FullMethodName},
		func(context.Context, any) (any, error) {
			queuedHandlerCalled = true
			return nil, nil
		},
	)
	if status.Code(err) != codes.Canceled {
		t.Fatalf("queued mutation status = %v, want canceled", status.Code(err))
	}
	if queuedHandlerCalled {
		t.Fatal("cancelled queued mutation entered the service handler")
	}

	readHandlerCalled := false
	if _, err := interceptor(
		authContext(context.Background()),
		nil,
		&grpc.UnaryServerInfo{FullMethod: pb.GatewayControlService_GetRules_FullMethodName},
		func(context.Context, any) (any, error) {
			readHandlerCalled = true
			return nil, nil
		},
	); err != nil || !readHandlerCalled {
		t.Fatalf("read RPC was blocked by mutation: called=%v err=%v", readHandlerCalled, err)
	}

	close(releaseFirst)
	if err := <-firstResult; err != nil {
		t.Fatalf("first mutation returned error: %v", err)
	}
}
