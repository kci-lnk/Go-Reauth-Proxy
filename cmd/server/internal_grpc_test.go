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

type waitingWafControl struct {
	pb.UnimplementedGatewayControlServiceServer
	pb.UnimplementedWafServiceServer
	started chan struct{}
}

func (s *waitingWafControl) WaitWafEvents(ctx context.Context, _ *pb.WafWaitRequest) (*pb.WafWaitResult, error) {
	close(s.started)
	<-ctx.Done()
	return nil, status.FromContextError(ctx.Err()).Err()
}

func TestInternalGRPCStopCancelsIdleWafWaitBeforeGracefulStop(t *testing.T) {
	control := &waitingWafControl{started: make(chan struct{})}
	server, err := startInternalGRPCServer(0, "secret", control, rpcbridge.NewAuthBridgeManager("secret"))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Stop(context.Background())
	conn, err := grpc.NewClient(server.listeners[0].Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs(rpcbridge.InternalTokenMetadataKey, "secret"))
	done := make(chan error, 1)
	go func() { _, err := pb.NewWafServiceClient(conn).WaitWafEvents(ctx, &pb.WafWaitRequest{}); done <- err }()
	select {
	case <-control.started:
	case <-time.After(time.Second):
		t.Fatal("wait not started")
	}
	started := time.Now()
	server.Stop(context.Background())
	if time.Since(started) > time.Second {
		t.Fatal("idle WAF wait delayed graceful shutdown")
	}
	if err := <-done; status.Code(err) != codes.Canceled {
		t.Fatalf("wait status = %v", err)
	}
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

func TestInternalGRPCMutationGateDropsExpiredQueuedRetry(t *testing.T) {
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

	ctx, cancel := context.WithTimeout(authContext(context.Background()), 25*time.Millisecond)
	defer cancel()
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
	if status.Code(err) != codes.DeadlineExceeded {
		t.Fatalf("queued mutation status = %v, want deadline exceeded", status.Code(err))
	}
	if queuedHandlerCalled {
		t.Fatal("expired queued mutation entered the service handler")
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

	firewallHandlerCalled := false
	if _, err := interceptor(
		authContext(context.Background()),
		nil,
		&grpc.UnaryServerInfo{FullMethod: pb.FirewallService_BlockAll_FullMethodName},
		func(context.Context, any) (any, error) {
			firewallHandlerCalled = true
			return nil, nil
		},
	); err != nil || !firewallHandlerCalled {
		t.Fatalf("firewall RPC was blocked by durable mutation: called=%v err=%v", firewallHandlerCalled, err)
	}

	close(releaseFirst)
	if err := <-firstResult; err != nil {
		t.Fatalf("first mutation returned error: %v", err)
	}
}

func TestInternalGRPCMutationClassificationCoversDurableOperations(t *testing.T) {
	for _, fullMethod := range []string{
		pb.GatewayControlService_SetAuthConfig_FullMethodName,
		pb.GatewayControlService_SetRules_FullMethodName,
		pb.GatewayControlService_ResetAllData_FullMethodName,
		pb.GatewayLogsService_SetLoggingConfig_FullMethodName,
		pb.SecurityService_AddGeneralBlacklist_FullMethodName,
		pb.WafService_SetWafConfig_FullMethodName,
		pb.WafService_ReloadWafBundle_FullMethodName,
		pb.SslService_SetSslDeployment_FullMethodName,
		pb.SslService_SetSslPem_FullMethodName,
		pb.SslService_ClearSsl_FullMethodName,
	} {
		if !isSerializedDurableMutation(fullMethod) {
			t.Errorf("durable mutation %q is not serialized", fullMethod)
		}
	}
	for _, fullMethod := range []string{
		pb.GatewayControlService_GetRules_FullMethodName,
		pb.GatewayControlService_SetGatewayMemoryConfig_FullMethodName,
		pb.GatewayControlService_ReclaimGatewayMemory_FullMethodName,
		pb.WafService_ValidateWafBundle_FullMethodName,
		pb.FirewallService_BlockAll_FullMethodName,
	} {
		if isSerializedDurableMutation(fullMethod) {
			t.Errorf("independent operation %q uses the durable mutation gate", fullMethod)
		}
	}
	if !isSerializedFirewallMutation(pb.FirewallService_BlockAll_FullMethodName) {
		t.Fatal("firewall mutation is not serialized")
	}
	if isSerializedFirewallMutation(pb.FirewallService_ListIptables_FullMethodName) {
		t.Fatal("firewall read unexpectedly uses the mutation gate")
	}
}
