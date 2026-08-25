package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"go-reauth-proxy/pkg/grpc/pb"
	"go-reauth-proxy/pkg/logger"
	"go-reauth-proxy/pkg/rpcbridge"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
)

const internalGRPCMaxMessageSize = 16 << 20

const (
	healthGatewayProcess    = "fnknock.gateway.process"
	healthGatewayDataplane  = "fnknock.gateway.dataplane"
	healthGatewayAuthBridge = "fnknock.gateway.auth_bridge"
)

type internalGRPCServer struct {
	server    *grpc.Server
	health    *health.Server
	listeners []net.Listener
	wg        sync.WaitGroup
	stopOnce  sync.Once
}

func startInternalGRPCServer(port int, token string, control pb.GatewayControlServiceServer, bridge pb.AuthBridgeServiceServer) (*internalGRPCServer, error) {
	server := grpc.NewServer(
		grpc.MaxRecvMsgSize(internalGRPCMaxMessageSize),
		grpc.MaxSendMsgSize(internalGRPCMaxMessageSize),
		grpc.UnaryInterceptor(newInternalUnaryInterceptor(token)),
		grpc.StreamInterceptor(func(srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
			if err := rpcbridge.CheckInternalToken(stream.Context(), token); err != nil {
				return err
			}
			return handler(srv, stream)
		}),
	)
	healthServer := health.NewServer()
	for _, service := range []string{healthGatewayProcess, healthGatewayDataplane, healthGatewayAuthBridge} {
		healthServer.SetServingStatus(service, healthpb.HealthCheckResponse_NOT_SERVING)
	}
	healthpb.RegisterHealthServer(server, healthServer)
	pb.RegisterGatewayControlServiceServer(server, control)
	if logs, ok := control.(pb.GatewayLogsServiceServer); ok {
		pb.RegisterGatewayLogsServiceServer(server, logs)
	}
	if deepMonitor, ok := control.(pb.DeepMonitorServiceServer); ok {
		pb.RegisterDeepMonitorServiceServer(server, deepMonitor)
	}
	if security, ok := control.(pb.SecurityServiceServer); ok {
		pb.RegisterSecurityServiceServer(server, security)
	}
	if traffic, ok := control.(pb.TrafficServiceServer); ok {
		pb.RegisterTrafficServiceServer(server, traffic)
	}
	if waf, ok := control.(pb.WafServiceServer); ok {
		pb.RegisterWafServiceServer(server, waf)
	}
	if ssl, ok := control.(pb.SslServiceServer); ok {
		pb.RegisterSslServiceServer(server, ssl)
	}
	registerFirewallService(server, control)
	pb.RegisterAuthBridgeServiceServer(server, bridge)

	listenTargets := []struct {
		network string
		host    string
	}{
		{network: "tcp4", host: "127.0.0.1"},
		{network: "tcp6", host: "::1"},
	}

	var listeners []net.Listener
	var listenAddrs []string
	for _, target := range listenTargets {
		addr := net.JoinHostPort(target.host, strconv.Itoa(port))
		listener, err := net.Listen(target.network, addr)
		if err != nil {
			if target.network == "tcp6" {
				log.Printf("Internal gRPC IPv6 listener unavailable on %s: %v", addr, err)
				continue
			}
			for _, openListener := range listeners {
				_ = openListener.Close()
			}
			return nil, err
		}
		listeners = append(listeners, listener)
		listenAddrs = append(listenAddrs, listener.Addr().String())
	}
	if len(listeners) == 0 {
		return nil, fmt.Errorf("no internal gRPC listeners started on port %d", port)
	}

	runtimeServer := &internalGRPCServer{
		server:    server,
		health:    healthServer,
		listeners: listeners,
	}
	for _, listener := range listeners {
		runtimeServer.wg.Add(1)
		go func(l net.Listener) {
			defer runtimeServer.wg.Done()
			if err := server.Serve(l); err != nil {
				log.Printf("Internal gRPC server stopped on %s: %v", l.Addr().String(), err)
			}
		}(listener)
	}
	log.Printf("Internal gRPC server listening on %s", strings.Join(listenAddrs, ", "))
	healthServer.SetServingStatus(healthGatewayProcess, healthpb.HealthCheckResponse_SERVING)
	logger.Diagnostic("INFO", "gateway_process", "ready", "grpc_serving", nil)
	return runtimeServer, nil
}

func newInternalUnaryInterceptor(token string) grpc.UnaryServerInterceptor {
	// Handler and firewall mutations are already serialized internally, but an
	// ordinary mutex keeps cancelled RPC goroutines queued behind a slow durable
	// flush or host command. Separate gates prevent a hibernating config volume
	// from delaying independent firewall recovery.
	// These context-aware gates drop expired retries before they enter the
	// handler, while the original mutation is allowed to finish atomically.
	durableMutationGate := make(chan struct{}, 1)
	durableMutationGate <- struct{}{}
	firewallMutationGate := make(chan struct{}, 1)
	firewallMutationGate <- struct{}{}
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		if err := rpcbridge.CheckInternalToken(ctx, token); err != nil {
			return nil, err
		}
		var mutationGate chan struct{}
		switch {
		case isSerializedDurableMutation(info.FullMethod):
			mutationGate = durableMutationGate
		case isSerializedFirewallMutation(info.FullMethod):
			mutationGate = firewallMutationGate
		default:
			return handler(ctx, req)
		}
		select {
		case <-ctx.Done():
			return nil, status.FromContextError(ctx.Err()).Err()
		case <-mutationGate:
		}
		defer func() { mutationGate <- struct{}{} }()
		if err := ctx.Err(); err != nil {
			return nil, status.FromContextError(err).Err()
		}
		return handler(ctx, req)
	}
}

func isSerializedDurableMutation(fullMethod string) bool {
	switch fullMethod {
	case pb.GatewayControlService_SetGatewayListenerConfig_FullMethodName,
		pb.GatewayControlService_SetGatewayProxyProtocolConfig_FullMethodName,
		pb.GatewayControlService_ResetAllData_FullMethodName,
		pb.GatewayControlService_SetRules_FullMethodName,
		pb.GatewayControlService_FlushRules_FullMethodName,
		pb.GatewayControlService_SetHostRules_FullMethodName,
		pb.GatewayControlService_FlushHostRules_FullMethodName,
		pb.GatewayControlService_SetStreamRules_FullMethodName,
		pb.GatewayControlService_FlushStreamRules_FullMethodName,
		pb.GatewayControlService_SetAuthConfig_FullMethodName,
		pb.GatewayControlService_SetDefaultRoute_FullMethodName,
		pb.GatewayControlService_SetProxyProtocolForce_FullMethodName,
		pb.GatewayControlService_SetLocaleConfig_FullMethodName,
		pb.GatewayControlService_SetReverseProxyThrottle_FullMethodName,
		pb.GatewayControlService_SetGatewayVisibility_FullMethodName,
		pb.GatewayControlService_SetForwardedHeadersConfig_FullMethodName,
		pb.GatewayControlService_SetPreserveHostConfig_FullMethodName,
		pb.GatewayControlService_SetCrawlerBlockerConfig_FullMethodName,
		pb.GatewayControlService_SetGatewayPortalConfig_FullMethodName,
		pb.GatewayControlService_SetGatewayUnmatchedRouteConfig_FullMethodName,
		pb.GatewayControlService_SetFnosPortIconHijackConfig_FullMethodName,
		pb.GatewayControlService_SetFnosConnectIngressConfig_FullMethodName,
		pb.GatewayControlService_SetReverseProxyThrottleExemptIps_FullMethodName,
		pb.GatewayControlService_SetGatewayTrustedClientIps_FullMethodName,
		pb.GatewayControlService_SetCommonLocationExemptions_FullMethodName,
		pb.GatewayLogsService_SetLoggingConfig_FullMethodName,
		pb.SecurityService_AddGeneralBlacklist_FullMethodName,
		pb.SecurityService_RemoveGeneralBlacklist_FullMethodName,
		pb.WafService_SetWafConfig_FullMethodName,
		pb.WafService_ReloadWafBundle_FullMethodName,
		pb.SslService_SetSslDeployment_FullMethodName,
		pb.SslService_SetSslPem_FullMethodName,
		pb.SslService_ClearSsl_FullMethodName:
		return true
	default:
		return false
	}
}

func isSerializedFirewallMutation(fullMethod string) bool {
	switch fullMethod {
	case pb.FirewallService_InitIptables_FullMethodName,
		pb.FirewallService_CleanIptables_FullMethodName,
		pb.FirewallService_FlushIptables_FullMethodName,
		pb.FirewallService_AllowIp_FullMethodName,
		pb.FirewallService_BlockIp_FullMethodName,
		pb.FirewallService_RemoveIp_FullMethodName,
		pb.FirewallService_BlockTcpPortForIp_FullMethodName,
		pb.FirewallService_RemoveTcpPortRule_FullMethodName,
		pb.FirewallService_SyncSshFirewall_FullMethodName,
		pb.FirewallService_ClearSshFirewall_FullMethodName,
		pb.FirewallService_SyncWhitelistFirewall_FullMethodName,
		pb.FirewallService_BlockAll_FullMethodName,
		pb.FirewallService_AllowAll_FullMethodName,
		pb.FirewallService_EnsureTcpRedirect_FullMethodName,
		pb.FirewallService_ClearTcpRedirect_FullMethodName:
		return true
	default:
		return false
	}
}

func (s *internalGRPCServer) SetServingStatus(service string, serving bool) {
	if s == nil || s.health == nil {
		return
	}
	status := healthpb.HealthCheckResponse_NOT_SERVING
	if serving {
		status = healthpb.HealthCheckResponse_SERVING
	}
	s.health.SetServingStatus(service, status)
	component := strings.TrimPrefix(service, "fnknock.gateway.")
	if component == "process" {
		component = "gateway_process"
	} else {
		component = "gateway_" + component
	}
	state := "unhealthy"
	if serving {
		state = "healthy"
	}
	logger.Diagnostic("INFO", component, "health_status", state, map[string]any{"status": state})
}

func (s *internalGRPCServer) Stop(ctx context.Context) {
	if s == nil {
		return
	}
	s.stopOnce.Do(func() {
		logger.Diagnostic("INFO", "gateway_process", "stopping", "graceful_shutdown", nil)
		for _, service := range []string{healthGatewayProcess, healthGatewayDataplane, healthGatewayAuthBridge} {
			s.health.SetServingStatus(service, healthpb.HealthCheckResponse_NOT_SERVING)
		}
		done := make(chan struct{})
		go func() {
			s.server.GracefulStop()
			close(done)
		}()
		if ctx == nil {
			ctx = context.Background()
		}
		select {
		case <-done:
		case <-ctx.Done():
			s.server.Stop()
			<-done
		case <-time.After(15 * time.Second):
			s.server.Stop()
			<-done
		}
		s.wg.Wait()
		logger.Diagnostic("INFO", "gateway_process", "stopped", "graceful_shutdown", nil)
	})
}
