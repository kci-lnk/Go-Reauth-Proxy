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
	"go-reauth-proxy/pkg/rpcbridge"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
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
		grpc.UnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
			if err := rpcbridge.CheckInternalToken(ctx, token); err != nil {
				return nil, err
			}
			return handler(ctx, req)
		}),
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
	return runtimeServer, nil
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
}

func (s *internalGRPCServer) Stop(ctx context.Context) {
	if s == nil {
		return
	}
	s.stopOnce.Do(func() {
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
	})
}
