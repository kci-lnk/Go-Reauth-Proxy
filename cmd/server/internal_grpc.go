package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"

	"go-reauth-proxy/pkg/grpc/pb"
	"go-reauth-proxy/pkg/rpcbridge"

	"google.golang.org/grpc"
)

const internalGRPCMaxMessageSize = 16 << 20

func startInternalGRPCServer(port int, token string, control pb.GatewayControlServiceServer, bridge pb.AuthBridgeServiceServer) (func(), error) {
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
	if firewall, ok := control.(pb.FirewallServiceServer); ok {
		pb.RegisterFirewallServiceServer(server, firewall)
	}
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

	var wg sync.WaitGroup
	for _, listener := range listeners {
		wg.Add(1)
		go func(l net.Listener) {
			defer wg.Done()
			if err := server.Serve(l); err != nil {
				log.Printf("Internal gRPC server stopped on %s: %v", l.Addr().String(), err)
			}
		}(listener)
	}
	log.Printf("Internal gRPC server listening on %s", strings.Join(listenAddrs, ", "))

	stop := func() {
		server.Stop()
		wg.Wait()
	}
	return stop, nil
}
