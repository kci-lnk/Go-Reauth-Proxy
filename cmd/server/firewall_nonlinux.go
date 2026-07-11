//go:build !linux

package main

import (
	"go-reauth-proxy/pkg/grpc/pb"

	"google.golang.org/grpc"
)

type unsupportedFirewallServer struct {
	pb.UnimplementedFirewallServiceServer
}

func registerFirewallService(server *grpc.Server, _ pb.GatewayControlServiceServer) {
	// Registering the generated unimplemented server makes every firewall RPC
	// return the canonical gRPC Unimplemented status on non-Linux platforms.
	pb.RegisterFirewallServiceServer(server, &unsupportedFirewallServer{})
}
