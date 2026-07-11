//go:build linux

package main

import (
	"go-reauth-proxy/pkg/grpc/pb"

	"google.golang.org/grpc"
)

func registerFirewallService(server *grpc.Server, control pb.GatewayControlServiceServer) {
	if firewall, ok := control.(pb.FirewallServiceServer); ok {
		pb.RegisterFirewallServiceServer(server, firewall)
	}
}
