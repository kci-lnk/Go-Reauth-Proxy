package admin

import (
	"context"

	"go-reauth-proxy/pkg/grpc/pb"
	"go-reauth-proxy/pkg/rpcbridge"
	"go-reauth-proxy/pkg/version"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

type GRPCServer struct {
	pb.UnimplementedGatewayControlServiceServer
	pb.UnimplementedGatewayLogsServiceServer
	pb.UnimplementedSecurityServiceServer
	pb.UnimplementedTrafficServiceServer
	pb.UnimplementedWafServiceServer
	pb.UnimplementedSslServiceServer
	pb.UnimplementedFirewallServiceServer

	admin *Server
	token string
}

func NewGRPCServer(adminServer *Server, token string) *GRPCServer {
	return &GRPCServer{
		admin: adminServer,
		token: token,
	}
}

func (s *GRPCServer) checkToken(ctx context.Context) error {
	return rpcbridge.CheckInternalToken(ctx, s.token)
}

func (s *GRPCServer) GetServerInfo(ctx context.Context, _ *emptypb.Empty) (*pb.ServerInfo, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	return &pb.ServerInfo{Version: version.Version}, nil
}

func (s *GRPCServer) GetProxyProtocolForce(ctx context.Context, _ *emptypb.Empty) (*pb.BoolValue, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	return &pb.BoolValue{Value: s.admin.ProxyHandler.GetProxyProtocolForce()}, nil
}

func (s *GRPCServer) SetProxyProtocolForce(ctx context.Context, req *pb.BoolValue) (*pb.BoolValue, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	if err := s.admin.ProxyHandler.SetProxyProtocolForce(req.GetValue()); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &pb.BoolValue{Value: s.admin.ProxyHandler.GetProxyProtocolForce()}, nil
}
