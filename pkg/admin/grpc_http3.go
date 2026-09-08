package admin

import (
	"context"
	pb "go-reauth-proxy/pkg/grpc/pb"
	"go-reauth-proxy/pkg/models"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

func (s *GRPCServer) GetGatewayHttp3Status(ctx context.Context, _ *emptypb.Empty) (*pb.GatewayHttp3Status, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	v := s.admin.ProxyHandler.GetGatewayHttp3Status()
	return &pb.GatewayHttp3Status{Config: &pb.GatewayHttp3Config{Enabled: v.Config.Enabled, AdvertisedPort: uint32(v.Config.AdvertisedPort)}, State: v.State, ListenAddresses: v.ListenAddresses, Error: v.Error, ActiveConnections: v.ActiveConnections, HandshakeFailures: v.HandshakeFailures}, nil
}
func (s *GRPCServer) SetGatewayHttp3Config(ctx context.Context, req *pb.GatewayHttp3Config) (*pb.GatewayHttp3Status, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	if req == nil || req.AdvertisedPort > 65535 {
		return nil, status.Error(codes.InvalidArgument, "invalid HTTP/3 configuration")
	}
	s.admin.streamConfigMu.Lock()
	defer s.admin.streamConfigMu.Unlock()
	if err := s.admin.ProxyHandler.SetGatewayHttp3Config(models.GatewayHttp3Config{Enabled: req.Enabled, AdvertisedPort: int(req.AdvertisedPort)}); err != nil {
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}
	return s.GetGatewayHttp3Status(ctx, &emptypb.Empty{})
}
