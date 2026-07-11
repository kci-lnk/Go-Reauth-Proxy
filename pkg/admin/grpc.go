package admin

import (
	"context"
	"runtime"
	"sync"

	"go-reauth-proxy/pkg/grpc/pb"
	"go-reauth-proxy/pkg/models"
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

	shutdownMu   sync.RWMutex
	shutdownOnce sync.Once
	shutdown     func()
}

// SetShutdownRequest wires the process lifecycle into the control service.
// It is separate from the constructor to preserve compatibility with tests and
// embedders that do not own the process lifecycle.
func (s *GRPCServer) SetShutdownRequest(shutdown func()) {
	s.shutdownMu.Lock()
	s.shutdown = shutdown
	s.shutdownMu.Unlock()
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
	return &pb.ServerInfo{
		Version:           version.Version,
		Os:                runtime.GOOS,
		Arch:              runtime.GOARCH,
		ControlApiVersion: version.ControlAPIVersion,
		Capabilities:      gatewayCapabilities(),
		Commit:            version.Commit,
	}, nil
}

func (s *GRPCServer) GetGatewayListenerConfig(ctx context.Context, _ *emptypb.Empty) (*pb.GatewayListenerConfig, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	config := s.admin.ProxyHandler.GetGatewayListenerConfig()
	return &pb.GatewayListenerConfig{Scope: config.Scope}, nil
}

func (s *GRPCServer) SetGatewayListenerConfig(ctx context.Context, req *pb.GatewayListenerConfig) (*pb.GatewayListenerConfig, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	scope := models.NormalizeGatewayListenerScope(req.GetScope())
	if scope == "" {
		return nil, status.Errorf(
			codes.InvalidArgument,
			"listener scope must be %q or %q",
			models.GatewayListenerScopeLoopback,
			models.GatewayListenerScopeAll,
		)
	}
	if err := s.admin.ProxyHandler.SetGatewayListenerConfig(models.GatewayListenerConfig{Scope: scope}); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	config := s.admin.ProxyHandler.GetGatewayListenerConfig()
	return &pb.GatewayListenerConfig{Scope: config.Scope}, nil
}

func (s *GRPCServer) RequestShutdown(ctx context.Context, _ *emptypb.Empty) (*pb.RpcStatus, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	s.shutdownMu.RLock()
	shutdown := s.shutdown
	s.shutdownMu.RUnlock()
	if shutdown == nil {
		return nil, status.Error(codes.FailedPrecondition, "shutdown lifecycle is not configured")
	}
	go s.shutdownOnce.Do(shutdown)
	return rpcOK(), nil
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
