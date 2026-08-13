package admin

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go-reauth-proxy/pkg/grpc/pb"
	operationallog "go-reauth-proxy/pkg/logger"
	"go-reauth-proxy/pkg/models"
	"go-reauth-proxy/pkg/rpcbridge"
	"go-reauth-proxy/pkg/version"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

const defaultGCPercent int32 = 100

type GRPCServer struct {
	pb.UnimplementedGatewayControlServiceServer
	pb.UnimplementedGatewayLogsServiceServer
	pb.UnimplementedDeepMonitorServiceServer
	pb.UnimplementedSecurityServiceServer
	pb.UnimplementedTrafficServiceServer
	pb.UnimplementedWafServiceServer
	pb.UnimplementedSslServiceServer
	pb.UnimplementedFirewallServiceServer

	admin *Server
	token string

	instanceID string
	startedAt  time.Time
	gcPercent  atomic.Int32
	gcUpdateMu sync.Mutex

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
	server := &GRPCServer{
		admin:      adminServer,
		token:      token,
		instanceID: newRuntimeInstanceID(),
		startedAt:  time.Now(),
	}
	server.gcPercent.Store(initialGCPercent())
	return server
}

func initialGCPercent() int32 {
	raw := strings.TrimSpace(os.Getenv("GOGC"))
	if strings.EqualFold(raw, "off") {
		return -1
	}
	if value, err := strconv.ParseInt(raw, 10, 32); err == nil {
		return int32(value)
	}
	return defaultGCPercent
}

func (s *GRPCServer) applyGCPercent(gcPercent int32) {
	debug.SetGCPercent(int(gcPercent))
	s.gcPercent.Store(gcPercent)
}

func newRuntimeInstanceID() string {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err == nil {
		return hex.EncodeToString(raw[:])
	}
	return fmt.Sprintf("%d-%d", os.Getpid(), time.Now().UnixNano())
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
		ControlApiVersion: uint32(pb.ControlApiVersion_CONTROL_API_VERSION_CURRENT),
		Capabilities:      gatewayCapabilities(),
		Commit:            version.Commit,
	}, nil
}

func (s *GRPCServer) GetRuntimeInfo(ctx context.Context, _ *emptypb.Empty) (*pb.GatewayRuntimeInfo, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	return s.runtimeInfo(), nil
}

func (s *GRPCServer) runtimeInfo() *pb.GatewayRuntimeInfo {
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	uptime := time.Since(s.startedAt)
	if uptime < 0 {
		uptime = 0
	}
	return &pb.GatewayRuntimeInfo{
		InstanceId:      s.instanceID,
		Pid:             int64(os.Getpid()),
		StartedAtUnixMs: s.startedAt.UnixMilli(),
		UptimeMs:        uint64(uptime / time.Millisecond),
		GoVersion:       runtime.Version(),
		Goroutines:      uint64(runtime.NumGoroutine()),
		HeapAllocBytes:  memory.HeapAlloc,
		HeapSysBytes:    memory.HeapSys,
		RssBytes:        currentProcessRSSBytes(),
		GcPercent:       s.gcPercent.Load(),
	}
}

func (s *GRPCServer) SetGatewayMemoryConfig(ctx context.Context, req *pb.GatewayMemoryConfig) (*pb.GatewayMemoryConfig, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	gcPercent := req.GetGcPercent()
	if gcPercent < 25 || gcPercent > 500 {
		return nil, status.Error(codes.InvalidArgument, "gc_percent must be between 25 and 500")
	}
	s.gcUpdateMu.Lock()
	s.applyGCPercent(gcPercent)
	s.gcUpdateMu.Unlock()
	operationallog.Diagnostic("INFO", "gateway_process", "memory_config_applied", "gc_percent_updated", map[string]any{
		"gc_percent": gcPercent,
		"result":     "success",
	})
	return &pb.GatewayMemoryConfig{GcPercent: gcPercent}, nil
}

func (s *GRPCServer) ReclaimGatewayMemory(ctx context.Context, _ *emptypb.Empty) (*pb.GatewayRuntimeInfo, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	s.gcUpdateMu.Lock()
	debug.FreeOSMemory()
	info := s.runtimeInfo()
	s.gcUpdateMu.Unlock()
	operationallog.Diagnostic("INFO", "gateway_process", "memory_reclaimed", "manual_gc_completed", map[string]any{
		"heap_alloc_bytes": info.GetHeapAllocBytes(),
		"heap_sys_bytes":   info.GetHeapSysBytes(),
		"rss_bytes":        info.GetRssBytes(),
		"result":           "success",
	})
	return info, nil
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
		operationallog.Diagnostic("ERROR", "gateway_dataplane", "listener_reload_failed", "listener_config_rejected", map[string]any{
			"listener": scope,
			"result":   "failed",
		})
		return nil, status.Error(codes.Internal, err.Error())
	}
	config := s.admin.ProxyHandler.GetGatewayListenerConfig()
	operationallog.Diagnostic("INFO", "gateway_dataplane", "listener_reloaded", "listener_config_applied", map[string]any{
		"listener": config.Scope,
		"result":   "success",
	})
	return &pb.GatewayListenerConfig{Scope: config.Scope}, nil
}

func (s *GRPCServer) ResetAllData(ctx context.Context, _ *emptypb.Empty) (*pb.RpcStatus, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	if s.admin == nil {
		return nil, status.Error(codes.FailedPrecondition, "admin server is not initialized")
	}
	if err := s.admin.ResetAllData(); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	s.gcUpdateMu.Lock()
	s.applyGCPercent(defaultGCPercent)
	s.gcUpdateMu.Unlock()
	return rpcOK(), nil
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
