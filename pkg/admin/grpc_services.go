package admin

import (
	"context"
	"errors"
	"strings"
	"time"

	"go-reauth-proxy/pkg/config"
	"go-reauth-proxy/pkg/diagnostics"
	"go-reauth-proxy/pkg/grpc/pb"
	"go-reauth-proxy/pkg/i18n"
	compiledipset "go-reauth-proxy/pkg/ipset"
	"go-reauth-proxy/pkg/iptables"
	"go-reauth-proxy/pkg/models"
	"go-reauth-proxy/pkg/proxy"
	"go-reauth-proxy/pkg/streamprobe"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

func grpcBadRequest(format string, args ...any) error {
	return status.Errorf(codes.InvalidArgument, format, args...)
}

func grpcInternal(format string, args ...any) error {
	return status.Errorf(codes.Internal, format, args...)
}

func (s *GRPCServer) GetRules(ctx context.Context, _ *emptypb.Empty) (*pb.Rules, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	return rulesToProto(s.admin.ProxyHandler.GetRules()), nil
}

func (s *GRPCServer) SetRules(ctx context.Context, req *pb.Rules) (*pb.Rules, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, grpcBadRequest("request is required")
	}
	if err := s.admin.ProxyHandler.SetRules(protoToRules(req)); err != nil {
		return nil, grpcBadRequest("failed to set rules: %v", err)
	}
	return rulesToProto(s.admin.ProxyHandler.GetRules()), nil
}

func (s *GRPCServer) FlushRules(ctx context.Context, _ *emptypb.Empty) (*pb.RpcStatus, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	if err := s.admin.ProxyHandler.FlushRules(); err != nil {
		return nil, grpcInternal("failed to flush rules: %v", err)
	}
	return rpcOK(), nil
}

func (s *GRPCServer) GetHostRules(ctx context.Context, _ *emptypb.Empty) (*pb.HostRules, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	return hostRulesBundleToProto(
		s.admin.ProxyHandler.GetHostRules(),
		s.admin.ProxyHandler.GetVisibilityPoliciesForHostRules(),
	), nil
}

func (s *GRPCServer) SetHostRules(ctx context.Context, req *pb.HostRules) (*pb.HostRules, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, grpcBadRequest("request is required")
	}
	if err := s.admin.ProxyHandler.SetHostRulesBundle(
		protoToHostRules(req),
		protoToVisibilityPolicies(req.GetVisibilityPolicies()),
	); err != nil {
		if proxy.IsHostRulesPersistenceError(err) {
			return nil, grpcInternal("failed to set host rules: %v", err)
		}
		return nil, grpcBadRequest("failed to set host rules: %v", err)
	}
	return hostRulesBundleToProto(
		s.admin.ProxyHandler.GetHostRules(),
		s.admin.ProxyHandler.GetVisibilityPoliciesForHostRules(),
	), nil
}

func (s *GRPCServer) FlushHostRules(ctx context.Context, _ *emptypb.Empty) (*pb.RpcStatus, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	if err := s.admin.ProxyHandler.FlushHostRules(); err != nil {
		return nil, grpcInternal("failed to flush host rules: %v", err)
	}
	return rpcOK(), nil
}

func (s *GRPCServer) GetStreamRules(ctx context.Context, _ *emptypb.Empty) (*pb.StreamRules, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	rules, availability, policies := s.admin.ProxyHandler.GetStreamRulesBundle()
	return streamRulesBundleToProto(rules, availability, policies), nil
}

func (s *GRPCServer) SetStreamRules(ctx context.Context, req *pb.StreamRules) (*pb.StreamRules, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, grpcBadRequest("request is required")
	}
	normalizedRules, normalizedPolicies, err := s.admin.ProxyHandler.ValidateStreamRulesBundle(
		protoToStreamRules(req),
		protoToVisibilityPolicies(req.GetAccessPolicies()),
	)
	if err != nil {
		return nil, grpcBadRequest("failed to set stream rules: %v", err)
	}
	if req.GetAvailability() != nil && !req.GetAvailability().GetEnabled() {
		return nil, grpcBadRequest("failed to set stream availability: enabled must be true when availability is present")
	}
	normalizedAvailability, err := models.NormalizeDailyAvailability(
		protoToStreamAvailability(req.GetAvailability()),
	)
	if err != nil {
		return nil, grpcBadRequest("failed to set stream availability: %v", err)
	}
	s.admin.streamConfigMu.Lock()
	defer s.admin.streamConfigMu.Unlock()
	previousRuntime := captureStreamRuntime(s.admin.StreamManager)
	if s.admin.StreamManager != nil {
		if err := s.admin.StreamManager.ReconcileConfigBundle(normalizedRules, normalizedAvailability, normalizedPolicies); err != nil {
			return nil, grpcBadRequest("failed to reconcile stream configuration: %v", err)
		}
	}
	if err := s.admin.ProxyHandler.SetStreamRulesBundle(normalizedRules, normalizedAvailability, normalizedPolicies); err != nil {
		if rollbackErr := restoreStreamRuntime(s.admin.StreamManager, previousRuntime); rollbackErr != nil {
			return nil, grpcInternal("failed to persist stream rules: %v; runtime rollback failed: %v", err, rollbackErr)
		}
		return nil, grpcInternal("failed to persist stream rules: %v", err)
	}
	storedRules, storedAvailability, storedPolicies := s.admin.ProxyHandler.GetStreamRulesBundle()
	return streamRulesBundleToProto(storedRules, storedAvailability, storedPolicies), nil
}

func (s *GRPCServer) ProbeStreamTarget(ctx context.Context, req *pb.StreamProbeRequest) (*pb.StreamProbeResult, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, grpcBadRequest("request is required")
	}
	result := streamprobe.Probe(ctx, req.GetProtocol(), req.GetTarget())
	diagnostics.RecordStreamProbe(result.Status == "verified")
	var profile *pb.StreamServiceProfile
	if result.Profile.ServiceID != "" {
		profile = streamServiceProfileToProto(result.Profile)
	}
	return &pb.StreamProbeResult{
		Status:  result.Status,
		Profile: profile,
		Message: result.Message,
	}, nil
}

func (s *GRPCServer) GetStreamServiceCatalog(ctx context.Context, _ *emptypb.Empty) (*pb.StreamServiceCatalog, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	items := streamprobe.Catalog()
	protoItems := make([]*pb.StreamServiceDescriptor, 0, len(items))
	for _, item := range items {
		protoItems = append(protoItems, &pb.StreamServiceDescriptor{
			ServiceId:            item.ServiceID,
			DisplayName:          item.DisplayName,
			ServiceFamily:        item.ServiceFamily,
			Transports:           append([]string(nil), item.Transports...),
			ActiveProbeSupported: item.ActiveProbeSupported,
			StrictCapable:        item.StrictCapable,
		})
	}
	return &pb.StreamServiceCatalog{ClassifierVersion: streamprobe.ClassifierVersion, Items: protoItems}, nil
}

func (s *GRPCServer) FlushStreamRules(ctx context.Context, _ *emptypb.Empty) (*pb.RpcStatus, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	s.admin.streamConfigMu.Lock()
	defer s.admin.streamConfigMu.Unlock()
	previousRuntime := captureStreamRuntime(s.admin.StreamManager)
	if s.admin.StreamManager != nil {
		if err := s.admin.StreamManager.ReconcileConfig(nil, nil); err != nil {
			return nil, grpcBadRequest("failed to flush stream listeners: %v", err)
		}
	}
	if err := s.admin.ProxyHandler.FlushStreamRules(); err != nil {
		if rollbackErr := restoreStreamRuntime(s.admin.StreamManager, previousRuntime); rollbackErr != nil {
			return nil, grpcInternal("failed to flush stream rules: %v; runtime rollback failed: %v", err, rollbackErr)
		}
		return nil, grpcInternal("failed to flush stream rules: %v", err)
	}
	return rpcOK(), nil
}

func (s *GRPCServer) GetAuthConfig(ctx context.Context, _ *emptypb.Empty) (*pb.AuthConfig, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	return authConfigToProto(s.admin.ProxyHandler.GetAuthConfig()), nil
}

func (s *GRPCServer) SetAuthConfig(ctx context.Context, req *pb.AuthConfig) (*pb.RpcStatus, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, grpcBadRequest("request is required")
	}
	if err := s.admin.ProxyHandler.SetAuthConfig(protoToAuthConfig(req)); err != nil {
		return nil, grpcBadRequest("%v", err)
	}
	return rpcOK(), nil
}

func (s *GRPCServer) GetDefaultRoute(ctx context.Context, _ *emptypb.Empty) (*pb.StringValue, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	return &pb.StringValue{Value: s.admin.ProxyHandler.GetDefaultRoute()}, nil
}

func (s *GRPCServer) SetDefaultRoute(ctx context.Context, req *pb.StringValue) (*pb.RpcStatus, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	if req == nil || req.GetValue() == "" {
		return nil, grpcBadRequest("default_route is required")
	}
	if err := s.admin.ProxyHandler.SetDefaultRoute(req.GetValue()); err != nil {
		return nil, grpcInternal("failed to set default route: %v", err)
	}
	return rpcOK(), nil
}

func (s *GRPCServer) GetLocaleConfig(ctx context.Context, _ *emptypb.Empty) (*pb.LocaleConfig, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	if s.admin.ConfigManager == nil {
		return nil, grpcInternal("config manager not initialized")
	}
	cfg, err := s.admin.ConfigManager.Load()
	if err != nil {
		return nil, grpcInternal("failed to load config: %v", err)
	}
	normalized := i18n.NormalizeConfig(i18n.LocaleConfig{DefaultLocale: cfg.Locale.DefaultLocale})
	return &pb.LocaleConfig{DefaultLocale: normalized.DefaultLocale}, nil
}

func (s *GRPCServer) SetLocaleConfig(ctx context.Context, req *pb.LocaleConfig) (*pb.LocaleConfig, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, grpcBadRequest("request is required")
	}
	if s.admin.ConfigManager == nil {
		return nil, grpcInternal("config manager not initialized")
	}
	normalized := i18n.NormalizeConfig(i18n.LocaleConfig{DefaultLocale: req.GetDefaultLocale()})
	if err := s.admin.ConfigManager.Update(func(cfg *config.AppConfig) error {
		cfg.Locale.DefaultLocale = normalized.DefaultLocale
		return nil
	}); err != nil {
		return nil, grpcInternal("failed to save config: %v", err)
	}
	i18n.SetDefaultLocale(normalized.DefaultLocale)
	return &pb.LocaleConfig{DefaultLocale: normalized.DefaultLocale}, nil
}

func (s *GRPCServer) GetReverseProxyThrottle(ctx context.Context, _ *emptypb.Empty) (*pb.ReverseProxyThrottleConfig, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	return reverseProxyThrottleToProto(s.admin.ProxyHandler.GetReverseProxyThrottle()), nil
}

func (s *GRPCServer) SetReverseProxyThrottle(ctx context.Context, req *pb.ReverseProxyThrottleConfig) (*pb.ReverseProxyThrottleConfig, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, grpcBadRequest("request is required")
	}
	if err := s.admin.ProxyHandler.SetReverseProxyThrottle(protoToReverseProxyThrottle(req)); err != nil {
		return nil, grpcInternal("failed to set reverse proxy throttle: %v", err)
	}
	return reverseProxyThrottleToProto(s.admin.ProxyHandler.GetReverseProxyThrottle()), nil
}

func (s *GRPCServer) GetGatewayVisibility(ctx context.Context, _ *emptypb.Empty) (*pb.GatewayVisibilityConfig, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	return gatewayVisibilityToProto(s.admin.ProxyHandler.GetGatewayVisibility()), nil
}

func (s *GRPCServer) SetGatewayVisibility(ctx context.Context, req *pb.GatewayVisibilityConfig) (*pb.GatewayVisibilityConfig, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, grpcBadRequest("request is required")
	}
	if err := s.admin.ProxyHandler.SetGatewayVisibilityContext(ctx, protoToGatewayVisibility(req)); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, status.FromContextError(err).Err()
		}
		return nil, grpcBadRequest("%v", err)
	}
	return gatewayVisibilityToProto(s.admin.ProxyHandler.GetGatewayVisibility()), nil
}

func (s *GRPCServer) GetForwardedHeadersConfig(ctx context.Context, _ *emptypb.Empty) (*pb.OmitTargetsConfig, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	return forwardedHeadersToProto(s.admin.ProxyHandler.GetForwardedHeadersConfig()), nil
}

func (s *GRPCServer) SetForwardedHeadersConfig(ctx context.Context, req *pb.OmitTargetsConfig) (*pb.OmitTargetsConfig, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, grpcBadRequest("request is required")
	}
	if err := s.admin.ProxyHandler.SetForwardedHeadersConfig(protoToForwardedHeaders(req)); err != nil {
		return nil, grpcInternal("failed to set forwarded headers config: %v", err)
	}
	return forwardedHeadersToProto(s.admin.ProxyHandler.GetForwardedHeadersConfig()), nil
}

func (s *GRPCServer) GetPreserveHostConfig(ctx context.Context, _ *emptypb.Empty) (*pb.OmitTargetsConfig, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	return preserveHostToProto(s.admin.ProxyHandler.GetPreserveHostConfig()), nil
}

func (s *GRPCServer) SetPreserveHostConfig(ctx context.Context, req *pb.OmitTargetsConfig) (*pb.OmitTargetsConfig, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, grpcBadRequest("request is required")
	}
	if err := s.admin.ProxyHandler.SetPreserveHostConfig(protoToPreserveHost(req)); err != nil {
		return nil, grpcInternal("failed to set preserve host config: %v", err)
	}
	return preserveHostToProto(s.admin.ProxyHandler.GetPreserveHostConfig()), nil
}

func (s *GRPCServer) GetCrawlerBlockerConfig(ctx context.Context, _ *emptypb.Empty) (*pb.CrawlerBlockerConfig, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	return crawlerBlockerToProto(s.admin.ProxyHandler.GetCrawlerBlockerConfig()), nil
}

func (s *GRPCServer) SetCrawlerBlockerConfig(ctx context.Context, req *pb.CrawlerBlockerConfig) (*pb.CrawlerBlockerConfig, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, grpcBadRequest("request is required")
	}
	cfg, err := s.admin.ProxyHandler.SetCrawlerBlockerConfig(protoToCrawlerBlocker(req))
	if err != nil {
		return nil, grpcInternal("failed to set crawler blocker config: %v", err)
	}
	return crawlerBlockerToProto(cfg), nil
}

func (s *GRPCServer) GetGatewayPortalConfig(ctx context.Context, _ *emptypb.Empty) (*pb.GatewayPortalConfig, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	return gatewayPortalToProto(s.admin.ProxyHandler.GetGatewayPortalConfig()), nil
}

func (s *GRPCServer) SetGatewayPortalConfig(ctx context.Context, req *pb.GatewayPortalConfig) (*pb.GatewayPortalConfig, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, grpcBadRequest("request is required")
	}
	cfg, err := s.admin.ProxyHandler.SetGatewayPortalConfig(protoToGatewayPortal(req))
	if err != nil {
		return nil, grpcInternal("failed to set gateway portal config: %v", err)
	}
	return gatewayPortalToProto(cfg), nil
}

func (s *GRPCServer) GetGatewayUnmatchedRouteConfig(ctx context.Context, _ *emptypb.Empty) (*pb.GatewayUnmatchedRouteConfig, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	return gatewayUnmatchedRouteToProto(s.admin.ProxyHandler.GetGatewayUnmatchedRouteConfig()), nil
}

func (s *GRPCServer) SetGatewayUnmatchedRouteConfig(ctx context.Context, req *pb.GatewayUnmatchedRouteConfig) (*pb.GatewayUnmatchedRouteConfig, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, grpcBadRequest("request is required")
	}
	cfg, err := s.admin.ProxyHandler.SetGatewayUnmatchedRouteConfig(protoToGatewayUnmatchedRoute(req))
	if err != nil {
		return nil, grpcInternal("failed to set gateway unmatched route config: %v", err)
	}
	return gatewayUnmatchedRouteToProto(cfg), nil
}

func (s *GRPCServer) GetFnosPortIconHijackConfig(ctx context.Context, _ *emptypb.Empty) (*pb.FnosPortIconHijackConfig, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	return fnosPortIconHijackToProto(s.admin.ProxyHandler.GetFnosPortIconHijackConfig()), nil
}

func (s *GRPCServer) SetFnosPortIconHijackConfig(ctx context.Context, req *pb.FnosPortIconHijackConfig) (*pb.FnosPortIconHijackConfig, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, grpcBadRequest("request is required")
	}
	cfg, err := s.admin.ProxyHandler.SetFnosPortIconHijackConfig(protoToFnosPortIconHijack(req))
	if err != nil {
		return nil, grpcInternal("failed to set FNOS port icon hijack config: %v", err)
	}
	return fnosPortIconHijackToProto(cfg), nil
}

func (s *GRPCServer) GetFnosConnectIngressStatus(ctx context.Context, _ *emptypb.Empty) (*pb.FnosConnectIngressStatus, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	return s.fnosConnectIngressStatus()
}

func (s *GRPCServer) SetFnosConnectIngressConfig(ctx context.Context, req *pb.FnosConnectIngressConfig) (*pb.FnosConnectIngressStatus, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, grpcBadRequest("request is required")
	}
	if s.admin == nil || s.admin.FnosConnectIngress == nil {
		return nil, status.Error(codes.Unavailable, "FN Connect ingress is unavailable")
	}
	if req.GetEnabled() && (req.GetUpstreamHttpPort() < 1 || req.GetUpstreamHttpPort() > 65535) {
		return nil, grpcBadRequest("upstream_http_port must be between 1 and 65535")
	}
	if _, err := s.admin.FnosConnectIngress.Apply(req.GetEnabled(), int(req.GetUpstreamHttpPort())); err != nil {
		return nil, grpcInternal("failed to apply FN Connect ingress config: %v", err)
	}
	return s.fnosConnectIngressStatus()
}

func (s *GRPCServer) fnosConnectIngressStatus() (*pb.FnosConnectIngressStatus, error) {
	if s.admin == nil || s.admin.FnosConnectIngress == nil {
		return nil, status.Error(codes.Unavailable, "FN Connect ingress is unavailable")
	}
	current := s.admin.FnosConnectIngress.Status()
	waf := s.admin.ProxyHandler.GetWAFStatus()
	return &pb.FnosConnectIngressStatus{
		Enabled:          current.Enabled,
		ListenerActive:   current.ListenerActive,
		ListenPort:       int32(current.ListenPort),
		UpstreamHttpPort: int32(current.UpstreamHTTPPort),
		Ipv4Active:       current.IPv4Active,
		Ipv6Active:       current.IPv6Active,
		WafActive:        waf.Enabled && waf.Loaded && !strings.EqualFold(waf.Mode, "off"),
		WafMode:          waf.Mode,
		LastError:        current.LastError,
	}, nil
}

func (s *GRPCServer) GetReverseProxyThrottleExemptIps(ctx context.Context, _ *emptypb.Empty) (*pb.ReverseProxyThrottleExemptIpsRuntime, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	return throttleExemptIPsToProto(s.admin.ProxyHandler.GetReverseProxyThrottleExemptIPs()), nil
}

func (s *GRPCServer) SetReverseProxyThrottleExemptIps(ctx context.Context, req *pb.ReverseProxyThrottleExemptIpsRuntime) (*pb.ReverseProxyThrottleExemptIpsRuntime, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, grpcBadRequest("request is required")
	}
	if err := s.admin.ProxyHandler.SetReverseProxyThrottleExemptIPs(protoToThrottleExemptIPs(req)); err != nil {
		return nil, grpcBadRequest("%s", err)
	}
	return throttleExemptIPsToProto(s.admin.ProxyHandler.GetReverseProxyThrottleExemptIPs()), nil
}

func (s *GRPCServer) GetGatewayTrustedClientIps(ctx context.Context, _ *emptypb.Empty) (*pb.GatewayTrustedClientIpsRuntime, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	return gatewayTrustedClientIPsToProto(s.admin.ProxyHandler.GetGatewayTrustedClientIPs()), nil
}

func (s *GRPCServer) SetGatewayTrustedClientIps(ctx context.Context, req *pb.GatewayTrustedClientIpsRuntime) (*pb.GatewayTrustedClientIpsRuntime, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, grpcBadRequest("request is required")
	}
	if err := s.admin.ProxyHandler.SetGatewayTrustedClientIPs(protoToGatewayTrustedClientIPs(req)); err != nil {
		return nil, grpcBadRequest("%s", err)
	}
	return gatewayTrustedClientIPsToProto(s.admin.ProxyHandler.GetGatewayTrustedClientIPs()), nil
}

func (s *GRPCServer) GetCommonLocationExemptions(ctx context.Context, _ *emptypb.Empty) (*pb.CommonLocationExemptionsRuntime, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	return commonLocationExemptionsToProto(s.admin.ProxyHandler.GetCommonLocationExemptions()), nil
}

func (s *GRPCServer) SetCommonLocationExemptions(ctx context.Context, req *pb.CommonLocationExemptionsRuntime) (*pb.CommonLocationExemptionsRuntime, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, grpcBadRequest("request is required")
	}
	if err := s.admin.ProxyHandler.SetCommonLocationExemptions(protoToCommonLocationExemptions(req)); err != nil {
		return nil, grpcBadRequest("%s", err)
	}
	return commonLocationExemptionsToProto(s.admin.ProxyHandler.GetCommonLocationExemptions()), nil
}

func (s *GRPCServer) GetLoggingConfig(ctx context.Context, _ *emptypb.Empty) (*pb.LoggingConfig, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	return loggingConfigToProto(s.admin.ProxyHandler.GetLoggingConfig()), nil
}

func (s *GRPCServer) SetLoggingConfig(ctx context.Context, req *pb.LoggingConfig) (*pb.LoggingConfig, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, grpcBadRequest("request is required")
	}
	if req.GetMaxDays() < 0 {
		return nil, grpcBadRequest("max_days must be greater than 0")
	}
	cfg, err := s.admin.ProxyHandler.SetLoggingConfig(protoToLoggingConfig(req))
	if err != nil {
		return nil, grpcInternal("failed to set logging config: %v", err)
	}
	return loggingConfigToProto(cfg), nil
}

func (s *GRPCServer) GetLoggingDirectory(ctx context.Context, _ *emptypb.Empty) (*pb.StringValue, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	return &pb.StringValue{Value: s.admin.ProxyHandler.GetLoggingDirectory().LogsDir}, nil
}

func (s *GRPCServer) GetLogDates(ctx context.Context, _ *emptypb.Empty) (*pb.GatewayLogDates, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	result, err := s.admin.ProxyHandler.GetLogDates()
	if err != nil {
		return nil, grpcInternal("failed to list log dates: %v", err)
	}
	return logDatesToProto(result), nil
}

func (s *GRPCServer) QueryLogEntries(ctx context.Context, req *pb.GatewayLogQuery) (*pb.GatewayLogQueryResult, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, grpcBadRequest("request is required")
	}
	pagination := strings.TrimSpace(req.GetPagination())
	paginationMode := "page"
	if strings.EqualFold(pagination, "cursor") {
		paginationMode = "cursor"
	} else if pagination != "" && !strings.EqualFold(pagination, "page") {
		return nil, grpcBadRequest("pagination must be 'page' or 'cursor'")
	}
	page := int(req.GetPage())
	if paginationMode == "page" && page <= 0 {
		page = 1
	}
	limit := int(req.GetLimit())
	if limit <= 0 {
		limit = 20
	}
	result, err := s.admin.ProxyHandler.QueryLogEntries(
		req.GetDate(),
		page,
		limit,
		req.GetSearch(),
		req.GetStatus(),
		req.GetLoggedIn(),
		req.GetCredential(),
		req.GetCursor(),
		paginationMode,
	)
	if err != nil {
		return nil, grpcBadRequest("%v", err)
	}
	return logQueryResultToProto(result), nil
}

func (s *GRPCServer) FindLogEntryByTraceId(ctx context.Context, req *pb.GatewayLogTraceRequest) (*pb.GatewayLogTraceResult, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	if req == nil || strings.TrimSpace(req.GetTraceId()) == "" {
		return nil, grpcBadRequest("trace_id is required")
	}
	result, err := s.admin.ProxyHandler.FindLogEntryByTraceID(req.GetTraceId())
	if err != nil {
		return nil, grpcInternal("failed to find log entry: %v", err)
	}
	response := &pb.GatewayLogTraceResult{TraceId: result.TraceID, Found: result.Found}
	if result.Found {
		response.Entry = logEntryToProto(result.Entry)
	}
	return response, nil
}

func (s *GRPCServer) AnalyzeLogEntries(ctx context.Context, req *pb.GatewayLogAnalyticsQuery) (*pb.GatewayLogAnalyticsResult, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, grpcBadRequest("request is required")
	}
	result, err := s.admin.ProxyHandler.AnalyzeLogEntriesContext(ctx, req.GetFromDate(), req.GetToDate())
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, status.FromContextError(err).Err()
		}
		return nil, grpcBadRequest("%v", err)
	}
	return logAnalyticsResultToProto(result), nil
}

func (s *GRPCServer) DeleteLogDate(ctx context.Context, req *pb.StringValue) (*pb.GatewayLogDeleteResult, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, grpcBadRequest("request is required")
	}
	result, err := s.admin.ProxyHandler.DeleteLogDate(req.GetValue())
	if err != nil {
		return nil, grpcBadRequest("%v", err)
	}
	return logDeleteResultToProto(result), nil
}

func (s *GRPCServer) ListGeneralBlacklist(ctx context.Context, req *pb.GeneralBlacklistListRequest) (*pb.GeneralBlacklistList, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	if req == nil {
		req = &pb.GeneralBlacklistListRequest{}
	}
	return generalBlacklistListToProto(s.admin.ProxyHandler.ListGeneralBlacklist(int(req.GetPage()), int(req.GetLimit()), req.GetSearch())), nil
}

func (s *GRPCServer) CheckGeneralBlacklist(ctx context.Context, req *pb.IpListRequest) (*pb.GeneralBlacklistStatus, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, grpcBadRequest("request is required")
	}
	result, err := s.admin.ProxyHandler.CheckGeneralBlacklist(req.GetIps())
	if err != nil {
		return nil, grpcBadRequest("%v", err)
	}
	return generalBlacklistStatusToProto(result), nil
}

func (s *GRPCServer) AddGeneralBlacklist(ctx context.Context, req *pb.IpListRequest) (*pb.GeneralBlacklistMutationResult, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, grpcBadRequest("request is required")
	}
	result, err := s.admin.ProxyHandler.AddGeneralBlacklist(req.GetIps(), req.GetSource(), req.GetComment())
	if err != nil {
		return nil, grpcBadRequest("%v", err)
	}
	return generalBlacklistMutationToProto(result), nil
}

func (s *GRPCServer) RemoveGeneralBlacklist(ctx context.Context, req *pb.IpListRequest) (*pb.GeneralBlacklistMutationResult, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, grpcBadRequest("request is required")
	}
	result, err := s.admin.ProxyHandler.RemoveGeneralBlacklist(req.GetIps())
	if err != nil {
		return nil, grpcBadRequest("%v", err)
	}
	return generalBlacklistMutationToProto(result), nil
}

func (s *GRPCServer) GetTrafficStats(ctx context.Context, _ *emptypb.Empty) (*pb.TrafficStats, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	return trafficStatsToProto(s.admin.ProxyHandler.GetTrafficStats(time.Now())), nil
}

func (s *GRPCServer) GetHostActiveIps(ctx context.Context, req *pb.HostRequest) (*pb.HostActiveIpsStats, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	if req == nil || strings.TrimSpace(req.GetHost()) == "" {
		return nil, grpcBadRequest("host is required")
	}
	return hostActiveIPsToProto(s.admin.ProxyHandler.GetHostActiveIPs(req.GetHost(), time.Now())), nil
}

func (s *GRPCServer) GetStreamActiveIps(ctx context.Context, req *pb.StreamRequest) (*pb.StreamActiveIpsStats, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, grpcBadRequest("request is required")
	}
	protocol := strings.ToLower(strings.TrimSpace(req.GetProtocol()))
	if protocol != models.StreamProtocolTCP && protocol != models.StreamProtocolUDP {
		return nil, grpcBadRequest("protocol must be tcp or udp")
	}
	listenPort := int(req.GetListenPort())
	if listenPort <= 0 || listenPort > 65535 {
		return nil, grpcBadRequest("listen_port must be between 1 and 65535")
	}
	return streamActiveIPsToProto(s.admin.ProxyHandler.GetStreamActiveIPs(protocol, listenPort, time.Now())), nil
}

func (s *GRPCServer) GetWafStatus(ctx context.Context, _ *emptypb.Empty) (*pb.WafStatus, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	return wafStatusToProto(s.admin.ProxyHandler.GetWAFStatus()), nil
}

func (s *GRPCServer) SetWafConfig(ctx context.Context, req *pb.WafConfig) (*pb.WafStatus, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, grpcBadRequest("request is required")
	}
	result, err := s.admin.ProxyHandler.SetWAFConfig(protoToWAFConfig(req))
	if err != nil {
		return nil, grpcBadRequest("%v", err)
	}
	return wafStatusToProto(result), nil
}

func (s *GRPCServer) ValidateWafBundle(ctx context.Context, req *pb.WafBundleRequest) (*pb.WafValidationResult, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, grpcBadRequest("request is required")
	}
	cfg := s.admin.ProxyHandler.GetWAFConfig()
	if req.GetHasConfig() {
		cfg = protoToWAFConfig(req.GetConfig())
	}
	result, err := s.admin.ProxyHandler.ValidateWAFBundle(cfg, req.GetBundleId(), req.GetBundlePath())
	if err != nil {
		return wafValidationToProto(result), nil
	}
	return wafValidationToProto(result), nil
}

func (s *GRPCServer) ReloadWafBundle(ctx context.Context, req *pb.WafBundleRequest) (*pb.WafStatus, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, grpcBadRequest("request is required")
	}
	cfg := s.admin.ProxyHandler.GetWAFConfig()
	if req.GetHasConfig() {
		cfg = protoToWAFConfig(req.GetConfig())
	}
	bundleID := strings.TrimSpace(req.GetBundleId())
	if bundleID == "" {
		bundleID = cfg.ActiveBundleID
	}
	result, err := s.admin.ProxyHandler.ReloadWAFBundle(cfg, bundleID, req.GetBundlePath())
	if err != nil {
		return nil, grpcBadRequest("%v", err)
	}
	return wafStatusToProto(result), nil
}

func (s *GRPCServer) DrainWafEvents(ctx context.Context, req *pb.WafDrainRequest) (*pb.WafDrainResult, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, grpcBadRequest("request is required")
	}
	switch req.GetOperation() {
	case pb.WafDrainOperation_WAF_DRAIN_OPERATION_ACKNOWLEDGE:
		if strings.TrimSpace(req.GetLeaseId()) == "" {
			return nil, grpcBadRequest("lease_id is required")
		}
		return wafDrainToProto(s.admin.ProxyHandler.AcknowledgeWAFEventLease(req.GetLeaseId())), nil
	case pb.WafDrainOperation_WAF_DRAIN_OPERATION_RELEASE:
		if strings.TrimSpace(req.GetLeaseId()) == "" {
			return nil, grpcBadRequest("lease_id is required")
		}
		return wafDrainToProto(s.admin.ProxyHandler.ReleaseWAFEventLease(req.GetLeaseId())), nil
	}
	limit := 500
	if req.GetLimit() > 0 {
		limit = int(req.GetLimit())
	}
	if limit > 5000 {
		limit = 5000
	}
	switch req.GetOperation() {
	case pb.WafDrainOperation_WAF_DRAIN_OPERATION_LEASE:
		return wafDrainToProto(s.admin.ProxyHandler.LeaseWAFEvents(limit)), nil
	case pb.WafDrainOperation_WAF_DRAIN_OPERATION_UNSPECIFIED:
		// Legacy control planes (before the lease protocol) send UNSPECIFIED and
		// expect an immediate drain without a delivery lease. Keep that path
		// working across version skew.
		return wafDrainToProto(s.admin.ProxyHandler.DrainWAFEvents(limit)), nil
	default:
		return nil, grpcBadRequest("unsupported WAF drain operation")
	}
}

func (s *GRPCServer) GetSslInfo(ctx context.Context, _ *emptypb.Empty) (*pb.SslInfo, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	return sslInfoToProto(s.admin.ProxyHandler.GetSSLInfo()), nil
}

func (s *GRPCServer) SetSslDeployment(ctx context.Context, req *pb.SslConfig) (*pb.RpcStatus, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, grpcBadRequest("request is required")
	}
	if err := s.admin.ProxyHandler.SetSSLDeployment(protoToSSLConfig(req)); err != nil {
		return nil, grpcBadRequest("%v", err)
	}
	return rpcOK(), nil
}

func (s *GRPCServer) SetSslPem(ctx context.Context, req *pb.SslDeployedCertificate) (*pb.RpcStatus, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, grpcBadRequest("request is required")
	}
	if err := s.admin.ProxyHandler.SetSSLCertificatePEM(req.GetCert(), req.GetKey()); err != nil {
		return nil, grpcBadRequest("invalid certificate or key: %v", err)
	}
	return rpcOK(), nil
}

func (s *GRPCServer) ClearSsl(ctx context.Context, _ *emptypb.Empty) (*pb.RpcStatus, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	if err := s.admin.ProxyHandler.ClearSSLCertificate(); err != nil {
		return nil, grpcInternal("failed to clear SSL certificate: %v", err)
	}
	return rpcOK(), nil
}

func (s *GRPCServer) InitIptables(ctx context.Context, req *pb.IptablesInitRequest) (*pb.RpcStatus, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	manager := s.admin.IptablesHandler.Manager
	chainName := ""
	if req != nil {
		if strings.TrimSpace(req.GetChainName()) != "" {
			manager.Chain = req.GetChainName()
			chainName = req.GetChainName()
		}
		if len(req.GetParentChains()) > 0 {
			manager.ParentChains = req.GetParentChains()
		}
		if req.GetExemptPorts() != nil {
			manager.ExemptPorts = req.GetExemptPorts()
		}
	}
	if err := manager.Init(); err != nil {
		return nil, grpcInternal("%v", err)
	}
	if chainName != "" && s.admin.ConfigManager != nil {
		if err := s.admin.ConfigManager.Update(func(cfg *config.AppConfig) error {
			cfg.IptablesChainName = chainName
			return nil
		}); err != nil {
			return nil, grpcInternal("failed to save config: %v", err)
		}
	}
	return rpcOK(), nil
}

func (s *GRPCServer) CleanIptables(ctx context.Context, _ *emptypb.Empty) (*pb.RpcStatus, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	if err := s.admin.IptablesHandler.Manager.Destroy(); err != nil {
		return nil, grpcInternal("%v", err)
	}
	return rpcOK(), nil
}

func (s *GRPCServer) FlushIptables(ctx context.Context, _ *emptypb.Empty) (*pb.RpcStatus, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	if err := s.admin.IptablesHandler.Manager.Flush(); err != nil {
		return nil, grpcInternal("%v", err)
	}
	return rpcOK(), nil
}

func (s *GRPCServer) AllowIp(ctx context.Context, req *pb.IpRequest) (*pb.RpcStatus, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	ip, err := requireIP(req)
	if err != nil {
		return nil, err
	}
	if err := s.admin.IptablesHandler.Manager.AllowIP(ip); err != nil {
		return nil, grpcInternal("%v", err)
	}
	return rpcOK(), nil
}

func (s *GRPCServer) BlockIp(ctx context.Context, req *pb.IpRequest) (*pb.RpcStatus, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	ip, err := requireIP(req)
	if err != nil {
		return nil, err
	}
	if err := s.admin.IptablesHandler.Manager.BlockIP(ip); err != nil {
		return nil, grpcInternal("%v", err)
	}
	return rpcOK(), nil
}

func (s *GRPCServer) RemoveIp(ctx context.Context, req *pb.IpRequest) (*pb.RpcStatus, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	ip, err := requireIP(req)
	if err != nil {
		return nil, err
	}
	if err := s.admin.IptablesHandler.Manager.RemoveIPRule(ip); err != nil {
		return nil, grpcInternal("%v", err)
	}
	return rpcOK(), nil
}

func (s *GRPCServer) SyncWhitelistFirewall(
	ctx context.Context,
	req *pb.WhitelistFirewallSyncRequest,
) (*pb.RpcStatus, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, grpcBadRequest("request is required")
	}
	_, whitelist, err := compiledipset.Resolve(
		req.GetPolicyId(),
		protoToCompiledIPSetPointer(req.GetPolicy()),
		nil,
	)
	if err != nil {
		return nil, grpcBadRequest("invalid whitelist firewall policy: %v", err)
	}
	if err := s.admin.IptablesHandler.Manager.SyncWhitelistIPSet(whitelist.Prefixes()); err != nil {
		return nil, grpcInternal("%v", err)
	}
	return rpcOK(), nil
}

func requireIP(req *pb.IpRequest) (string, error) {
	if req == nil || strings.TrimSpace(req.GetIp()) == "" {
		return "", grpcBadRequest("IP is required")
	}
	return req.GetIp(), nil
}

func (s *GRPCServer) BlockTcpPortForIp(ctx context.Context, req *pb.TcpPortRuleRequest) (*pb.RpcStatus, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	if req == nil || strings.TrimSpace(req.GetIp()) == "" {
		return nil, grpcBadRequest("IP is required")
	}
	if err := s.admin.IptablesHandler.Manager.BlockTCPPortForIP(req.GetIp(), int(req.GetPort())); err != nil {
		return nil, grpcInternal("%v", err)
	}
	return rpcOK(), nil
}

func (s *GRPCServer) RemoveTcpPortRule(ctx context.Context, req *pb.TcpPortRuleRequest) (*pb.RpcStatus, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	if req == nil || strings.TrimSpace(req.GetIp()) == "" {
		return nil, grpcBadRequest("IP is required")
	}
	if err := s.admin.IptablesHandler.Manager.RemoveTCPPortRule(req.GetIp(), int(req.GetPort())); err != nil {
		return nil, grpcInternal("%v", err)
	}
	return rpcOK(), nil
}

func defaultParentChains(parentChains []string) []string {
	if len(parentChains) > 0 {
		return parentChains
	}
	return []string{"INPUT", "DOCKER-USER"}
}

func (s *GRPCServer) SyncSshFirewall(ctx context.Context, req *pb.SshFirewallSyncRequest) (*pb.RpcStatus, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, grpcBadRequest("request is required")
	}
	chainName := req.GetChainName()
	if strings.TrimSpace(chainName) == "" {
		chainName = iptables.DefaultSSHFirewallChain
	}
	_, allowSet, err := compiledipset.Resolve(
		req.GetPolicyId(),
		protoToCompiledIPSetPointer(req.GetPolicy()),
		req.GetAllowedCidrs(),
	)
	if err != nil {
		return nil, grpcBadRequest("invalid SSH allow policy: %v", err)
	}
	allowSources := allowSet.Prefixes()
	defaultAction := "RETURN"
	if allowSet.RangeCount() > 0 {
		defaultAction = "DROP"
	}
	ports := make([]int, 0, len(req.GetPorts()))
	for _, port := range req.GetPorts() {
		if port > 0 {
			ports = append(ports, int(port))
		}
	}
	if err := s.admin.IptablesHandler.Manager.SyncTCPPortAccessPolicy(iptables.TCPPortAccessPolicy{
		Chain:             chainName,
		ParentChains:      defaultParentChains(req.GetParentChains()),
		Ports:             ports,
		AllowSources:      allowSources,
		BlockSources:      req.GetBlockedIps(),
		IncludeLocalCIDRs: req.GetIncludeLocalCidrs(),
		DefaultAction:     defaultAction,
	}); err != nil {
		return nil, grpcInternal("%v", err)
	}
	return rpcOK(), nil
}

func (s *GRPCServer) ClearSshFirewall(ctx context.Context, req *pb.SshFirewallClearRequest) (*pb.RpcStatus, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	chainName := ""
	var parentChains []string
	if req != nil {
		chainName = req.GetChainName()
		parentChains = req.GetParentChains()
	}
	if strings.TrimSpace(chainName) == "" {
		chainName = iptables.DefaultSSHFirewallChain
	}
	if err := s.admin.IptablesHandler.Manager.ClearTCPPortAccessPolicy(chainName, defaultParentChains(parentChains)); err != nil {
		return nil, grpcInternal("%v", err)
	}
	return rpcOK(), nil
}

func (s *GRPCServer) BlockAll(ctx context.Context, _ *emptypb.Empty) (*pb.RpcStatus, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	if err := s.admin.IptablesHandler.Manager.BlockAll(); err != nil {
		return nil, grpcInternal("%v", err)
	}
	return rpcOK(), nil
}

func (s *GRPCServer) AllowAll(ctx context.Context, _ *emptypb.Empty) (*pb.RpcStatus, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	if err := s.admin.IptablesHandler.Manager.AllowAll(); err != nil {
		return nil, grpcInternal("%v", err)
	}
	return rpcOK(), nil
}

func (s *GRPCServer) EnsureTcpRedirect(ctx context.Context, req *pb.TcpRedirectRequest) (*pb.RpcStatus, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, grpcBadRequest("request is required")
	}
	if err := s.admin.IptablesHandler.Manager.EnsureTCPRedirect(int(req.GetListenPort()), int(req.GetTargetPort())); err != nil {
		return nil, grpcInternal("%v", err)
	}
	return rpcOK(), nil
}

func (s *GRPCServer) ClearTcpRedirect(ctx context.Context, req *pb.TcpRedirectRequest) (*pb.RpcStatus, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, grpcBadRequest("request is required")
	}
	if err := s.admin.IptablesHandler.Manager.ClearTCPRedirect(int(req.GetListenPort()), int(req.GetTargetPort())); err != nil {
		return nil, grpcInternal("%v", err)
	}
	return rpcOK(), nil
}

func (s *GRPCServer) ListIptables(ctx context.Context, _ *emptypb.Empty) (*pb.IptablesRules, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	rules, err := s.admin.IptablesHandler.Manager.ParseRules()
	if err != nil {
		return nil, grpcInternal("%v", err)
	}
	return iptablesRulesToProto(rules), nil
}
