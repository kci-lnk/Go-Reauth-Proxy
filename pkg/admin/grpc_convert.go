package admin

import (
	"time"

	"go-reauth-proxy/pkg/gatewaylog"
	"go-reauth-proxy/pkg/grpc/pb"
	"go-reauth-proxy/pkg/iptables"
	"go-reauth-proxy/pkg/models"
	"go-reauth-proxy/pkg/proxy"
	proxywaf "go-reauth-proxy/pkg/waf"
)

func rpcOK() *pb.RpcStatus {
	return &pb.RpcStatus{Success: true, Code: 200, Message: "success"}
}

func rulesToProto(rules []models.Rule) *pb.Rules {
	items := make([]*pb.Rule, 0, len(rules))
	for _, rule := range rules {
		items = append(items, &pb.Rule{
			Path:        rule.Path,
			Target:      rule.Target,
			UseAuth:     rule.UseAuth,
			StripPath:   rule.StripPath,
			RewriteHtml: rule.RewriteHTML,
			UseRootMode: rule.UseRootMode,
		})
	}
	return &pb.Rules{Items: items}
}

func protoToRules(req *pb.Rules) []models.Rule {
	if req == nil {
		return nil
	}
	rules := make([]models.Rule, 0, len(req.GetItems()))
	for _, rule := range req.GetItems() {
		if rule == nil {
			continue
		}
		rules = append(rules, models.Rule{
			Path:        rule.GetPath(),
			Target:      rule.GetTarget(),
			UseAuth:     rule.GetUseAuth(),
			StripPath:   rule.GetStripPath(),
			RewriteHTML: rule.GetRewriteHtml(),
			UseRootMode: rule.GetUseRootMode(),
		})
	}
	return rules
}

func basicAuthToProto(cfg models.BasicAuthConfig) *pb.BasicAuthConfig {
	return &pb.BasicAuthConfig{
		Enabled:  cfg.Enabled,
		Username: cfg.Username,
		Password: cfg.Password,
	}
}

func protoToBasicAuth(cfg *pb.BasicAuthConfig) models.BasicAuthConfig {
	if cfg == nil {
		return models.BasicAuthConfig{}
	}
	return models.BasicAuthConfig{
		Enabled:  cfg.GetEnabled(),
		Username: cfg.GetUsername(),
		Password: cfg.GetPassword(),
	}
}

func hostLocationResponseToProto(resp models.HostLocationResponse) *pb.HostLocationResponse {
	headers := make(map[string]string, len(resp.Headers))
	for key, value := range resp.Headers {
		headers[key] = value
	}
	return &pb.HostLocationResponse{
		Status:      int32(resp.Status),
		ContentType: resp.ContentType,
		Headers:     headers,
		Body:        resp.Body,
	}
}

func protoToHostLocationResponse(resp *pb.HostLocationResponse) models.HostLocationResponse {
	if resp == nil {
		return models.HostLocationResponse{}
	}
	headers := make(map[string]string, len(resp.GetHeaders()))
	for key, value := range resp.GetHeaders() {
		headers[key] = value
	}
	return models.HostLocationResponse{
		Status:      int(resp.GetStatus()),
		ContentType: resp.GetContentType(),
		Headers:     headers,
		Body:        resp.GetBody(),
	}
}

func hostLocationsToProto(locations []models.HostLocation) []*pb.HostLocation {
	items := make([]*pb.HostLocation, 0, len(locations))
	for _, location := range locations {
		items = append(items, &pb.HostLocation{
			Path:        location.Path,
			Match:       location.Match,
			Action:      location.Action,
			Target:      location.Target,
			StripPath:   location.StripPath,
			RewriteHtml: location.RewriteHTML,
			Response:    hostLocationResponseToProto(location.Response),
		})
	}
	return items
}

func protoToHostLocations(locations []*pb.HostLocation) []models.HostLocation {
	items := make([]models.HostLocation, 0, len(locations))
	for _, location := range locations {
		if location == nil {
			continue
		}
		items = append(items, models.HostLocation{
			Path:        location.GetPath(),
			Match:       location.GetMatch(),
			Action:      location.GetAction(),
			Target:      location.GetTarget(),
			StripPath:   location.GetStripPath(),
			RewriteHTML: location.GetRewriteHtml(),
			Response:    protoToHostLocationResponse(location.GetResponse()),
		})
	}
	return items
}

func hostRuleAvailabilityToProto(value *models.HostRuleAvailability) *pb.HostRuleAvailability {
	if value == nil {
		return nil
	}
	return &pb.HostRuleAvailability{
		Enabled:   value.Enabled,
		StartTime: value.StartTime,
		EndTime:   value.EndTime,
	}
}

func protoToHostRuleAvailability(value *pb.HostRuleAvailability) *models.HostRuleAvailability {
	if value == nil {
		return nil
	}
	return &models.HostRuleAvailability{
		Enabled:   value.GetEnabled(),
		StartTime: value.GetStartTime(),
		EndTime:   value.GetEndTime(),
	}
}

func hostRulesToProto(rules []models.HostRule) *pb.HostRules {
	items := make([]*pb.HostRule, 0, len(rules))
	for _, rule := range rules {
		items = append(items, &pb.HostRule{
			Host:            rule.Host,
			Target:          rule.Target,
			UseAuth:         rule.UseAuth,
			AccessMode:      rule.AccessMode,
			SuppressToolbar: rule.SuppressToolbar,
			PreserveHost:    rule.PreserveHost,
			IsDefault:       rule.IsDefault,
			Title:           rule.Title,
			Favicon:         rule.Favicon,
			BasicAuth:       basicAuthToProto(rule.BasicAuth),
			Locations:       hostLocationsToProto(rule.Locations),
			Disabled:        rule.Disabled,
			Availability:    hostRuleAvailabilityToProto(rule.Availability),
		})
	}
	return &pb.HostRules{Items: items}
}

func protoToHostRules(req *pb.HostRules) []models.HostRule {
	if req == nil {
		return nil
	}
	rules := make([]models.HostRule, 0, len(req.GetItems()))
	for _, rule := range req.GetItems() {
		if rule == nil {
			continue
		}
		rules = append(rules, models.HostRule{
			Host:            rule.GetHost(),
			Target:          rule.GetTarget(),
			UseAuth:         rule.GetUseAuth(),
			AccessMode:      rule.GetAccessMode(),
			SuppressToolbar: rule.GetSuppressToolbar(),
			PreserveHost:    rule.GetPreserveHost(),
			IsDefault:       rule.GetIsDefault(),
			Title:           rule.GetTitle(),
			Favicon:         rule.GetFavicon(),
			BasicAuth:       protoToBasicAuth(rule.GetBasicAuth()),
			Locations:       protoToHostLocations(rule.GetLocations()),
			Disabled:        rule.GetDisabled(),
			Availability:    protoToHostRuleAvailability(rule.GetAvailability()),
		})
	}
	return rules
}

func streamRulesToProto(rules []models.StreamRule) *pb.StreamRules {
	items := make([]*pb.StreamRule, 0, len(rules))
	for _, rule := range rules {
		items = append(items, &pb.StreamRule{
			Protocol:   rule.Protocol,
			ListenPort: int32(rule.ListenPort),
			Target:     rule.Target,
			UseAuth:    rule.UseAuth,
		})
	}
	return &pb.StreamRules{Items: items}
}

func protoToStreamRules(req *pb.StreamRules) []models.StreamRule {
	if req == nil {
		return nil
	}
	rules := make([]models.StreamRule, 0, len(req.GetItems()))
	for _, rule := range req.GetItems() {
		if rule == nil {
			continue
		}
		rules = append(rules, models.StreamRule{
			Protocol:   rule.GetProtocol(),
			ListenPort: int(rule.GetListenPort()),
			Target:     rule.GetTarget(),
			UseAuth:    rule.GetUseAuth(),
		})
	}
	return rules
}

func authConfigToProto(cfg models.AuthConfig) *pb.AuthConfig {
	return &pb.AuthConfig{
		AuthPort:                        int32(cfg.AuthPort),
		AuthUrl:                         cfg.AuthURL,
		LoginUrl:                        cfg.LoginURL,
		LogoutUrl:                       cfg.LogoutURL,
		PreflightUrl:                    cfg.PreflightURL,
		AuthCacheTtlSeconds:             int32(cfg.AuthCacheTTL),
		AuthCacheUnauthorizedTtlSeconds: int32(cfg.AuthCacheFailTTL),
		EdgeClientIpEnabled:             cfg.EdgeClientIPEnabled,
		AliyunEsaEnabled:                cfg.AliyunESAEnabled,
		TencentEdgeoneEnabled:           cfg.TencentEdgeOneEnabled,
		PublicAuthBaseUrl:               cfg.PublicAuthBaseURL,
		PublicHttpPort:                  int32(cfg.PublicHTTPPort),
		PublicHttpsPort:                 int32(cfg.PublicHTTPSPort),
		AuthHost:                        cfg.AuthHost,
		TrustForwardedProto:             cfg.TrustForwardedProto,
	}
}

func protoToAuthConfig(cfg *pb.AuthConfig) models.AuthConfig {
	if cfg == nil {
		return models.AuthConfig{}
	}
	return models.AuthConfig{
		AuthPort:              int(cfg.GetAuthPort()),
		AuthURL:               cfg.GetAuthUrl(),
		LoginURL:              cfg.GetLoginUrl(),
		LogoutURL:             cfg.GetLogoutUrl(),
		PreflightURL:          cfg.GetPreflightUrl(),
		AuthCacheTTL:          int(cfg.GetAuthCacheTtlSeconds()),
		AuthCacheFailTTL:      int(cfg.GetAuthCacheUnauthorizedTtlSeconds()),
		EdgeClientIPEnabled:   cfg.GetEdgeClientIpEnabled(),
		AliyunESAEnabled:      cfg.GetAliyunEsaEnabled(),
		TencentEdgeOneEnabled: cfg.GetTencentEdgeoneEnabled(),
		PublicAuthBaseURL:     cfg.GetPublicAuthBaseUrl(),
		PublicHTTPPort:        int(cfg.GetPublicHttpPort()),
		PublicHTTPSPort:       int(cfg.GetPublicHttpsPort()),
		AuthHost:              cfg.GetAuthHost(),
		TrustForwardedProto:   cfg.GetTrustForwardedProto(),
	}
}

func loggingConfigToProto(cfg gatewaylog.ConfigInfo) *pb.LoggingConfig {
	return &pb.LoggingConfig{
		Enabled:        cfg.Enabled,
		MaxDays:        int32(cfg.MaxDays),
		LogsDir:        cfg.LogsDir,
		DroppedEntries: cfg.DroppedEntries,
		QueueSize:      int32(cfg.QueueSize),
		QueueDepth:     int32(cfg.QueueDepth),
	}
}

func protoToLoggingConfig(cfg *pb.LoggingConfig) models.LoggingConfig {
	if cfg == nil {
		return models.LoggingConfig{}
	}
	return models.LoggingConfig{Enabled: cfg.GetEnabled(), MaxDays: int(cfg.GetMaxDays())}
}

func reverseProxyThrottleToProto(cfg models.ReverseProxyThrottleConfig) *pb.ReverseProxyThrottleConfig {
	return &pb.ReverseProxyThrottleConfig{
		Enabled:           cfg.Enabled,
		RequestsPerSecond: int32(cfg.RequestsPerSecond),
		Burst:             int32(cfg.Burst),
		BlockSeconds:      int32(cfg.BlockSeconds),
	}
}

func protoToReverseProxyThrottle(cfg *pb.ReverseProxyThrottleConfig) models.ReverseProxyThrottleConfig {
	if cfg == nil {
		return models.ReverseProxyThrottleConfig{}
	}
	return models.ReverseProxyThrottleConfig{
		Enabled:           cfg.GetEnabled(),
		RequestsPerSecond: int(cfg.GetRequestsPerSecond()),
		Burst:             int(cfg.GetBurst()),
		BlockSeconds:      int(cfg.GetBlockSeconds()),
	}
}

func gatewayVisibilityToProto(cfg models.GatewayVisibilityConfig) *pb.GatewayVisibilityConfig {
	return &pb.GatewayVisibilityConfig{Enabled: cfg.Enabled, Cidrs: cfg.CIDRs, UpdatedAt: cfg.UpdatedAt}
}

func protoToGatewayVisibility(cfg *pb.GatewayVisibilityConfig) models.GatewayVisibilityConfig {
	if cfg == nil {
		return models.GatewayVisibilityConfig{}
	}
	return models.GatewayVisibilityConfig{Enabled: cfg.GetEnabled(), CIDRs: cfg.GetCidrs(), UpdatedAt: cfg.GetUpdatedAt()}
}

func omitTargetsToProto(enabled bool, targets []string, updatedAt string) *pb.OmitTargetsConfig {
	return &pb.OmitTargetsConfig{Enabled: enabled, OmitTargets: targets, UpdatedAt: updatedAt}
}

func forwardedHeadersToProto(cfg models.ForwardedHeadersConfig) *pb.OmitTargetsConfig {
	return omitTargetsToProto(cfg.Enabled, cfg.OmitTargets, cfg.UpdatedAt)
}

func protoToForwardedHeaders(cfg *pb.OmitTargetsConfig) models.ForwardedHeadersConfig {
	if cfg == nil {
		return models.ForwardedHeadersConfig{}
	}
	return models.ForwardedHeadersConfig{Enabled: cfg.GetEnabled(), OmitTargets: cfg.GetOmitTargets(), UpdatedAt: cfg.GetUpdatedAt()}
}

func preserveHostToProto(cfg models.PreserveHostConfig) *pb.OmitTargetsConfig {
	return omitTargetsToProto(cfg.Enabled, cfg.OmitTargets, cfg.UpdatedAt)
}

func protoToPreserveHost(cfg *pb.OmitTargetsConfig) models.PreserveHostConfig {
	if cfg == nil {
		return models.PreserveHostConfig{}
	}
	return models.PreserveHostConfig{Enabled: cfg.GetEnabled(), OmitTargets: cfg.GetOmitTargets(), UpdatedAt: cfg.GetUpdatedAt()}
}

func crawlerBlockerToProto(cfg models.CrawlerBlockerConfig) *pb.CrawlerBlockerConfig {
	return &pb.CrawlerBlockerConfig{Enabled: cfg.Enabled, UpdatedAt: cfg.UpdatedAt}
}

func protoToCrawlerBlocker(cfg *pb.CrawlerBlockerConfig) models.CrawlerBlockerConfig {
	if cfg == nil {
		return models.CrawlerBlockerConfig{}
	}
	return models.CrawlerBlockerConfig{Enabled: cfg.GetEnabled(), UpdatedAt: cfg.GetUpdatedAt()}
}

func gatewayPortalToProto(cfg models.GatewayPortalConfig) *pb.GatewayPortalConfig {
	return &pb.GatewayPortalConfig{
		Enabled:      cfg.Enabled,
		DisplayStyle: cfg.DisplayStyle,
		ShowAppIcon:  cfg.ShowAppIcon,
		IconDragMode: cfg.IconDragMode,
	}
}

func protoToGatewayPortal(cfg *pb.GatewayPortalConfig) models.GatewayPortalConfig {
	if cfg == nil {
		return models.GatewayPortalConfig{}
	}
	return models.GatewayPortalConfig{
		Enabled:      cfg.GetEnabled(),
		DisplayStyle: cfg.GetDisplayStyle(),
		ShowAppIcon:  cfg.GetShowAppIcon(),
		IconDragMode: cfg.GetIconDragMode(),
	}
}

func fnosPortIconHijackToProto(cfg models.FnosPortIconHijackConfig) *pb.FnosPortIconHijackConfig {
	return &pb.FnosPortIconHijackConfig{Enabled: cfg.Enabled, UpdatedAt: cfg.UpdatedAt}
}

func protoToFnosPortIconHijack(cfg *pb.FnosPortIconHijackConfig) models.FnosPortIconHijackConfig {
	if cfg == nil {
		return models.FnosPortIconHijackConfig{}
	}
	return models.FnosPortIconHijackConfig{Enabled: cfg.GetEnabled(), UpdatedAt: cfg.GetUpdatedAt()}
}

func throttleExemptIPsToProto(cfg models.ReverseProxyThrottleExemptIPsRuntime) *pb.ReverseProxyThrottleExemptIpsRuntime {
	return &pb.ReverseProxyThrottleExemptIpsRuntime{
		Enabled:   cfg.Enabled,
		Ips:       cfg.IPs,
		Cidrs:     cfg.CIDRs,
		UpdatedAt: cfg.UpdatedAt,
	}
}

func protoToThrottleExemptIPs(cfg *pb.ReverseProxyThrottleExemptIpsRuntime) models.ReverseProxyThrottleExemptIPsRuntime {
	if cfg == nil {
		return models.ReverseProxyThrottleExemptIPsRuntime{}
	}
	return models.ReverseProxyThrottleExemptIPsRuntime{
		Enabled:   cfg.GetEnabled(),
		IPs:       cfg.GetIps(),
		CIDRs:     cfg.GetCidrs(),
		UpdatedAt: cfg.GetUpdatedAt(),
	}
}

func commonLocationExemptionsToProto(cfg models.CommonLocationExemptionsRuntime) *pb.CommonLocationExemptionsRuntime {
	return &pb.CommonLocationExemptionsRuntime{
		Enabled:    cfg.Enabled,
		WafEnabled: cfg.WAFEnabled,
		Cidrs:      cfg.CIDRs,
		UpdatedAt:  cfg.UpdatedAt,
	}
}

func protoToCommonLocationExemptions(cfg *pb.CommonLocationExemptionsRuntime) models.CommonLocationExemptionsRuntime {
	if cfg == nil {
		return models.CommonLocationExemptionsRuntime{}
	}
	return models.CommonLocationExemptionsRuntime{
		Enabled:    cfg.GetEnabled(),
		WAFEnabled: cfg.GetWafEnabled(),
		CIDRs:      cfg.GetCidrs(),
		UpdatedAt:  cfg.GetUpdatedAt(),
	}
}

func generalBlacklistRecordToProto(record models.GeneralBlacklistRecord) *pb.GeneralBlacklistRecord {
	return &pb.GeneralBlacklistRecord{
		Ip:        record.IP,
		Source:    record.Source,
		Comment:   record.Comment,
		CreatedAt: record.CreatedAt,
		UpdatedAt: record.UpdatedAt,
	}
}

func generalBlacklistListToProto(result models.GeneralBlacklistList) *pb.GeneralBlacklistList {
	items := make([]*pb.GeneralBlacklistRecord, 0, len(result.Items))
	for _, item := range result.Items {
		items = append(items, generalBlacklistRecordToProto(item))
	}
	return &pb.GeneralBlacklistList{Total: int32(result.Total), Items: items}
}

func generalBlacklistMutationToProto(result models.GeneralBlacklistMutationResult) *pb.GeneralBlacklistMutationResult {
	items := make([]*pb.GeneralBlacklistRecord, 0, len(result.Items))
	for _, item := range result.Items {
		items = append(items, generalBlacklistRecordToProto(item))
	}
	return &pb.GeneralBlacklistMutationResult{
		Added:   int32(result.Added),
		Updated: int32(result.Updated),
		Removed: int32(result.Removed),
		Total:   int32(result.Total),
		Items:   items,
	}
}

func generalBlacklistStatusToProto(result models.GeneralBlacklistStatus) *pb.GeneralBlacklistStatus {
	records := make(map[string]*pb.GeneralBlacklistRecord, len(result.Records))
	for key, value := range result.Records {
		records[key] = generalBlacklistRecordToProto(value)
	}
	return &pb.GeneralBlacklistStatus{Records: records}
}

func trafficStatsToProto(stats proxy.TrafficStats) *pb.TrafficStats {
	byHost := make([]*pb.HostTrafficStats, 0, len(stats.ByHost))
	for _, item := range stats.ByHost {
		byHost = append(byHost, &pb.HostTrafficStats{
			Host:          item.Host,
			TotalIn:       item.TotalIn,
			TotalOut:      item.TotalOut,
			Error_5Xx:     item.Error5xx,
			ActiveIpCount: int32(item.ActiveIPCount),
		})
	}
	return &pb.TrafficStats{
		TotalIn:     stats.TotalIn,
		TotalOut:    stats.TotalOut,
		ActiveConns: stats.ActiveConns,
		Error_5Xx:   stats.Error5xx,
		ByHost:      byHost,
	}
}

func hostActiveIPsToProto(stats proxy.HostActiveIPsStats) *pb.HostActiveIpsStats {
	items := make([]*pb.HostActiveIpStats, 0, len(stats.Items))
	for _, item := range stats.Items {
		items = append(items, &pb.HostActiveIpStats{
			Ip:          item.IP,
			LastSeenAt:  item.LastSeenAt.Format(time.RFC3339Nano),
			ActiveConns: item.ActiveConns,
		})
	}
	return &pb.HostActiveIpsStats{Host: stats.Host, WindowSeconds: int32(stats.WindowSeconds), Items: items}
}

func wafConfigToProto(cfg models.WAFConfig) *pb.WafConfig {
	return &pb.WafConfig{
		Enabled:                       cfg.Enabled,
		Mode:                          cfg.Mode,
		RulesDir:                      cfg.RulesDir,
		ActiveBundleId:                cfg.ActiveBundleID,
		ParanoiaLevel:                 int32(cfg.ParanoiaLevel),
		ExecutingParanoiaLevel:        int32(cfg.ExecutingParanoiaLevel),
		InboundAnomalyThreshold:       int32(cfg.InboundAnomalyThreshold),
		OutboundAnomalyThreshold:      int32(cfg.OutboundAnomalyThreshold),
		RequestBodyAccess:             cfg.RequestBodyAccess,
		RequestBodyLimitBytes:         int32(cfg.RequestBodyLimitBytes),
		RequestBodyInMemoryLimitBytes: int32(cfg.RequestBodyInMemoryLimitBytes),
		ResponseBodyAccess:            cfg.ResponseBodyAccess,
		DisabledHosts:                 cfg.DisabledHosts,
		DisabledPathPrefixes:          cfg.DisabledPathPrefixes,
		UpdatedAt:                     cfg.UpdatedAt,
	}
}

func protoToWAFConfig(cfg *pb.WafConfig) models.WAFConfig {
	if cfg == nil {
		return models.WAFConfig{}
	}
	return models.WAFConfig{
		Enabled:                       cfg.GetEnabled(),
		Mode:                          cfg.GetMode(),
		RulesDir:                      cfg.GetRulesDir(),
		ActiveBundleID:                cfg.GetActiveBundleId(),
		ParanoiaLevel:                 int(cfg.GetParanoiaLevel()),
		ExecutingParanoiaLevel:        int(cfg.GetExecutingParanoiaLevel()),
		InboundAnomalyThreshold:       int(cfg.GetInboundAnomalyThreshold()),
		OutboundAnomalyThreshold:      int(cfg.GetOutboundAnomalyThreshold()),
		RequestBodyAccess:             cfg.GetRequestBodyAccess(),
		RequestBodyLimitBytes:         int(cfg.GetRequestBodyLimitBytes()),
		RequestBodyInMemoryLimitBytes: int(cfg.GetRequestBodyInMemoryLimitBytes()),
		ResponseBodyAccess:            cfg.GetResponseBodyAccess(),
		DisabledHosts:                 cfg.GetDisabledHosts(),
		DisabledPathPrefixes:          cfg.GetDisabledPathPrefixes(),
		UpdatedAt:                     cfg.GetUpdatedAt(),
	}
}

func wafStatusToProto(status proxywaf.Status) *pb.WafStatus {
	return &pb.WafStatus{
		Enabled:       status.Enabled,
		Mode:          status.Mode,
		Loaded:        status.Loaded,
		BundleId:      status.BundleID,
		BundleHash:    status.BundleHash,
		LoadedAt:      status.LoadedAt,
		RulesDir:      status.RulesDir,
		PendingEvents: int32(status.PendingEvents),
		LastError:     status.LastError,
	}
}

func wafValidationToProto(result proxywaf.ValidationResult) *pb.WafValidationResult {
	return &pb.WafValidationResult{
		Ok:         result.OK,
		BundleId:   result.BundleID,
		BundlePath: result.BundlePath,
		BundleHash: result.BundleHash,
		Error:      result.Error,
	}
}

func wafDrainToProto(result proxywaf.DrainResult) *pb.WafDrainResult {
	events := make([]*pb.WafEvent, 0, len(result.Events))
	for _, event := range result.Events {
		events = append(events, wafEventToProto(event))
	}
	return &pb.WafDrainResult{Events: events, Drained: int32(result.Drained), Remaining: int32(result.Remaining)}
}

func wafEventToProto(event proxywaf.Event) *pb.WafEvent {
	rules := make([]*pb.WafRuleMatch, 0, len(event.Rules))
	for _, rule := range event.Rules {
		vars := make([]*pb.WafMatchedVariable, 0, len(rule.MatchedVariables))
		for _, matched := range rule.MatchedVariables {
			vars = append(vars, &pb.WafMatchedVariable{
				Variable:     matched.Variable,
				Key:          matched.Key,
				ValuePreview: matched.ValuePreview,
			})
		}
		rules = append(rules, &pb.WafRuleMatch{
			Id:               int32(rule.ID),
			Message:          rule.Message,
			Data:             rule.Data,
			Severity:         rule.Severity,
			Phase:            int32(rule.Phase),
			File:             rule.File,
			Line:             int32(rule.Line),
			Tags:             rule.Tags,
			Disruptive:       rule.Disruptive,
			MatchedVariables: vars,
		})
	}
	ruleIDs := make([]int32, 0, len(event.RuleIDs))
	for _, id := range event.RuleIDs {
		ruleIDs = append(ruleIDs, int32(id))
	}
	var interruption *pb.WafInterruptionInfo
	if event.Interruption != nil {
		interruption = &pb.WafInterruptionInfo{
			RuleId: int32(event.Interruption.RuleID),
			Action: event.Interruption.Action,
			Status: int32(event.Interruption.Status),
		}
	}
	return &pb.WafEvent{
		TraceId:       event.TraceID,
		TransactionId: event.TransactionID,
		Time:          event.Time,
		Mode:          event.Mode,
		Action:        event.Action,
		Status:        int32(event.Status),
		ClientIp:      event.ClientIP,
		RemoteAddr:    event.RemoteAddr,
		Method:        event.Method,
		Scheme:        event.Scheme,
		Host:          event.Host,
		Path:          event.Path,
		Query:         event.Query,
		RequestUri:    event.RequestURI,
		UserAgent:     event.UserAgent,
		Referer:       event.Referer,
		RouteType:     event.RouteType,
		RouteKey:      event.RouteKey,
		Upstream:      event.Upstream,
		BundleId:      event.BundleID,
		BundleHash:    event.BundleHash,
		RuleIds:       ruleIDs,
		Rules:         rules,
		Interruption:  interruption,
		Error:         event.Error,
	}
}

func sslConfigToProto(cfg models.SSLConfig) *pb.SslConfig {
	items := make([]*pb.SslDeployedCertificate, 0, len(cfg.Certificates))
	for _, cert := range cfg.Certificates {
		items = append(items, &pb.SslDeployedCertificate{
			Id:        cert.ID,
			Label:     cert.Label,
			Cert:      cert.Cert,
			Key:       cert.Key,
			IsDefault: cert.IsDefault,
		})
	}
	return &pb.SslConfig{DeploymentMode: string(cfg.DeploymentMode), Certificates: items}
}

func protoToSSLConfig(cfg *pb.SslConfig) models.SSLConfig {
	if cfg == nil {
		return models.SSLConfig{}
	}
	certs := make([]models.SSLDeployedCertificate, 0, len(cfg.GetCertificates()))
	for _, cert := range cfg.GetCertificates() {
		if cert == nil {
			continue
		}
		certs = append(certs, models.SSLDeployedCertificate{
			ID:        cert.GetId(),
			Label:     cert.GetLabel(),
			Cert:      cert.GetCert(),
			Key:       cert.GetKey(),
			IsDefault: cert.GetIsDefault(),
		})
	}
	return models.SSLConfig{DeploymentMode: models.SSLDeploymentMode(cfg.GetDeploymentMode()), Certificates: certs}
}

func sslInfoToProto(info models.SSLInfo) *pb.SslInfo {
	certs := make([]*pb.SslDeployedCertificateInfo, 0, len(info.Certificates))
	for _, cert := range info.Certificates {
		certs = append(certs, &pb.SslDeployedCertificateInfo{
			Id:        cert.ID,
			Label:     cert.Label,
			Domains:   cert.Domains,
			IsDefault: cert.IsDefault,
		})
	}
	return &pb.SslInfo{Enabled: info.Enabled, DeploymentMode: string(info.DeploymentMode), Certificates: certs}
}

func logDatesToProto(result gatewaylog.DatesResult) *pb.GatewayLogDates {
	return &pb.GatewayLogDates{Today: result.Today, LogsDir: result.LogsDir, Dates: result.Dates}
}

func logEntryToProto(entry gatewaylog.Entry) *pb.GatewayLogEntry {
	ruleIDs := make([]int32, 0, len(entry.WAFRuleIDs))
	for _, id := range entry.WAFRuleIDs {
		ruleIDs = append(ruleIDs, int32(id))
	}
	return &pb.GatewayLogEntry{
		Time:                    entry.Time,
		Level:                   entry.Level,
		Method:                  entry.Method,
		Scheme:                  entry.Scheme,
		Host:                    entry.Host,
		Path:                    entry.Path,
		Query:                   entry.Query,
		RequestUri:              entry.RequestURI,
		Protocol:                entry.Protocol,
		Status:                  int32(entry.Status),
		DurationMs:              entry.DurationMs,
		RemoteIp:                entry.RemoteIP,
		RemoteAddr:              entry.RemoteAddr,
		UserAgent:               entry.UserAgent,
		Referer:                 entry.Referer,
		LoggedIn:                entry.LoggedIn,
		AuthRequired:            entry.AuthRequired,
		AuthDecision:            entry.AuthDecision,
		AuthCredentialId:        entry.AuthCredentialID,
		AuthCredentialName:      entry.AuthCredentialName,
		AuthCredentialMethod:    entry.AuthCredentialMethod,
		AuthLinkedTotpId:        entry.AuthLinkedTOTPID,
		AuthLinkedTotpName:      entry.AuthLinkedTOTPName,
		AccessMode:              entry.AccessMode,
		RouteType:               entry.RouteType,
		RouteKey:                entry.RouteKey,
		Upstream:                entry.Upstream,
		Matched:                 entry.Matched,
		BytesIn:                 entry.BytesIn,
		BytesOut:                entry.BytesOut,
		Tls:                     entry.TLS,
		Websocket:               entry.WebSocket,
		AliRealClientIp:         entry.AliRealClientIP,
		EoConnectingIp:          entry.EOConnectingIP,
		XForwardedFor:           entry.XForwardedFor,
		XRealIp:                 entry.XRealIP,
		WafBlocked:              entry.WAFBlocked,
		WafTraceId:              entry.WAFTraceID,
		WafMode:                 entry.WAFMode,
		WafRuleIds:              ruleIDs,
		WafAction:               entry.WAFAction,
		WafBundle:               entry.WAFBundle,
		GeneralBlacklistBlocked: entry.GeneralBlacklistBlocked,
	}
}

func logQueryResultToProto(result gatewaylog.QueryResult) *pb.GatewayLogQueryResult {
	items := make([]*pb.GatewayLogEntry, 0, len(result.Items))
	for _, item := range result.Items {
		items = append(items, logEntryToProto(item))
	}
	return &pb.GatewayLogQueryResult{
		Date:           result.Date,
		LogsDir:        result.LogsDir,
		AvailableDates: result.AvailableDates,
		Pagination:     result.Pagination,
		Page:           int32(result.Page),
		Limit:          int32(result.Limit),
		Total:          int32(result.Total),
		Cursor:         result.Cursor,
		NextCursor:     result.NextCursor,
		HasMore:        result.HasMore,
		Items:          items,
	}
}

func logDeleteResultToProto(result gatewaylog.DeleteResult) *pb.GatewayLogDeleteResult {
	return &pb.GatewayLogDeleteResult{
		Date:           result.Date,
		LogsDir:        result.LogsDir,
		Deleted:        result.Deleted,
		AvailableDates: result.AvailableDates,
	}
}

func iptablesRulesToProto(rules []iptables.Rule) *pb.IptablesRules {
	items := make([]*pb.IptablesRule, 0, len(rules))
	for _, rule := range rules {
		items = append(items, &pb.IptablesRule{
			Ip:       rule.IP,
			Action:   rule.Action,
			Protocol: rule.Protocol,
			Port:     int32(rule.Port),
		})
	}
	return &pb.IptablesRules{Items: items}
}
