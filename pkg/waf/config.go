package waf

import (
	"path/filepath"
	"strings"

	"go-reauth-proxy/pkg/models"
)

const (
	defaultParanoiaLevel          = 1
	defaultInboundThreshold       = 5
	defaultOutboundThreshold      = 4
	defaultRequestBodyLimit       = 131072
	defaultRequestBodyMemoryLimit = 65536
)

func DefaultRulesDir(runtimeDir string) string {
	runtimeDir = strings.TrimSpace(runtimeDir)
	if runtimeDir == "" {
		runtimeDir = "."
	}
	return filepath.Join(runtimeDir, "waf")
}

func NormalizeConfig(cfg models.WAFConfig, defaultRulesDir string) models.WAFConfig {
	defaulted := strings.TrimSpace(cfg.Mode) == ""
	cfg.Mode = strings.ToLower(strings.TrimSpace(cfg.Mode))
	switch cfg.Mode {
	case ModeOff, ModeDetection, ModeBlocking:
	default:
		cfg.Mode = ModeBlocking
	}

	cfg.RulesDir = strings.TrimSpace(cfg.RulesDir)
	if cfg.RulesDir == "" {
		cfg.RulesDir = defaultRulesDir
	}
	if cfg.RulesDir == "" {
		cfg.RulesDir = DefaultRulesDir(".")
	}
	if !filepath.IsAbs(cfg.RulesDir) {
		cfg.RulesDir = filepath.Clean(cfg.RulesDir)
	}

	cfg.ActiveBundleID = strings.TrimSpace(cfg.ActiveBundleID)
	if cfg.ParanoiaLevel < 1 || cfg.ParanoiaLevel > 4 {
		cfg.ParanoiaLevel = defaultParanoiaLevel
	}
	if cfg.ExecutingParanoiaLevel < 1 || cfg.ExecutingParanoiaLevel > 4 {
		cfg.ExecutingParanoiaLevel = cfg.ParanoiaLevel
	}
	if cfg.ExecutingParanoiaLevel < cfg.ParanoiaLevel {
		cfg.ExecutingParanoiaLevel = cfg.ParanoiaLevel
	}
	if cfg.InboundAnomalyThreshold <= 0 {
		cfg.InboundAnomalyThreshold = defaultInboundThreshold
	}
	if cfg.OutboundAnomalyThreshold <= 0 {
		cfg.OutboundAnomalyThreshold = defaultOutboundThreshold
	}
	if defaulted {
		cfg.RequestBodyAccess = true
	}
	if cfg.RequestBodyLimitBytes <= 0 {
		cfg.RequestBodyLimitBytes = defaultRequestBodyLimit
	}
	if cfg.RequestBodyInMemoryLimitBytes <= 0 {
		cfg.RequestBodyInMemoryLimitBytes = defaultRequestBodyMemoryLimit
	}
	if cfg.RequestBodyInMemoryLimitBytes > cfg.RequestBodyLimitBytes {
		cfg.RequestBodyInMemoryLimitBytes = cfg.RequestBodyLimitBytes
	}
	cfg.ResponseBodyAccess = false
	cfg.DisabledHosts = normalizeStringList(cfg.DisabledHosts, true)
	cfg.DisabledPathPrefixes = normalizePathPrefixes(cfg.DisabledPathPrefixes)
	cfg.UpdatedAt = strings.TrimSpace(cfg.UpdatedAt)
	return cfg
}

func CopyConfig(cfg models.WAFConfig) models.WAFConfig {
	cfg.DisabledHosts = append([]string(nil), cfg.DisabledHosts...)
	cfg.DisabledPathPrefixes = append([]string(nil), cfg.DisabledPathPrefixes...)
	return cfg
}

func IsActive(cfg models.WAFConfig) bool {
	return cfg.Enabled && cfg.Mode != ModeOff
}

func normalizeStringList(values []string, lower bool) []string {
	if len(values) == 0 {
		return []string{}
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if lower {
			value = strings.ToLower(value)
		}
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func normalizePathPrefixes(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if !strings.HasPrefix(value, "/") {
			value = "/" + value
		}
		value = filepath.ToSlash(filepath.Clean(value))
		if value == "." {
			value = "/"
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
