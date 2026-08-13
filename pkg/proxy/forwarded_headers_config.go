package proxy

import (
	"go-reauth-proxy/pkg/models"
	"net/url"
	"path"
	"strings"
	"sync"
)

type forwardedHeadersConfig struct {
	mu          sync.RWMutex
	config      models.ForwardedHeadersConfig
	omitTargets map[string]struct{}
}

func newForwardedHeadersConfig(cfg models.ForwardedHeadersConfig) *forwardedHeadersConfig {
	runtime := &forwardedHeadersConfig{
		omitTargets: make(map[string]struct{}),
	}
	runtime.updateConfig(cfg)
	return runtime
}

func (c *forwardedHeadersConfig) updateConfig(cfg models.ForwardedHeadersConfig) {
	normalized, omitTargets := normalizeForwardedHeadersConfig(cfg)

	c.mu.Lock()
	c.config = normalized
	c.omitTargets = omitTargets
	c.mu.Unlock()
}

func (c *forwardedHeadersConfig) shouldOmit(target *url.URL) bool {
	if c == nil {
		return false
	}

	key, ok := forwardedHeadersTargetKeyForURL(target)
	if !ok {
		return false
	}

	return c.shouldOmitKey(key)
}

func (c *forwardedHeadersConfig) shouldOmitKey(key string) bool {
	if c == nil || key == "" {
		return false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.config.Enabled {
		return false
	}
	_, exists := c.omitTargets[key]
	return exists
}

func (c *forwardedHeadersConfig) getConfig() models.ForwardedHeadersConfig {
	if c == nil {
		return models.ForwardedHeadersConfig{
			Enabled:     false,
			OmitTargets: []string{},
			UpdatedAt:   "",
		}
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	omitTargets := make([]string, len(c.config.OmitTargets))
	copy(omitTargets, c.config.OmitTargets)

	return models.ForwardedHeadersConfig{
		Enabled:     c.config.Enabled,
		OmitTargets: omitTargets,
		UpdatedAt:   c.config.UpdatedAt,
	}
}

func normalizeForwardedHeadersConfig(cfg models.ForwardedHeadersConfig) (models.ForwardedHeadersConfig, map[string]struct{}) {
	omitTargets := make([]string, 0, len(cfg.OmitTargets))
	omitTargetSet := make(map[string]struct{}, len(cfg.OmitTargets))

	for _, rawTarget := range cfg.OmitTargets {
		normalized, ok := normalizeForwardedHeadersTarget(rawTarget)
		if !ok {
			continue
		}
		if _, exists := omitTargetSet[normalized]; exists {
			continue
		}
		omitTargetSet[normalized] = struct{}{}
		omitTargets = append(omitTargets, normalized)
	}

	return models.ForwardedHeadersConfig{
		Enabled:     cfg.Enabled,
		OmitTargets: omitTargets,
		UpdatedAt:   strings.TrimSpace(cfg.UpdatedAt),
	}, omitTargetSet
}

func normalizeForwardedHeadersTarget(rawTarget string) (string, bool) {
	parsed, err := url.Parse(strings.TrimSpace(rawTarget))
	if err != nil {
		return "", false
	}

	_, normalized, ok := normalizeForwardedHeadersTargetURL(parsed)
	return normalized, ok
}

func normalizeForwardedHeadersTargetURL(target *url.URL) (*url.URL, string, bool) {
	scheme, targetPath, key, ok := normalizedForwardedHeadersTargetParts(target)
	if !ok {
		return nil, "", false
	}

	normalized := *target
	normalized.Scheme = scheme
	normalized.User = nil
	normalized.RawQuery = ""
	normalized.Fragment = ""
	normalized.RawPath = ""
	normalized.Path = targetPath

	return &normalized, key, true
}

func forwardedHeadersTargetKeyForURL(target *url.URL) (string, bool) {
	_, _, key, ok := normalizedForwardedHeadersTargetParts(target)
	return key, ok
}

func normalizedForwardedHeadersTargetParts(target *url.URL) (string, string, string, bool) {
	if target == nil {
		return "", "", "", false
	}

	scheme := normalizeForwardedHeadersTargetScheme(target.Scheme)
	switch scheme {
	case "ws":
		scheme = "http"
	case "wss":
		scheme = "https"
	case "http", "https":
	default:
		return "", "", "", false
	}

	if strings.TrimSpace(target.Host) == "" {
		return "", "", "", false
	}

	targetPath := canonicalForwardedHeadersBasePath(target.Path)
	return scheme, targetPath, forwardedHeadersTargetKeyParts(scheme, target.Host, targetPath), true
}

func normalizeForwardedHeadersTargetScheme(scheme string) string {
	scheme = strings.TrimSpace(scheme)
	switch len(scheme) {
	case len("ws"):
		if equalFoldASCIIString(scheme, "ws") {
			return "ws"
		}
	case len("wss"):
		if equalFoldASCIIString(scheme, "wss") {
			return "wss"
		}
	case len("http"):
		if equalFoldASCIIString(scheme, "http") {
			return "http"
		}
	case len("https"):
		if equalFoldASCIIString(scheme, "https") {
			return "https"
		}
	}
	return lowerASCIIString(scheme)
}

func forwardedHeadersTargetKey(target *url.URL) string {
	if target == nil {
		return ""
	}
	return forwardedHeadersTargetKeyParts(target.Scheme, target.Host, target.EscapedPath())
}

func forwardedHeadersTargetKeyParts(scheme string, host string, targetPath string) string {
	var stack [128]byte
	buf := stack[:0]
	buf = append(buf, scheme...)
	buf = append(buf, "://"...)
	buf = append(buf, host...)
	if targetPath != "" {
		targetURL := url.URL{Path: targetPath}
		targetPath = targetURL.EscapedPath()
		buf = append(buf, targetPath...)
	}
	return string(buf)
}

func canonicalForwardedHeadersBasePath(rawPath string) string {
	rawPath = strings.TrimSpace(rawPath)
	if rawPath == "" || rawPath == "/" {
		return ""
	}

	cleaned := path.Clean(ensureLeadingSlash(rawPath))
	if cleaned == "." || cleaned == "/" {
		return ""
	}

	return cleaned
}
