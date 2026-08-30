package proxy

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"

	"go-reauth-proxy/pkg/gatewaylog"
	"go-reauth-proxy/pkg/logger"
	"go-reauth-proxy/pkg/models"
	"go-reauth-proxy/pkg/response"
	"go-reauth-proxy/pkg/staticserve"
)

func (h *Handler) staticServeProtectedPaths() []string {
	runtimeDir := ""
	if h != nil && h.configManager != nil {
		runtimeDir = h.configManager.RuntimeDir()
	}
	return staticserve.GatewayProtectedPaths(runtimeDir, os.Getenv(logger.DataDirEnv))
}

func (h *Handler) normalizeHostRuleTarget(rule *models.HostRule) error {
	if rule == nil {
		return fmt.Errorf("host rule is required")
	}
	targetType := models.NormalizeHostRuleTargetType(rule.TargetType)
	if targetType == "" {
		return fmt.Errorf("invalid host rule target type %q", rule.TargetType)
	}
	rule.TargetType = targetType
	if targetType == models.HostRuleTargetTypeProxy {
		if rule.Target == "" {
			return fmt.Errorf("cannot add host rule with empty target")
		}
		if err := h.checkSafeTarget(rule.Target); err != nil {
			return fmt.Errorf("invalid target: %v", err)
		}
		rule.StaticServe = nil
		rule.TargetPathMode = models.NormalizeHostTargetPathMode(rule.TargetPathMode)
		return nil
	}

	staticConfig, err := staticserve.NormalizeConfig(
		targetType,
		rule.StaticServe,
		h.staticServeProtectedPaths()...,
	)
	if err != nil {
		return fmt.Errorf("invalid static serve configuration: %w", err)
	}
	rule.StaticServe = staticConfig
	rule.Target = ""
	rule.TargetPathMode = models.HostTargetPathModeEntry
	rule.SuppressToolbar = true
	rule.PreserveHost = false
	return nil
}

func staticHostRouteIncarnationSignature(rule *models.HostRule) (string, bool) {
	if rule == nil {
		return "", false
	}
	targetType := models.NormalizeHostRuleTargetType(rule.TargetType)
	if targetType != models.HostRuleTargetTypeFile && targetType != models.HostRuleTargetTypeDirectory {
		return "", false
	}
	staticPath := ""
	indexFiles := ""
	listingEnabled := false
	readmeEnabled := false
	if rule.StaticServe != nil {
		staticPath = rule.StaticServe.Path
		indexFiles = strings.Join(rule.StaticServe.IndexFiles, "\x1f")
		listingEnabled = rule.StaticServe.DirectoryListing.Enabled
		readmeEnabled = rule.StaticServe.DirectoryListing.RenderReadme
	}
	return "type=" + targetType +
		"\x00path=" + staticPath +
		"\x00indexes=" + indexFiles +
		"\x00listing=" + strconv.FormatBool(listingEnabled) +
		"\x00readme=" + strconv.FormatBool(readmeEnabled), true
}

func canonicalizeRequestPathForRouting(r *http.Request, requestID string) (originalPath, originalRawPath, canonicalPath string) {
	originalPath, originalRawPath = r.URL.Path, r.URL.RawPath
	canonicalPath = path.Clean(originalPath)
	if strings.HasSuffix(originalPath, "/") && canonicalPath != "/" {
		canonicalPath += "/"
	}
	r.URL.Path = canonicalPath
	if originalPath == canonicalPath {
		return originalPath, originalRawPath, canonicalPath
	}

	// RawPath can retain pre-normalization dot segments and is used by
	// RequestURI() for auth context. Keep Rust and the rule engine canonical.
	r.URL.RawPath = ""
	if event := debugProxyEvent("path_normalized", requestID); event != nil {
		event.Str("original_path", logger.SanitizeLogString(originalPath)).
			Str("cleaned_path", logger.SanitizeLogString(canonicalPath)).
			Send()
	}
	return originalPath, originalRawPath, canonicalPath
}

func invalidStaticRequestPath(originalPath, canonicalPath, rawPath string) bool {
	if originalPath != canonicalPath {
		return true
	}
	if rawPath != "" {
		decodedPath, err := url.PathUnescape(rawPath)
		if err != nil || decodedPath != originalPath {
			return true
		}
	}
	for index := 0; index < len(rawPath); index++ {
		if rawPath[index] != '%' {
			continue
		}
		if index+2 >= len(rawPath) {
			return true
		}
		high, highOK := staticPathHexValue(rawPath[index+1])
		low, lowOK := staticPathHexValue(rawPath[index+2])
		if !highOK || !lowOK {
			return true
		}
		decoded := high<<4 | low
		if decoded == '/' || decoded == '\\' || decoded < 0x20 || decoded == 0x7f {
			return true
		}
		index += 2
	}
	return false
}

func isNonCanonicalStaticRequest(
	rule *models.HostRule,
	originalPath string,
	canonicalPath string,
	originalRawPath string,
) bool {
	if rule == nil {
		return false
	}
	targetType := models.NormalizeHostRuleTargetType(rule.TargetType)
	if targetType != models.HostRuleTargetTypeFile && targetType != models.HostRuleTargetTypeDirectory {
		return false
	}
	return invalidStaticRequestPath(originalPath, canonicalPath, originalRawPath)
}

func rejectNonCanonicalStaticRequest(
	w http.ResponseWriter,
	r *http.Request,
	rule *models.HostRule,
	accessEntry *gatewaylog.Entry,
) {
	accessEntry.RouteType = hostRuleRouteType(rule)
	accessEntry.RouteKey = rule.Host
	accessEntry.Upstream = ""
	accessEntry.Matched = true
	accessEntry.AuthDecision = "invalid_static_path"
	response.RouteNotFound(w, r, nil, false)
}

func staticPathHexValue(value byte) (byte, bool) {
	switch {
	case value >= '0' && value <= '9':
		return value - '0', true
	case value >= 'a' && value <= 'f':
		return value - 'a' + 10, true
	case value >= 'A' && value <= 'F':
		return value - 'A' + 10, true
	default:
		return 0, false
	}
}
