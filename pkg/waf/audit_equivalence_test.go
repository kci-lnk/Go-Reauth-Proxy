package waf

import (
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"go-reauth-proxy/pkg/models"
)

// oldIsExcludedByConfig reconstructs the pre-optimization exclusion logic so
// the new fast-path implementation can be validated against it over a corpus
// of unusual paths.
func oldIsExcludedByConfig(exclusions exclusionConfig, r *http.Request) bool {
	hasDisabledHosts := len(exclusions.disabledHosts) > 0
	hasDisabledPathPrefixes := len(exclusions.disabledPathPrefixes) > 0
	if !hasDisabledHosts && !hasDisabledPathPrefixes {
		return false
	}

	if hasDisabledHosts {
		host := normalizeHost(r.Host)
		if _, ok := exclusions.disabledHosts[host]; ok {
			return true
		}
	}

	if !hasDisabledPathPrefixes {
		return false
	}
	requestPath := filepath.ToSlash(filepath.Clean(r.URL.Path))
	if !strings.HasPrefix(requestPath, "/") {
		requestPath = "/" + requestPath
	}
	for _, prefix := range exclusions.disabledPathPrefixes {
		if prefix == "/" || requestPath == prefix || strings.HasPrefix(requestPath, strings.TrimRight(prefix, "/")+"/") {
			return true
		}
	}
	return false
}

func TestAuditExclusionEquivalenceWithLegacyImplementation(t *testing.T) {
	paths := []string{
		"", "/", "a", "a/b", "/admin", "/admin/", "/admin/dashboard",
		"/admin//x", "/a/./b", "/a/../b", "/foo.", "/foo/.", "/foo/..",
		"/.hidden", "//x", "/a\\b", "/a%2eb", "admin/users", "/internal/status",
		"/private/", "/private/x", "/other", "/a/b/c/d/../e", "C:\\foo\\bar",
		"/../", "/a/../", "/a//", "/a/b/./", "/a/.", "/a/..", "/...", "/..a",
	}
	prefixSets := [][]string{
		{"/admin"},
		{"/internal/"},
		{"/private"},
		{"/"},
		{"/a/b"},
		{"admin"},
		{"/a//b"},
		{"/foo/"},
		{"/admin", "/internal/"},
		{"/a", "/a/b", "/a/b/c"},
		{"/...", "/..a"},
	}

	for _, path := range paths {
		for _, prefixes := range prefixSets {
			cfg := models.WAFConfig{DisabledPathPrefixes: prefixes}
			// buildExclusionConfig mirrors what newRuntimeState does after
			// NormalizeConfig; use the normalized prefix list like production.
			normalized := NormalizeConfig(cfg, t.TempDir())
			exclusions := buildExclusionConfig(normalized)
			req := &http.Request{
				Host: "gateway.test",
				URL:  &url.URL{Path: path},
			}
			old := oldIsExcludedByConfig(exclusions, req)
			new := isExcludedByConfig(&exclusions, req)
			if old != new {
				t.Fatalf(
					"exclusion mismatch for path %q prefixes %v: legacy=%v new=%v",
					path, prefixes, old, new,
				)
			}
		}
	}
}
