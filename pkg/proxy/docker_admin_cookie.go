package proxy

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"path"
	"strings"
)

const (
	dockerAdminPanelSessionCookieName = "fn-knock-admin-panel-session"
	dockerAdminPanelScopedCookieInfix = "-p-"
)

func normalizeDockerAdminPanelCookiePath(value string) string {
	normalized := strings.TrimSpace(value)
	if normalized == "" || normalized == "/" {
		return "/"
	}
	if !strings.HasPrefix(normalized, "/") {
		normalized = "/" + normalized
	}
	normalized = path.Clean(normalized)
	if normalized == "." || normalized == "" {
		return "/"
	}
	return normalized
}

func dockerAdminPanelExternalCookieName(proxyPath string) string {
	normalizedPath := normalizeDockerAdminPanelCookiePath(proxyPath)
	if normalizedPath == "/" {
		return dockerAdminPanelSessionCookieName
	}
	digest := sha256.Sum256([]byte(normalizedPath))
	return fmt.Sprintf(
		"%s%s%x",
		dockerAdminPanelSessionCookieName,
		dockerAdminPanelScopedCookieInfix,
		digest[:6],
	)
}

func isDockerAdminPanelCookieFamily(name string) bool {
	return name == dockerAdminPanelSessionCookieName ||
		strings.HasPrefix(
			name,
			dockerAdminPanelSessionCookieName+dockerAdminPanelScopedCookieInfix,
		)
}

// scopeDockerAdminPanelRequestCookie virtualizes the panel cookie for a public
// path rule. The upstream always sees the canonical cookie name, while cookies
// belonging to other public paths (and the legacy root cookie) are never sent.
func scopeDockerAdminPanelRequestCookie(req *http.Request, proxyPath string) {
	if req == nil || req.Header == nil {
		return
	}
	values, exists := advancedAuthHeaderValues(req.Header, "Cookie")
	if !exists {
		return
	}

	externalName := dockerAdminPanelExternalCookieName(proxyPath)
	foundFamily := false
	selectedFound := false
	selectedValue := ""
	preservedHeaders := make([]string, 0, len(values))
	for _, value := range values {
		parts := splitDockerAdminRawCookieSegments(value)
		preservedParts := make([]string, 0, len(parts))
		for _, part := range parts {
			name, cookieValue, hasValue := strings.Cut(strings.TrimSpace(part), "=")
			cookieName := strings.TrimSpace(name)
			if !hasValue || !isDockerAdminPanelCookieFamily(cookieName) {
				preservedParts = append(preservedParts, part)
				continue
			}

			foundFamily = true
			if cookieName == externalName && !selectedFound {
				selectedFound = true
				selectedValue = strings.TrimSpace(cookieValue)
			}
		}
		if len(preservedParts) > 0 {
			preservedHeaders = append(preservedHeaders, strings.Join(preservedParts, ";"))
		}
	}
	if !foundFamily {
		return
	}

	for key := range req.Header {
		if strings.EqualFold(key, "Cookie") {
			delete(req.Header, key)
		}
	}
	for _, value := range preservedHeaders {
		req.Header.Add("Cookie", value)
	}
	if selectedFound && selectedValue != "" {
		req.Header.Add("Cookie", dockerAdminPanelSessionCookieName+"="+selectedValue)
	}
}

func splitDockerAdminRawCookieSegments(value string) []string {
	segments := make([]string, 0, strings.Count(value, ";")+1)
	start := 0
	quoted := false
	escaped := false
	for index := 0; index < len(value); index++ {
		character := value[index]
		if escaped {
			escaped = false
			continue
		}
		if quoted && character == '\\' {
			escaped = true
			continue
		}
		if character == '"' {
			quoted = !quoted
			continue
		}
		if character == ';' && !quoted {
			segments = append(segments, value[start:index])
			start = index + 1
		}
	}
	return append(segments, value[start:])
}

// scopeDockerAdminPanelResponseCookie maps only the fn-knock Docker panel
// session cookie back to the public path. All unrelated upstream cookies retain
// their original serialization and attributes.
func scopeDockerAdminPanelResponseCookie(resp *http.Response, proxyPath string) {
	if resp == nil || resp.Header == nil {
		return
	}
	values := resp.Header.Values("Set-Cookie")
	if len(values) == 0 {
		return
	}

	externalName := dockerAdminPanelExternalCookieName(proxyPath)
	externalPath := normalizeDockerAdminPanelCookiePath(proxyPath)
	resp.Header.Del("Set-Cookie")
	for _, value := range values {
		cookie, err := http.ParseSetCookie(value)
		if err != nil || cookie.Name != dockerAdminPanelSessionCookieName {
			resp.Header.Add("Set-Cookie", value)
			continue
		}
		cookie.Name = externalName
		cookie.Path = externalPath
		resp.Header.Add("Set-Cookie", cookie.String())
	}
}
