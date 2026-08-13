package proxy

import (
	"net/url"
	"strings"

	"go-reauth-proxy/pkg/models"
)

type reverseProxyRoutePathOptions struct {
	targetURL  *url.URL
	incoming   *url.URL
	stripPath  bool
	pathPrefix string
}

func applyReverseProxyRoutePath(out *url.URL, opts reverseProxyRoutePathOptions) {
	if out == nil {
		return
	}

	targetPath := ""
	if opts.targetURL != nil {
		targetPath = opts.targetURL.Path
	}

	requestPath := "/"
	if opts.incoming != nil {
		requestPath = opts.incoming.Path
	}

	out.Path = buildReverseProxyRoutePath(targetPath, requestPath, opts.stripPath, opts.pathPrefix)
	out.RawPath = ""
}

// applyHostReverseProxyPath applies the explicit Host target path mode.
// Entry mode preserves the historical whole-origin behavior; prefix mode
// mounts every incoming path below the path in the target URL.
func applyHostReverseProxyPath(out *url.URL, targetURL *url.URL, incoming *url.URL, targetPathMode string) {
	if out == nil {
		return
	}

	targetPath := ""
	targetEscapedPath := ""
	if targetURL != nil {
		targetPath = targetURL.Path
		targetEscapedPath = targetURL.EscapedPath()
	}

	requestPath := "/"
	requestEscapedPath := "/"
	if incoming != nil {
		requestPath = incoming.Path
		requestEscapedPath = incoming.EscapedPath()
	}

	out.Path, out.RawPath = buildHostReverseProxyPathParts(
		targetPath,
		targetEscapedPath,
		requestPath,
		requestEscapedPath,
		targetPathMode,
	)
}

func buildHostReverseProxyPath(targetPath string, requestPath string, targetPathMode string) string {
	path, _ := buildHostReverseProxyPathParts(
		targetPath,
		(&url.URL{Path: targetPath}).EscapedPath(),
		requestPath,
		(&url.URL{Path: requestPath}).EscapedPath(),
		targetPathMode,
	)
	return path
}

func buildHostReverseProxyPathParts(
	targetPath string,
	targetEscapedPath string,
	requestPath string,
	requestEscapedPath string,
	targetPathMode string,
) (string, string) {
	originalRequestPath := requestPath
	requestPath = ensureLeadingSlash(requestPath)
	requestEscapedPath = ensureEscapedPathLeadingSlash(originalRequestPath, requestEscapedPath)

	var joinedPath string
	var joinedEscapedPath string
	if models.NormalizeHostTargetPathMode(targetPathMode) == models.HostTargetPathModePrefix {
		joinedPath = buildReverseProxyRoutePath(targetPath, requestPath, false, "")
		joinedEscapedPath = buildReverseProxyEscapedPath(
			targetPath,
			targetEscapedPath,
			requestPath,
			requestEscapedPath,
		)
	} else if requestPath != "/" || targetPath == "" {
		joinedPath = requestPath
		joinedEscapedPath = requestEscapedPath
	} else {
		joinedPath = ensureLeadingSlash(targetPath)
		joinedEscapedPath = ensureEscapedPathLeadingSlash(targetPath, targetEscapedPath)
	}

	return joinedPath, nonCanonicalRawPath(joinedPath, joinedEscapedPath)
}

func buildReverseProxyEscapedPath(
	targetPath string,
	targetEscapedPath string,
	requestPath string,
	requestEscapedPath string,
) string {
	if targetPath == "" {
		return requestEscapedPath
	}

	targetHasSlash := strings.HasSuffix(targetPath, "/")
	requestHasSlash := strings.HasPrefix(requestPath, "/")
	switch {
	case targetHasSlash && requestHasSlash:
		return targetEscapedPath + trimEscapedLeadingSlash(requestEscapedPath)
	case !targetHasSlash && !requestHasSlash:
		return targetEscapedPath + "/" + requestEscapedPath
	default:
		return targetEscapedPath + requestEscapedPath
	}
}

func ensureEscapedPathLeadingSlash(decodedPath string, escapedPath string) string {
	if decodedPath == "" {
		return "/"
	}
	if strings.HasPrefix(decodedPath, "/") {
		return escapedPath
	}
	return "/" + escapedPath
}

func trimEscapedLeadingSlash(escapedPath string) string {
	if strings.HasPrefix(escapedPath, "/") {
		return escapedPath[1:]
	}
	if len(escapedPath) >= 3 && strings.EqualFold(escapedPath[:3], "%2f") {
		return escapedPath[3:]
	}
	return escapedPath
}

// nonCanonicalRawPath retains an original escaping only when it is both valid
// for path and observably different from Go's canonical escaping. This keeps
// encoded slashes and exact WebDAV resource names intact without populating a
// redundant RawPath for ordinary URLs.
func nonCanonicalRawPath(path string, escapedPath string) string {
	if escapedPath == "" || escapedPath == (&url.URL{Path: path}).EscapedPath() {
		return ""
	}
	candidate := &url.URL{Path: path, RawPath: escapedPath}
	if candidate.EscapedPath() != escapedPath {
		return ""
	}
	return escapedPath
}

func buildHostReverseProxyEntryPath(targetPath string, requestPath string) string {
	requestPath = ensureLeadingSlash(requestPath)
	if requestPath != "/" || targetPath == "" {
		return requestPath
	}
	return ensureLeadingSlash(targetPath)
}

func buildReverseProxyRoutePath(targetPath string, requestPath string, stripPath bool, pathPrefix string) string {
	upstreamPath := ensureLeadingSlash(requestPath)
	if stripPath {
		upstreamPath = stripMatchedPathPrefix(upstreamPath, pathPrefix)
	}

	if targetPath == "" {
		return upstreamPath
	}
	return singleJoiningSlash(targetPath, upstreamPath)
}

func stripMatchedPathPrefix(requestPath string, pathPrefix string) string {
	requestPath = ensureLeadingSlash(requestPath)
	if pathPrefix == "" || pathPrefix == "/" {
		return requestPath
	}

	upstreamPath := requestPath
	if len(requestPath) >= len(pathPrefix) && requestPath[:len(pathPrefix)] == pathPrefix {
		upstreamPath = requestPath[len(pathPrefix):]
	}
	return ensureLeadingSlash(upstreamPath)
}
