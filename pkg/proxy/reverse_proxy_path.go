package proxy

import "net/url"

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

// applyHostReverseProxyEntryPath treats a Host rule target path as the
// upstream entry point for the public root, not as a mount prefix.
//
// For example, a target of /p maps an incoming / request to /p. Requests for
// /p/assets/app.js, /login, /assets/app.js, and other non-root paths keep
// their original paths because a Host mapping proxies the whole origin.
func applyHostReverseProxyEntryPath(out *url.URL, targetURL *url.URL, incoming *url.URL) {
	if out == nil {
		return
	}

	targetPath := ""
	if targetURL != nil {
		targetPath = targetURL.Path
	}

	requestPath := "/"
	if incoming != nil {
		requestPath = incoming.Path
	}

	out.Path = buildHostReverseProxyEntryPath(targetPath, requestPath)
	out.RawPath = ""
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
