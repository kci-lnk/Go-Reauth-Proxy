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
