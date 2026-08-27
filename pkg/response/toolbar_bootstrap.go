package response

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

const toolbarDataPath = "/__assets__/toolbar/data"

const toolbarBootstrapScript = `(function(window, document) {
    var bootstrap = document.getElementById('reauth-proxy-toolbar-bootstrap');
    if (!bootstrap || typeof window.fetch !== 'function') return;

    var endpoint = bootstrap.getAttribute('data-endpoint') || '/__assets__/toolbar/data';
    var pagePath = window.location && window.location.pathname ? window.location.pathname : '/';
    var separator = endpoint.indexOf('?') === -1 ? '?' : '&';

    window.fetch(endpoint + separator + 'page_path=' + encodeURIComponent(pagePath), {
        method: 'GET',
        credentials: 'same-origin',
        cache: 'no-store',
		headers: {
			Accept: 'application/json',
			'X-Reauth-Toolbar-Page-Query': window.location && window.location.search ? window.location.search.slice(1) : ''
		}
    }).then(function(response) {
        if (response.status === 204) return null;
        if (!response.ok) throw new Error('toolbar data request failed');
        return response.json();
    }).then(function(payload) {
		if (!payload || typeof payload.runtime_url !== 'string' ||
			typeof payload.data !== 'object' || Array.isArray(payload.data)) return;
		if (!/^\/__assets__\/toolbar\/toolbar(?:-v2)?\.[0-9a-f]{64}\.js$/.test(payload.runtime_url)) return;
        if (document.getElementById('reauth-proxy-toolbar-loader') ||
            document.getElementById('reauth-proxy-toolbar-v2-loader')) return;

        var loader = document.createElement('script');
        loader.id = 'reauth-proxy-toolbar-loader';
        loader.src = payload.runtime_url;
        loader.setAttribute('data-toolbar', JSON.stringify(payload.data));
        loader.defer = true;
        loader.async = false;
        if (bootstrap.parentNode) bootstrap.parentNode.insertBefore(loader, bootstrap.nextSibling);
    }).catch(function() {});
})(window, document);`

var (
	toolbarBootstrapRuntime  []byte
	toolbarBootstrapAssetURL string
	toolbarBootstrapHTML     string
)

func initToolbarBootstrap() {
	toolbarBootstrapRuntime = []byte(strings.TrimSpace(toolbarBootstrapScript))
	digest := sha256.Sum256(toolbarBootstrapRuntime)
	toolbarBootstrapAssetURL = "/__assets__/toolbar/bootstrap." + hex.EncodeToString(digest[:]) + ".js"
	toolbarBootstrapHTML = `<script id="reauth-proxy-toolbar-bootstrap" src="` + toolbarBootstrapAssetURL + `" data-endpoint="` + toolbarDataPath + `" defer></script>`
}

// ToolbarBootstrapAssetPath returns the content-addressed bootstrap URL used
// by cacheable proxied HTML documents.
func ToolbarBootstrapAssetPath() string {
	return toolbarBootstrapAssetURL
}

// ToolbarDataPath returns the exact reserved endpoint used for fresh toolbar
// configuration data.
func ToolbarDataPath() string {
	return toolbarDataPath
}

// IsToolbarDataPath reports whether requestPath names the dynamic data
// endpoint. The endpoint is intentionally separate from immutable assets.
func IsToolbarDataPath(requestPath string) bool {
	return requestPath == toolbarDataPath
}

// GenerateToolbarBootstrap returns the static loader injected into proxied
// HTML. It contains no route, identity, locale, or portal configuration data.
func GenerateToolbarBootstrap() string {
	return toolbarBootstrapHTML
}
