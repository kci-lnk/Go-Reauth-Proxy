package proxy

import (
	"net/http"
	"strings"

	"go-reauth-proxy/pkg/gatewaylog"
	"go-reauth-proxy/pkg/models"
	"go-reauth-proxy/pkg/response"
)

// serveWebsiteIconRequest handles only the per-host opaque icon asset path.
// Similar-looking paths fail closed instead of reaching the upstream app.
func serveWebsiteIconRequest(
	w http.ResponseWriter,
	r *http.Request,
	rule *models.HostRule,
	accessEntry *gatewaylog.Entry,
	requestID string,
) bool {
	if rule == nil || !strings.HasPrefix(r.URL.Path, response.WebsiteIconPathPrefix) {
		return false
	}
	configuredPath := response.EffectiveWebsiteIconPath(rule.WebsiteIconPath, "")
	iconPath := configuredPath
	if iconPath == "" {
		iconPath = response.EffectiveWebsiteIconPath("", rule.Favicon)
	}
	if iconPath == "" || r.URL.Path != iconPath {
		http.NotFound(w, r)
		return true
	}
	accessEntry.RouteType = "favicon"
	accessEntry.RouteKey = iconPath
	accessEntry.Matched = true
	if event := debugProxyEvent("favicon_served", requestID); event != nil {
		event.Str("path", iconPath).Send()
	}
	if configuredPath == "" {
		response.ServeContentAddressedWebsiteIcon(w, r, rule.Favicon)
	} else {
		response.ServeWebsiteIcon(w, r, rule.Favicon)
	}
	return true
}
