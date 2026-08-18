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
	if rule.WebsiteIconPath == "" || r.URL.Path != rule.WebsiteIconPath {
		http.NotFound(w, r)
		return true
	}
	accessEntry.RouteType = "favicon"
	accessEntry.RouteKey = rule.WebsiteIconPath
	accessEntry.Matched = true
	if event := debugProxyEvent("favicon_served", requestID); event != nil {
		event.Str("path", rule.WebsiteIconPath).Send()
	}
	response.ServeWebsiteIcon(w, r, rule.Favicon)
	return true
}
