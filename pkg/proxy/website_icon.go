package proxy

import (
	"net/http"
	"strings"

	"go-reauth-proxy/pkg/gatewaylog"
	"go-reauth-proxy/pkg/models"
	"go-reauth-proxy/pkg/response"
)

type websiteIconAsset struct {
	favicon          string
	contentAddressed bool
	valid            bool
}

// buildWebsiteIconAssets indexes every configured HostRule icon by its opaque
// asset path. This lets an injected toolbar load all of its icons through the
// current page origin, including icons owned by sibling host mappings. Paths
// that ambiguously identify different assets are deliberately left invalid.
func buildWebsiteIconAssets(rules []models.HostRule) map[string]websiteIconAsset {
	assets := make(map[string]websiteIconAsset, len(rules))
	for i := range rules {
		path, asset := websiteIconAssetForRule(&rules[i])
		if path == "" {
			continue
		}
		if existing, ok := assets[path]; ok {
			if !existing.valid || existing.favicon != asset.favicon || existing.contentAddressed != asset.contentAddressed {
				assets[path] = websiteIconAsset{}
			}
			continue
		}
		assets[path] = asset
	}
	return assets
}

func websiteIconAssetForRule(rule *models.HostRule) (string, websiteIconAsset) {
	if rule == nil {
		return "", websiteIconAsset{}
	}
	if path := response.EffectiveWebsiteIconPath(rule.WebsiteIconPath, ""); path != "" {
		return path, websiteIconAsset{favicon: rule.Favicon, valid: true}
	}
	if path := response.EffectiveWebsiteIconPath("", rule.Favicon); path != "" {
		return path, websiteIconAsset{favicon: rule.Favicon, contentAddressed: true, valid: true}
	}
	return "", websiteIconAsset{}
}

// serveWebsiteIconRequest handles only opaque icon asset paths on configured
// HostRule origins. Similar-looking, unknown, or ambiguous paths fail closed
// instead of reaching the upstream app.
func serveWebsiteIconRequest(
	w http.ResponseWriter,
	r *http.Request,
	currentRule *models.HostRule,
	assets map[string]websiteIconAsset,
	accessEntry *gatewaylog.Entry,
	requestID string,
) bool {
	if currentRule == nil || !strings.HasPrefix(r.URL.Path, response.WebsiteIconPathPrefix) {
		return false
	}
	asset, ok := assets[r.URL.Path]
	if !ok || !asset.valid {
		http.NotFound(w, r)
		return true
	}
	accessEntry.RouteType = "favicon"
	accessEntry.RouteKey = r.URL.Path
	accessEntry.Matched = true
	if event := debugProxyEvent("favicon_served", requestID); event != nil {
		event.Str("path", r.URL.Path).Send()
	}
	if asset.contentAddressed {
		response.ServeContentAddressedWebsiteIcon(w, r, asset.favicon)
	} else {
		response.ServeWebsiteIcon(w, r, asset.favicon)
	}
	return true
}
