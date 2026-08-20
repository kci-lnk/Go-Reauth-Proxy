package proxy

import (
	"net/http"

	"go-reauth-proxy/pkg/models"
)

func classifyReverseProxyRouteType(requestPath string, isAuthRoute bool, matchedHostRule *models.HostRule, matchedHostLocation *models.HostLocation, matchedRule *models.Rule) string {
	switch {
	case isAuthRoute:
		return "auth_proxy"
	case requestPath == "/__select__":
		return "select"
	case requestPath == "/__wol__":
		return "wol"
	case matchedHostRule != nil && matchedHostLocation != nil:
		return "host_location"
	case matchedHostRule != nil:
		return "host_rule"
	case matchedRule != nil:
		return "path_rule"
	default:
		return "not_found"
	}
}

func wafRouteContext(r *http.Request, snapshot requestSnapshot, isAuthRoute bool, matchedHostRule *models.HostRule, matchedHostLocation *models.HostLocation, matchedRule *models.Rule) (string, string, string) {
	requestPath := ""
	if r != nil && r.URL != nil {
		requestPath = r.URL.Path
	}
	routeType := classifyReverseProxyRouteType(requestPath, isAuthRoute, matchedHostRule, matchedHostLocation, matchedRule)
	switch {
	case isAuthRoute:
		upstream := ""
		if snapshot.authConfig.AuthPort > 0 {
			upstream = localServiceBaseURL(snapshot.authConfig.AuthPort)
		}
		return routeType, requestPath, upstream
	case requestPath == "/__select__" || requestPath == "/__wol__":
		return routeType, requestPath, ""
	case matchedHostRule != nil && matchedHostLocation != nil:
		upstream := ""
		if matchedHostLocation.Action == models.HostLocationActionProxy {
			upstream = matchedHostLocation.Target
		}
		return routeType, hostLocationRouteKey(matchedHostRule, matchedHostLocation), upstream
	case matchedHostRule != nil:
		return routeType, matchedHostRule.Host, matchedHostRule.Target
	case matchedRule != nil:
		return routeType, matchedRule.Path, matchedRule.Target
	default:
		return routeType, requestPath, ""
	}
}
