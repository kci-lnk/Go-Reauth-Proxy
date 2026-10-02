package proxy

import (
	"net/netip"

	"go-reauth-proxy/pkg/models"
)

var portalVPNPrefix = netip.MustParsePrefix("100.64.0.0/10")

// gatewayPortalForNavigation resolves navigation for this request only. It uses
// the gateway's already-resolved client IP, never forwarded headers itself.
func gatewayPortalForNavigation(portal models.GatewayPortalConfig, clientIP string) models.GatewayPortalConfig {
	portal = models.NormalizeGatewayPortalConfig(portal)
	if !portal.SmartLANDetection {
		return portal
	}
	portal.NavigationMode = models.GatewayPortalNavigationInternet
	addr, err := netip.ParseAddr(clientIP)
	if err != nil {
		return portal
	}
	addr = addr.Unmap()
	// A loopback peer may be a reverse proxy whose real client is unknown.
	if addr.IsPrivate() || portalVPNPrefix.Contains(addr) {
		portal.NavigationMode = models.GatewayPortalNavigationLAN
	}
	return portal
}
