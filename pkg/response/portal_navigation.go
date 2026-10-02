package response

import (
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"go-reauth-proxy/pkg/models"

	"golang.org/x/net/idna"
)

var portalHostnameProfile = idna.New(idna.MapForLookup(), idna.StrictDomainName(false), idna.CheckHyphens(false))

// gatewayPortalTargetHref exposes a configured target only for LAN navigation.
// Targets must be browser-navigable and must not point at the visitor's own host.
func gatewayPortalTargetHref(target string, portal models.GatewayPortalConfig) string {
	if portal.NavigationMode != models.GatewayPortalNavigationLAN {
		return ""
	}
	target = strings.TrimSpace(target)
	if target == "" || toolbarInputInvalidURL(target) {
		return ""
	}
	parsed, err := url.Parse(target)
	if err != nil || parsed.Opaque != "" || parsed.User != nil || parsed.Host == "" ||
		(parsed.Scheme != "http" && parsed.Scheme != "https") {
		return ""
	}
	port := parsed.Port()
	if port != "" {
		value, err := strconv.Atoi(port)
		if err != nil || value < 1 || value > 65535 {
			return ""
		}
	}
	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	if _, err := netip.ParseAddr(host); err != nil {
		// Browser hostnames use IDNA and permit underscores in local names.
		asciiHost, err := portalHostnameProfile.ToASCII(host)
		if err != nil {
			return ""
		}
		asciiHost = normalizeToolbarHost(asciiHost)
		if asciiHost != host {
			parsed.Host = asciiHost
			if port != "" {
				parsed.Host += ":" + port
			}
		}
		host = asciiHost
	}
	if host == "" || host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return ""
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.Zone() != "" || strings.HasPrefix(parsed.Host, "[") != addr.Is6() {
			return ""
		}
		addr = addr.Unmap()
		if addr.IsLoopback() || addr.IsUnspecified() || addr.IsLinkLocalUnicast() || addr.IsMulticast() {
			return ""
		}
	} else {
		if strings.HasPrefix(parsed.Host, "[") || !isPortalDNSHostname(host) {
			return ""
		}
		// Browsers treat numeric-ending hosts as IPv4, including shortened,
		// octal and hex forms. Accept only the canonical IPs parsed above.
		labels := strings.Split(host, ".")
		last := labels[len(labels)-1]
		if strings.Trim(last, "0123456789") == "" || strings.HasPrefix(last, "0x") {
			return ""
		}
	}
	return parsed.String()
}

func isPortalDNSHostname(host string) bool {
	if len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for _, char := range label {
			if !(char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '-' || char == '_') {
				return false
			}
		}
	}
	return true
}

func toolbarInputInvalidURL(value string) bool {
	return strings.ContainsAny(value, "\\ \t\r\n")
}

func gatewayPortalPathHref(rule models.Rule, portal models.GatewayPortalConfig) string {
	if href := gatewayPortalTargetHref(rule.Target, portal); href != "" {
		return href
	}
	if strings.HasSuffix(rule.Path, "/") {
		return rule.Path
	}
	return rule.Path + "/"
}
