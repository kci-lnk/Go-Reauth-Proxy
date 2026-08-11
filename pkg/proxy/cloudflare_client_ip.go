package proxy

import (
	"net/http"
	"net/netip"
	"strings"
)

var cloudflarePseudoIPv4Prefix = netip.MustParsePrefix("240.0.0.0/4")

// resolveManagedCloudflareClientIP resolves the visitor address on the
// dedicated loopback listener used exclusively by fn-knock-managed Cloudflare
// Tunnels. Cloudflare Pseudo IPv4 in Overwrite Headers mode replaces
// CF-Connecting-IP with a Class E address and preserves the original visitor
// IPv6 address in CF-Connecting-IPv6.
func resolveManagedCloudflareClientIP(r *http.Request) string {
	if r == nil {
		return ""
	}

	addr, ok := parseCloudflareSingleIPHeader(r.Header, "CF-Connecting-IP")
	if !ok {
		return ""
	}
	if !addr.Is4() || !cloudflarePseudoIPv4Prefix.Contains(addr) {
		return addr.String()
	}

	originalAddr, ok := parseCloudflareSingleIPHeader(r.Header, "CF-Connecting-IPv6")
	if !ok {
		return addr.String()
	}
	if !originalAddr.Is6() || !originalAddr.IsGlobalUnicast() || originalAddr.IsPrivate() {
		return addr.String()
	}

	return originalAddr.String()
}

// parseCloudflareSingleIPHeader intentionally accepts less syntax than the
// general client-address normalizer. Cloudflare documents these headers as one
// bare IP address, so host:port values, bracketed literals, zones, lists and
// duplicate field lines are malformed and must fail closed.
func parseCloudflareSingleIPHeader(header http.Header, name string) (netip.Addr, bool) {
	values := header.Values(name)
	if len(values) != 1 {
		return netip.Addr{}, false
	}

	value := strings.TrimSpace(values[0])
	addr, err := netip.ParseAddr(value)
	if err != nil || addr.Zone() != "" || addr.Is4In6() {
		return netip.Addr{}, false
	}
	return addr, true
}
