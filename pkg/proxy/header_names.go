package proxy

// Keep gateway-owned hot-path header names in the canonical form used by
// net/textproto. Passing a non-canonical literal to http.Header otherwise
// canonicalizes and allocates on every Get, Set, or Del call.
const (
	headerAccessToken       = "Accesstoken"
	headerAccessTokenDashed = "Access-Token"
	headerAliRealClientIP   = "Ali-Real-Client-Ip"
	headerEOConnectingIP    = "Eo-Connecting-Ip"
	headerXRealIP           = "X-Real-Ip"
	headerCFConnectingIP    = "Cf-Connecting-Ip"
	headerCFConnectingIPv6  = "Cf-Connecting-Ipv6"
)
