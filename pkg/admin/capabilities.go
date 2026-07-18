package admin

var commonGatewayCapabilities = []string{
	"http",
	"https",
	"http2",
	"websocket",
	"tcp",
	"udp",
	"waf",
	"blacklist",
	"logs",
	"lifecycle",
	// Auth bridge capability required before the control plane can enable
	// host-scoped temporary subdomain-rule grants.
	"subdomain_rule_grant_v1",
}
