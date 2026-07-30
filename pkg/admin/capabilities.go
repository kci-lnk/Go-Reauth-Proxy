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
	"host_rule_groups_v1",
	"compiled_visibility_ipset_v1",
	"compiled_ipset_v2",
	"compiled_whitelist_firewall_v1",
	// Auth bridge capability required before the control plane can enable
	// host-scoped temporary subdomain-rule grants.
	"subdomain_rule_grant_v1",
}
