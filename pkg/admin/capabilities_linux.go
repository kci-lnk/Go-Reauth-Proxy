//go:build linux

package admin

func gatewayCapabilities() []string {
	capabilities := append([]string(nil), commonGatewayCapabilities...)
	return append(capabilities, "firewall.iptables")
}
