//go:build !linux

package admin

func gatewayCapabilities() []string {
	return append([]string(nil), commonGatewayCapabilities...)
}
