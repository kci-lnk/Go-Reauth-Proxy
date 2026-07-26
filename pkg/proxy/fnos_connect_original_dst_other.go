//go:build !linux

package proxy

import (
	"errors"
	"net"
)

func fnosConnectOriginalDestinationPort(net.Conn) (int, error) {
	return 0, errors.New("FN Connect direct ingress requires Linux SO_ORIGINAL_DST")
}
