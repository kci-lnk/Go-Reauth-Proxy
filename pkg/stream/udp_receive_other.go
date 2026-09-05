//go:build !linux && !darwin

package stream

import "net"

func newReadyUDPPacketReader(*net.UDPConn, *udpBufferBudget) (udpPacketReader, bool, error) {
	return nil, false, nil
}
