//go:build linux || darwin

package stream

import (
	"net"

	"golang.org/x/sys/unix"
)

func newReadyUDPPacketReader(conn *net.UDPConn, budget *udpBufferBudget) (udpPacketReader, bool, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return nil, true, err
	}
	// Each session has one reader. Reuse its callback and output slots so
	// RawConn's escaping callback does not allocate for every received packet.
	var packet udpPacket
	var recvErr error
	receive := func(fd uintptr) bool {
		var ok bool
		packet, ok = acquireUDPPacketWithBudget(udpLargePacketBufferSize, budget)
		if !ok {
			recvErr = errUDPBufferBudgetExhausted
			return true
		}
		for {
			// net.UDPConn owns a nonblocking socket. Read also avoids
			// allocating a peer address for this already-connected socket.
			n, err := unix.Read(int(fd), packet.payload)
			if err == unix.EINTR {
				continue
			}
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
				// Return the buffer before handing the socket back to Go's
				// netpoller. Idle sessions now retain no receive buffer.
				releaseUDPPacket(packet)
				packet = udpPacket{}
				return false
			}
			recvErr = err
			packet.payload = packet.payload[:max(n, 0)]
			return true
		}
	}
	return func() (udpPacket, error) {
		recvErr = nil
		err := raw.Read(receive)
		result := packet
		packet = udpPacket{}
		if err != nil {
			return result, err
		}
		return result, recvErr
	}, true, nil
}
