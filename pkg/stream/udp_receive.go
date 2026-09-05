package stream

import "net"

type udpPacketReader func() (udpPacket, error)

func newUDPPacketReader(conn net.Conn, budget *udpBufferBudget) (udpPacketReader, error) {
	if udp, ok := conn.(*net.UDPConn); ok {
		reader, supported, err := newReadyUDPPacketReader(udp, budget)
		if supported || err != nil {
			return reader, err
		}
	}
	// Custom connections and platforms without the readiness adapter retain a
	// full datagram buffer across Read, with the same optional shared budget.
	return func() (udpPacket, error) {
		packet, ok := acquireUDPPacketWithBudget(udpLargePacketBufferSize, budget)
		if !ok {
			return udpPacket{}, errUDPBufferBudgetExhausted
		}
		n, err := conn.Read(packet.payload)
		packet.payload = packet.payload[:n]
		return packet, err
	}, nil
}
