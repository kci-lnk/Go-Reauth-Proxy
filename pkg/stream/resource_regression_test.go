package stream

import (
	"bytes"
	"errors"
	"io"
	"net"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"
)

func TestRelayBidirectionalResetUnblocksOtherDirection(t *testing.T) {
	for _, resetSide := range []string{"upstream", "client"} {
		t.Run(resetSide, func(t *testing.T) {
			client, proxyClient := tcpConnPair(t)
			proxyUpstream, upstream := tcpConnPair(t)
			defer client.Close()
			defer proxyClient.Close()
			defer proxyUpstream.Close()
			defer upstream.Close()
			done := make(chan struct{})
			go func() {
				relayBidirectional(proxyClient, proxyUpstream, nil)
				close(done)
			}()
			peer := upstream
			if resetSide == "client" {
				peer = client
			}
			if err := peer.SetLinger(0); err != nil {
				t.Fatal(err)
			}
			if err := peer.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("reset left the opposite direction blocked on its open peer")
			}
		})
	}
}

type shortWriteConn struct{ net.Conn }

func (c shortWriteConn) Write(p []byte) (int, error) { return len(p) - 1, nil }

func TestCopyStreamRejectsShortWrite(t *testing.T) {
	reader, writer := net.Pipe()
	defer reader.Close()
	defer writer.Close()
	go func() { _, _ = writer.Write([]byte("hello")); _ = writer.Close() }()
	n, err := copyStream(shortWriteConn{}, reader, nil)
	if n != 4 || !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("copy result = %d, %v", n, err)
	}
}

func TestUDPBufferBudgetFollowsPacketThroughQueueAndWrite(t *testing.T) {
	listener, session, cleanup := newUDPQueueTestSession(t)
	defer cleanup()
	budget := &udpBufferBudget{limit: udp16KPacketBufferSize}
	packet, ok := acquireUDPPacketWithBudget(udpMediumPacketBufferSize+1, budget)
	if !ok || !session.enqueue(packet) {
		t.Fatal("initial packet was rejected")
	}
	if got := budget.used.Load(); got != udp16KPacketBufferSize {
		t.Fatalf("budget = %d, want full 16 KiB pool footprint", got)
	}
	if rejected, ok := acquireUDPPacketWithBudget(1, budget); ok {
		releaseUDPPacket(rejected)
		t.Fatal("allocation exceeded shared budget")
	}
	dequeued, ok := session.dequeue()
	if !ok || listener.queuedBytes.Load() != 0 || budget.used.Load() != udp16KPacketBufferSize {
		t.Fatal("dequeue released memory budget before upstream Write completed")
	}
	releaseUDPPacket(dequeued)
	if budget.used.Load() != 0 {
		t.Fatal("packet release leaked budget")
	}
	packet, ok = acquireUDPPacketWithBudget(1, budget)
	if !ok || !session.enqueue(packet) {
		t.Fatal("released budget was not reusable")
	}
	session.close()
	session.close()
	if budget.used.Load() != 0 {
		t.Fatal("session close leaked or double released queued packet")
	}
}

func TestUDPPacketReaderPreservesDatagrams(t *testing.T) {
	upstream, proxy := udpReaderTestPair(t)
	budget := &udpBufferBudget{limit: udpLargePacketBufferSize}
	read, err := newUDPPacketReader(proxy, budget)
	if err != nil {
		t.Fatal(err)
	}
	for _, size := range []int{0, 1, 8193, 16385, 32769, 65000} {
		payload := bytes.Repeat([]byte{byte(size)}, size)
		if _, err := upstream.WriteToUDP(payload, proxy.LocalAddr().(*net.UDPAddr)); err != nil {
			t.Fatal(err)
		}
		if err := proxy.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		packet, err := read()
		if err != nil {
			releaseUDPPacket(packet)
			t.Fatal(err)
		}
		if !bytes.Equal(packet.payload, payload) {
			releaseUDPPacket(packet)
			t.Fatalf("datagram size %d was truncated or changed", size)
		}
		releaseUDPPacket(packet)
		if budget.used.Load() != 0 {
			t.Fatal("completed read retained budget")
		}
	}
}

func TestUDPPacketReaderIdleDeadlineAndCloseReleaseBudget(t *testing.T) {
	_, proxy := udpReaderTestPair(t)
	budget := &udpBufferBudget{limit: udpLargePacketBufferSize}
	read, err := newUDPPacketReader(proxy, budget)
	if err != nil {
		t.Fatal(err)
	}
	if err := proxy.SetReadDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	packet, err := read()
	releaseUDPPacket(packet)
	if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
		t.Fatalf("deadline error = %v", err)
	}
	if budget.used.Load() != 0 {
		t.Fatal("timed-out read retained buffer")
	}
	if err := proxy.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { packet, err := read(); releaseUDPPacket(packet); done <- err }()
	// Give the blocking read time to enter the netpoller, then observe its live
	// reservations. On supported platforms no 64 KiB packet should be retained.
	time.Sleep(30 * time.Millisecond)
	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		if got := budget.used.Load(); got != 0 {
			t.Errorf("idle reader retained %d bytes", got)
		}
	}
	_ = proxy.Close()
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("close error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("close did not interrupt the idle reader")
	}
	if budget.used.Load() != 0 {
		t.Fatal("closed reader retained buffer")
	}
}

func TestUDPPacketReaderBudgetExhaustion(t *testing.T) {
	_, proxy := udpReaderTestPair(t)
	budget := &udpBufferBudget{limit: 1}
	read, err := newUDPPacketReader(proxy, budget)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := read()
	releaseUDPPacket(packet)
	if !errors.Is(err, errUDPBufferBudgetExhausted) || budget.used.Load() != 0 {
		t.Fatalf("budget rejection = %v, retained %d", err, budget.used.Load())
	}
}

type udpReadBudgetFailureConn struct {
	net.Conn
	writeStarted chan struct{}
	writeOnce    sync.Once
}

func (c *udpReadBudgetFailureConn) Write(payload []byte) (int, error) {
	c.writeOnce.Do(func() { close(c.writeStarted) })
	return c.Conn.Write(payload)
}

func (c *udpReadBudgetFailureConn) Read([]byte) (int, error) {
	// Inject the same admission error after Write begins. The actual allocation
	// rejection is checked separately in TestUDPPacketReaderBudgetExhaustion.
	<-c.writeStarted
	return 0, errUDPBufferBudgetExhausted
}

func TestUDPSessionBudgetReadFailureInterruptsBlockedWrite(t *testing.T) {
	listener, session, cleanup := newUDPQueueTestSession(t)
	defer cleanup()
	writer, peer := net.Pipe()
	defer writer.Close()
	defer peer.Close()
	upstream := &udpReadBudgetFailureConn{Conn: writer, writeStarted: make(chan struct{})}
	if !session.setUpstream(upstream) {
		t.Fatal("could not set upstream")
	}
	listener.bufferBudget = &udpBufferBudget{limit: udpLargePacketBufferSize + udpSmallPacketBufferSize}
	packet, ok := acquireUDPPacketWithBudget(1, listener.bufferBudget)
	if !ok || !session.enqueue(packet) {
		t.Fatal("could not enqueue request")
	}
	done := make(chan struct{})
	go func() {
		(&Manager{}).relayUDPSession(session)
		close(done)
	}()
	// Nothing reads the peer: the request Write can only finish by cancellation.
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("reader failure left upstream Write and relay goroutine blocked")
	}
	if got := listener.bufferBudget.used.Load(); got != 0 {
		t.Fatalf("terminated session retained %d buffer bytes", got)
	}
	if !session.closed.Load() {
		t.Fatal("reader failure left the session open")
	}
}

func TestUDPPacketReaderFallbackReleasesOnClose(t *testing.T) {
	reader, peer := net.Pipe()
	defer reader.Close()
	defer peer.Close()
	budget := &udpBufferBudget{limit: udpLargePacketBufferSize}
	read, err := newUDPPacketReader(reader, budget)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		packet, err := read()
		releaseUDPPacket(packet)
		done <- err
	}()
	_ = peer.Close()
	select {
	case err := <-done:
		if !errors.Is(err, io.EOF) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("fallback reader did not finish after close")
	}
	if budget.used.Load() != 0 {
		t.Fatal("fallback reader leaked buffer budget")
	}
}

func TestUDPConfiguredIdleTimeoutAndEnvironment(t *testing.T) {
	listener := &udpListenerState{sessions: make(map[string]*udpSession), idleTimeout: time.Second}
	session := newBareUDPSession(listener, "idle")
	defer session.close()
	now := time.Now()
	session.lastActivity.Store(now.Add(-2 * time.Second).UnixNano())
	listener.sessions[session.id] = session
	listener.reapIdleSessions(now)
	select {
	case <-session.done:
	default:
		t.Fatal("configured idle timeout was ignored")
	}
	for _, test := range []struct {
		value string
		want  int64
	}{{"", 120}, {"60", 60}, {"0", 120}, {"86401", 120}, {"invalid", 120}} {
		t.Setenv("FN_KNOCK_TEST_UDP_RESOURCE", test.value)
		if got := udpResourceEnv("FN_KNOCK_TEST_UDP_RESOURCE", 120, 1, 86400); got != test.want {
			t.Fatalf("value %q = %d, want %d", test.value, got, test.want)
		}
	}
}

func udpReaderTestPair(t *testing.T) (*net.UDPConn, *net.UDPConn) {
	t.Helper()
	upstream, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = upstream.Close() })
	// Darwin's default UDP send buffer can be smaller than a valid datagram.
	if err := upstream.SetWriteBuffer(128 * 1024); err != nil {
		t.Fatal(err)
	}
	proxy, err := net.DialUDP("udp4", nil, upstream.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = proxy.Close() })
	return upstream, proxy
}

func BenchmarkUDPPacketReceive(b *testing.B) {
	for _, size := range []int{1024, 32768} {
		for _, readiness := range []bool{false, true} {
			b.Run(strconv.Itoa(size)+"/readiness="+strconv.FormatBool(readiness), func(b *testing.B) {
				upstream, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
				if err != nil {
					b.Fatal(err)
				}
				defer upstream.Close()
				if err := upstream.SetWriteBuffer(128 * 1024); err != nil {
					b.Fatal(err)
				}
				proxy, err := net.DialUDP("udp4", nil, upstream.LocalAddr().(*net.UDPAddr))
				if err != nil {
					b.Fatal(err)
				}
				defer proxy.Close()
				var conn net.Conn = proxy
				if !readiness {
					conn = &struct{ net.Conn }{proxy}
				}
				read, err := newUDPPacketReader(conn, nil)
				if err != nil {
					b.Fatal(err)
				}
				payload := make([]byte, size)
				addr := proxy.LocalAddr().(*net.UDPAddr)
				b.ReportAllocs()
				b.SetBytes(int64(size))
				b.ResetTimer()
				for b.Loop() {
					if _, err := upstream.WriteToUDP(payload, addr); err != nil {
						b.Fatal(err)
					}
					packet, err := read()
					if err != nil {
						releaseUDPPacket(packet)
						b.Fatal(err)
					}
					if len(packet.payload) != size {
						releaseUDPPacket(packet)
						b.Fatal("truncated datagram")
					}
					releaseUDPPacket(packet)
				}
			})
		}
	}
}
