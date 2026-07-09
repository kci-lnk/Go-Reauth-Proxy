package stream

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"go-reauth-proxy/pkg/diagnostics"
	"go-reauth-proxy/pkg/models"
)

func TestUDPPacketBufferPoolsUseSizeClasses(t *testing.T) {
	tests := []struct {
		size      int
		wantClass int
	}{
		{size: 1, wantClass: udpSmallPacketBufferSize},
		{size: udpSmallPacketBufferSize, wantClass: udpSmallPacketBufferSize},
		{size: udpSmallPacketBufferSize + 1, wantClass: udpMediumPacketBufferSize},
		{size: udpMediumPacketBufferSize + 1, wantClass: udpLargePacketBufferSize},
	}

	for _, tt := range tests {
		packet := acquireUDPPacket(tt.size)
		if len(packet.payload) != tt.size || packet.poolClass != tt.wantClass || cap(packet.payload) != tt.wantClass {
			t.Fatalf("acquireUDPPacket(%d) = len %d cap %d class %d", tt.size, len(packet.payload), cap(packet.payload), packet.poolClass)
		}
		releaseUDPPacket(packet)
	}
}

func TestUDPSessionQueuePreservesOrderAndLimitsPackets(t *testing.T) {
	diagnostics.SetEnabled(true)
	t.Cleanup(func() { diagnostics.SetEnabled(false) })
	listener, session, cleanup := newUDPQueueTestSession(t)
	defer cleanup()
	dropsBefore := diagnosticUDPQueueDrops(t)

	for i := 0; i < udpSessionQueuePacketLimit; i++ {
		packet := acquireUDPPacket(1)
		packet.payload[0] = byte(i)
		if !session.enqueue(packet) {
			t.Fatalf("enqueue packet %d failed", i)
		}
	}
	if got, want := listener.queuedBytes.Load(), int64(udpSessionQueuePacketLimit*udpSmallPacketBufferSize); got != want {
		t.Fatalf("listener queued footprint = %d, want %d", got, want)
	}
	overflow := acquireUDPPacket(1)
	if session.enqueue(overflow) {
		t.Fatal("queue accepted packet beyond packet limit")
	}
	listener.dropPacket(overflow)
	if got := listener.droppedPackets.Load(); got != 1 {
		t.Fatalf("dropped packets = %d, want 1", got)
	}
	if got := diagnosticUDPQueueDrops(t); got != dropsBefore+1 {
		t.Fatalf("diagnostic UDP queue drops = %d, want %d", got, dropsBefore+1)
	}

	for i := 0; i < udpSessionQueuePacketLimit; i++ {
		packet, ok := session.dequeue()
		if !ok {
			t.Fatalf("dequeue packet %d failed", i)
		}
		if packet.payload[0] != byte(i) {
			t.Fatalf("packet %d payload = %d", i, packet.payload[0])
		}
		releaseUDPPacket(packet)
	}
	if got := listener.queuedBytes.Load(); got != 0 {
		t.Fatalf("listener queued bytes = %d", got)
	}
}

func TestUDPSessionQueueLimitsBytes(t *testing.T) {
	listener, session, cleanup := newUDPQueueTestSession(t)
	defer cleanup()

	for i := 0; i < udpSessionQueueByteLimit/udpLargePacketBufferSize; i++ {
		packet := acquireUDPPacket(udpLargePacketBufferSize)
		if !session.enqueue(packet) {
			t.Fatalf("enqueue packet %d failed", i)
		}
	}
	overflow := acquireUDPPacket(1)
	if session.enqueue(overflow) {
		t.Fatal("queue accepted packet beyond byte limit")
	}
	listener.dropPacket(overflow)
	if got := listener.queuedBytes.Load(); got != udpSessionQueueByteLimit {
		t.Fatalf("listener queued bytes = %d, want %d", got, udpSessionQueueByteLimit)
	}
}

func TestUDPIdleReaperClosesOnlyExpiredSessions(t *testing.T) {
	listener := &udpListenerState{sessions: make(map[string]*udpSession)}
	idle := newBareUDPSession(listener, "idle")
	active := newBareUDPSession(listener, "active")
	now := time.Now()
	idle.lastActivity.Store(now.Add(-udpSessionIdleTimeout - time.Second).UnixNano())
	active.lastActivity.Store(now.Add(-udpSessionIdleTimeout + time.Second).UnixNano())
	listener.sessions[idle.id] = idle
	listener.sessions[active.id] = active

	listener.reapIdleSessions(now)
	select {
	case <-idle.done:
	default:
		t.Fatal("idle session was not closed")
	}
	select {
	case <-active.done:
		t.Fatal("active session was closed")
	default:
	}
	active.close()
}

func TestUDPIdleCloseRechecksActivityUnderQueueLock(t *testing.T) {
	listener := &udpListenerState{}
	session := newBareUDPSession(listener, "reactivated")
	now := time.Now()
	session.lastActivity.Store(now.Add(-udpSessionIdleTimeout - time.Second).UnixNano())

	session.queueMu.Lock()
	done := make(chan struct{})
	go func() {
		session.closeIfIdle(now.Add(-udpSessionIdleTimeout).UnixNano())
		close(done)
	}()
	session.lastActivity.Store(now.UnixNano())
	session.queueMu.Unlock()
	<-done
	select {
	case <-session.done:
		t.Fatal("reactivated session was closed")
	default:
	}
	session.close()
}

func TestUDPNewSessionAdmissionIsBoundedByInitSlots(t *testing.T) {
	listener := &udpListenerState{
		initSlots: make(chan struct{}, 1),
		sessions:  make(map[string]*udpSession),
	}
	packetConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer packetConn.Close()
	rule := models.StreamRule{Protocol: models.StreamProtocolUDP, ListenPort: 5353, Target: "127.0.0.1:9"}
	first, loaded, ok := listener.getOrCreateSession(packetConn, &net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: 10001}, rule)
	if !ok || loaded || first == nil {
		t.Fatalf("first admission = session %v loaded %v ok %v", first, loaded, ok)
	}
	if second, _, ok := listener.getOrCreateSession(packetConn, &net.UDPAddr{IP: net.ParseIP("127.0.0.3"), Port: 10002}, rule); ok || second != nil {
		t.Fatalf("second session bypassed full init admission: %v", second)
	}
	if got := len(listener.sessions); got != 1 {
		t.Fatalf("sessions = %d, want 1", got)
	}
	first.close()
	listener.removeSession(first.id, first)
	first.releaseInitReservation()
}

func TestUDPListenerSessionAdmissionHasHardLimit(t *testing.T) {
	listener := &udpListenerState{
		initSlots: make(chan struct{}, udpSessionInitLimit),
		sessions:  make(map[string]*udpSession, udpListenerSessionLimit),
	}
	for i := 0; i < udpListenerSessionLimit; i++ {
		id := strconv.Itoa(i)
		listener.sessions[id] = &udpSession{id: id}
	}
	packetConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer packetConn.Close()
	rule := models.StreamRule{Protocol: models.StreamProtocolUDP, ListenPort: 5353, Target: "127.0.0.1:9"}
	session, _, ok := listener.getOrCreateSession(packetConn, &net.UDPAddr{IP: net.ParseIP("127.0.0.4"), Port: 10003}, rule)
	if ok || session != nil {
		t.Fatalf("session admission exceeded hard limit: %v", session)
	}
	if got := len(listener.initSlots); got != 0 {
		t.Fatalf("rejected session consumed %d init slots", got)
	}
}

func TestUDPHandlePacketDoesNotBlockOnInitializationLimit(t *testing.T) {
	handler := newStreamTestProxyHandler(t)
	defer handler.Close()
	manager := NewManager(handler)
	key := streamRuleKey{Protocol: models.StreamProtocolUDP, ListenPort: 5353}
	rule := models.StreamRule{Protocol: models.StreamProtocolUDP, ListenPort: key.ListenPort, Target: "127.0.0.1:9"}
	manager.rules = map[streamRuleKey]models.StreamRule{key: rule}
	manager.ruleSnapshot.Store(&streamRuleSnapshot{rules: manager.rules})

	listener := &udpListenerState{
		key:       key,
		stop:      make(chan struct{}),
		initSlots: make(chan struct{}, udpSessionInitLimit),
		sessions:  make(map[string]*udpSession),
	}
	for i := 0; i < udpSessionInitLimit; i++ {
		listener.initSlots <- struct{}{}
	}
	packetConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer packetConn.Close()
	clientAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: 12345}

	started := time.Now()
	for i := 0; i < udpSessionQueuePacketLimit+1; i++ {
		packet := acquireUDPPacket(1)
		packet.payload[0] = byte(i)
		manager.handleUDPPacket(listener, packetConn, clientAddr, packet, key)
	}
	if elapsed := time.Since(started); elapsed > 50*time.Millisecond {
		t.Fatalf("packet handling blocked for %v", elapsed)
	}
	if got, want := listener.droppedPackets.Load(), uint64(udpSessionQueuePacketLimit+1); got != want {
		t.Fatalf("dropped packets = %d, want %d", got, want)
	}
	if got := len(listener.sessions); got != 0 {
		t.Fatalf("waiting initialization sessions = %d, want 0", got)
	}
	listener.close()
}

func TestUDPProxyRoundTrip(t *testing.T) {
	upstream, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("upstream ListenPacket: %v", err)
	}
	defer upstream.Close()
	upstreamDone := make(chan struct{})
	go func() {
		defer close(upstreamDone)
		buffer := make([]byte, 64*1024)
		for {
			n, addr, readErr := upstream.ReadFrom(buffer)
			if readErr != nil {
				return
			}
			if _, writeErr := upstream.WriteTo(buffer[:n], addr); writeErr != nil {
				return
			}
		}
	}()

	handler := newStreamTestProxyHandler(t)
	defer handler.Close()
	manager := NewManager(handler)
	defer manager.Stop()
	listenPort := freeUDPPort(t)
	rule := models.StreamRule{
		Protocol:   models.StreamProtocolUDP,
		ListenPort: listenPort,
		Target:     upstream.LocalAddr().String(),
	}
	if err := manager.Reconcile([]models.StreamRule{rule}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	client, err := net.Dial("udp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(listenPort)))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()
	if err := client.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	for i := byte(0); i < 10; i++ {
		payload := []byte{i, i + 1, i + 2}
		if _, err := client.Write(payload); err != nil {
			t.Fatalf("Write packet %d: %v", i, err)
		}
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(client, got); err != nil {
			t.Fatalf("Read packet %d: %v", i, err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("packet %d = %v, want %v", i, got, payload)
		}
	}

	upstream.Close()
	<-upstreamDone
}

func TestRelayBidirectionalPreservesHalfClose(t *testing.T) {
	clientPeer, proxyClient := tcpConnPair(t)
	proxyUpstream, upstreamPeer := tcpConnPair(t)
	defer clientPeer.Close()
	defer proxyClient.Close()
	defer proxyUpstream.Close()
	defer upstreamPeer.Close()

	type result struct {
		bytesIn  uint64
		bytesOut uint64
		err      error
	}
	done := make(chan result, 1)
	go func() {
		bytesIn, bytesOut, err := relayBidirectional(proxyClient, proxyUpstream)
		done <- result{bytesIn: bytesIn, bytesOut: bytesOut, err: err}
	}()

	request := []byte("client request")
	response := []byte("upstream response")
	if _, err := clientPeer.Write(request); err != nil {
		t.Fatalf("client write: %v", err)
	}
	if err := clientPeer.CloseWrite(); err != nil {
		t.Fatalf("client CloseWrite: %v", err)
	}
	gotRequest, err := io.ReadAll(upstreamPeer)
	if err != nil {
		t.Fatalf("upstream read: %v", err)
	}
	if !bytes.Equal(gotRequest, request) {
		t.Fatalf("upstream got %q, want %q", gotRequest, request)
	}
	if _, err := upstreamPeer.Write(response); err != nil {
		t.Fatalf("upstream write: %v", err)
	}
	if err := upstreamPeer.CloseWrite(); err != nil {
		t.Fatalf("upstream CloseWrite: %v", err)
	}
	gotResponse, err := io.ReadAll(clientPeer)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if !bytes.Equal(gotResponse, response) {
		t.Fatalf("client got %q, want %q", gotResponse, response)
	}

	select {
	case got := <-done:
		if got.err != nil || got.bytesIn != uint64(len(request)) || got.bytesOut != uint64(len(response)) {
			t.Fatalf("relay result = %#v", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("relay did not finish after both half-closes")
	}
}

func BenchmarkRelayBidirectional(b *testing.B) {
	request := bytes.Repeat([]byte{'i'}, 64*1024)
	response := bytes.Repeat([]byte{'o'}, 64*1024)
	readBuffer := make([]byte, 64*1024)
	b.ReportAllocs()
	b.SetBytes(int64(len(request) + len(response)))
	for b.Loop() {
		clientPeer, proxyClient := benchmarkTCPConnPair(b)
		proxyUpstream, upstreamPeer := benchmarkTCPConnPair(b)
		done := make(chan relayResult, 1)
		go func() {
			bytesIn, bytesOut, err := relayBidirectional(proxyClient, proxyUpstream)
			done <- relayResult{bytes: bytesIn + bytesOut, err: err}
		}()

		if _, err := clientPeer.Write(request); err != nil {
			b.Fatal(err)
		}
		if err := clientPeer.CloseWrite(); err != nil {
			b.Fatal(err)
		}
		if _, err := io.ReadFull(upstreamPeer, readBuffer); err != nil {
			b.Fatal(err)
		}
		if _, err := upstreamPeer.Write(response); err != nil {
			b.Fatal(err)
		}
		if err := upstreamPeer.CloseWrite(); err != nil {
			b.Fatal(err)
		}
		if _, err := io.ReadFull(clientPeer, readBuffer); err != nil {
			b.Fatal(err)
		}
		result := <-done
		if result.err != nil || result.bytes != uint64(len(request)+len(response)) {
			b.Fatalf("relay result = %#v", result)
		}
		clientPeer.Close()
		proxyClient.Close()
		proxyUpstream.Close()
		upstreamPeer.Close()
	}
}

func BenchmarkUDPSessionQueue(b *testing.B) {
	_, session, cleanup := newUDPQueueBenchmarkSession()
	defer cleanup()
	payload := bytes.Repeat([]byte{'x'}, 1400)
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	for b.Loop() {
		packet := acquireUDPPacket(len(payload))
		copy(packet.payload, payload)
		if !session.enqueue(packet) {
			b.Fatal("enqueue failed")
		}
		packet, ok := session.dequeue()
		if !ok {
			b.Fatal("dequeue failed")
		}
		releaseUDPPacket(packet)
	}
}

func newUDPQueueTestSession(t *testing.T) (*udpListenerState, *udpSession, func()) {
	t.Helper()
	listener, session, cleanup := newUDPQueueBenchmarkSession()
	return listener, session, cleanup
}

func newUDPQueueBenchmarkSession() (*udpListenerState, *udpSession, func()) {
	listener := &udpListenerState{stop: make(chan struct{}), sessions: make(map[string]*udpSession)}
	session := newBareUDPSession(listener, "test")
	cleanup := func() { session.close() }
	return listener, session, cleanup
}

func newBareUDPSession(listener *udpListenerState, id string) *udpSession {
	ctx, cancel := context.WithCancel(context.Background())
	session := &udpSession{
		id:       id,
		listener: listener,
		ctx:      ctx,
		cancel:   cancel,
		done:     make(chan struct{}),
		notify:   make(chan struct{}, 1),
		entry:    newStreamEntry(streamRuleKey{Protocol: models.StreamProtocolUDP}, "", ""),
	}
	session.status.Store(int64(http.StatusOK))
	return session
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).Port
}

func tcpConnPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	dialed, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		listener.Close()
		t.Fatalf("DialTCP: %v", err)
	}
	accepted, err := listener.AcceptTCP()
	listener.Close()
	if err != nil {
		dialed.Close()
		t.Fatalf("AcceptTCP: %v", err)
	}
	return dialed, accepted
}

func benchmarkTCPConnPair(b *testing.B) (*net.TCPConn, *net.TCPConn) {
	b.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		b.Fatal(err)
	}
	dialed, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		listener.Close()
		b.Fatal(err)
	}
	accepted, err := listener.AcceptTCP()
	listener.Close()
	if err != nil {
		dialed.Close()
		b.Fatal(err)
	}
	return dialed, accepted
}

func diagnosticUDPQueueDrops(t *testing.T) uint64 {
	t.Helper()
	recorder := httptest.NewRecorder()
	diagnostics.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/debug/metrics", nil))
	var payload struct {
		UDP struct {
			QueueDrops uint64 `json:"queue_drops"`
		} `json:"udp"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode diagnostics: %v", err)
	}
	return payload.UDP.QueueDrops
}
