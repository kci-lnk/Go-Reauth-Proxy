package stream

import (
	"bytes"
	"io"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"go-reauth-proxy/pkg/models"
)

func TestScheduleClosedRejectsTCPBeforeAuthOrDial(t *testing.T) {
	handler := newStreamTestProxyHandler(t)
	defer handler.Close()
	manager := NewManager(handler)
	defer manager.Stop()
	manager.now = func() time.Time {
		return time.Date(2026, 1, 1, 12, 0, 0, 0, time.Local)
	}
	key := streamRuleKey{Protocol: models.StreamProtocolTCP, ListenPort: 3306}
	rule := models.StreamRule{
		Protocol: models.StreamProtocolTCP, ListenPort: key.ListenPort,
		Target: "127.0.0.1:1", UseAuth: true,
	}
	manager.rules = map[streamRuleKey]models.StreamRule{key: rule}
	manager.ruleSnapshot.Store(&streamRuleSnapshot{
		rules: manager.rules,
		availability: &models.StreamAvailability{
			Enabled: true, StartTime: "22:00", EndTime: "06:00",
		},
	})

	client, server := net.Pipe()
	done := make(chan struct{})
	go func() {
		manager.handleConn(server, key)
		close(done)
	}()
	if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buffer := make([]byte, 1)
	if _, err := client.Read(buffer); err == nil {
		t.Fatal("schedule-closed TCP connection remained open")
	}
	client.Close()
	<-done
}

func TestScheduleClosedDropsUDPBeforeCreatingSession(t *testing.T) {
	handler := newStreamTestProxyHandler(t)
	defer handler.Close()
	manager := NewManager(handler)
	manager.now = func() time.Time {
		return time.Date(2026, 1, 1, 12, 0, 0, 0, time.Local)
	}
	key := streamRuleKey{Protocol: models.StreamProtocolUDP, ListenPort: 5353}
	rule := models.StreamRule{
		Protocol: models.StreamProtocolUDP, ListenPort: key.ListenPort,
		Target: "127.0.0.1:5354", UseAuth: true,
	}
	manager.ruleSnapshot.Store(&streamRuleSnapshot{
		rules: map[streamRuleKey]models.StreamRule{key: rule},
		availability: &models.StreamAvailability{
			Enabled: true, StartTime: "22:00", EndTime: "06:00",
		},
	})
	listener := &udpListenerState{sessions: make(map[string]*udpSession)}
	packet := acquireUDPPacket(1)
	packet.payload[0] = 1
	manager.handleUDPPacket(listener, nil, nil, packet, key)
	if len(listener.sessions) != 0 {
		t.Fatalf("schedule-closed UDP created %d sessions", len(listener.sessions))
	}
}

func TestConfigSnapshotReturnsActualRuntimeRulesAndAvailability(t *testing.T) {
	handler := newStreamTestProxyHandler(t)
	defer handler.Close()
	manager := NewManager(handler)
	defer manager.Stop()
	availability := &models.StreamAvailability{
		Enabled: true, StartTime: "22:00", EndTime: "06:00",
	}
	rules := []models.StreamRule{
		{Protocol: models.StreamProtocolUDP, ListenPort: freeUDPPort(t), Target: "127.0.0.1:5354"},
		{Protocol: models.StreamProtocolTCP, ListenPort: freeTCPPort(t), Target: "127.0.0.1:3307"},
	}
	if err := manager.ReconcileConfig(rules, availability); err != nil {
		t.Fatalf("ReconcileConfig: %v", err)
	}

	gotRules, gotAvailability := manager.ConfigSnapshot()
	if len(gotRules) != 2 || gotRules[0].Protocol != models.StreamProtocolTCP || gotRules[1].Protocol != models.StreamProtocolUDP {
		t.Fatalf("snapshot rules = %#v", gotRules)
	}
	if gotAvailability == nil || gotAvailability.StartTime != "22:00" {
		t.Fatalf("snapshot availability = %#v", gotAvailability)
	}
	gotAvailability.StartTime = "00:00"
	_, currentAvailability := manager.ConfigSnapshot()
	if currentAvailability == nil || currentAvailability.StartTime != "22:00" {
		t.Fatalf("snapshot leaked mutable availability: %#v", currentAvailability)
	}
}

func TestEstablishedTCPContinuesAfterScheduleCloses(t *testing.T) {
	upstream, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("upstream Listen: %v", err)
	}
	defer upstream.Close()
	upstreamDone := make(chan struct{})
	go func() {
		defer close(upstreamDone)
		conn, acceptErr := upstream.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}()

	handler := newStreamTestProxyHandler(t)
	defer handler.Close()
	manager := NewManager(handler)
	defer manager.Stop()
	var currentTime atomic.Int64
	setTime := func(hour int) {
		currentTime.Store(time.Date(2026, 1, 1, hour, 0, 0, 0, time.Local).UnixNano())
	}
	setTime(10)
	manager.now = func() time.Time {
		return time.Unix(0, currentTime.Load()).Local()
	}
	listenPort := freeTCPPort(t)
	rule := models.StreamRule{
		Protocol:   models.StreamProtocolTCP,
		ListenPort: listenPort,
		Target:     upstream.Addr().String(),
	}
	if err := manager.ReconcileConfig([]models.StreamRule{rule}, &models.StreamAvailability{
		Enabled: true, StartTime: "09:00", EndTime: "18:00",
	}); err != nil {
		t.Fatalf("ReconcileConfig: %v", err)
	}

	client, err := net.Dial("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(listenPort)))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if err := client.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	assertEcho := func(payload []byte) {
		t.Helper()
		if _, err := client.Write(payload); err != nil {
			t.Fatalf("Write: %v", err)
		}
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(client, got); err != nil {
			t.Fatalf("ReadFull: %v", err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("echo = %q, want %q", got, payload)
		}
	}
	assertEcho([]byte("before-close"))
	setTime(19)
	assertEcho([]byte("after-close"))
	client.Close()
	upstream.Close()
	<-upstreamDone
}
