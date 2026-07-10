package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go-reauth-proxy/pkg/models"
)

type protocolModeTLSProvider struct {
	certificate *tls.Certificate
	modes       map[string]string
}

func (p protocolModeTLSProvider) GetCertificate(*tls.ClientHelloInfo) *tls.Certificate {
	return p.certificate
}

func (p protocolModeTLSProvider) GetHostProtocolMode(serverName string) string {
	return p.modes[serverName]
}

func TestProxyTLSConfigSelectsALPNBySNI(t *testing.T) {
	certificate := newProtocolModeTestCertificate(t)
	provider := protocolModeTLSProvider{
		certificate: &certificate,
		modes: map[string]string{
			"h1.example.test":      models.HostProtocolModeHTTP1,
			"h2.example.test":      models.HostProtocolModeHTTP2,
			"invalid.example.test": "unexpected",
		},
	}
	serverConfig := newProxyTLSConfig(provider)

	tests := []struct {
		name       string
		serverName string
		clientALPN []string
		wantALPN   string
	}{
		{name: "default auto prefers HTTP2", serverName: "auto.example.test", clientALPN: []string{"h2", "http/1.1"}, wantALPN: "h2"},
		{name: "default auto retains HTTP1 fallback", serverName: "auto.example.test", clientALPN: []string{"http/1.1"}, wantALPN: "http/1.1"},
		{name: "explicit HTTP1", serverName: "h1.example.test", clientALPN: []string{"h2", "http/1.1"}, wantALPN: "http/1.1"},
		{name: "explicit HTTP2", serverName: "h2.example.test", clientALPN: []string{"h2", "http/1.1"}, wantALPN: "h2"},
		{name: "invalid is auto", serverName: "invalid.example.test", clientALPN: []string{"h2", "http/1.1"}, wantALPN: "h2"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := negotiateTestALPN(serverConfig, tt.serverName, tt.clientALPN)
			if err != nil {
				t.Fatalf("TLS handshake: %v", err)
			}
			if got != tt.wantALPN {
				t.Fatalf("negotiated ALPN = %q, want %q", got, tt.wantALPN)
			}
		})
	}

	if got := serverConfig.NextProtos; len(got) != 2 || got[0] != "h2" || got[1] != "http/1.1" {
		t.Fatalf("base config was mutated: NextProtos = %#v", got)
	}
}

func TestProxyTLSConfigHTTP2RejectsClientsWithoutH2ALPN(t *testing.T) {
	certificate := newProtocolModeTestCertificate(t)
	serverConfig := newProxyTLSConfig(protocolModeTLSProvider{
		certificate: &certificate,
		modes: map[string]string{
			"h2.example.test": models.HostProtocolModeHTTP2,
		},
	})

	for _, tt := range []struct {
		name       string
		clientALPN []string
	}{
		{name: "HTTP1 only", clientALPN: []string{"http/1.1"}},
		{name: "no ALPN", clientALPN: nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := negotiateTestALPN(serverConfig, "h2.example.test", tt.clientALPN); err == nil {
				t.Fatal("TLS handshake succeeded, want HTTP/2 requirement failure")
			}
		})
	}
}

func TestProxyConnTrackerRetiresOnlyAffectedSNI(t *testing.T) {
	tracker := &proxyConnTracker{}
	connA, peerA := newCloseRecordingConn(t)
	connB, peerB := newCloseRecordingConn(t)
	connActive, peerActive := newCloseRecordingConn(t)
	defer peerA.Close()
	defer peerB.Close()
	defer peerActive.Close()
	defer connB.Close()

	tracker.m.Store(connA, &trackedProxyConnState{state: http.StateIdle, serverName: "a.example.test"})
	tracker.m.Store(connB, &trackedProxyConnState{state: http.StateIdle, serverName: "b.example.test"})
	tracker.m.Store(connActive, &trackedProxyConnState{state: http.StateActive, serverName: "a.example.test"})

	tracker.retireForServerNames([]string{"A.EXAMPLE.TEST"})
	if connA.closed.Load() {
		t.Fatal("observed-idle connection was closed before a safe state transition")
	}
	if connB.closed.Load() {
		t.Fatal("unrelated SNI connection was closed")
	}
	if connActive.closed.Load() {
		t.Fatal("active affected connection was interrupted")
	}

	tracker.update(connA, http.StateActive)
	if connA.closed.Load() {
		t.Fatal("affected connection was interrupted while active")
	}
	tracker.update(connA, http.StateIdle)
	if !connA.closed.Load() {
		t.Fatal("affected idle connection was not retired after one safe reuse")
	}
	tracker.update(connActive, http.StateIdle)
	if !connActive.closed.Load() {
		t.Fatal("affected active connection was not retired after becoming idle")
	}
}

func TestProxyConnTrackerBlockingCloseDoesNotBlockRetirement(t *testing.T) {
	server, peer := net.Pipe()
	conn := &blockingCloseConn{
		Conn:         server,
		closeStarted: make(chan struct{}),
		releaseClose: make(chan struct{}),
	}
	var releaseOnce sync.Once
	release := func() {
		releaseOnce.Do(func() { close(conn.releaseClose) })
	}
	t.Cleanup(func() {
		release()
		_ = conn.Conn.Close()
		_ = peer.Close()
	})

	tracker := &proxyConnTracker{}
	tracker.m.Store(conn, &trackedProxyConnState{
		state:      http.StateActive,
		serverName: "video.example.test",
		retiring:   true,
	})

	updateDone := make(chan struct{})
	go func() {
		tracker.update(conn, http.StateIdle)
		close(updateDone)
	}()

	select {
	case <-conn.closeStarted:
	case <-time.After(2 * time.Second):
		release()
		<-updateDone
		t.Fatal("idle transition did not start closing the retired connection")
	}

	retireDone := make(chan struct{})
	go func() {
		tracker.retireForServerNames([]string{"video.example.test"})
		close(retireDone)
	}()

	retireCompletedWhileCloseBlocked := false
	select {
	case <-retireDone:
		retireCompletedWhileCloseBlocked = true
	case <-time.After(250 * time.Millisecond):
	}

	// Always unblock and join both goroutines before reporting a failure so a
	// regression in the lock boundary cannot leak test goroutines.
	release()
	select {
	case <-updateDone:
	case <-time.After(2 * time.Second):
		t.Fatal("connection update did not complete after Close was released")
	}
	select {
	case <-retireDone:
	case <-time.After(2 * time.Second):
		t.Fatal("retirement did not complete after Close was released")
	}
	if !retireCompletedWhileCloseBlocked {
		t.Fatal("retirement waited for a blocking Close while tracked.mu was held")
	}
}

func TestProxyConnTrackerCapturesTLSServerName(t *testing.T) {
	certificate := newProtocolModeTestCertificate(t)
	serverConfig := newProxyTLSConfig(protocolModeTLSProvider{certificate: &certificate})
	serverRaw, clientRaw := net.Pipe()
	defer serverRaw.Close()
	defer clientRaw.Close()
	serverTLS := tls.Server(serverRaw, serverConfig)
	clientTLS := tls.Client(clientRaw, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "Tracked.Example.Test",
		NextProtos:         []string{"http/1.1"},
	})
	serverErr := make(chan error, 1)
	go func() { serverErr <- serverTLS.Handshake() }()
	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("server handshake: %v", err)
	}

	tracker := &proxyConnTracker{}
	tracker.update(serverTLS, http.StateIdle)
	value, ok := tracker.m.Load(serverTLS)
	if !ok {
		t.Fatal("TLS connection was not tracked")
	}
	tracked := value.(*trackedProxyConnState)
	tracked.mu.Lock()
	serverName := tracked.serverName
	tracked.mu.Unlock()
	if serverName != "tracked.example.test" {
		t.Fatalf("tracked server name = %q", serverName)
	}
}

type closeRecordingConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *closeRecordingConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

func newCloseRecordingConn(t *testing.T) (*closeRecordingConn, net.Conn) {
	t.Helper()
	server, client := net.Pipe()
	return &closeRecordingConn{Conn: server}, client
}

type blockingCloseConn struct {
	net.Conn
	closeStarted     chan struct{}
	releaseClose     chan struct{}
	closeStartedOnce sync.Once
}

func (c *blockingCloseConn) Close() error {
	c.closeStartedOnce.Do(func() { close(c.closeStarted) })
	<-c.releaseClose
	return c.Conn.Close()
}

func negotiateTestALPN(serverConfig *tls.Config, serverName string, clientALPN []string) (string, error) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()
	serverTLS := tls.Server(serverConn, serverConfig)
	clientTLS := tls.Client(clientConn, &tls.Config{
		InsecureSkipVerify: true, // The test verifies ALPN selection, not PKI validation.
		ServerName:         serverName,
		NextProtos:         clientALPN,
	})

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- serverTLS.Handshake()
	}()
	clientErr := clientTLS.Handshake()
	serverHandshakeErr := <-serverErr
	if clientErr != nil {
		return "", clientErr
	}
	if serverHandshakeErr != nil {
		return "", serverHandshakeErr
	}
	return clientTLS.ConnectionState().NegotiatedProtocol, nil
}

func newProtocolModeTestCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
