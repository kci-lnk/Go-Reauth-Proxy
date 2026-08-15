package streamprobe

import (
	"encoding/binary"
	"testing"
)

func tlsHelloRecord(handshakeType byte) []byte {
	bodyLength := 41
	if handshakeType == 2 {
		bodyLength = 38
	}
	payload := make([]byte, 4+bodyLength)
	payload[0] = handshakeType
	payload[3] = byte(bodyLength)
	body := payload[4:]
	body[0], body[1] = 3, 3
	if handshakeType == 1 {
		body[35], body[36] = 0, 2
		body[37], body[38] = 0x13, 0x01
		body[39], body[40] = 1, 0
	} else {
		body[35], body[36], body[37] = 0x13, 0x01, 0
	}
	record := make([]byte, 5+len(payload))
	record[0], record[1], record[2] = 22, 3, 3
	binary.BigEndian.PutUint16(record[3:5], uint16(len(payload)))
	copy(record[5:], payload)
	return record
}

func TestStrongSignatureFixtures(t *testing.T) {
	t.Parallel()
	mongo := make([]byte, 16)
	binary.LittleEndian.PutUint32(mongo[:4], 16)
	binary.LittleEndian.PutUint32(mongo[12:16], 2013)
	mysql := make([]byte, 38)
	mysql[0] = 34
	mysql[4] = 0x0a
	copy(mysql[5:], []byte("8.0.0\x00"))
	dtls := make([]byte, 13+12+34)
	dtls[0], dtls[1], dtls[2] = 22, 0xfe, 0xfd
	binary.BigEndian.PutUint16(dtls[11:13], uint16(len(dtls)-13))
	dtls[13] = 1
	dtls[16] = 34
	dtls[24] = 34
	dhcp := make([]byte, 240)
	dhcp[0] = 1
	copy(dhcp[236:], []byte{0x63, 0x82, 0x53, 0x63})
	fixtures := []struct {
		service   string
		transport string
		direction string
		data      []byte
	}{
		{"rfb", "tcp", DirectionServer, []byte("RFB 003.008\n")},
		{"ssh", "tcp", DirectionServer, []byte("SSH-2.0-OpenSSH_9.9\r\n")},
		{"rtsp", "tcp", DirectionClient, []byte("OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n")},
		{"http1", "tcp", DirectionClient, []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")},
		{"webdav", "tcp", DirectionServer, []byte("HTTP/1.1 200 OK\r\nDAV: 1, 2\r\nContent-Length: 0\r\n\r\n")},
		{"webdav_tls", "tcp", DirectionClient, tlsHelloRecord(1)},
		{"http2", "tcp", DirectionClient, []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")},
		{"tls", "tcp", DirectionClient, tlsHelloRecord(1)},
		{"mysql", "tcp", DirectionServer, mysql},
		{"rdp", "tcp", DirectionClient, []byte{3, 0, 0, 7, 0, 0xe0, 0}},
		{"smb", "tcp", DirectionClient, []byte{0, 0, 0, 4, 0xfe, 'S', 'M', 'B'}},
		{"ftp", "tcp", DirectionServer, []byte("220 example FTP server\r\n")},
		{"smtp", "tcp", DirectionServer, []byte("220 mail.example ESMTP\r\n")},
		{"pop3", "tcp", DirectionServer, []byte("+OK POP3 server ready\r\n")},
		{"imap", "tcp", DirectionServer, []byte("* OK IMAP server ready\r\n")},
		{"ldap", "tcp", DirectionClient, []byte{0x30, 5, 0x02, 1, 1, 0x60, 0}},
		{"postgresql", "tcp", DirectionClient, []byte{0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f}},
		{"redis", "tcp", DirectionClient, []byte("*1\r\n$4\r\nPING\r\n")},
		{"mongodb", "tcp", DirectionClient, mongo},
		{"mssql", "tcp", DirectionClient, []byte{0x12, 0x01, 0, 8, 0, 0, 0, 0}},
		{"mqtt", "tcp", DirectionClient, []byte{0x10, 0x0c, 0, 4, 'M', 'Q', 'T', 'T', 4, 2, 0, 60, 0, 0}},
		{"dns", "udp", DirectionClient, []byte{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1}},
		{"dhcp", "udp", DirectionClient, dhcp},
		{"ntp", "udp", DirectionClient, append([]byte{0x23}, make([]byte, 47)...)},
		{"stun", "udp", DirectionClient, []byte{0, 1, 0, 0, 0x21, 0x12, 0xa4, 0x42, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}},
		{"sip", "udp", DirectionClient, []byte("OPTIONS sip:camera@example.test SIP/2.0\r\nVia: SIP/2.0/UDP host\r\n\r\n")},
		{"quic", "udp", DirectionClient, []byte{0xc0, 0, 0, 0, 1, 0, 0}},
		{"dtls", "udp", DirectionClient, dtls},
		{"wireguard", "udp", DirectionClient, append([]byte{1, 0, 0, 0}, make([]byte, 144)...)},
		{"ssdp", "udp", DirectionClient, []byte("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n\r\n")},
		{"onvif", "udp", DirectionClient, []byte(`<d:Probe xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">Probe</d:Probe>`)},
		{"snmp", "udp", DirectionClient, []byte{0x30, 6, 0x02, 0x01, 0, 0x04, 0x01, 0}},
		{"tftp", "udp", DirectionClient, []byte{0, 1, 'f', 0, 'o', 'c', 't', 'e', 't', 0}},
	}
	for _, fixture := range fixtures {
		fixture := fixture
		t.Run(fixture.service, func(t *testing.T) {
			if got := Validate(fixture.service, fixture.transport, fixture.direction, fixture.data); got != ValidationMatch {
				t.Fatalf("Validate() = %v, want match", got)
			}
		})
	}
}

func TestRTPRemainsProbable(t *testing.T) {
	t.Parallel()
	packet := []byte{0x80, 96, 0, 1, 0, 0, 0, 1, 0, 0, 0, 2}
	if got := Validate("rtp", "udp", DirectionClient, packet); got != ValidationProbable {
		t.Fatalf("Validate(rtp) = %v, want probable", got)
	}
	if got := Classify("udp", DirectionClient, packet); got.ServiceID != "rtp" || got.State != ValidationProbable {
		t.Fatalf("Classify(rtp) = %#v", got)
	}
}

func TestFragmentedRFBNeedsMore(t *testing.T) {
	t.Parallel()
	full := []byte("RFB 003.008\n")
	for split := 1; split < len(full); split++ {
		if got := Validate("rfb", "tcp", DirectionServer, full[:split]); got != ValidationNeedMore {
			t.Fatalf("split %d = %v, want need-more", split, got)
		}
	}
}

func TestSSHRequiresACompleteIdentificationLine(t *testing.T) {
	t.Parallel()
	full := []byte("SSH-2.0-OpenSSH_9.9\r\n")
	for split := 1; split < len(full); split++ {
		if got := Validate("ssh", "tcp", DirectionServer, full[:split]); got != ValidationNeedMore {
			t.Fatalf("split %d = %v, want need-more", split, got)
		}
	}
	if got := Validate("ssh", "tcp", DirectionServer, []byte("notice\r\nSSH-2.0-OpenSSH_9.9\r\n")); got != ValidationMatch {
		t.Fatalf("server pre-banner = %v, want match", got)
	}
	if got := Validate("ssh", "tcp", DirectionClient, []byte("notice\r\nSSH-2.0-client\r\n")); got != ValidationMismatch {
		t.Fatalf("client pre-banner = %v, want mismatch", got)
	}
}

func TestRTSPRequiresCompleteHeadersAndNumericCSeq(t *testing.T) {
	t.Parallel()
	if got := Validate("rtsp", "tcp", DirectionClient, []byte("OPTIONS * RTSP/1.0\r\n")); got != ValidationNeedMore {
		t.Fatalf("request line only = %v, want need-more", got)
	}
	if got := Validate("rtsp", "tcp", DirectionClient, []byte("OPTIONS * RTSP/1.0\r\nUser-Agent: test\r\n\r\n")); got != ValidationMismatch {
		t.Fatalf("missing CSeq = %v, want mismatch", got)
	}
	if got := Validate("rtsp", "tcp", DirectionServer, []byte("RTSP/1.0 200 OK\r\nCSeq: abc\r\n\r\n")); got != ValidationMismatch {
		t.Fatalf("non-numeric CSeq = %v, want mismatch", got)
	}
	if got := Validate("rtsp", "tcp", DirectionServer, []byte("RTSP/1.0 OK\r\nCSeq: 1\r\n\r\n")); got != ValidationMismatch {
		t.Fatalf("non-numeric status = %v, want mismatch", got)
	}
}

func TestMQTTRequiresACompleteValidConnectPacket(t *testing.T) {
	t.Parallel()
	valid := []byte{0x10, 0x0c, 0, 4, 'M', 'Q', 'T', 'T', 4, 2, 0, 60, 0, 0}
	for split := 1; split < len(valid); split++ {
		if got := Validate("mqtt", "tcp", DirectionClient, valid[:split]); got != ValidationNeedMore {
			t.Fatalf("split %d = %v, want need-more", split, got)
		}
	}
	if got := Validate("mqtt", "tcp", DirectionClient, []byte{0x10, 0}); got != ValidationMismatch {
		t.Fatalf("empty CONNECT = %v, want mismatch", got)
	}
	invalidFlags := append([]byte(nil), valid...)
	invalidFlags[9] = 3
	if got := Validate("mqtt", "tcp", DirectionClient, invalidFlags); got != ValidationMismatch {
		t.Fatalf("reserved connect flag = %v, want mismatch", got)
	}
}

func TestWebDAVRequiresCapabilityEvidenceDuringDetection(t *testing.T) {
	t.Parallel()
	plainHTTP := []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	if got := Validate("webdav", "tcp", DirectionServer, plainHTTP); got != ValidationMismatch {
		t.Fatalf("plain HTTP response = %v, want mismatch", got)
	}
	response := []byte("HTTP/1.1 200 OK\r\nDAV: 1, 2\r\n\r\n")
	classification := Classify("tcp", DirectionServer, response)
	if classification.ServiceID != "webdav" || classification.State != ValidationMatch {
		t.Fatalf("Classify(WebDAV) = %#v", classification)
	}
	if got := Validate("webdav", "tcp", DirectionClient, []byte("PROPFIND /files HTTP/1.1\r\nDepth: 1\r\n\r\n")); got != ValidationMatch {
		t.Fatalf("PROPFIND = %v, want match", got)
	}
	clientClassification := Classify("tcp", DirectionClient, []byte("PROPFIND /files HTTP/1.1\r\nDepth: 1\r\n\r\n"))
	if clientClassification.ServiceID != "webdav" || clientClassification.Evidence != "webdav_method" {
		t.Fatalf("client Classify(WebDAV) = %#v", clientClassification)
	}
	multiStatus := []byte("HTTP/1.1 207 Multi-Status\r\nContent-Type: application/xml\r\n\r\n<?xml version=\"1.0\"?><D:multistatus xmlns:D=\"DAV:\"></D:multistatus>")
	multiStatusClassification := Classify("tcp", DirectionServer, multiStatus)
	if multiStatusClassification.ServiceID != "webdav" || multiStatusClassification.Evidence != "webdav_multistatus" {
		t.Fatalf("207 DAV multistatus = %#v", multiStatusClassification)
	}
	if got := Validate("webdav", "tcp", DirectionClient, []byte("GET /files/a HTTP/1.1\r\nHost: files\r\n\r\n")); got != ValidationMatch {
		t.Fatalf("ordinary HTTP on verified WebDAV = %v, want carrier match", got)
	}
	malformedStatus := []byte("HTTP/1.1 READY\r\nDAV: 1, 2\r\n\r\n")
	if got := Validate("webdav", "tcp", DirectionServer, malformedStatus); got != ValidationMismatch {
		t.Fatalf("non-numeric WebDAV status = %v, want mismatch", got)
	}
}

func TestLengthFramedProtocolsWaitForTheDeclaredPayload(t *testing.T) {
	t.Parallel()
	fixtures := []struct {
		service   string
		transport string
		data      []byte
	}{
		{"tls", "tcp", []byte{22, 3, 3, 0, 4, 1, 0}},
		{"postgresql", "tcp", []byte{0, 0, 0, 12, 0, 3, 0, 0}},
		{"mongodb", "tcp", []byte{32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xdd, 7, 0, 0}},
		{"mssql", "tcp", []byte{0x12, 1, 0, 16, 0, 0, 0, 0}},
		{"rdp", "tcp", []byte{3, 0, 0, 19, 0, 0xe0, 0}},
		{"smb", "tcp", []byte{0, 0, 0, 32, 0xfe, 'S', 'M', 'B'}},
		{"dns", "tcp", []byte{0, 17, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}},
		{"stun", "udp", []byte{0, 1, 0, 4, 0x21, 0x12, 0xa4, 0x42, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}},
	}
	for _, fixture := range fixtures {
		if got := Validate(fixture.service, fixture.transport, DirectionClient, fixture.data); got != ValidationNeedMore {
			t.Errorf("%s truncated frame = %v, want need-more", fixture.service, got)
		}
	}
}

func TestTLSRequiresTheCompleteDirectionSpecificHelloAcrossRecords(t *testing.T) {
	t.Parallel()
	full := tlsHelloRecord(1)
	payload := full[5:]
	firstPayload := payload[:10]
	secondPayload := payload[10:]
	first := append([]byte{22, 3, 3, 0, byte(len(firstPayload))}, firstPayload...)
	second := make([]byte, 5+len(secondPayload))
	second[0], second[1], second[2] = 22, 3, 3
	binary.BigEndian.PutUint16(second[3:5], uint16(len(secondPayload)))
	copy(second[5:], secondPayload)
	fragmented := append(first, second...)
	if got := Validate("tls", "tcp", DirectionClient, fragmented); got != ValidationMatch {
		t.Fatalf("fragmented ClientHello = %v, want match", got)
	}
	if got := Validate("tls", "tcp", DirectionServer, fragmented); got != ValidationMismatch {
		t.Fatalf("ClientHello from server = %v, want mismatch", got)
	}
	truncated := full[:len(full)-1]
	if got := Validate("tls", "tcp", DirectionClient, truncated); got != ValidationNeedMore {
		t.Fatalf("truncated ClientHello = %v, want need-more", got)
	}
	malformed := []byte{22, 3, 3, 0, 4, 1, 0, 0, 1}
	if got := Validate("tls", "tcp", DirectionClient, malformed); got != ValidationMismatch {
		t.Fatalf("undersized ClientHello = %v, want mismatch", got)
	}
}

func TestUDPStrictMatchersValidateDirectionAndStructure(t *testing.T) {
	t.Parallel()
	if got := Validate("ntp", "udp", DirectionClient, append([]byte{0x24}, make([]byte, 47)...)); got != ValidationMismatch {
		t.Fatalf("server NTP mode from client = %v, want mismatch", got)
	}
	if got := Validate("ntp", "udp", DirectionServer, append([]byte{0x24}, make([]byte, 47)...)); got != ValidationMatch {
		t.Fatalf("server NTP response = %v, want match", got)
	}
	if got := Validate("tftp", "udp", DirectionClient, []byte{0, 1, 'f', 0}); got != ValidationMismatch {
		t.Fatalf("TFTP without mode = %v, want mismatch", got)
	}
	if got := Validate("quic", "udp", DirectionClient, []byte{0xc0, 0, 0, 0, 1, 21, 0}); got != ValidationMismatch {
		t.Fatalf("QUIC oversized CID = %v, want mismatch", got)
	}
}
