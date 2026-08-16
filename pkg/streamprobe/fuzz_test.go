package streamprobe

import "testing"

func FuzzValidateNeverPanics(f *testing.F) {
	for _, seed := range [][]byte{
		easyTierProbePayload(),
		[]byte("RFB 003.008\n"),
		[]byte("OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n"),
		{22, 3, 3, 0, 1, 1},
		{0x80, 0x60, 0, 1},
		nil,
	} {
		f.Add(seed)
	}
	services := []string{
		"easytier", "http1", "http2", "webdav", "webdav_tls", "tls", "ssh", "rfb", "rtsp", "rdp", "smb",
		"ftp", "smtp", "pop3", "imap", "ldap", "mysql", "postgresql",
		"redis", "mongodb", "mssql", "mqtt", "dns", "dhcp", "ntp", "stun",
		"sip", "quic", "dtls", "wireguard", "ssdp", "onvif", "snmp", "tftp", "rtp",
	}
	f.Fuzz(func(t *testing.T, payload []byte) {
		for _, service := range services {
			_ = Validate(service, "tcp", DirectionClient, payload)
			_ = Validate(service, "tcp", DirectionServer, payload)
			_ = Validate(service, "udp", DirectionClient, payload)
			_ = Validate(service, "udp", DirectionServer, payload)
		}
		_ = Classify("tcp", DirectionClient, payload)
		_ = Classify("tcp", DirectionServer, payload)
		_ = Classify("udp", DirectionClient, payload)
		_ = extractMetadata("onvif", payload)
		_ = extractMetadata("webdav", payload)
	})
}
