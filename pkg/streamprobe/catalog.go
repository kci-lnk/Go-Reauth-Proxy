package streamprobe

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"go-reauth-proxy/pkg/models"
)

// Bump this whenever probe or inline-classification semantics change so stored
// profiles retain an auditable link to the signature set that produced them.
const ClassifierVersion = "stream-signatures-v3"

const (
	DirectionClient = "client"
	DirectionServer = "server"
)

type serviceDefinition struct {
	descriptor models.StreamServiceDescriptor
	direction  string
	role       string
}

var serviceDefinitions = []serviceDefinition{
	{models.StreamServiceDescriptor{ServiceID: "http1", DisplayName: "HTTP/1.x", ServiceFamily: "web", Transports: []string{"tcp"}, ActiveProbeSupported: true, StrictCapable: true}, DirectionClient, "web_service"},
	{models.StreamServiceDescriptor{ServiceID: "webdav", DisplayName: "WebDAV", ServiceFamily: "file_service", Transports: []string{"tcp"}, ActiveProbeSupported: true, StrictCapable: true}, DirectionClient, "file_service"},
	{models.StreamServiceDescriptor{ServiceID: "webdav_tls", DisplayName: "WebDAV over TLS", ServiceFamily: "file_service", Transports: []string{"tcp"}, ActiveProbeSupported: true, StrictCapable: true}, DirectionClient, "file_service"},
	{models.StreamServiceDescriptor{ServiceID: "http2", DisplayName: "HTTP/2 cleartext", ServiceFamily: "web", Transports: []string{"tcp"}, StrictCapable: true}, DirectionClient, "web_service"},
	{models.StreamServiceDescriptor{ServiceID: "tls", DisplayName: "TLS", ServiceFamily: "encrypted", Transports: []string{"tcp"}, ActiveProbeSupported: true, StrictCapable: true}, DirectionClient, "encrypted_service"},
	{models.StreamServiceDescriptor{ServiceID: "ssh", DisplayName: "SSH", ServiceFamily: "remote_access", Transports: []string{"tcp"}, ActiveProbeSupported: true, StrictCapable: true}, DirectionServer, "remote_shell"},
	{models.StreamServiceDescriptor{ServiceID: "rfb", DisplayName: "VNC / RFB", ServiceFamily: "remote_access", Transports: []string{"tcp"}, ActiveProbeSupported: true, StrictCapable: true}, DirectionServer, "remote_desktop"},
	{models.StreamServiceDescriptor{ServiceID: "rtsp", DisplayName: "RTSP", ServiceFamily: "video", Transports: []string{"tcp"}, ActiveProbeSupported: true, StrictCapable: true}, DirectionClient, "video_service"},
	{models.StreamServiceDescriptor{ServiceID: "rdp", DisplayName: "Remote Desktop Protocol", ServiceFamily: "remote_access", Transports: []string{"tcp"}, ActiveProbeSupported: true, StrictCapable: true}, DirectionClient, "remote_desktop"},
	{models.StreamServiceDescriptor{ServiceID: "smb", DisplayName: "SMB", ServiceFamily: "file_service", Transports: []string{"tcp"}, StrictCapable: true}, DirectionClient, "file_server"},
	{models.StreamServiceDescriptor{ServiceID: "ftp", DisplayName: "FTP", ServiceFamily: "file_service", Transports: []string{"tcp"}, ActiveProbeSupported: true, StrictCapable: true}, DirectionServer, "file_server"},
	{models.StreamServiceDescriptor{ServiceID: "smtp", DisplayName: "SMTP", ServiceFamily: "mail", Transports: []string{"tcp"}, ActiveProbeSupported: true, StrictCapable: true}, DirectionServer, "mail_server"},
	{models.StreamServiceDescriptor{ServiceID: "pop3", DisplayName: "POP3", ServiceFamily: "mail", Transports: []string{"tcp"}, ActiveProbeSupported: true, StrictCapable: true}, DirectionServer, "mail_server"},
	{models.StreamServiceDescriptor{ServiceID: "imap", DisplayName: "IMAP", ServiceFamily: "mail", Transports: []string{"tcp"}, ActiveProbeSupported: true, StrictCapable: true}, DirectionServer, "mail_server"},
	{models.StreamServiceDescriptor{ServiceID: "ldap", DisplayName: "LDAP", ServiceFamily: "directory", Transports: []string{"tcp", "udp"}, StrictCapable: true}, DirectionClient, "directory_service"},
	{models.StreamServiceDescriptor{ServiceID: "mysql", DisplayName: "MySQL / MariaDB", ServiceFamily: "database", Transports: []string{"tcp"}, ActiveProbeSupported: true, StrictCapable: true}, DirectionServer, "database"},
	{models.StreamServiceDescriptor{ServiceID: "postgresql", DisplayName: "PostgreSQL", ServiceFamily: "database", Transports: []string{"tcp"}, ActiveProbeSupported: true, StrictCapable: true}, DirectionClient, "database"},
	{models.StreamServiceDescriptor{ServiceID: "redis", DisplayName: "Redis / RESP", ServiceFamily: "database", Transports: []string{"tcp"}, ActiveProbeSupported: true, StrictCapable: true}, DirectionClient, "database"},
	{models.StreamServiceDescriptor{ServiceID: "mongodb", DisplayName: "MongoDB", ServiceFamily: "database", Transports: []string{"tcp"}, StrictCapable: true}, DirectionClient, "database"},
	{models.StreamServiceDescriptor{ServiceID: "mssql", DisplayName: "Microsoft SQL Server / TDS", ServiceFamily: "database", Transports: []string{"tcp"}, StrictCapable: true}, DirectionClient, "database"},
	{models.StreamServiceDescriptor{ServiceID: "mqtt", DisplayName: "MQTT", ServiceFamily: "messaging", Transports: []string{"tcp"}, StrictCapable: true}, DirectionClient, "message_broker"},
	{models.StreamServiceDescriptor{ServiceID: "dns", DisplayName: "DNS", ServiceFamily: "infrastructure", Transports: []string{"udp", "tcp"}, ActiveProbeSupported: true, StrictCapable: true}, DirectionClient, "dns_server"},
	{models.StreamServiceDescriptor{ServiceID: "dhcp", DisplayName: "DHCP", ServiceFamily: "infrastructure", Transports: []string{"udp"}, StrictCapable: true}, DirectionClient, "dhcp_server"},
	{models.StreamServiceDescriptor{ServiceID: "ntp", DisplayName: "NTP", ServiceFamily: "infrastructure", Transports: []string{"udp"}, ActiveProbeSupported: true, StrictCapable: true}, DirectionClient, "time_server"},
	{models.StreamServiceDescriptor{ServiceID: "stun", DisplayName: "STUN / TURN", ServiceFamily: "realtime", Transports: []string{"udp", "tcp"}, ActiveProbeSupported: true, StrictCapable: true}, DirectionClient, "realtime_service"},
	{models.StreamServiceDescriptor{ServiceID: "sip", DisplayName: "SIP", ServiceFamily: "realtime", Transports: []string{"udp", "tcp"}, StrictCapable: true}, DirectionClient, "voice_service"},
	{models.StreamServiceDescriptor{ServiceID: "quic", DisplayName: "QUIC", ServiceFamily: "encrypted", Transports: []string{"udp"}, StrictCapable: true}, DirectionClient, "encrypted_service"},
	{models.StreamServiceDescriptor{ServiceID: "dtls", DisplayName: "DTLS", ServiceFamily: "encrypted", Transports: []string{"udp"}, StrictCapable: true}, DirectionClient, "encrypted_service"},
	{models.StreamServiceDescriptor{ServiceID: "wireguard", DisplayName: "WireGuard", ServiceFamily: "vpn", Transports: []string{"udp"}, StrictCapable: true}, DirectionClient, "vpn"},
	{models.StreamServiceDescriptor{ServiceID: "ssdp", DisplayName: "SSDP / UPnP", ServiceFamily: "discovery", Transports: []string{"udp"}, ActiveProbeSupported: true, StrictCapable: true}, DirectionClient, "discovery_service"},
	{models.StreamServiceDescriptor{ServiceID: "onvif", DisplayName: "ONVIF WS-Discovery", ServiceFamily: "video", Transports: []string{"udp"}, ActiveProbeSupported: true, StrictCapable: true}, DirectionClient, "video_device"},
	{models.StreamServiceDescriptor{ServiceID: "snmp", DisplayName: "SNMP", ServiceFamily: "management", Transports: []string{"udp"}, StrictCapable: true}, DirectionClient, "managed_device"},
	{models.StreamServiceDescriptor{ServiceID: "tftp", DisplayName: "TFTP", ServiceFamily: "file_service", Transports: []string{"udp"}, StrictCapable: true}, DirectionClient, "file_server"},
	{models.StreamServiceDescriptor{ServiceID: "rtp", DisplayName: "RTP / RTCP (probable only)", ServiceFamily: "realtime", Transports: []string{"udp"}}, DirectionClient, "media_stream"},
}

func Catalog() []models.StreamServiceDescriptor {
	items := make([]models.StreamServiceDescriptor, 0, len(serviceDefinitions))
	for _, definition := range serviceDefinitions {
		item := definition.descriptor
		item.Transports = append([]string(nil), item.Transports...)
		items = append(items, item)
	}
	return items
}

func Definition(serviceID string) (models.StreamServiceDescriptor, string, string, bool) {
	serviceID = strings.ToLower(strings.TrimSpace(serviceID))
	for _, definition := range serviceDefinitions {
		if definition.descriptor.ServiceID == serviceID {
			item := definition.descriptor
			item.Transports = append([]string(nil), item.Transports...)
			return item, definition.direction, definition.role, true
		}
	}
	return models.StreamServiceDescriptor{}, "", "", false
}

func SupportsTransport(descriptor models.StreamServiceDescriptor, transport string) bool {
	transport = strings.ToLower(strings.TrimSpace(transport))
	for _, candidate := range descriptor.Transports {
		if candidate == transport {
			return true
		}
	}
	return false
}

func TargetFingerprint(transport, target string) string {
	digest := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(transport)) + "\x00" + strings.TrimSpace(target)))
	return hex.EncodeToString(digest[:])
}
