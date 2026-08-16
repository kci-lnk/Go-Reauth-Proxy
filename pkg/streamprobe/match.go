package streamprobe

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"strings"
)

type ValidationState uint8

const (
	ValidationNeedMore ValidationState = iota
	ValidationMatch
	ValidationMismatch
	ValidationProbable
)

type Classification struct {
	ServiceID string
	State     ValidationState
	Evidence  string
}

func Validate(serviceID, transport, direction string, data []byte) ValidationState {
	serviceID = strings.ToLower(strings.TrimSpace(serviceID))
	transport = strings.ToLower(strings.TrimSpace(transport))
	direction = strings.ToLower(strings.TrimSpace(direction))
	if len(data) == 0 {
		return ValidationNeedMore
	}
	if serviceID == "rtp" {
		if looksLikeRTP(data) {
			return ValidationProbable
		}
		return ValidationMismatch
	}
	classification := classifyExpected(serviceID, transport, direction, data)
	return classification.State
}

func Classify(transport, direction string, data []byte) Classification {
	transport = strings.ToLower(strings.TrimSpace(transport))
	direction = strings.ToLower(strings.TrimSpace(direction))
	if len(data) == 0 {
		return Classification{State: ValidationMismatch}
	}
	if transport == "udp" {
		for _, serviceID := range []string{"onvif", "ssdp", "stun", "wireguard", "dtls", "quic", "dhcp", "dns", "ntp", "sip", "snmp", "tftp", "ldap"} {
			if result := classifyExpected(serviceID, transport, direction, data); result.State == ValidationMatch {
				return result
			}
		}
		if looksLikeRTP(data) {
			return Classification{ServiceID: "rtp", State: ValidationProbable, Evidence: "rtp_v2_header"}
		}
		return Classification{State: ValidationMismatch}
	}

	serverOrder := []string{"easytier", "rfb", "ssh", "rtsp", "webdav", "http1", "tls", "mysql", "ftp", "smtp", "pop3", "imap", "redis", "rdp", "smb", "mssql", "ldap"}
	clientOrder := []string{"easytier", "http2", "rtsp", "webdav", "http1", "tls", "rdp", "smb", "postgresql", "redis", "mongodb", "mssql", "mqtt", "dns", "stun", "sip", "ldap"}
	order := clientOrder
	if direction == DirectionServer {
		order = serverOrder
	}
	for _, serviceID := range order {
		if result := classifyExpected(serviceID, transport, direction, data); result.State == ValidationMatch {
			return result
		}
	}
	return Classification{State: ValidationMismatch}
}

func classifyExpected(serviceID, transport, direction string, data []byte) Classification {
	match := func(ok bool, evidence string) Classification {
		if ok {
			return Classification{ServiceID: serviceID, State: ValidationMatch, Evidence: evidence}
		}
		return Classification{ServiceID: serviceID, State: ValidationMismatch}
	}
	need := func(min int) (Classification, bool) {
		if len(data) < min {
			return Classification{ServiceID: serviceID, State: ValidationNeedMore}, true
		}
		return Classification{}, false
	}

	switch serviceID {
	case "easytier":
		return classifyEasyTierHandshake(data)
	case "rfb":
		if result, ok := need(12); ok {
			return result
		}
		return match(data[0] == 'R' && data[1] == 'F' && data[2] == 'B' && data[3] == ' ' &&
			isDigit3(data[4:7]) && data[7] == '.' && isDigit3(data[8:11]) && data[11] == '\n', "rfb_version_banner")
	case "ssh":
		return classifySSHIdentification(serviceID, direction, data)
	case "http2":
		preface := []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
		if len(data) < len(preface) && bytes.HasPrefix(preface, data) {
			return Classification{ServiceID: serviceID, State: ValidationNeedMore}
		}
		return match(bytes.HasPrefix(data, preface), "http2_connection_preface")
	case "http1":
		line, complete := firstLine(data)
		if !complete {
			return Classification{ServiceID: serviceID, State: ValidationNeedMore}
		}
		upper := strings.ToUpper(line)
		if direction == DirectionServer {
			return match(isStatusLine(upper, "HTTP/1.0", "HTTP/1.1"), "http_status_line")
		}
		for _, method := range []string{"GET ", "HEAD ", "POST ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE "} {
			if strings.HasPrefix(upper, method) && (strings.HasSuffix(upper, " HTTP/1.0") || strings.HasSuffix(upper, " HTTP/1.1")) {
				return Classification{ServiceID: serviceID, State: ValidationMatch, Evidence: "http_request_line"}
			}
		}
		return Classification{ServiceID: serviceID, State: ValidationMismatch}
	case "webdav":
		if !headerBlockComplete(data) {
			return Classification{ServiceID: serviceID, State: ValidationNeedMore}
		}
		line, complete := firstLine(data)
		if !complete {
			return Classification{ServiceID: serviceID, State: ValidationNeedMore}
		}
		upper := strings.ToUpper(line)
		if direction == DirectionServer {
			if !isStatusLine(upper, "HTTP/1.0", "HTTP/1.1") {
				return Classification{ServiceID: serviceID, State: ValidationMismatch}
			}
			if hasNonEmptyHeader(data, "DAV") {
				return Classification{ServiceID: serviceID, State: ValidationMatch, Evidence: "webdav_dav_header"}
			}
			if hasWebDAVAllowHeader(data) {
				return Classification{ServiceID: serviceID, State: ValidationMatch, Evidence: "webdav_allow_header"}
			}
			if httpStatusCode(upper) == "207" && hasWebDAVMultiStatus(data) {
				return Classification{ServiceID: serviceID, State: ValidationMatch, Evidence: "webdav_multistatus"}
			}
			return Classification{ServiceID: serviceID, State: ValidationMismatch}
		}
		if !isHTTP1RequestLine(upper) {
			return Classification{ServiceID: serviceID, State: ValidationMismatch}
		}
		for _, method := range []string{"PROPFIND ", "PROPPATCH ", "MKCOL ", "COPY ", "MOVE ", "LOCK ", "UNLOCK "} {
			if strings.HasPrefix(upper, method) {
				return Classification{ServiceID: serviceID, State: ValidationMatch, Evidence: "webdav_method"}
			}
		}
		// A verified WebDAV endpoint can legitimately receive ordinary HTTP methods
		// (for example GET, PUT, DELETE, or an initial OPTIONS request). Inline
		// validation therefore verifies the HTTP carrier while the configuration
		// probe supplies the DAV capability evidence.
		return Classification{ServiceID: serviceID, State: ValidationMatch, Evidence: "webdav_http_request"}
	case "webdav_tls":
		carrier := classifyExpected("tls", transport, direction, data)
		carrier.ServiceID = serviceID
		if carrier.State == ValidationMatch {
			carrier.Evidence = "webdav_tls_client_hello"
		}
		return carrier
	case "rtsp":
		if !headerBlockComplete(data) {
			return Classification{ServiceID: serviceID, State: ValidationNeedMore}
		}
		line, complete := firstLine(data)
		if !complete {
			return Classification{ServiceID: serviceID, State: ValidationNeedMore}
		}
		upper := strings.ToUpper(line)
		if isStatusLine(upper, "RTSP/1.0", "RTSP/2.0") && hasNumericHeader(data, "CSeq") {
			return Classification{ServiceID: serviceID, State: ValidationMatch, Evidence: "rtsp_status_line"}
		}
		for _, method := range []string{"OPTIONS ", "DESCRIBE ", "ANNOUNCE ", "SETUP ", "PLAY ", "PAUSE ", "TEARDOWN ", "GET_PARAMETER ", "SET_PARAMETER ", "RECORD ", "REDIRECT "} {
			if strings.HasPrefix(upper, method) && (strings.HasSuffix(upper, " RTSP/1.0") || strings.HasSuffix(upper, " RTSP/2.0")) && hasNumericHeader(data, "CSeq") {
				return Classification{ServiceID: serviceID, State: ValidationMatch, Evidence: "rtsp_request_line"}
			}
		}
		return Classification{ServiceID: serviceID, State: ValidationMismatch}
	case "tls":
		return classifyTLSHandshake(serviceID, direction, data)
	case "ftp", "smtp":
		line, complete := firstLine(data)
		if !complete {
			return Classification{ServiceID: serviceID, State: ValidationNeedMore}
		}
		upper := strings.ToUpper(line)
		if serviceID == "ftp" {
			return match(strings.HasPrefix(upper, "220 ") && (strings.Contains(upper, "FTP") || strings.Contains(upper, "FILEZILLA")), "ftp_welcome")
		}
		return match(strings.HasPrefix(upper, "220 ") && (strings.Contains(upper, "SMTP") || strings.Contains(upper, "ESMTP")), "smtp_welcome")
	case "pop3":
		line, complete := firstLine(data)
		if !complete {
			return Classification{ServiceID: serviceID, State: ValidationNeedMore}
		}
		return match(strings.HasPrefix(strings.ToUpper(line), "+OK"), "pop3_welcome")
	case "imap":
		line, complete := firstLine(data)
		if !complete {
			return Classification{ServiceID: serviceID, State: ValidationNeedMore}
		}
		return match(strings.HasPrefix(strings.ToUpper(line), "* OK") || strings.HasPrefix(strings.ToUpper(line), "* PREAUTH"), "imap_welcome")
	case "mysql":
		if result, ok := need(5); ok {
			return result
		}
		length := int(data[0]) | int(data[1])<<8 | int(data[2])<<16
		if data[3] != 0 || data[4] != 0x0a || length < 34 || length > 0x00ffffff {
			return Classification{ServiceID: serviceID, State: ValidationMismatch}
		}
		if len(data) < 4+length {
			return Classification{ServiceID: serviceID, State: ValidationNeedMore}
		}
		return match(bytes.IndexByte(data[5:min(len(data), 4+length)], 0) > 0, "mysql_handshake_v10")
	case "postgresql":
		if result, ok := need(8); ok {
			return result
		}
		length := int(binary.BigEndian.Uint32(data[:4]))
		code := binary.BigEndian.Uint32(data[4:8])
		if length < 8 || length > 1<<20 || (code != 196608 && code != 80877103 && code != 80877104) {
			return Classification{ServiceID: serviceID, State: ValidationMismatch}
		}
		if len(data) < length {
			return Classification{ServiceID: serviceID, State: ValidationNeedMore}
		}
		return match(true, "postgres_startup")
	case "redis":
		first := data[0]
		if !bytes.Contains(data, []byte("\r\n")) && len(data) < 16 {
			return Classification{ServiceID: serviceID, State: ValidationNeedMore}
		}
		return match(bytes.Contains([]byte("+-:$*_,#(!=%~>"), []byte{first}) || isASCIIRedisCommand(data), "redis_resp")
	case "mongodb":
		if result, ok := need(16); ok {
			return result
		}
		length := int(int32(binary.LittleEndian.Uint32(data[:4])))
		opcode := int32(binary.LittleEndian.Uint32(data[12:16]))
		if length < 16 || length > 48<<20 || (opcode != 1 && opcode != 2004 && opcode != 2013) {
			return Classification{ServiceID: serviceID, State: ValidationMismatch}
		}
		if len(data) < length {
			return Classification{ServiceID: serviceID, State: ValidationNeedMore}
		}
		return match(true, "mongodb_message_header")
	case "mssql":
		if result, ok := need(8); ok {
			return result
		}
		packetType := data[0]
		length := int(binary.BigEndian.Uint16(data[2:4]))
		if (packetType != 0x04 && packetType != 0x10 && packetType != 0x12) || length < 8 {
			return Classification{ServiceID: serviceID, State: ValidationMismatch}
		}
		if len(data) < length {
			return Classification{ServiceID: serviceID, State: ValidationNeedMore}
		}
		return match(true, "tds_packet_header")
	case "mqtt":
		return classifyMQTTConnect(serviceID, data)
	case "rdp":
		if result, ok := need(7); ok {
			return result
		}
		length := int(binary.BigEndian.Uint16(data[2:4]))
		if data[0] != 3 || data[1] != 0 || length < 7 || (data[5] != 0xe0 && data[5] != 0xd0) {
			return Classification{ServiceID: serviceID, State: ValidationMismatch}
		}
		if len(data) < length {
			return Classification{ServiceID: serviceID, State: ValidationNeedMore}
		}
		return match(true, "rdp_x224")
	case "smb":
		if result, ok := need(8); ok {
			return result
		}
		length := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
		if data[0] != 0 || length < 4 || length > 1<<20 {
			return Classification{ServiceID: serviceID, State: ValidationMismatch}
		}
		if len(data) < 4+length {
			return Classification{ServiceID: serviceID, State: ValidationNeedMore}
		}
		return match(bytes.Equal(data[4:8], []byte{0xff, 'S', 'M', 'B'}) || bytes.Equal(data[4:8], []byte{0xfe, 'S', 'M', 'B'}), "smb_signature")
	case "ldap":
		if result, ok := need(7); ok {
			return result
		}
		return match(data[0] == 0x30 && data[2] == 0x02 && data[3] >= 1 && data[3] <= 4, "ldap_ber_message")
	case "dns":
		payload := data
		if transport == "tcp" {
			if result, ok := need(14); ok {
				return result
			}
			length := int(binary.BigEndian.Uint16(data[:2]))
			if length < 12 || length > 65535 {
				return Classification{ServiceID: serviceID, State: ValidationMismatch}
			}
			if len(data) < 2+length {
				return Classification{ServiceID: serviceID, State: ValidationNeedMore}
			}
			payload = data[2 : 2+length]
		}
		return match(looksLikeDNS(payload), "dns_message")
	case "dhcp":
		if result, ok := need(240); ok {
			return result
		}
		return match((data[0] == 1 || data[0] == 2) && bytes.Equal(data[236:240], []byte{0x63, 0x82, 0x53, 0x63}), "dhcp_magic_cookie")
	case "ntp":
		if result, ok := need(48); ok {
			return result
		}
		version := (data[0] >> 3) & 0x07
		mode := data[0] & 0x07
		validMode := mode == 1 || mode == 3
		if direction == DirectionServer {
			validMode = mode == 2 || mode == 4 || mode == 5
		}
		return match(version >= 1 && version <= 4 && validMode, "ntp_header")
	case "stun":
		if result, ok := need(20); ok {
			return result
		}
		length := int(binary.BigEndian.Uint16(data[2:4]))
		if data[0]&0xc0 != 0 || binary.BigEndian.Uint32(data[4:8]) != 0x2112a442 || length%4 != 0 || length > 65515 {
			return Classification{ServiceID: serviceID, State: ValidationMismatch}
		}
		if len(data) < 20+length {
			return Classification{ServiceID: serviceID, State: ValidationNeedMore}
		}
		return match(true, "stun_magic_cookie")
	case "sip":
		line, complete := firstLine(data)
		if !complete {
			return Classification{ServiceID: serviceID, State: ValidationNeedMore}
		}
		upper := strings.ToUpper(line)
		if strings.HasPrefix(upper, "SIP/2.0 ") {
			return Classification{ServiceID: serviceID, State: ValidationMatch, Evidence: "sip_status_line"}
		}
		for _, method := range []string{"INVITE ", "ACK ", "BYE ", "CANCEL ", "OPTIONS ", "REGISTER ", "PRACK ", "SUBSCRIBE ", "NOTIFY ", "PUBLISH ", "INFO ", "REFER ", "MESSAGE ", "UPDATE "} {
			if strings.HasPrefix(upper, method) && strings.HasSuffix(upper, " SIP/2.0") {
				return Classification{ServiceID: serviceID, State: ValidationMatch, Evidence: "sip_request_line"}
			}
		}
		return Classification{ServiceID: serviceID, State: ValidationMismatch}
	case "quic":
		if result, ok := need(7); ok {
			return result
		}
		if data[0]&0xc0 != 0xc0 || binary.BigEndian.Uint32(data[1:5]) == 0 {
			return Classification{ServiceID: serviceID, State: ValidationMismatch}
		}
		destinationLength := int(data[5])
		if destinationLength > 20 || len(data) < 7+destinationLength {
			if destinationLength <= 20 {
				return Classification{ServiceID: serviceID, State: ValidationNeedMore}
			}
			return Classification{ServiceID: serviceID, State: ValidationMismatch}
		}
		sourceLength := int(data[6+destinationLength])
		if sourceLength > 20 {
			return Classification{ServiceID: serviceID, State: ValidationMismatch}
		}
		if len(data) < 7+destinationLength+sourceLength {
			return Classification{ServiceID: serviceID, State: ValidationNeedMore}
		}
		return match(true, "quic_long_header")
	case "dtls":
		if result, ok := need(13); ok {
			return result
		}
		recordLength := int(binary.BigEndian.Uint16(data[11:13]))
		if data[0] != 22 || data[1] != 0xfe || (data[2] != 0xff && data[2] != 0xfd && data[2] != 0xfc) || recordLength < 12 || recordLength > 18432 {
			return Classification{ServiceID: serviceID, State: ValidationMismatch}
		}
		if len(data) < 13+recordLength {
			return Classification{ServiceID: serviceID, State: ValidationNeedMore}
		}
		payload := data[13 : 13+recordLength]
		handshakeType := payload[0]
		expectedType := byte(1)
		if direction == DirectionServer && handshakeType != 2 && handshakeType != 3 {
			return Classification{ServiceID: serviceID, State: ValidationMismatch}
		}
		if direction != DirectionServer && handshakeType != expectedType {
			return Classification{ServiceID: serviceID, State: ValidationMismatch}
		}
		messageLength := uint24(payload[1:4])
		fragmentOffset := uint24(payload[6:9])
		fragmentLength := uint24(payload[9:12])
		return match(messageLength > 0 && fragmentLength > 0 && fragmentOffset+fragmentLength <= messageLength && 12+fragmentLength <= len(payload), "dtls_handshake_record")
	case "wireguard":
		if result, ok := need(4); ok {
			return result
		}
		typeID := binary.LittleEndian.Uint32(data[:4])
		validLength := (typeID == 1 && len(data) == 148) || (typeID == 2 && len(data) == 92) || (typeID == 3 && len(data) == 64) || (typeID == 4 && len(data) >= 32)
		return match(typeID >= 1 && typeID <= 4 && validLength, "wireguard_message")
	case "ssdp":
		upper := bytes.ToUpper(data)
		if !bytes.Contains(upper, []byte("\r\n")) && len(data) < 32 {
			return Classification{ServiceID: serviceID, State: ValidationNeedMore}
		}
		return match(bytes.HasPrefix(upper, []byte("M-SEARCH * HTTP/1.1")) || bytes.HasPrefix(upper, []byte("NOTIFY * HTTP/1.1")) || bytes.HasPrefix(upper, []byte("HTTP/1.1 200")), "ssdp_start_line")
	case "onvif":
		lower := bytes.ToLower(data)
		if len(data) < 48 {
			return Classification{ServiceID: serviceID, State: ValidationNeedMore}
		}
		return match((bytes.Contains(lower, []byte("schemas.xmlsoap.org/ws/2005/04/discovery")) || bytes.Contains(lower, []byte("docs.oasis-open.org/ws-dd/ns/discovery"))) &&
			(bytes.Contains(lower, []byte("probe")) || bytes.Contains(lower, []byte("probematches"))), "onvif_ws_discovery")
	case "snmp":
		if result, ok := need(8); ok {
			return result
		}
		return match(data[0] == 0x30 && bytes.Contains(data[:min(len(data), 24)], []byte{0x02, 0x01}), "snmp_ber_message")
	case "tftp":
		if result, ok := need(4); ok {
			return result
		}
		opcode := binary.BigEndian.Uint16(data[:2])
		if direction == DirectionClient {
			return match((opcode == 1 || opcode == 2) && validTFTPRequest(data[2:]), "tftp_request")
		}
		return match(validTFTPServerPacket(opcode, data), "tftp_response")
	}
	return Classification{ServiceID: serviceID, State: ValidationMismatch}
}

func firstLine(data []byte) (string, bool) {
	if index := bytes.Index(data, []byte("\r\n")); index >= 0 {
		return string(data[:index]), true
	}
	if index := bytes.IndexByte(data, '\n'); index >= 0 {
		return strings.TrimSuffix(string(data[:index]), "\r"), true
	}
	return "", false
}

func classifySSHIdentification(serviceID, direction string, data []byte) Classification {
	offset := 0
	for lines := 0; lines < 50; lines++ {
		relativeEnd := bytes.IndexByte(data[offset:], '\n')
		if relativeEnd < 0 {
			if len(data)-offset > 255 || len(data) > 8192 {
				return Classification{ServiceID: serviceID, State: ValidationMismatch}
			}
			return Classification{ServiceID: serviceID, State: ValidationNeedMore}
		}
		end := offset + relativeEnd + 1
		if end-offset > 255 {
			return Classification{ServiceID: serviceID, State: ValidationMismatch}
		}
		line := strings.TrimSuffix(strings.TrimSuffix(string(data[offset:end]), "\n"), "\r")
		if strings.HasPrefix(line, "SSH-") {
			if !strings.HasPrefix(line, "SSH-2.0-") && !strings.HasPrefix(line, "SSH-1.99-") {
				return Classification{ServiceID: serviceID, State: ValidationMismatch}
			}
			software := strings.TrimPrefix(strings.TrimPrefix(line, "SSH-2.0-"), "SSH-1.99-")
			if software == "" || strings.IndexFunc(software, func(character rune) bool {
				return character < 0x20 || character == 0x7f
			}) >= 0 {
				return Classification{ServiceID: serviceID, State: ValidationMismatch}
			}
			return Classification{ServiceID: serviceID, State: ValidationMatch, Evidence: "ssh_identification"}
		}
		if direction != DirectionServer {
			return Classification{ServiceID: serviceID, State: ValidationMismatch}
		}
		offset = end
		if offset >= len(data) {
			return Classification{ServiceID: serviceID, State: ValidationNeedMore}
		}
	}
	return Classification{ServiceID: serviceID, State: ValidationMismatch}
}

func headerBlockComplete(data []byte) bool {
	return bytes.Contains(data, []byte("\r\n\r\n")) || bytes.Contains(data, []byte("\n\n"))
}

func hasNumericHeader(data []byte, expected string) bool {
	for _, line := range strings.Split(string(data), "\n")[1:] {
		line = strings.TrimSuffix(line, "\r")
		if line == "" {
			break
		}
		name, value, found := strings.Cut(line, ":")
		if !found || !strings.EqualFold(strings.TrimSpace(name), expected) {
			continue
		}
		value = strings.TrimSpace(value)
		if value == "" {
			return false
		}
		for _, character := range value {
			if character < '0' || character > '9' {
				return false
			}
		}
		return true
	}
	return false
}

func hasNonEmptyHeader(data []byte, expected string) bool {
	for _, line := range strings.Split(string(data), "\n")[1:] {
		line = strings.TrimSuffix(line, "\r")
		if line == "" {
			break
		}
		name, value, found := strings.Cut(line, ":")
		if found && strings.EqualFold(strings.TrimSpace(name), expected) {
			return strings.TrimSpace(value) != ""
		}
	}
	return false
}

func headerValue(data []byte, expected string) (string, bool) {
	for _, line := range strings.Split(string(data), "\n")[1:] {
		line = strings.TrimSuffix(line, "\r")
		if line == "" {
			break
		}
		name, value, found := strings.Cut(line, ":")
		if found && strings.EqualFold(strings.TrimSpace(name), expected) {
			value = strings.TrimSpace(value)
			return value, value != ""
		}
	}
	return "", false
}

func hasWebDAVAllowHeader(data []byte) bool {
	value, found := headerValue(data, "Allow")
	if !found {
		return false
	}
	for method := range strings.SplitSeq(value, ",") {
		switch strings.ToUpper(strings.TrimSpace(method)) {
		case "PROPFIND", "PROPPATCH", "MKCOL", "LOCK", "UNLOCK":
			return true
		}
	}
	return false
}

func hasWebDAVMultiStatus(data []byte) bool {
	body := data
	if index := bytes.Index(data, []byte("\r\n\r\n")); index >= 0 {
		body = data[index+4:]
	} else if index := bytes.Index(data, []byte("\n\n")); index >= 0 {
		body = data[index+2:]
	}
	decoder := xml.NewDecoder(bytes.NewReader(body))
	decoder.Strict = false
	for {
		token, err := decoder.Token()
		if err != nil {
			return false
		}
		start, ok := token.(xml.StartElement)
		if !ok {
			continue
		}
		return strings.EqualFold(start.Name.Local, "multistatus") && strings.EqualFold(start.Name.Space, "DAV:")
	}
}

func isHTTP1RequestLine(upper string) bool {
	for _, method := range []string{
		"GET ", "HEAD ", "POST ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE ",
		"PROPFIND ", "PROPPATCH ", "MKCOL ", "COPY ", "MOVE ", "LOCK ", "UNLOCK ",
	} {
		if strings.HasPrefix(upper, method) && (strings.HasSuffix(upper, " HTTP/1.0") || strings.HasSuffix(upper, " HTTP/1.1")) {
			return true
		}
	}
	return false
}

func isStatusLine(line string, versions ...string) bool {
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 || len(parts[1]) != 3 {
		return false
	}
	versionOK := false
	for _, version := range versions {
		if parts[0] == version {
			versionOK = true
			break
		}
	}
	if !versionOK {
		return false
	}
	for _, character := range parts[1] {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func httpStatusCode(line string) string {
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 || len(parts[1]) != 3 {
		return ""
	}
	for _, character := range parts[1] {
		if character < '0' || character > '9' {
			return ""
		}
	}
	return parts[1]
}

func classifyTLSHandshake(serviceID, direction string, data []byte) Classification {
	expectedType := byte(1)
	if direction == DirectionServer {
		expectedType = 2
	}
	handshake := make([]byte, 0, len(data))
	for offset := 0; ; {
		if len(data)-offset < 5 {
			return Classification{ServiceID: serviceID, State: ValidationNeedMore}
		}
		if data[offset] != 22 || data[offset+1] != 3 || data[offset+2] > 4 {
			return Classification{ServiceID: serviceID, State: ValidationMismatch}
		}
		recordLength := int(binary.BigEndian.Uint16(data[offset+3 : offset+5]))
		if recordLength == 0 || recordLength > 18432 {
			return Classification{ServiceID: serviceID, State: ValidationMismatch}
		}
		recordEnd := offset + 5 + recordLength
		if len(data) < recordEnd {
			return Classification{ServiceID: serviceID, State: ValidationNeedMore}
		}
		handshake = append(handshake, data[offset+5:recordEnd]...)
		if len(handshake) >= 4 {
			handshakeLength := uint24(handshake[1:4])
			if handshake[0] != expectedType || handshakeLength < 34 {
				return Classification{ServiceID: serviceID, State: ValidationMismatch}
			}
			if handshakeLength <= len(handshake)-4 {
				if !validTLSHelloBody(expectedType, handshake[4:4+handshakeLength]) {
					return Classification{ServiceID: serviceID, State: ValidationMismatch}
				}
				return Classification{ServiceID: serviceID, State: ValidationMatch, Evidence: "tls_handshake_record"}
			}
		}
		offset = recordEnd
		if offset == len(data) {
			return Classification{ServiceID: serviceID, State: ValidationNeedMore}
		}
	}
}

func validTLSHelloBody(handshakeType byte, body []byte) bool {
	if len(body) < 35 || body[0] != 3 || body[1] < 1 || body[1] > 4 {
		return false
	}
	offset := 34 // legacy_version and random
	sessionIDLength := int(body[offset])
	offset++
	if sessionIDLength > 32 || len(body) < offset+sessionIDLength {
		return false
	}
	offset += sessionIDLength
	if handshakeType == 1 {
		if len(body) < offset+2 {
			return false
		}
		cipherSuitesLength := int(binary.BigEndian.Uint16(body[offset : offset+2]))
		offset += 2
		if cipherSuitesLength < 2 || cipherSuitesLength%2 != 0 || len(body) < offset+cipherSuitesLength+1 {
			return false
		}
		offset += cipherSuitesLength
		compressionMethodsLength := int(body[offset])
		offset++
		if compressionMethodsLength == 0 || len(body) < offset+compressionMethodsLength {
			return false
		}
		offset += compressionMethodsLength
	} else {
		// ServerHello carries one selected cipher suite and one compression method.
		if len(body) < offset+3 {
			return false
		}
		offset += 3
	}
	if offset == len(body) {
		return true
	}
	if len(body) < offset+2 {
		return false
	}
	extensionsLength := int(binary.BigEndian.Uint16(body[offset : offset+2]))
	return extensionsLength == len(body)-offset-2
}

func classifyMQTTConnect(serviceID string, data []byte) Classification {
	if len(data) < 2 {
		return Classification{ServiceID: serviceID, State: ValidationNeedMore}
	}
	remaining, encodedBytes, valid, complete := mqttRemainingLength(data[1:])
	if !complete {
		return Classification{ServiceID: serviceID, State: ValidationNeedMore}
	}
	if data[0] != 0x10 || !valid || remaining < 10 {
		return Classification{ServiceID: serviceID, State: ValidationMismatch}
	}
	headerBytes := 1 + encodedBytes
	if remaining > int(^uint(0)>>1)-headerBytes {
		return Classification{ServiceID: serviceID, State: ValidationMismatch}
	}
	totalBytes := headerBytes + remaining
	if len(data) < totalBytes {
		return Classification{ServiceID: serviceID, State: ValidationNeedMore}
	}
	payload := data[headerBytes:totalBytes]
	if len(payload) < 8 {
		return Classification{ServiceID: serviceID, State: ValidationMismatch}
	}
	nameLength := int(binary.BigEndian.Uint16(payload[:2]))
	if nameLength <= 0 || len(payload) < 2+nameLength+4 {
		return Classification{ServiceID: serviceID, State: ValidationMismatch}
	}
	name := string(payload[2 : 2+nameLength])
	level := payload[2+nameLength]
	flags := payload[3+nameLength]
	validProtocol := (name == "MQTT" && (level == 4 || level == 5)) || (name == "MQIsdp" && level == 3)
	if !validProtocol || flags&0x01 != 0 {
		return Classification{ServiceID: serviceID, State: ValidationMismatch}
	}
	return Classification{ServiceID: serviceID, State: ValidationMatch, Evidence: "mqtt_connect"}
}

func isDigit3(value []byte) bool {
	return len(value) == 3 && value[0] >= '0' && value[0] <= '9' && value[1] >= '0' && value[1] <= '9' && value[2] >= '0' && value[2] <= '9'
}

func uint24(value []byte) int {
	if len(value) < 3 {
		return 0
	}
	return int(value[0])<<16 | int(value[1])<<8 | int(value[2])
}

func validTFTPRequest(payload []byte) bool {
	parts := bytes.Split(payload, []byte{0})
	if len(parts) < 3 || len(parts[0]) == 0 || len(parts[1]) == 0 || len(parts[len(parts)-1]) != 0 {
		return false
	}
	mode := strings.ToLower(string(parts[1]))
	if mode != "netascii" && mode != "octet" && mode != "mail" {
		return false
	}
	// Optional RFC 2347 option name/value fields must occur in pairs and be non-empty.
	options := parts[2 : len(parts)-1]
	if len(options)%2 != 0 {
		return false
	}
	for _, option := range options {
		if len(option) == 0 {
			return false
		}
	}
	return true
}

func validTFTPServerPacket(opcode uint16, data []byte) bool {
	switch opcode {
	case 3:
		return len(data) >= 4
	case 4:
		return len(data) == 4
	case 5:
		return len(data) >= 5 && data[len(data)-1] == 0
	case 6:
		parts := bytes.Split(data[2:], []byte{0})
		if len(parts) < 3 || len(parts[len(parts)-1]) != 0 || (len(parts)-1)%2 != 0 {
			return false
		}
		for _, part := range parts[:len(parts)-1] {
			if len(part) == 0 {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func mqttRemainingLength(data []byte) (int, int, bool, bool) {
	value, multiplier := 0, 1
	for index, encoded := range data {
		value += int(encoded&127) * multiplier
		if encoded&128 == 0 {
			return value, index + 1, value <= 268435455, true
		}
		if index == 3 {
			return 0, index + 1, false, true
		}
		multiplier *= 128
	}
	return 0, len(data), false, false
}

func looksLikeDNS(data []byte) bool {
	if len(data) < 12 {
		return false
	}
	flags := binary.BigEndian.Uint16(data[2:4])
	opcode := (flags >> 11) & 0x0f
	questions := binary.BigEndian.Uint16(data[4:6])
	answers := binary.BigEndian.Uint16(data[6:8])
	authority := binary.BigEndian.Uint16(data[8:10])
	additional := binary.BigEndian.Uint16(data[10:12])
	return len(data) > 12 && opcode <= 5 && questions <= 64 && answers <= 4096 && authority <= 4096 && additional <= 4096 && (questions+answers+authority+additional) > 0
}

func looksLikeRTP(data []byte) bool {
	if len(data) < 12 || data[0]>>6 != 2 {
		return false
	}
	payloadType := data[1] & 0x7f
	return payloadType <= 127
}

func isASCIIRedisCommand(data []byte) bool {
	line, complete := firstLine(data)
	if !complete {
		return false
	}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return false
	}
	command := strings.ToUpper(fields[0])
	switch command {
	case "PING", "AUTH", "GET", "SET", "DEL", "EXISTS", "INFO", "HELLO", "SELECT", "QUIT":
		return true
	default:
		return false
	}
}
