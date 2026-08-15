package streamprobe

import (
	"context"
	"crypto/tls"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"go-reauth-proxy/pkg/models"
)

const (
	probeTotalTimeout = 15 * time.Second
	probeIOTimeout    = 2 * time.Second
	probeBannerWait   = 700 * time.Millisecond
	probeMaxResponse  = 64 * 1024
	probeMaxAttempts  = 8
)

var errProbeResponseTooLarge = errors.New("probe response exceeds limit")

type activeProbe struct {
	name      string
	payload   []byte
	expected  string
	direction string
}

func Probe(ctx context.Context, transport, target string) models.StreamProbeResult {
	transport = strings.ToLower(strings.TrimSpace(transport))
	target = strings.TrimSpace(target)
	if transport != "tcp" && transport != "udp" {
		return models.StreamProbeResult{Status: "unknown", Message: "unsupported transport"}
	}
	if _, _, err := net.SplitHostPort(target); err != nil {
		return models.StreamProbeResult{Status: "unreachable", Message: "target must be host:port"}
	}
	probeCtx, cancel := context.WithTimeout(ctx, probeTotalTimeout)
	defer cancel()

	var result models.StreamProbeResult
	if transport == "tcp" {
		result = probeTCP(probeCtx, target)
	} else {
		result = probeUDP(probeCtx, target)
	}
	if result.Profile.ServiceID != "" {
		result.Profile.Source = "probe"
		result.Profile.ObservedAt = time.Now().UTC().Format(time.RFC3339)
		result.Profile.ClassifierVersion = ClassifierVersion
		result.Profile.TargetFingerprint = TargetFingerprint(transport, target)
	}
	return result
}

func probeTCP(ctx context.Context, target string) models.StreamProbeResult {
	data, dialed, err := tcpExchange(ctx, target, nil, probeBannerWait)
	if errors.Is(err, errProbeResponseTooLarge) {
		return models.StreamProbeResult{Status: "unknown", Message: "probe response exceeds 64 KiB"}
	}
	if len(data) > 0 {
		if classification := Classify("tcp", DirectionServer, data); classification.State == ValidationMatch {
			return matchedProbeResult(classification, data)
		}
	}
	if err != nil && !dialed {
		return probeErrorResult(ctx, err)
	}
	if excludedActiveProbePort(target) {
		return models.StreamProbeResult{Status: "unknown", Message: "active payload probes are disabled for this port"}
	}

	var authenticatedHTTPStatus string
	var authenticatedHTTPScheme string
	for _, probe := range tcpActiveProbes(target) {
		if ctx.Err() != nil {
			return models.StreamProbeResult{Status: "timeout", Message: "probe deadline exceeded"}
		}
		if probe.name == "tls_client_hello" {
			if result, ok := probeTLS(ctx, target); ok {
				return result
			}
			continue
		}
		response, _, exchangeErr := tcpExchange(ctx, target, probe.payload, probeIOTimeout)
		if errors.Is(exchangeErr, errProbeResponseTooLarge) {
			return models.StreamProbeResult{Status: "unknown", Message: "probe response exceeds 64 KiB"}
		}
		if probe.expected == "postgresql" && len(response) == 1 && (response[0] == 'S' || response[0] == 'N') {
			return profileResult("postgresql", "strong", "postgres_ssl_negotiation", nil)
		}
		if len(response) == 0 {
			if exchangeErr != nil && ctx.Err() != nil {
				return models.StreamProbeResult{Status: "timeout", Message: "probe deadline exceeded"}
			}
			continue
		}
		classification := Classify("tcp", probe.direction, response)
		if classification.State != ValidationMatch {
			continue
		}
		candidate := matchedProbeResult(classification, response)
		if status, scheme, ok := authenticatedHTTPChallenge(candidate); ok {
			authenticatedHTTPStatus = status
			authenticatedHTTPScheme = scheme
		}
		if probe.expected == "" || classification.ServiceID == probe.expected {
			return withAuthenticatedHTTPAmbiguity(candidate, authenticatedHTTPStatus, authenticatedHTTPScheme)
		}
	}
	return models.StreamProbeResult{Status: "unknown", Message: "target responded but no strong service signature matched"}
}

func probeUDP(ctx context.Context, target string) models.StreamProbeResult {
	probes := []activeProbe{
		{name: "dns_query", payload: []byte{0x51, 0xa7, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0x02, 0, 0x01}, expected: "dns", direction: DirectionServer},
		{name: "ntp_client", payload: append([]byte{0x23}, make([]byte, 47)...), expected: "ntp", direction: DirectionServer},
		{name: "stun_binding", payload: []byte{0x00, 0x01, 0, 0, 0x21, 0x12, 0xa4, 0x42, 0x46, 0x4e, 0x4b, 0x4e, 0x4f, 0x43, 0x4b, 0x50, 0x52, 0x4f, 0x42, 0x45}, expected: "stun", direction: DirectionServer},
		{name: "ssdp_search", payload: []byte("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n"), expected: "ssdp", direction: DirectionServer},
		{name: "onvif_probe", payload: []byte(onvifProbeEnvelope), expected: "onvif", direction: DirectionServer},
	}
	var firstErr error
	attempts := 0
	for retry := 0; retry < 2; retry++ {
		for _, probe := range probes {
			if attempts >= probeMaxAttempts {
				break
			}
			attempts++
			response, dialed, err := udpExchange(ctx, target, probe.payload)
			if err != nil && !dialed && firstErr == nil {
				firstErr = err
			}
			if len(response) > 0 {
				classification := Classify("udp", probe.direction, response)
				if classification.State == ValidationMatch && classification.ServiceID == probe.expected {
					return matchedProbeResult(classification, response)
				}
			}
			if ctx.Err() != nil {
				return models.StreamProbeResult{Status: "timeout", Message: "probe deadline exceeded"}
			}
		}
		if attempts >= probeMaxAttempts {
			break
		}
	}
	if firstErr != nil {
		return probeErrorResult(ctx, firstErr)
	}
	return models.StreamProbeResult{Status: "unknown", Message: "no UDP service returned a strong signature"}
}

func tcpActiveProbes(target string) []activeProbe {
	port := targetPort(target)
	hostHeader := httpProbeHost(target)
	all := []activeProbe{
		{name: "tls_client_hello", expected: "tls"},
		{name: "webdav_options", payload: []byte("OPTIONS / HTTP/1.1\r\nHost: " + hostHeader + "\r\nConnection: close\r\nUser-Agent: fn-knock-service-probe/1\r\n\r\n"), expected: "webdav", direction: DirectionServer},
		{name: "webdav_propfind", payload: []byte("PROPFIND / HTTP/1.1\r\nHost: " + hostHeader + "\r\nDepth: 0\r\nContent-Length: 0\r\nConnection: close\r\nUser-Agent: fn-knock-service-probe/1\r\n\r\n"), expected: "webdav", direction: DirectionServer},
		{name: "rtsp_options", payload: []byte("OPTIONS * RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: fn-knock-service-probe/1\r\n\r\n"), expected: "rtsp", direction: DirectionServer},
		{name: "http_options", payload: []byte("OPTIONS * HTTP/1.1\r\nHost: " + hostHeader + "\r\nConnection: close\r\nUser-Agent: fn-knock-service-probe/1\r\n\r\n"), expected: "http1", direction: DirectionServer},
		{name: "redis_ping", payload: []byte("*1\r\n$4\r\nPING\r\n"), expected: "redis", direction: DirectionServer},
		{name: "postgres_ssl", payload: []byte{0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f}, expected: "postgresql", direction: DirectionServer},
		{name: "rdp_negotiation", payload: []byte{0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00}, expected: "rdp", direction: DirectionServer},
	}
	// Keep the WebDAV capability probes ahead of the generic HTTP probe even
	// on conventional HTTP ports. HTTP is the carrier protocol and is only a
	// soft match while a DAV header or multistatus body identifies the more
	// specific service.
	priority := map[int]string{443: "tls_client_hello", 554: "rtsp_options", 8554: "rtsp_options", 6379: "redis_ping", 5432: "postgres_ssl", 3389: "rdp_negotiation"}[port]
	if priority == "" {
		return all
	}
	ordered := make([]activeProbe, 0, len(all))
	for _, probe := range all {
		if probe.name == priority {
			ordered = append(ordered, probe)
		}
	}
	for _, probe := range all {
		if probe.name != priority {
			ordered = append(ordered, probe)
		}
	}
	return ordered
}

func probeTLS(ctx context.Context, target string) (models.StreamProbeResult, bool) {
	dialer := &net.Dialer{Timeout: probeIOTimeout}
	raw, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return models.StreamProbeResult{}, false
	}
	defer raw.Close()
	host, port, _ := net.SplitHostPort(target)
	serverName := strings.Trim(host, "[]")
	if address, parseErr := netip.ParseAddr(serverName); parseErr == nil && address.IsValid() {
		serverName = ""
	}
	_ = raw.SetDeadline(time.Now().Add(probeIOTimeout))
	conn := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, ServerName: serverName, MinVersion: tls.VersionTLS10}) // #nosec G402 -- identification probe deliberately accepts unknown certificates.
	if err := conn.HandshakeContext(ctx); err != nil {
		return models.StreamProbeResult{}, false
	}
	state := conn.ConnectionState()
	metadata := map[string]string{}
	if state.NegotiatedProtocol != "" {
		metadata["alpn"] = safeMetadata(state.NegotiatedProtocol)
	}
	if len(state.PeerCertificates) > 0 && state.PeerCertificates[0].Subject.CommonName != "" {
		metadata["certificate_common_name"] = safeMetadata(state.PeerCertificates[0].Subject.CommonName)
	}
	if !strings.ContainsAny(host, "\r\n") && !strings.ContainsAny(port, "\r\n") {
		hostHeader := httpProbeHost(target)
		request := []byte("OPTIONS / HTTP/1.1\r\nHost: " + hostHeader + "\r\nConnection: close\r\nUser-Agent: fn-knock-service-probe/1\r\n\r\n")
		if _, writeErr := conn.Write(request); writeErr == nil {
			response, readErr := readBounded(conn)
			if !errors.Is(readErr, errProbeResponseTooLarge) {
				classification := Classify("tcp", DirectionServer, response)
				if classification.State == ValidationMatch && classification.ServiceID == "webdav" {
					for key, value := range extractMetadata("webdav", response) {
						metadata[key] = value
					}
					return profileResult("webdav_tls", "strong", "webdav_tls_dav_header", metadata), true
				}
				for key, value := range extractMetadata("http1", response) {
					metadata[key] = value
				}
			}
		}
	}
	result := profileResult("tls", "strong", "tls_handshake", metadata)
	status, scheme, _ := authenticatedHTTPChallenge(result)
	return withAuthenticatedHTTPAmbiguity(result, status, scheme), true
}

func tcpExchange(ctx context.Context, target string, payload []byte, wait time.Duration) ([]byte, bool, error) {
	dialer := &net.Dialer{Timeout: probeIOTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return nil, false, err
	}
	defer conn.Close()
	deadline := time.Now().Add(wait)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	_ = conn.SetDeadline(deadline)
	if len(payload) > 0 {
		if _, err := conn.Write(payload); err != nil {
			return nil, true, err
		}
	}
	data, err := readBounded(conn)
	return data, true, err
}

func udpExchange(ctx context.Context, target string, payload []byte) ([]byte, bool, error) {
	dialer := &net.Dialer{Timeout: probeIOTimeout}
	conn, err := dialer.DialContext(ctx, "udp", target)
	if err != nil {
		return nil, false, err
	}
	defer conn.Close()
	deadline := time.Now().Add(probeIOTimeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	_ = conn.SetDeadline(deadline)
	if _, err := conn.Write(payload); err != nil {
		return nil, true, err
	}
	buffer := make([]byte, probeMaxResponse)
	n, err := conn.Read(buffer)
	return append([]byte(nil), buffer[:max(n, 0)]...), true, err
}

func readBounded(reader io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, probeMaxResponse+1))
	if len(data) > probeMaxResponse {
		return data[:probeMaxResponse], fmt.Errorf("%w: %d bytes", errProbeResponseTooLarge, probeMaxResponse)
	}
	return data, err
}

func matchedProbeResult(classification Classification, data []byte) models.StreamProbeResult {
	confidence := "strong"
	if classification.State == ValidationProbable {
		confidence = "probable"
	}
	metadata := extractMetadata(classification.ServiceID, data)
	return profileResult(classification.ServiceID, confidence, classification.Evidence, metadata)
}

func authenticatedHTTPChallenge(result models.StreamProbeResult) (string, string, bool) {
	if result.Profile.ServiceID != "http1" && result.Profile.ServiceID != "tls" {
		return "", "", false
	}
	status := result.Profile.Metadata["http_status"]
	scheme := result.Profile.Metadata["auth_scheme"]
	return status, scheme, status == "401" && scheme != ""
}

func withAuthenticatedHTTPAmbiguity(result models.StreamProbeResult, status, scheme string) models.StreamProbeResult {
	// A generic authentication gateway can emit the same challenge for ordinary
	// HTTP, WebDAV, CalDAV, and other HTTP extensions. The carrier is known, but
	// the configured application service is not. Keep the mapping fail-closed and
	// let an administrator select the expected strict-capable service.
	if (result.Profile.ServiceID == "http1" || result.Profile.ServiceID == "tls") && status == "401" && scheme != "" {
		if result.Profile.Metadata == nil {
			result.Profile.Metadata = map[string]string{}
		}
		result.Profile.Metadata["auth_probe_status"] = status
		result.Profile.Metadata["auth_scheme"] = scheme
		result.Profile.EvidenceCodes = append(result.Profile.EvidenceCodes, "http_auth_challenge")
		result.Status = "unknown"
		result.Message = "HTTP authentication challenge hides the application service; manual confirmation is required"
	}
	return result
}

func profileResult(serviceID, confidence, evidence string, metadata map[string]string) models.StreamProbeResult {
	descriptor, _, role, ok := Definition(serviceID)
	if !ok {
		return models.StreamProbeResult{Status: "unknown", Message: "unregistered service signature"}
	}
	roleConfidence := "strong"
	if role == "video_service" || role == "video_device" {
		roleConfidence = "probable"
	}
	if serviceID == "onvif" && metadata["device_type"] == "nvr" {
		role = "nvr"
		roleConfidence = "strong"
	}
	status := "verified"
	if confidence != "strong" || !descriptor.StrictCapable {
		status = "unknown"
	}
	profile := models.StreamServiceProfile{
		ServiceID:         serviceID,
		ServiceFamily:     descriptor.ServiceFamily,
		DeviceRole:        role,
		ServiceConfidence: confidence,
		RoleConfidence:    roleConfidence,
		EvidenceCodes:     []string{evidence},
		StrictCapable:     descriptor.StrictCapable,
		Metadata:          metadata,
	}
	return models.StreamProbeResult{Status: status, Profile: profile}
}

func extractMetadata(serviceID string, data []byte) map[string]string {
	metadata := map[string]string{}
	if serviceID == "onvif" && onvifDeclaresNVR(data) {
		metadata["device_type"] = "nvr"
	}
	if serviceID == "rtsp" || serviceID == "http1" || serviceID == "webdav" || serviceID == "webdav_tls" {
		for _, line := range strings.Split(string(data), "\n") {
			name, value, found := strings.Cut(line, ":")
			if found && strings.EqualFold(strings.TrimSpace(name), "Server") {
				metadata["server"] = safeMetadata(value)
			}
			if serviceID == "webdav" && found && strings.EqualFold(strings.TrimSpace(name), "DAV") {
				metadata["dav"] = safeMetadata(value)
			}
		}
		if line, complete := firstLine(data); complete {
			if status := httpStatusCode(strings.ToUpper(line)); status != "" {
				metadata["http_status"] = status
			}
		}
		if challenge, found := headerValue(data, "WWW-Authenticate"); found {
			if scheme, _, _ := strings.Cut(challenge, " "); scheme != "" {
				metadata["auth_scheme"] = safeMetadata(strings.ToLower(scheme))
			}
		}
	}
	if serviceID == "ssh" {
		if line, complete := firstLine(data); complete {
			metadata["software"] = safeMetadata(strings.TrimPrefix(line, "SSH-"))
		}
	}
	if len(metadata) == 0 {
		return nil
	}
	return metadata
}

func onvifDeclaresNVR(data []byte) bool {
	decoder := xml.NewDecoder(strings.NewReader(string(data)))
	decoder.Strict = false
	field := ""
	depth := 0
	var value strings.Builder
	for {
		token, err := decoder.Token()
		if err != nil {
			return false
		}
		switch typed := token.(type) {
		case xml.StartElement:
			if field != "" {
				depth++
				continue
			}
			candidate := strings.ToLower(strings.TrimSpace(typed.Name.Local))
			if candidate == "types" || candidate == "scopes" || candidate == "xaddrs" {
				field = candidate
				depth = 1
				value.Reset()
			}
		case xml.CharData:
			if field != "" && value.Len() < 4096 {
				remaining := 4096 - value.Len()
				chunk := []byte(typed)
				if len(chunk) > remaining {
					chunk = chunk[:remaining]
				}
				value.Write(chunk)
			}
		case xml.EndElement:
			if field == "" {
				continue
			}
			depth--
			if depth == 0 {
				if onvifFieldDeclaresNVR(field, value.String()) {
					return true
				}
				field = ""
				value.Reset()
			}
		}
	}
}

func onvifFieldDeclaresNVR(field, rawValue string) bool {
	value := strings.ToLower(rawValue)
	switch field {
	case "types":
		for token := range strings.FieldsSeq(value) {
			local := token
			if separator := strings.LastIndexByte(local, ':'); separator >= 0 {
				local = local[separator+1:]
			}
			if local == "nvr" || local == "networkvideorecorder" {
				return true
			}
		}
	case "scopes":
		for scope := range strings.FieldsSeq(value) {
			if containsPathSegment(scope, "/type/nvr") ||
				containsPathSegment(scope, "/type/networkvideorecorder") ||
				containsPathSegment(scope, "/name/nvr") {
				return true
			}
		}
	case "xaddrs":
		for address := range strings.FieldsSeq(value) {
			if containsPathSegment(address, "/nvr") || containsPathSegment(address, "/networkvideorecorder") {
				return true
			}
		}
	}
	return false
}

func containsPathSegment(value, marker string) bool {
	for offset := 0; offset < len(value); {
		index := strings.Index(value[offset:], marker)
		if index < 0 {
			return false
		}
		end := offset + index + len(marker)
		if end == len(value) || strings.ContainsRune("/?#", rune(value[end])) {
			return true
		}
		offset = end
	}
	return false
}

func safeMetadata(value string) string {
	value = strings.TrimSpace(value)
	var builder strings.Builder
	for _, character := range value {
		if character >= 0x20 && character != 0x7f {
			builder.WriteRune(character)
		}
		if builder.Len() >= 160 {
			break
		}
	}
	return builder.String()
}

func probeErrorResult(ctx context.Context, err error) models.StreamProbeResult {
	if ctx.Err() != nil || errors.Is(err, context.DeadlineExceeded) {
		return models.StreamProbeResult{Status: "timeout", Message: "probe deadline exceeded"}
	}
	if networkError, ok := err.(net.Error); ok && networkError.Timeout() {
		return models.StreamProbeResult{Status: "timeout", Message: "target did not respond before timeout"}
	}
	return models.StreamProbeResult{Status: "unreachable", Message: "target connection failed"}
}

func excludedActiveProbePort(target string) bool {
	port := targetPort(target)
	return port >= 9100 && port <= 9107
}

func targetPort(target string) int {
	_, rawPort, err := net.SplitHostPort(target)
	if err != nil {
		return 0
	}
	port, _ := strconv.Atoi(rawPort)
	return port
}

func httpProbeHost(target string) string {
	host, port, err := net.SplitHostPort(target)
	if err != nil || strings.ContainsAny(host, "\r\n") || strings.ContainsAny(port, "\r\n") {
		return "service-probe.invalid"
	}
	return net.JoinHostPort(host, port)
}

const onvifProbeEnvelope = `<?xml version="1.0" encoding="UTF-8"?>
<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:dn="http://www.onvif.org/ver10/network/wsdl"><e:Header><w:MessageID>uuid:4f4e4b4e-4f43-4b50-524f-424500000001</w:MessageID><w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To><w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action></e:Header><e:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe></e:Body></e:Envelope>`
