package proxy

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptrace"
	"strconv"
	"strings"
	"sync"
	"time"

	"go-reauth-proxy/pkg/deepmonitor"
	"go-reauth-proxy/pkg/gatewaylog"
	"go-reauth-proxy/pkg/grpc/pb"
)

var errDeepMonitorUnavailable = errors.New("deep monitor storage is unavailable")

func (h *Handler) DeepMonitorManager() *deepmonitor.Manager {
	if h == nil {
		return nil
	}
	return h.deepMonitorManager
}

func (h *Handler) StartDeepMonitor(host string, duration time.Duration) (*pb.DeepMonitorSession, error) {
	if h == nil || h.deepMonitorManager == nil {
		return nil, errDeepMonitorUnavailable
	}
	host = deepmonitor.NormalizeHost(host)
	if host == "" || strings.Contains(host, "*") {
		return nil, errors.New("an exact host is required")
	}
	snapshot := h.snapshotForRequest()
	if _, ok := snapshot.hostRulesByHost[host]; !ok {
		return nil, errors.New("host rule not found")
	}
	return h.deepMonitorManager.Start(host, duration)
}

type deepMonitorContextKey struct{}

type cappedCapture struct{ *deepmonitor.Capture }

func newCappedCapture(managers ...*deepmonitor.Manager) *cappedCapture {
	var manager *deepmonitor.Manager
	if len(managers) > 0 {
		manager = managers[0]
	}
	return &cappedCapture{Capture: manager.NewCapture()}
}

func (c *cappedCapture) snapshot(part, contentType string) (*pb.DeepMonitorPayloadRef, []byte) {
	if c == nil {
		return nil, nil
	}
	return c.Reference(part, contentType), c.Snapshot()
}

type deepMonitorReadCloser struct {
	io.ReadCloser
	capture *cappedCapture
}

func (r *deepMonitorReadCloser) Read(data []byte) (int, error) {
	n, err := r.ReadCloser.Read(data)
	if n > 0 {
		_, _ = r.capture.Write(data[:n])
	}
	return n, err
}

type deepMonitorRequest struct {
	manager   *deepmonitor.Manager
	sessionID string
	start     time.Time
	exchange  string
	host      string
	path      string

	mu                      sync.Mutex
	finished                bool
	clientRequestHeaders    http.Header
	upstreamRequestHeaders  http.Header
	upstreamResponseHeaders http.Header
	clientResponseHeaders   http.Header
	upstream                string
	upstreamProtocol        string
	upstreamStatus          int
	errorText               string
	requestBody             *cappedCapture
	upstreamResponseBody    *cappedCapture
	clientResponseBody      *cappedCapture
	websocket               bool
	websocketOpened         bool
	websocketSubprotocol    string
	websocketExtensions     string
	clientIP                string
	identity                string

	dnsStart, dnsDone         time.Time
	connectStart, connectDone time.Time
	tlsStart, tlsDone         time.Time
	gotConn                   time.Time
	requestWritten, firstByte time.Time
	upstreamResponseStart     time.Time
	upstreamResponseFinished  time.Time
	authDuration              time.Duration
	wafDuration               time.Duration
	routeDuration             time.Duration
}

func (h *Handler) beginDeepMonitor(r *http.Request, start time.Time) *deepMonitorRequest {
	if h == nil || h.deepMonitorManager == nil || r == nil {
		return nil
	}
	sessionID, ok := h.deepMonitorManager.ActiveSession(requestHostForRouting(r))
	if !ok {
		return nil
	}
	trace := &deepMonitorRequest{
		manager: h.deepMonitorManager, sessionID: sessionID, start: start,
		exchange: newDeepMonitorExchangeID(), host: requestHostForRouting(r), path: r.URL.Path,
		clientRequestHeaders: r.Header.Clone(),
		requestBody:          &cappedCapture{h.deepMonitorManager.NewCapture(sessionID)}, upstreamResponseBody: &cappedCapture{h.deepMonitorManager.NewCapture(sessionID)},
		clientResponseBody: &cappedCapture{h.deepMonitorManager.NewCapture(sessionID)},
		websocket:          strings.EqualFold(strings.TrimSpace(r.Header.Get("Upgrade")), "websocket"),
	}
	event := trace.baseEvent(r, "http_started")
	trace.manager.Record(sessionID, event, nil)
	return trace
}

func withDeepMonitor(r *http.Request, trace *deepMonitorRequest) *http.Request {
	if r == nil || trace == nil {
		return r
	}
	r = r.WithContext(context.WithValue(r.Context(), deepMonitorContextKey{}, trace))
	if r.Body != nil {
		r.Body = &deepMonitorReadCloser{ReadCloser: r.Body, capture: trace.requestBody}
	}
	return r
}

func deepMonitorFromRequest(r *http.Request) *deepMonitorRequest {
	if r == nil {
		return nil
	}
	trace, _ := r.Context().Value(deepMonitorContextKey{}).(*deepMonitorRequest)
	return trace
}

func (h *Handler) monitoredTransport(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	// The deep-monitor transport wrapper is stateless per request: it resolves
	// the active trace from the request context. Reuse the Handler's shared
	// wrapper for the common proxy transport instead of allocating a new one
	// per proxied request.
	if h != nil && h.proxyRoundTripper != nil && base == h.proxyTransport {
		return h.proxyRoundTripper
	}
	return deepMonitorTransport{base: base}
}

type deepMonitorTransport struct{ base http.RoundTripper }

func (t deepMonitorTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	trace := deepMonitorFromRequest(req)
	if trace == nil {
		return t.base.RoundTrip(req)
	}
	trace.mu.Lock()
	trace.upstreamRequestHeaders = req.Header.Clone()
	trace.upstream = req.URL.String()
	trace.mu.Unlock()
	clientTrace := &httptrace.ClientTrace{
		DNSStart:             func(httptrace.DNSStartInfo) { trace.setTime(&trace.dnsStart) },
		DNSDone:              func(httptrace.DNSDoneInfo) { trace.setTime(&trace.dnsDone) },
		ConnectStart:         func(_, _ string) { trace.setTime(&trace.connectStart) },
		ConnectDone:          func(_, _ string, _ error) { trace.setTime(&trace.connectDone) },
		TLSHandshakeStart:    func() { trace.setTime(&trace.tlsStart) },
		TLSHandshakeDone:     func(tls.ConnectionState, error) { trace.setTime(&trace.tlsDone) },
		GotConn:              func(httptrace.GotConnInfo) { trace.setTime(&trace.gotConn) },
		WroteRequest:         func(httptrace.WroteRequestInfo) { trace.setTime(&trace.requestWritten) },
		GotFirstResponseByte: func() { trace.setTime(&trace.firstByte) },
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), clientTrace))
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		trace.mu.Lock()
		trace.errorText = err.Error()
		trace.mu.Unlock()
		return nil, err
	}
	trace.mu.Lock()
	trace.upstreamResponseStart = time.Now()
	trace.upstreamResponseHeaders = resp.Header.Clone()
	trace.upstreamStatus = resp.StatusCode
	trace.upstreamProtocol = resp.Proto
	if resp.StatusCode == http.StatusSwitchingProtocols && strings.EqualFold(strings.TrimSpace(resp.Header.Get("Upgrade")), "websocket") {
		trace.websocket = true
		trace.websocketOpened = true
		trace.websocketSubprotocol = resp.Header.Get("Sec-WebSocket-Protocol")
		trace.websocketExtensions = resp.Header.Get("Sec-WebSocket-Extensions")
	}
	trace.mu.Unlock()
	if trace.websocketOpened {
		trace.recordWebSocketOpen(req, resp)
		resp.Body = newDeepMonitorWebSocketBody(resp.Body, trace)
	} else {
		resp.Body = &deepMonitorUpstreamBody{ReadCloser: resp.Body, trace: trace}
	}
	return resp, nil
}

func (t *deepMonitorRequest) setTime(target *time.Time) {
	t.mu.Lock()
	*target = time.Now()
	t.mu.Unlock()
}

func (t *deepMonitorRequest) addAuthDuration(duration time.Duration) {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.authDuration += duration
	t.mu.Unlock()
}

func (t *deepMonitorRequest) addWAFDuration(duration time.Duration) {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.wafDuration += duration
	t.mu.Unlock()
}

func (t *deepMonitorRequest) addRouteDuration(duration time.Duration) {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.routeDuration += duration
	t.mu.Unlock()
}

type deepMonitorUpstreamBody struct {
	io.ReadCloser
	trace *deepMonitorRequest
}

func (b *deepMonitorUpstreamBody) Read(data []byte) (int, error) {
	n, err := b.ReadCloser.Read(data)
	if n > 0 {
		_, _ = b.trace.upstreamResponseBody.Write(data[:n])
	}
	if err != nil {
		b.trace.mu.Lock()
		if b.trace.upstreamResponseFinished.IsZero() {
			b.trace.upstreamResponseFinished = time.Now()
		}
		b.trace.mu.Unlock()
	}
	return n, err
}

func (b *deepMonitorUpstreamBody) Close() error {
	b.trace.mu.Lock()
	if b.trace.upstreamResponseFinished.IsZero() {
		b.trace.upstreamResponseFinished = time.Now()
	}
	b.trace.mu.Unlock()
	return b.ReadCloser.Close()
}

func (t *deepMonitorRequest) captureClientHeader(header http.Header) {
	if t == nil {
		return
	}
	t.mu.Lock()
	if t.clientResponseHeaders == nil {
		t.clientResponseHeaders = header.Clone()
	}
	t.mu.Unlock()
}

func (t *deepMonitorRequest) captureClientBody(data []byte) {
	if t == nil {
		return
	}
	t.mu.Lock()
	opened := t.websocketOpened
	t.mu.Unlock()
	if !opened {
		_, _ = t.clientResponseBody.Write(data)
	}
}

func (t *deepMonitorRequest) finish(r *http.Request, entry gatewaylog.Entry) {
	if t == nil {
		return
	}
	t.mu.Lock()
	if t.finished {
		t.mu.Unlock()
		return
	}
	t.finished = true
	t.mu.Unlock()
	defer t.requestBody.Release()
	defer t.upstreamResponseBody.Release()
	defer t.clientResponseBody.Release()
	if !t.manager.IsActive(t.sessionID) {
		return
	}
	t.mu.Lock()
	clientReqHeaders := t.clientRequestHeaders.Clone()
	upstreamReqHeaders := t.upstreamRequestHeaders.Clone()
	upstreamRespHeaders := t.upstreamResponseHeaders.Clone()
	clientRespHeaders := t.clientResponseHeaders.Clone()
	upstream := t.upstream
	upstreamProtocol := t.upstreamProtocol
	upstreamStatus := t.upstreamStatus
	errorText := t.errorText
	websocket := t.websocket
	websocketOpened := t.websocketOpened
	timing := t.timingLocked()
	t.mu.Unlock()
	status := int32(entry.Status)
	if upstreamStatus == http.StatusSwitchingProtocols {
		status = http.StatusSwitchingProtocols
	}
	event := t.baseEvent(r, "http_exchange")
	event.Summary.Status = status
	event.Summary.ClientIp = entry.RemoteIP
	event.Summary.Identity = firstNonEmpty(entry.AuthCredentialName, entry.AuthCredentialID)
	event.Upstream = firstNonEmpty(upstream, entry.Upstream)
	event.Protocol = firstNonEmpty(upstreamProtocol, entry.Protocol)
	event.RemoteAddr = entry.RemoteAddr
	event.AuthCredentialId = entry.AuthCredentialID
	event.AuthCredentialName = entry.AuthCredentialName
	event.AuthCredentialMethod = entry.AuthCredentialMethod
	event.AuthLinkedTotpId = entry.AuthLinkedTOTPID
	event.AuthLinkedTotpName = entry.AuthLinkedTOTPName
	event.AuthDecision = entry.AuthDecision
	event.AuthRuleGroupId = entry.AuthRuleGroupID
	event.AuthGrantState = entry.AuthGrantState
	event.RouteType = entry.RouteType
	event.RouteKey = entry.RouteKey
	event.WafTraceId = entry.WAFTraceID
	event.WafMode = entry.WAFMode
	event.WafRuleIds = make([]int32, len(entry.WAFRuleIDs))
	for index, ruleID := range entry.WAFRuleIDs {
		event.WafRuleIds[index] = int32(ruleID)
	}
	event.WafAction = entry.WAFAction
	event.WafBundle = entry.WAFBundle
	event.WafBlocked = entry.WAFBlocked
	event.GeneralBlacklistBlocked = entry.GeneralBlacklistBlocked
	event.ClientIpSource = deepMonitorClientIPSource(entry)
	event.ClientRequestHeaders = headerList(clientReqHeaders)
	event.UpstreamRequestHeaders = headerList(upstreamReqHeaders)
	event.UpstreamResponseHeaders = headerList(upstreamRespHeaders)
	event.ClientResponseHeaders = headerList(clientRespHeaders)
	event.Timing = timing
	event.Error = errorText
	payloads := make(map[string]*deepmonitor.Capture)
	if ref := t.requestBody.Seal("request_body", r.Header.Get("Content-Type")); ref != nil {
		event.Payloads = append(event.Payloads, ref)
		payloads[ref.Part] = t.requestBody.Capture
	}
	upstreamRef := t.upstreamResponseBody.Seal("upstream_response_body", upstreamRespHeaders.Get("Content-Type"))
	clientRef := t.clientResponseBody.Seal("client_response_body", clientRespHeaders.Get("Content-Type"))
	if upstreamRef != nil {
		event.Payloads = append(event.Payloads, upstreamRef)
		payloads[upstreamRef.Part] = t.upstreamResponseBody.Capture
	}
	if clientRef != nil && (upstreamRef == nil || clientRef.Sha256 != upstreamRef.Sha256 || clientRef.ObservedBytes != upstreamRef.ObservedBytes || clientRef.CapturedBytes != upstreamRef.CapturedBytes) {
		event.Payloads = append(event.Payloads, clientRef)
		payloads[clientRef.Part] = t.clientResponseBody.Capture
	} else {
		t.clientResponseBody.Release()
	}
	for _, ref := range event.Payloads {
		event.Summary.PayloadBytes += ref.CapturedBytes
		event.Summary.Truncated = event.Summary.Truncated || ref.Truncated
	}
	t.manager.RecordCaptured(t.sessionID, event, payloads)
	if websocket && websocketOpened {
		closeEvent := t.baseEvent(r, "ws_close")
		closeEvent.Summary.Status = http.StatusSwitchingProtocols
		closeEvent.Summary.ClientIp = entry.RemoteIP
		closeEvent.Summary.Identity = event.Summary.Identity
		closeEvent.Timing = timing
		t.manager.Record(t.sessionID, closeEvent, nil)
	}
}

func (t *deepMonitorRequest) timingLocked() *pb.DeepMonitorTiming {
	return &pb.DeepMonitorTiming{
		TotalMs:        time.Since(t.start).Milliseconds(),
		DnsMs:          durationMillis(t.dnsStart, t.dnsDone),
		ConnectMs:      durationMillis(t.connectStart, t.connectDone),
		TlsMs:          durationMillis(t.tlsStart, t.tlsDone),
		RequestWriteMs: durationMillis(t.gotConn, t.requestWritten),
		TtfbMs:         durationMillis(t.requestWritten, t.firstByte),
		UpstreamReadMs: durationMillis(t.upstreamResponseStart, t.upstreamResponseFinished),
		AuthMs:         t.authDuration.Milliseconds(),
		WafMs:          t.wafDuration.Milliseconds(),
		RouteMs:        t.routeDuration.Milliseconds(),
	}
}

func (t *deepMonitorRequest) baseEvent(r *http.Request, eventType string) *pb.DeepMonitorEvent {
	host, method, requestURI, path, scheme, protocol, userAgent, referer := "", "", "", "", "", "", "", ""
	if r != nil {
		host, method, requestURI, path = requestHostForRouting(r), r.Method, r.URL.RequestURI(), r.URL.Path
		scheme, protocol, userAgent, referer = requestScheme(r), r.Proto, r.UserAgent(), r.Referer()
	}
	t.mu.Lock()
	monitorHost, monitorPath := t.host, t.path
	clientIP, identity := t.clientIP, t.identity
	t.mu.Unlock()
	if host == "" {
		host = monitorHost
	}
	if path == "" {
		path = monitorPath
	}
	event := &pb.DeepMonitorEvent{
		Summary: &pb.DeepMonitorEventSummary{Type: eventType, ExchangeId: t.exchange, Host: host, Method: method, Path: path, ClientIp: clientIP, Identity: identity},
		Scheme:  scheme, Protocol: protocol, RequestUri: requestURI,
		UserAgent: userAgent, Referer: referer,
	}
	if r != nil && r.TLS != nil {
		event.TlsVersion = tlsVersionName(r.TLS.Version)
		event.TlsCipher = tls.CipherSuiteName(r.TLS.CipherSuite)
		event.TlsServerName = r.TLS.ServerName
		event.TlsAlpn = r.TLS.NegotiatedProtocol
	}
	return event
}

func (t *deepMonitorRequest) setClientIP(clientIP string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.clientIP = clientIP
	t.mu.Unlock()
}

func (t *deepMonitorRequest) setConnectionIdentity(clientIP string, result authCheckResult) {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.clientIP = clientIP
	t.identity = firstNonEmpty(result.credentialIdentity.credentialName, result.credentialIdentity.credentialID)
	t.mu.Unlock()
}

func (t *deepMonitorRequest) recordWebSocketOpen(req *http.Request, resp *http.Response) {
	event := t.baseEvent(req, "ws_open")
	event.Summary.ConnectionId = t.exchange
	event.Summary.Status = http.StatusSwitchingProtocols
	event.Upstream = req.URL.String()
	event.UpstreamRequestHeaders = headerList(req.Header)
	event.UpstreamResponseHeaders = headerList(resp.Header)
	event.WebsocketSubprotocol = resp.Header.Get("Sec-WebSocket-Protocol")
	event.WebsocketExtensions = resp.Header.Get("Sec-WebSocket-Extensions")
	t.manager.Record(t.sessionID, event, nil)
}

func (t *deepMonitorRequest) recordCustomWebSocketOpen(req *http.Request, upstream string, requestHeaders, responseHeaders http.Header, subprotocol string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.websocket = true
	t.websocketOpened = true
	t.websocketSubprotocol = subprotocol
	t.upstream = upstream
	t.upstreamRequestHeaders = requestHeaders.Clone()
	t.upstreamResponseHeaders = responseHeaders.Clone()
	t.upstreamStatus = http.StatusSwitchingProtocols
	t.mu.Unlock()
	event := t.baseEvent(req, "ws_open")
	event.Summary.ConnectionId = t.exchange
	event.Summary.Status = http.StatusSwitchingProtocols
	event.Upstream = upstream
	event.UpstreamRequestHeaders = headerList(requestHeaders)
	event.UpstreamResponseHeaders = headerList(responseHeaders)
	event.WebsocketSubprotocol = subprotocol
	event.Error = "decoded gorilla/websocket relay; frame fragmentation and mask metadata are unavailable on this specialized path"
	t.manager.Record(t.sessionID, event, nil)
}

func (t *deepMonitorRequest) recordWebSocketMessage(direction string, messageType int, payload []byte) {
	if t == nil || !t.manager.IsActive(t.sessionID) {
		return
	}
	capture := t.manager.NewCapture(t.sessionID)
	_, _ = capture.Write(payload)
	frame := websocketFrameCapture{fin: true, opcode: byte(messageType),
		payloadLength: uint64(len(payload)), capture: capture}
	t.recordWebSocketFrame(direction, frame)
}

func (t *deepMonitorRequest) recordWebSocketFrame(direction string, frame websocketFrameCapture) {
	defer frame.capture.Release()
	ref := frame.capture.Seal("ws_"+direction+"_payload", "application/octet-stream")
	if ref == nil {
		ref = &pb.DeepMonitorPayloadRef{Part: "ws_" + direction + "_payload", ContentType: "application/octet-stream", Sha256: hex.EncodeToString(sha256.New().Sum(nil))}
	}
	t.mu.Lock()
	host, path, clientIP, identity := t.host, t.path, t.clientIP, t.identity
	t.mu.Unlock()
	event := &pb.DeepMonitorEvent{
		Summary: &pb.DeepMonitorEventSummary{
			Type: "ws_frame", ExchangeId: t.exchange, ConnectionId: t.exchange,
			Host: host, Path: path, ClientIp: clientIP, Identity: identity, Direction: direction,
			PayloadBytes: ref.CapturedBytes, Truncated: ref.Truncated,
		},
		WebsocketFrame: &pb.DeepMonitorWebSocketFrame{
			Direction: direction, Fin: frame.fin, Rsv1: frame.rsv1, Rsv2: frame.rsv2,
			Rsv3: frame.rsv3, Opcode: uint32(frame.opcode), Masked: frame.masked,
			MaskKey: frame.maskKey[:], PayloadLength: frame.payloadLength,
			CloseCode: int32(frame.closeCode), CloseReason: frame.closeReason,
			Compressed: frame.rsv1,
		},
	}
	part := "ws_" + direction + "_payload"
	contentType := "application/octet-stream"
	if frame.opcode == 1 && !frame.rsv1 {
		contentType = "text/plain; charset=utf-8"
	}
	ref.ContentType = contentType
	event.Payloads = []*pb.DeepMonitorPayloadRef{ref}
	t.manager.RecordCaptured(t.sessionID, event, map[string]*deepmonitor.Capture{part: frame.capture})
}

func (t *deepMonitorRequest) recordNotice(direction, notice string) {
	event := &pb.DeepMonitorEvent{Summary: &pb.DeepMonitorEventSummary{
		Type: "monitor_notice", ExchangeId: t.exchange, ConnectionId: t.exchange,
		Direction: direction, Notice: notice,
	}}
	t.manager.Record(t.sessionID, event, nil)
}

func headerList(header http.Header) *pb.HeaderList {
	if len(header) == 0 {
		return nil
	}
	names := make([]string, 0, len(header))
	for name := range header {
		names = append(names, name)
	}
	sortStrings(names)
	result := &pb.HeaderList{Headers: make([]*pb.Header, 0, len(names))}
	for _, name := range names {
		result.Headers = append(result.Headers, &pb.Header{Name: name, Values: append([]string(nil), header.Values(name)...)})
	}
	return result
}

func sortStrings(values []string) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}

func durationMillis(start, end time.Time) int64 {
	if start.IsZero() || end.IsZero() || end.Before(start) {
		return 0
	}
	return end.Sub(start).Milliseconds()
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return strconv.Itoa(int(version))
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func deepMonitorClientIPSource(entry gatewaylog.Entry) string {
	clientIP := normalizeIPAddress(entry.RemoteIP)
	for _, candidate := range []struct {
		name  string
		value string
	}{
		{name: "eo_connecting_ip", value: entry.EOConnectingIP},
		{name: "ali_real_client_ip", value: entry.AliRealClientIP},
		{name: "x_forwarded_for", value: entry.XForwardedFor},
		{name: "x_real_ip", value: entry.XRealIP},
	} {
		if value := normalizeIPAddress(candidate.value); value != "" && value == clientIP {
			return candidate.name
		}
	}
	if clientIP != "" {
		return "remote_addr"
	}
	return ""
}

func newDeepMonitorExchangeID() string { return strconv.FormatInt(time.Now().UnixNano(), 36) }

type deepMonitorWebSocketBody struct {
	io.ReadWriteCloser
	upstreamToClient *websocketFrameParser
	clientToUpstream *websocketFrameParser
}

func newDeepMonitorWebSocketBody(body io.ReadCloser, trace *deepMonitorRequest) io.ReadCloser {
	rwc, ok := body.(io.ReadWriteCloser)
	if !ok {
		trace.recordNotice("", "websocket upstream body is not writable")
		return body
	}
	return &deepMonitorWebSocketBody{
		ReadWriteCloser:  rwc,
		upstreamToClient: newWebSocketFrameParser(trace, "upstream_to_client", false),
		clientToUpstream: newWebSocketFrameParser(trace, "client_to_upstream", true),
	}
}

func (b *deepMonitorWebSocketBody) Read(data []byte) (int, error) {
	n, err := b.ReadWriteCloser.Read(data)
	if n > 0 {
		b.upstreamToClient.Feed(data[:n])
	}
	return n, err
}

func (b *deepMonitorWebSocketBody) Write(data []byte) (int, error) {
	n, err := b.ReadWriteCloser.Write(data)
	if n > 0 {
		b.clientToUpstream.Feed(data[:n])
	}
	return n, err
}

func (b *deepMonitorWebSocketBody) Close() error {
	err := b.ReadWriteCloser.Close()
	b.upstreamToClient.release()
	b.clientToUpstream.release()
	return err
}

type websocketFrameCapture struct {
	fin, rsv1, rsv2, rsv3, masked bool
	opcode                        byte
	maskKey                       [4]byte
	payloadLength                 uint64
	capture                       *deepmonitor.Capture
	closeCode                     int
	closeReason                   string
}

type websocketFrameParser struct {
	mu         sync.Mutex
	trace      *deepMonitorRequest
	direction  string
	expectMask bool
	disabled   bool
	header     []byte
	frame      websocketFrameCapture
	remaining  uint64
	position   uint64
}

func newWebSocketFrameParser(trace *deepMonitorRequest, direction string, expectMask bool) *websocketFrameParser {
	return &websocketFrameParser{trace: trace, direction: direction, expectMask: expectMask, header: make([]byte, 0, 14)}
}

func (p *websocketFrameParser) release() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.disabled = true
	p.frame.capture.Release()
}

func (p *websocketFrameParser) Feed(data []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.disabled || !p.trace.manager.IsActive(p.trace.sessionID) {
		p.disabled = true
		p.frame.capture.Release()
		return
	}
	for len(data) > 0 {
		if p.remaining == 0 && p.frame.capture == nil {
			needed := 2
			if len(p.header) >= 2 {
				lengthCode := p.header[1] & 0x7f
				if lengthCode == 126 {
					needed += 2
				} else if lengthCode == 127 {
					needed += 8
				}
				if p.header[1]&0x80 != 0 {
					needed += 4
				}
			}
			take := needed - len(p.header)
			if take > len(data) {
				take = len(data)
			}
			p.header = append(p.header, data[:take]...)
			data = data[take:]
			if len(p.header) < 2 {
				continue
			}
			lengthCode := p.header[1] & 0x7f
			needed = 2
			if lengthCode == 126 {
				needed += 2
			} else if lengthCode == 127 {
				needed += 8
			}
			if p.header[1]&0x80 != 0 {
				needed += 4
			}
			if len(p.header) < needed {
				continue
			}
			if !p.startFrame() {
				p.disabled = true
				p.trace.recordNotice(p.direction, "invalid RFC6455 frame header; parser disabled")
				return
			}
			if p.remaining == 0 {
				p.finishFrame()
			}
			continue
		}
		take := uint64(len(data))
		if take > p.remaining {
			take = p.remaining
		}
		chunk := data[:int(take)]
		if p.frame.masked {
			// Decode bounded chunks; a large Feed must not allocate a second frame.
			var decoded [4096]byte
			for offset := 0; offset < len(chunk); {
				n := min(len(decoded), len(chunk)-offset)
				copy(decoded[:n], chunk[offset:offset+n])
				for i := 0; i < n; i++ {
					decoded[i] ^= p.frame.maskKey[(p.position+uint64(offset+i))%4]
				}
				_, _ = p.frame.capture.Write(decoded[:n])
				offset += n
			}
		} else {
			_, _ = p.frame.capture.Write(chunk)
		}
		p.position += take
		p.remaining -= take
		data = data[int(take):]
		if p.remaining == 0 {
			p.finishFrame()
		}
	}
}

func (p *websocketFrameParser) startFrame() bool {
	b0, b1 := p.header[0], p.header[1]
	p.frame = websocketFrameCapture{fin: b0&0x80 != 0, rsv1: b0&0x40 != 0, rsv2: b0&0x20 != 0, rsv3: b0&0x10 != 0, opcode: b0 & 0x0f, masked: b1&0x80 != 0}
	switch p.frame.opcode {
	case 0, 1, 2, 8, 9, 10:
	default:
		return false
	}
	if p.expectMask != p.frame.masked {
		return false
	}
	index := 2
	lengthCode := b1 & 0x7f
	switch lengthCode {
	case 126:
		p.frame.payloadLength = uint64(binary.BigEndian.Uint16(p.header[index : index+2]))
		index += 2
		if p.frame.payloadLength < 126 {
			return false
		}
	case 127:
		p.frame.payloadLength = binary.BigEndian.Uint64(p.header[index : index+8])
		index += 8
		if p.frame.payloadLength&(uint64(1)<<63) != 0 || p.frame.payloadLength <= 65535 {
			return false
		}
	default:
		p.frame.payloadLength = uint64(lengthCode)
	}
	if p.frame.masked {
		copy(p.frame.maskKey[:], p.header[index:index+4])
	}
	if p.frame.opcode >= 8 && (!p.frame.fin || p.frame.payloadLength > 125) {
		return false
	}
	p.remaining = p.frame.payloadLength
	p.position = 0
	p.frame.capture = p.trace.manager.NewCapture(p.trace.sessionID)
	p.header = p.header[:0]
	return true
}

func (p *websocketFrameParser) finishFrame() {
	if p.frame.opcode == 8 {
		payload := p.frame.capture.Snapshot()
		if len(payload) >= 2 {
			p.frame.closeCode = int(binary.BigEndian.Uint16(payload[:2]))
			p.frame.closeReason = string(payload[2:])
		}
	}
	p.trace.recordWebSocketFrame(p.direction, p.frame)
	p.frame = websocketFrameCapture{}
	p.remaining = 0
	p.position = 0
}
