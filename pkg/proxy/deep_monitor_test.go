package proxy

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go-reauth-proxy/pkg/config"
	"go-reauth-proxy/pkg/deepmonitor"
	"go-reauth-proxy/pkg/grpc/pb"
	"go-reauth-proxy/pkg/models"
)

func TestDeepMonitorCapturesHTTPExchange(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Upstream", "yes")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write(append([]byte(`{"echo":`), append(body, '}')...))
	}))
	defer upstream.Close()
	logsDir := t.TempDir()
	handler := NewHandler(7996, 8080, nil, &config.AppConfig{
		HostRules: []models.HostRule{{Host: "abc.example.com", Target: upstream.URL}},
	}, logsDir, nil)
	defer handler.Close()
	session, err := handler.StartDeepMonitor("abc.example.com", deepmonitor.MinDuration)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "https://abc.example.com/api?full=1", bytes.NewBufferString(`{"secret":"value"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer raw-token")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	waitForDeepMonitorType(t, handler.DeepMonitorManager(), session.Id, "http_exchange")
	items, _, _, err := handler.DeepMonitorManager().Query(session.Id, "", 20, "http_exchange", "", "")
	if err != nil || len(items) != 1 {
		t.Fatalf("events = %#v, %v", items, err)
	}
	event, err := handler.DeepMonitorManager().GetEvent(session.Id, items[0].Id)
	if err != nil {
		t.Fatal(err)
	}
	if event.GetSummary().GetStatus() != http.StatusCreated || event.GetUpstream() == "" {
		t.Fatalf("event = %#v", event)
	}
	if got := headerValue(event.GetClientRequestHeaders(), "Authorization"); got != "Bearer raw-token" {
		t.Fatalf("authorization = %q", got)
	}
	if len(event.GetPayloads()) < 2 {
		t.Fatalf("payload refs = %#v", event.GetPayloads())
	}
}

func TestWebSocketFrameParserHandlesSplitMaskedFrame(t *testing.T) {
	manager, err := deepmonitor.NewManager(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	session, err := manager.Start("ws.example.com", deepmonitor.MinDuration)
	if err != nil {
		t.Fatal(err)
	}
	trace := &deepMonitorRequest{
		manager: manager, sessionID: session.Id, exchange: "connection",
		host: "ws.example.com", path: "/socket", clientIP: "198.51.100.8", identity: "alice",
	}
	parser := newWebSocketFrameParser(trace, "client_to_upstream", true)
	payload := []byte("hello")
	mask := [4]byte{1, 2, 3, 4}
	frame := []byte{0x81, 0x80 | byte(len(payload)), mask[0], mask[1], mask[2], mask[3]}
	for index, value := range payload {
		frame = append(frame, value^mask[index%4])
	}
	for _, part := range [][]byte{frame[:1], frame[1:4], frame[4:8], frame[8:]} {
		parser.Feed(part)
	}
	waitForDeepMonitorType(t, manager, session.Id, "ws_frame")
	items, _, _, _ := manager.Query(session.Id, "", 10, "ws_frame", "", "")
	event, err := manager.GetEvent(session.Id, items[0].Id)
	if err != nil {
		t.Fatal(err)
	}
	ws := event.GetWebsocketFrame()
	if !ws.GetMasked() || ws.GetOpcode() != 1 || ws.GetPayloadLength() != uint64(len(payload)) {
		t.Fatalf("websocket metadata = %#v", ws)
	}
	if summary := event.GetSummary(); summary.GetHost() != "ws.example.com" || summary.GetPath() != "/socket" || summary.GetClientIp() != "198.51.100.8" || summary.GetIdentity() != "alice" {
		t.Fatalf("websocket summary = %#v", summary)
	}
	if event.GetPayloads()[0].GetContentType() != "text/plain; charset=utf-8" {
		t.Fatalf("payload content type = %q", event.GetPayloads()[0].GetContentType())
	}
	file, _, _, err := manager.OpenPayload(session.Id, event.GetSummary().GetId(), event.GetPayloads()[0].GetPart(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	got, _ := io.ReadAll(file)
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload = %q", got)
	}
}

func TestWebSocketFrameParserCapturesRFC6455FrameSemantics(t *testing.T) {
	manager, err := deepmonitor.NewManager(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	session, err := manager.Start("frames.example.com", deepmonitor.MinDuration)
	if err != nil {
		t.Fatal(err)
	}
	trace := &deepMonitorRequest{manager: manager, sessionID: session.Id, exchange: "frames", host: "frames.example.com", path: "/ws"}
	parser := newWebSocketFrameParser(trace, "upstream_to_client", false)
	frames := [][]byte{
		{0x00, 0x01, 'c'},
		{0x82, 0x02, 0x00, 0xff},
		{0x89, 0x01, '!'},
		{0xc1, 0x03, 0xaa, 0xbb, 0xcc},
		{0x88, 0x05, 0x03, 0xe8, 'b', 'y', 'e'},
	}
	largePayload := bytes.Repeat([]byte{0x5a}, 65536)
	largeFrame := []byte{0x82, 0x7f, 0, 0, 0, 0, 0, 1, 0, 0}
	largeFrame = append(largeFrame, largePayload...)
	frames = append(frames, largeFrame)
	for _, frame := range frames {
		for len(frame) > 0 {
			n := min(17, len(frame))
			parser.Feed(frame[:n])
			frame = frame[n:]
		}
	}
	waitForDeepMonitorCount(t, manager, session.Id, "ws_frame", len(frames))
	items, _, _, err := manager.Query(session.Id, "", 20, "ws_frame", "", "")
	if err != nil {
		t.Fatal(err)
	}
	var compressed, closed, extended bool
	for _, item := range items {
		event, getErr := manager.GetEvent(session.Id, item.Id)
		if getErr != nil {
			t.Fatal(getErr)
		}
		frame := event.GetWebsocketFrame()
		compressed = compressed || (frame.GetOpcode() == 1 && frame.GetCompressed() && frame.GetRsv1())
		closed = closed || (frame.GetOpcode() == 8 && frame.GetCloseCode() == 1000 && frame.GetCloseReason() == "bye")
		extended = extended || (frame.GetPayloadLength() == uint64(len(largePayload)) && event.GetPayloads()[0].GetCapturedBytes() == uint64(len(largePayload)))
	}
	if !compressed || !closed || !extended {
		t.Fatalf("frame semantics: compressed=%v closed=%v extended=%v", compressed, closed, extended)
	}

	invalid := newWebSocketFrameParser(trace, "upstream_to_client", false)
	invalid.Feed([]byte{0x83, 0x00})
	invalid.Feed([]byte{0x81, 0x01, 'x'})
	waitForDeepMonitorCount(t, manager, session.Id, "monitor_notice", 1)
	items, _, _, err = manager.Query(session.Id, "", 20, "ws_frame", "", "")
	if err != nil || len(items) != len(frames) {
		t.Fatalf("invalid parser emitted frames: count=%d err=%v", len(items), err)
	}
}

func TestDeepMonitorWebSocketBodyIsByteTransparent(t *testing.T) {
	manager, err := deepmonitor.NewManager(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	session, err := manager.Start("transparent.example.com", deepmonitor.MinDuration)
	if err != nil {
		t.Fatal(err)
	}
	upstreamFrame := []byte{0x81, 0x02, 'o', 'k'}
	underlying := &memoryReadWriteCloser{reader: bytes.NewReader(upstreamFrame)}
	trace := &deepMonitorRequest{manager: manager, sessionID: session.Id, exchange: "transparent", host: "transparent.example.com", path: "/ws"}
	body := newDeepMonitorWebSocketBody(underlying, trace).(*deepMonitorWebSocketBody)
	read, err := io.ReadAll(body)
	if err != nil || !bytes.Equal(read, upstreamFrame) {
		t.Fatalf("read changed: %x err=%v", read, err)
	}
	clientPayload := []byte("hi")
	mask := [4]byte{9, 8, 7, 6}
	clientFrame := []byte{0x81, 0x82, mask[0], mask[1], mask[2], mask[3]}
	for index, value := range clientPayload {
		clientFrame = append(clientFrame, value^mask[index%4])
	}
	if _, err := body.Write(clientFrame); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(underlying.writes.Bytes(), clientFrame) {
		t.Fatalf("write changed: %x", underlying.writes.Bytes())
	}
	waitForDeepMonitorCount(t, manager, session.Id, "ws_frame", 2)
}

func TestCappedCaptureTracksObservedBytesAndTruncation(t *testing.T) {
	capture := newCappedCapture()
	payload := bytes.Repeat([]byte{0x42}, int(deepmonitor.PayloadLimitBytes)+1)
	if _, err := capture.Write(payload); err != nil {
		t.Fatal(err)
	}
	ref, captured := capture.snapshot("body", "application/octet-stream")
	if ref.GetObservedBytes() != uint64(len(payload)) || ref.GetCapturedBytes() != deepmonitor.PayloadLimitBytes || !ref.GetTruncated() {
		t.Fatalf("payload ref = %#v", ref)
	}
	if uint64(len(captured)) != deepmonitor.PayloadLimitBytes || ref.GetSha256() == "" {
		t.Fatalf("captured bytes = %d, sha256 = %q", len(captured), ref.GetSha256())
	}
}

type memoryReadWriteCloser struct {
	reader *bytes.Reader
	writes bytes.Buffer
}

func (m *memoryReadWriteCloser) Read(data []byte) (int, error)  { return m.reader.Read(data) }
func (m *memoryReadWriteCloser) Write(data []byte) (int, error) { return m.writes.Write(data) }
func (m *memoryReadWriteCloser) Close() error                   { return nil }

func headerValue(headers interface{ GetHeaders() []*pb.Header }, name string) string {
	for _, header := range headers.GetHeaders() {
		if header.GetName() == name && len(header.GetValues()) > 0 {
			return header.GetValues()[0]
		}
	}
	return ""
}

func waitForDeepMonitorType(t *testing.T, manager *deepmonitor.Manager, sessionID, eventType string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		items, _, _, _ := manager.Query(sessionID, "", 100, eventType, "", "")
		if len(items) > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("event type %s not recorded", eventType)
}

func waitForDeepMonitorCount(t *testing.T, manager *deepmonitor.Manager, sessionID, eventType string, count int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		items, _, _, _ := manager.Query(sessionID, "", 200, eventType, "", "")
		if len(items) >= count {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("event type %s did not reach %d events", eventType, count)
}
