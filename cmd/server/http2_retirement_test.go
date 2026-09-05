package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func newRetirementResponseServer(t *testing.T, useHTTP2 bool) (*httptest.Server, []byte) {
	t.Helper()
	tracker := &proxyConnTracker{}
	payload := bytes.Repeat([]byte("p"), 11740)
	server := httptest.NewUnstartedServer(proxyConnectionRetirementHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/retire" {
			// Model an SSL/protocol update after this request has entered the
			// handler. Its complete response must survive the idle transition.
			tracker.retireForServerNames(nil)
		}
		if r.URL.Path == "/override" {
			// Existing SSE/custom handlers may overwrite the retirement signal.
			// The next ordinary request should still request graceful shutdown.
			w.Header().Set("Connection", "keep-alive")
		}
		w.Header().Set("Content-Length", fmt.Sprint(len(payload)))
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write(payload)
	})))
	server.Config.ConnContext = tracker.connContext
	server.Config.ConnState = tracker.update
	server.Config.IdleTimeout = 120 * time.Second
	server.EnableHTTP2 = useHTTP2
	server.StartTLS()
	t.Cleanup(server.Close)
	return server, payload
}

func TestHTTP2RetirementFlushesEndStreamAndSendsGoAway(t *testing.T) {
	server, payload := newRetirementResponseServer(t, true)
	conn, err := tls.Dial("tcp", server.Listener.Addr().String(), &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if conn.ConnectionState().NegotiatedProtocol != "h2" {
		t.Fatal("HTTP/2 was not negotiated")
	}
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, http2.ClientPreface); err != nil {
		t.Fatal(err)
	}
	framer := http2.NewFramer(conn, conn)
	framer.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	if err := framer.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	var encoded bytes.Buffer
	encoder := hpack.NewEncoder(&encoded)
	for i, path := range []string{"/retire", "/override", "/drain"} {
		streamID := uint32(i*2 + 1)
		encoded.Reset()
		for _, field := range []hpack.HeaderField{{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "https"}, {Name: ":authority", Value: "example.test"}, {Name: ":path", Value: path}} {
			if err := encoder.WriteField(field); err != nil {
				t.Fatal(err)
			}
		}
		if err := framer.WriteHeaders(http2.HeadersFrameParam{StreamID: streamID, BlockFragment: encoded.Bytes(), EndHeaders: true, EndStream: true}); err != nil {
			t.Fatal(err)
		}
		var body []byte
		var endStream, goAway, gotStatus bool
		for !endStream || (path == "/drain" && !goAway) {
			frame, err := framer.ReadFrame()
			if err != nil {
				t.Fatalf("%s: received %d/%d bytes, END_STREAM=%v GOAWAY=%v: %v", path, len(body), len(payload), endStream, goAway, err)
			}
			switch frame := frame.(type) {
			case *http2.SettingsFrame:
				if !frame.IsAck() {
					if err := framer.WriteSettingsAck(); err != nil {
						t.Fatal(err)
					}
				}
			case *http2.MetaHeadersFrame:
				if frame.StreamID != streamID {
					t.Fatalf("unexpected response stream %d", frame.StreamID)
				}
				for _, field := range frame.Fields {
					if field.Name == "connection" {
						t.Fatal("internal Connection signal leaked to HTTP/2 wire")
					}
					if field.Name == ":status" {
						gotStatus = field.Value == "404"
					}
				}
				endStream = frame.StreamEnded()
			case *http2.DataFrame:
				if frame.StreamID != streamID {
					t.Fatalf("unexpected data stream %d", frame.StreamID)
				}
				body = append(body, frame.Data()...)
				endStream = frame.StreamEnded()
			case *http2.GoAwayFrame:
				if path != "/drain" || frame.ErrCode != http2.ErrCodeNo || frame.LastStreamID < streamID {
					t.Fatalf("%s: unexpected GOAWAY: %v", path, frame)
				}
				goAway = true
			case *http2.RSTStreamFrame:
				t.Fatalf("%s: response was reset: %v", path, frame)
			}
		}
		if !gotStatus || !bytes.Equal(body, payload) {
			t.Fatalf("%s: status404=%v body=%d/%d", path, gotStatus, len(body), len(payload))
		}
	}
}

func TestRetirementKeepsResponsesCompleteAndReconnects(t *testing.T) {
	for _, useHTTP2 := range []bool{false, true} {
		t.Run(fmt.Sprintf("http2=%v", useHTTP2), func(t *testing.T) {
			server, payload := newRetirementResponseServer(t, useHTTP2)
			client := server.Client()
			client.Timeout = 5 * time.Second
			var connections []net.Conn
			for _, path := range []string{"/retire", "/drain", "/after"} {
				var mu sync.Mutex
				var connection net.Conn
				request, err := http.NewRequest(http.MethodGet, server.URL+path, nil)
				if err != nil {
					t.Fatal(err)
				}
				request = request.WithContext(httptrace.WithClientTrace(request.Context(), &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
					mu.Lock()
					connection = info.Conn
					mu.Unlock()
				}}))
				response, err := client.Do(request)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(response.Body)
				response.Body.Close()
				if err != nil || !bytes.Equal(body, payload) || response.StatusCode != http.StatusNotFound {
					t.Fatalf("%s: status=%d bytes=%d/%d error=%v", path, response.StatusCode, len(body), len(payload), err)
				}
				if useHTTP2 && (response.ProtoMajor != 2 || response.Header.Get("Connection") != "") {
					t.Fatalf("unexpected HTTP/2 response protocol or Connection header: %s %v", response.Proto, response.Header)
				}
				mu.Lock()
				connections = append(connections, connection)
				mu.Unlock()
			}
			if useHTTP2 {
				if connections[0] != connections[1] || connections[1] == connections[2] {
					t.Fatal("HTTP/2 should finish the active request, drain on reuse, then reconnect")
				}
			} else if connections[0] == connections[1] {
				t.Fatal("HTTP/1 connection was not retired after the active response")
			}
		})
	}
}

func TestHTTP2RetirementDrainsAlreadyActiveStream(t *testing.T) {
	tracker := &proxyConnTracker{}
	payload := bytes.Repeat([]byte("s"), 11740)
	slowStarted := make(chan struct{})
	releaseSlow := make(chan struct{})
	slowCanceled := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseSlow) }) }
	server := httptest.NewUnstartedServer(proxyConnectionRetirementHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprint(len(payload)))
		w.WriteHeader(http.StatusNotFound)
		if r.URL.Path == "/slow" {
			_, _ = w.Write(payload[:1024])
			w.(http.Flusher).Flush()
			close(slowStarted)
			select {
			case <-releaseSlow:
				_, _ = w.Write(payload[1024:])
			case <-r.Context().Done():
				close(slowCanceled)
			}
			return
		}
		_, _ = w.Write(payload)
	})))
	server.Config.ConnContext = tracker.connContext
	server.Config.ConnState = tracker.update
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(func() { release(); server.Close() })
	conn, err := tls.Dial("tcp", server.Listener.Addr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, http2.ClientPreface); err != nil {
		t.Fatal(err)
	}
	framer := http2.NewFramer(conn, conn)
	framer.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	if err := framer.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	var encoded bytes.Buffer
	encoder := hpack.NewEncoder(&encoded)
	request := func(streamID uint32, path string) {
		t.Helper()
		encoded.Reset()
		for _, field := range []hpack.HeaderField{{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "https"}, {Name: ":authority", Value: "example.test"}, {Name: ":path", Value: path}} {
			if err := encoder.WriteField(field); err != nil {
				t.Fatal(err)
			}
		}
		if err := framer.WriteHeaders(http2.HeadersFrameParam{StreamID: streamID, BlockFragment: encoded.Bytes(), EndHeaders: true, EndStream: true}); err != nil {
			t.Fatal(err)
		}
	}
	bodies := map[uint32][]byte{}
	ended := map[uint32]bool{}
	var goAway bool
	readFrame := func() {
		t.Helper()
		frame, err := framer.ReadFrame()
		if err != nil {
			t.Fatalf("END_STREAM=%v GOAWAY=%v: %v", ended, goAway, err)
		}
		switch frame := frame.(type) {
		case *http2.SettingsFrame:
			if !frame.IsAck() {
				if err := framer.WriteSettingsAck(); err != nil {
					t.Fatal(err)
				}
			}
		case *http2.MetaHeadersFrame:
			for _, field := range frame.Fields {
				if field.Name == "connection" {
					t.Fatal("internal Connection header leaked to HTTP/2 wire")
				}
			}
			ended[frame.StreamID] = frame.StreamEnded()
		case *http2.DataFrame:
			bodies[frame.StreamID] = append(bodies[frame.StreamID], frame.Data()...)
			ended[frame.StreamID] = frame.StreamEnded()
		case *http2.GoAwayFrame:
			if frame.ErrCode != http2.ErrCodeNo || frame.LastStreamID < 3 {
				t.Fatalf("GOAWAY rejected an accepted stream: %v", frame)
			}
			goAway = true
		case *http2.RSTStreamFrame:
			t.Fatalf("retirement reset an accepted stream: %v", frame)
		}
	}
	request(1, "/slow")
	for len(bodies[1]) == 0 {
		readFrame()
	}
	select {
	case <-slowStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("slow handler did not reach its response gate")
	}
	tracker.retireForServerNames(nil)
	request(3, "/drain")
	for !goAway || !ended[3] {
		readFrame()
	}
	if ended[1] || !bytes.Equal(bodies[1], payload[:1024]) || !bytes.Equal(bodies[3], payload) {
		t.Fatalf("unexpected state before releasing active stream: ended=%v lengths=%d/%d", ended, len(bodies[1]), len(bodies[3]))
	}
	select {
	case <-slowCanceled:
		t.Fatal("GOAWAY canceled an already accepted response")
	default:
	}
	release()
	for !ended[1] {
		readFrame()
	}
	if !bytes.Equal(bodies[1], payload) {
		t.Fatalf("active response truncated after GOAWAY: %d/%d", len(bodies[1]), len(payload))
	}
}
