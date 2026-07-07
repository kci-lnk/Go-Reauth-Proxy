package events

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

var eventsBenchmarkStringSink string

func TestLocalSystemEventsURLMatchesLegacyFormat(t *testing.T) {
	for _, port := range []int{1, defaultSystemEventsPort, 65535} {
		if got, want := localSystemEventsURL(port), fmt.Sprintf("http://127.0.0.1:%d%s", port, internalSystemEventsPath); got != want {
			t.Fatalf("localSystemEventsURL(%d) = %q, want %q", port, got, want)
		}
	}
}

func TestNewClientUsesDefaultHTTPClientWhenNil(t *testing.T) {
	client := NewClient(nil)
	if client == nil || client.httpClient == nil {
		t.Fatal("NewClient(nil) did not initialize http client")
	}
	if client.httpClient.Timeout != 2*time.Second {
		t.Fatalf("timeout = %v, want 2s", client.httpClient.Timeout)
	}
}

func TestNewClientPreservesProvidedHTTPClient(t *testing.T) {
	httpClient := &http.Client{Timeout: 17 * time.Millisecond}
	client := NewClient(httpClient)
	if client.httpClient != httpClient {
		t.Fatalf("http client pointer was not preserved")
	}
}

func TestPublishNilClientReturnsError(t *testing.T) {
	var client *Client
	err := client.Publish(context.Background(), 1, SystemEventPublishInput{Type: "x"})
	if err == nil || !strings.Contains(err.Error(), "client is nil") {
		t.Fatalf("Publish() error = %v, want nil client error", err)
	}
}

func TestPublishSendsJSONPayload(t *testing.T) {
	port, stop, requests := startSystemEventsTestServer(t, http.StatusAccepted, "ok")
	defer stop()

	err := NewClient(nil).Publish(nil, port, SystemEventPublishInput{
		Type:   FnEventGatewayThrottleBlocked,
		Source: SystemEventSourceGoReauthProxy,
		Payload: GatewayThrottleBlockedPayload{
			IP:           "198.51.100.7",
			BlockSeconds: 30,
		},
	})
	if err != nil {
		t.Fatalf("Publish() returned error: %v", err)
	}

	req := <-requests
	if req.Method != http.MethodPost || req.Path != internalSystemEventsPath {
		t.Fatalf("request = %s %s, want POST %s", req.Method, req.Path, internalSystemEventsPath)
	}
	if got := req.Header.Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q", got)
	}
	var body SystemEventPublishInput
	if err := json.Unmarshal(req.Body, &body); err != nil {
		t.Fatalf("decode body: %v; raw=%s", err, string(req.Body))
	}
	if body.Type != FnEventGatewayThrottleBlocked || body.Source != SystemEventSourceGoReauthProxy {
		t.Fatalf("published body = %#v", body)
	}
}

func TestPublishReturnsBodyForNonSuccessStatus(t *testing.T) {
	port, stop, _ := startSystemEventsTestServer(t, http.StatusBadGateway, "upstream down")
	defer stop()

	err := NewClient(nil).Publish(context.Background(), port, SystemEventPublishInput{Type: "x"})
	if err == nil || !strings.Contains(err.Error(), "502: upstream down") {
		t.Fatalf("Publish() error = %v, want status and body", err)
	}
}

func TestPublishUsesStatusTextWhenErrorBodyIsEmpty(t *testing.T) {
	port, stop, _ := startSystemEventsTestServer(t, http.StatusTeapot, "   ")
	defer stop()

	err := NewClient(nil).Publish(context.Background(), port, SystemEventPublishInput{Type: "x"})
	if err == nil || !strings.Contains(err.Error(), "418: I'm a teapot") {
		t.Fatalf("Publish() error = %v, want status text fallback", err)
	}
}

func TestPublishWrapsTransportError(t *testing.T) {
	client := NewClient(&http.Client{Transport: failingRoundTripper{err: errors.New("boom")}})
	err := client.Publish(context.Background(), 7998, SystemEventPublishInput{Type: "x"})
	if err == nil || !strings.Contains(err.Error(), "send system event request") || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("Publish() error = %v, want wrapped transport error", err)
	}
}

func TestPublishHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := NewClient(nil).Publish(ctx, 65535, SystemEventPublishInput{Type: "x"})
	if err == nil || !strings.Contains(err.Error(), "send system event request") {
		t.Fatalf("Publish() error = %v, want canceled request error", err)
	}
}

func TestResolveSystemEventPortUsesExplicitTarget(t *testing.T) {
	t.Setenv("BACKEND_PORT", "7999")
	if got := resolveSystemEventPort(12345); got != 12345 {
		t.Fatalf("resolveSystemEventPort() = %d, want explicit target", got)
	}
}

func TestResolveSystemEventPortUsesBackendPortEnv(t *testing.T) {
	t.Setenv("BACKEND_PORT", "8123")
	t.Setenv("FN_INTERNAL_EVENTS_PORT", "8234")
	if got := resolveSystemEventPort(0); got != 8123 {
		t.Fatalf("resolveSystemEventPort() = %d, want BACKEND_PORT", got)
	}
}

func TestResolveSystemEventPortUsesInternalEventsEnv(t *testing.T) {
	t.Setenv("BACKEND_PORT", "not-a-port")
	t.Setenv("FN_INTERNAL_EVENTS_PORT", "8234")
	if got := resolveSystemEventPort(0); got != 8234 {
		t.Fatalf("resolveSystemEventPort() = %d, want FN_INTERNAL_EVENTS_PORT", got)
	}
}

func TestResolveSystemEventPortFallsBackToDefault(t *testing.T) {
	t.Setenv("BACKEND_PORT", "-1")
	t.Setenv("FN_INTERNAL_EVENTS_PORT", "70000")
	if got := resolveSystemEventPort(0); got != defaultSystemEventsPort {
		t.Fatalf("resolveSystemEventPort() = %d, want default", got)
	}
}

type capturedSystemEventRequest struct {
	Method string
	Path   string
	Header http.Header
	Body   []byte
}

func startSystemEventsTestServer(t *testing.T, status int, body string) (int, func(), <-chan capturedSystemEventRequest) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	requests := make(chan capturedSystemEventRequest, 1)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		requests <- capturedSystemEventRequest{
			Method: r.Method,
			Path:   r.URL.Path,
			Header: r.Header.Clone(),
			Body:   data,
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	})}
	go func() { _ = server.Serve(listener) }()
	port := listener.Addr().(*net.TCPAddr).Port
	return port, func() {
		_ = server.Close()
		_ = listener.Close()
	}, requests
}

type failingRoundTripper struct {
	err error
}

func (r failingRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, r.err
}

func BenchmarkLocalSystemEventsURL(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		eventsBenchmarkStringSink = localSystemEventsURL(defaultSystemEventsPort)
	}
}

func BenchmarkLocalSystemEventsURLOld(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		eventsBenchmarkStringSink = fmt.Sprintf("http://127.0.0.1:%d%s", defaultSystemEventsPort, internalSystemEventsPath)
	}
}
