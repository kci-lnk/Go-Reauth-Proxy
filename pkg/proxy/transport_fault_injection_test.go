package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func faultRequest(tr *http.Transport, url, host string, timeout time.Duration) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	req.Host = host
	resp, err := tr.RoundTrip(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, err = io.Copy(io.Discard, resp.Body)
	return resp.ProtoMajor, err
}

func TestTransportFaultStalledRequestsDoNotExhaustPool(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		name := "http1"
		if h2 {
			name = "http2"
		}
		t.Run(name, func(t *testing.T) {
			const count = 12
			entered, exited := make(chan struct{}, count), make(chan struct{}, count)
			upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/stall" {
					entered <- struct{}{}
					<-r.Context().Done()
					exited <- struct{}{}
					return
				}
				_, _ = io.WriteString(w, "healthy")
			}))
			upstream.EnableHTTP2 = h2
			upstream.StartTLS()
			defer upstream.Close()
			tr := newProxyTransport()
			tr.Proxy = nil
			defer tr.CloseIdleConnections()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, count)
			for i := 0; i < count; i++ {
				go func() {
					req, _ := http.NewRequestWithContext(ctx, http.MethodGet, upstream.URL+"/stall", nil)
					resp, err := tr.RoundTrip(req)
					if resp != nil {
						resp.Body.Close()
					}
					done <- err
				}()
			}
			for i := 0; i < count; i++ {
				select {
				case <-entered:
				case <-time.After(3 * time.Second):
					t.Fatal("stalled request failed to reach upstream")
				}
			}
			start := time.Now()
			major, err := faultRequest(tr, upstream.URL+"/healthy", "fnos.example", time.Second)
			if err != nil {
				t.Fatalf("healthy request blocked behind stalled requests: %v", err)
			}
			expected := 1
			if h2 {
				expected = 2
			}
			if major != expected {
				t.Fatalf("protocol = %d, want %d", major, expected)
			}
			t.Logf("%d stalled requests; healthy request completed in %s", count, time.Since(start))
			cancel()
			for i := 0; i < count; i++ {
				select {
				case err := <-done:
					if !errors.Is(err, context.Canceled) {
						t.Fatalf("cancel error = %v", err)
					}
				case <-time.After(time.Second):
					t.Fatal("transport did not cancel")
				}
				select {
				case <-exited:
				case <-time.After(time.Second):
					t.Fatal("upstream did not observe cancellation")
				}
			}
			if _, err := faultRequest(tr, upstream.URL+"/healthy", "fn.example", time.Second); err != nil {
				t.Fatal(err)
			}
			t.Log("all stalled handlers exited; subsequent request succeeded")
		})
	}
}

// Swallow encrypted response bytes without closing TCP. This simulates a
// connection whose peer still accepts requests but no longer delivers frames.
// Only the first connection is affected; replacement connections remain healthy.
type responseBlackholeListener struct {
	net.Listener
	first    atomic.Pointer[responseBlackholeConn]
	accepted atomic.Int64
}
type responseBlackholeConn struct {
	net.Conn
	drop atomic.Bool
}

func (c *responseBlackholeConn) Write(p []byte) (int, error) {
	if c.drop.Load() {
		return len(p), nil
	}
	return c.Conn.Write(p)
}
func (l *responseBlackholeListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	wrapped := &responseBlackholeConn{Conn: c}
	l.accepted.Add(1)
	l.first.CompareAndSwap(nil, wrapped)
	return wrapped, nil
}

func TestTransportFaultHTTP2BlackholedConnection(t *testing.T) {
	for _, ping := range []bool{false, true} {
		name := "healthcheck_disabled"
		if ping {
			name = "production_healthcheck"
		}
		t.Run(name, func(t *testing.T) {
			upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "healthy") }))
			listener := &responseBlackholeListener{Listener: upstream.Listener}
			upstream.Listener = listener
			upstream.EnableHTTP2 = true
			upstream.StartTLS()
			defer upstream.Close()
			tr := newProxyTransport()
			tr.Proxy = nil
			if ping {
				tr.HTTP2.SendPingTimeout = 50 * time.Millisecond
				tr.HTTP2.PingTimeout = 50 * time.Millisecond
			} else {
				tr.HTTP2.SendPingTimeout = 0
			}
			defer tr.CloseIdleConnections()
			major, err := faultRequest(tr, upstream.URL, "fnos.example", time.Second)
			if err != nil || major != 2 {
				t.Fatalf("warm HTTP/2: protocol=%d error=%v", major, err)
			}
			listener.first.Load().drop.Store(true)
			for _, host := range []string{"fnos.example", "fn.example"} {
				started := time.Now()
				_, err := faultRequest(tr, upstream.URL, host, 350*time.Millisecond)
				t.Logf("host=%s elapsed=%s error=%v connections=%d", host, time.Since(started), err, listener.accepted.Load())
				if !ping && !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("expected blocked connection to reach caller deadline: %v", err)
				}
			}
			if !ping && listener.accepted.Load() != 1 {
				t.Fatalf("unexpected replacement connection: %d", listener.accepted.Load())
			}
			if ping {
				if _, err := faultRequest(tr, upstream.URL, "fn.example", time.Second); err != nil {
					t.Fatalf("ping did not allow recovery: %v", err)
				}
				if listener.accepted.Load() < 2 {
					t.Fatal("ping did not replace unhealthy connection")
				}
				t.Log("HTTP/2 ping retired the unhealthy connection and restored requests")
			}
			fresh := newProxyTransport()
			fresh.Proxy = nil
			defer fresh.CloseIdleConnections()
			if _, err := faultRequest(fresh, upstream.URL, "fnos.example", time.Second); err != nil {
				t.Fatalf("fresh pool failed: %v", err)
			}
			t.Log("fresh pool to same upstream succeeded")
		})
	}
}

func TestTransportFaultHTTP1BlackholeRecoversAfterCancellation(t *testing.T) {
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "healthy") }))
	listener := &responseBlackholeListener{Listener: upstream.Listener}
	upstream.Listener = listener
	upstream.StartTLS()
	defer upstream.Close()
	tr := newProxyTransport()
	tr.Proxy = nil
	defer tr.CloseIdleConnections()
	major, err := faultRequest(tr, upstream.URL, "fnos.example", time.Second)
	if err != nil || major != 1 {
		t.Fatalf("warm HTTP/1: protocol=%d error=%v", major, err)
	}
	listener.first.Load().drop.Store(true)
	_, err = faultRequest(tr, upstream.URL, "fnos.example", 350*time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline: %v", err)
	}
	start := time.Now()
	if _, err := faultRequest(tr, upstream.URL, "fnos.example", time.Second); err != nil {
		t.Fatalf("request after cancellation: %v", err)
	}
	if listener.accepted.Load() < 2 {
		t.Fatal("HTTP/1 did not replace canceled connection")
	}
	t.Logf("HTTP/1 cancellation discarded broken connection; next request recovered in %s", time.Since(start))
}

func TestTransportFaultHTTP2PingPreservesSlowResponse(t *testing.T) {
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(300 * time.Millisecond):
			_, _ = io.WriteString(w, "slow but healthy")
		case <-r.Context().Done():
		}
	}))
	listener := &responseBlackholeListener{Listener: upstream.Listener}
	upstream.Listener = listener
	upstream.EnableHTTP2 = true
	upstream.StartTLS()
	defer upstream.Close()
	tr := newProxyTransport()
	tr.Proxy = nil
	tr.HTTP2.SendPingTimeout = 50 * time.Millisecond
	tr.HTTP2.PingTimeout = 50 * time.Millisecond
	defer tr.CloseIdleConnections()
	major, err := faultRequest(tr, upstream.URL, "fnos.example", 2*time.Second)
	if err != nil || major != 2 {
		t.Fatalf("slow response failed: protocol=%d error=%v", major, err)
	}
	if listener.accepted.Load() != 1 {
		t.Fatal("healthy connection was replaced")
	}
	t.Log("300ms response delay survived 50ms ping interval and 50ms ping timeout")
}

func TestTransportFaultHTTP2ConcurrentFailureAndNoPOSTReplay(t *testing.T) {
	const count = 4
	var posts, failures atomic.Int64
	entered := make(chan struct{}, count)
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/fault" {
			if r.Method == http.MethodPost {
				_, _ = io.Copy(io.Discard, r.Body)
				posts.Add(1)
			}
			entered <- struct{}{}
		}
		_, _ = io.WriteString(w, "ok")
	}))
	listener := &responseBlackholeListener{Listener: upstream.Listener}
	upstream.Listener = listener
	upstream.EnableHTTP2 = true
	upstream.StartTLS()
	defer upstream.Close()
	healthy := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "other upstream") }))
	healthy.EnableHTTP2 = true
	healthy.StartTLS()
	defer healthy.Close()
	tr := newProxyTransport()
	tr.Proxy = nil
	tr.HTTP2.SendPingTimeout = 200 * time.Millisecond
	tr.HTTP2.PingTimeout = 100 * time.Millisecond
	report := tr.HTTP2.CountError
	tr.HTTP2.CountError = func(kind string) {
		report(kind)
		if kind == "conn_close_lost_ping" {
			failures.Add(1)
		}
	}
	defer tr.CloseIdleConnections()
	if major, err := faultRequest(tr, upstream.URL, "fn.example", 2*time.Second); err != nil || major != 2 {
		t.Fatalf("warmup: %d %v", major, err)
	}
	listener.first.Load().drop.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, count)
	for i := 0; i < count; i++ {
		method := http.MethodGet
		if i == 0 {
			method = http.MethodPost
		}
		go func(method string) {
			var body io.Reader
			if method == http.MethodPost {
				body = strings.NewReader("side-effect")
			}
			req, _ := http.NewRequestWithContext(ctx, method, upstream.URL+"/fault", body)
			resp, err := tr.RoundTrip(req)
			if resp != nil {
				resp.Body.Close()
			}
			done <- err
		}(method)
	}
	for i := 0; i < count; i++ {
		select {
		case <-entered:
		case <-ctx.Done():
			t.Fatal("requests did not reach upstream")
		}
	}
	if _, err := faultRequest(tr, healthy.URL, "healthy.example", time.Second); err != nil {
		t.Fatalf("other upstream affected: %v", err)
	}
	for i := 0; i < count; i++ {
		select {
		case err := <-done:
			if err == nil || errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("request not terminated by health check: %v", err)
			}
		case <-ctx.Done():
			t.Fatal("affected request did not exit")
		}
	}
	if failures.Load() != 1 {
		t.Fatalf("healthcheck failures=%d, want one for the shared connection", failures.Load())
	}
	if _, err := faultRequest(tr, upstream.URL, "fn.example", time.Second); err != nil {
		t.Fatalf("recovery: %v", err)
	}
	if posts.Load() != 1 {
		t.Fatalf("POST executed %d times", posts.Load())
	}
	if listener.accepted.Load() != 2 {
		t.Fatalf("connections=%d, want failed and replacement", listener.accepted.Load())
	}
}

func TestTransportFaultHTTP2PingPreservesSilentSSE(t *testing.T) {
	exited := make(chan struct{})
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(exited)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	upstream.EnableHTTP2 = true
	upstream.StartTLS()
	defer upstream.Close()
	tr := newProxyTransport()
	tr.Proxy = nil
	tr.HTTP2.SendPingTimeout = 50 * time.Millisecond
	tr.HTTP2.PingTimeout = 50 * time.Millisecond
	defer tr.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, upstream.URL, nil)
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.ProtoMajor != 2 {
		t.Fatal("SSE did not negotiate HTTP/2")
	}
	done := make(chan error, 1)
	go func() { _, err := io.Copy(io.Discard, resp.Body); done <- err }()
	select {
	case err := <-done:
		t.Fatalf("silent healthy SSE terminated: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancel SSE: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("SSE reader did not exit")
	}
	select {
	case <-exited:
	case <-time.After(time.Second):
		t.Fatal("SSE handler did not exit")
	}
}

func TestProxyTransportRespectsHTTP2Disable(t *testing.T) {
	for _, tc := range []struct {
		setting  string
		protocol int
	}{
		{"http2client=0", 1},
		{"http2client=1,http2client=0", 1},
		{"http2client=0,http2client=1", 2},
		{"http2client=1", 2},
	} {
		t.Run(tc.setting, func(t *testing.T) {
			t.Setenv("GODEBUG", tc.setting)
			upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
			upstream.EnableHTTP2 = true
			upstream.StartTLS()
			defer upstream.Close()
			tr := newProxyTransport()
			tr.Proxy = nil
			defer tr.CloseIdleConnections()
			major, err := faultRequest(tr, upstream.URL, "fn.example", time.Second)
			if err != nil {
				t.Fatal(err)
			}
			if major != tc.protocol {
				t.Fatalf("GODEBUG=%s negotiated HTTP/%d, want %d", tc.setting, major, tc.protocol)
			}
		})
	}
}
