package proxy

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Opt-in, read-only comparison against a local upstream on a test machine.
// Run explicitly with FN_KNOCK_TEST_UPSTREAM=https://127.0.0.1:19123/.
func TestUpstreamLiveProtocolComparison(t *testing.T) {
	target := os.Getenv("FN_KNOCK_TEST_UPSTREAM")
	if target == "" {
		t.Skip("set FN_KNOCK_TEST_UPSTREAM for a live loopback comparison")
	}
	u, err := url.Parse(target)
	if err != nil || u.Scheme != "https" || !net.ParseIP(u.Hostname()).IsLoopback() || u.User != nil || u.RawQuery != "" || (u.Path != "" && u.Path != "/") {
		t.Fatal("live comparison requires a loopback HTTPS root URL without credentials")
	}
	for _, mode := range []string{"http1", "http2"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			tr := newProxyTransport()
			tr.Proxy = nil
			if mode == "http1" {
				tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
				tr.TLSClientConfig.NextProtos = []string{"http/1.1"}
				tr.ForceAttemptHTTP2 = false
			}
			defer tr.CloseIdleConnections()
			var fresh, reused, pingFailures, failures, requests atomic.Int64
			if tr.HTTP2 != nil {
				tr.HTTP2.CountError = func(kind string) {
					if kind == "conn_close_lost_ping" {
						pingFailures.Add(1)
					}
				}
			}
			request := func() {
				requests.Add(1)
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				req, _ := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
				req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
					if info.Reused {
						reused.Add(1)
					} else {
						fresh.Add(1)
					}
				}}))
				resp, err := tr.RoundTrip(req)
				if err != nil {
					failures.Add(1)
					t.Errorf("request: %v", err)
					return
				}
				defer resp.Body.Close()
				_, err = io.Copy(io.Discard, resp.Body)
				want := 1
				if mode == "http2" {
					want = 2
				}
				if err != nil || resp.ProtoMajor != want || resp.StatusCode >= 500 {
					failures.Add(1)
					t.Errorf("status=%d protocol=%s body_error=%v", resp.StatusCode, resp.Proto, err)
				}
			}
			request()
			// Real production ping timers: 30 seconds idle, 10 seconds for ACK.
			time.Sleep(45 * time.Second)
			request()
			var wg sync.WaitGroup
			for i := 0; i < 8; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for j := 0; j < 3; j++ {
						request()
					}
				}()
			}
			wg.Wait()
			t.Logf("requests=%d failures=%d fresh_connections=%d reused_connections=%d ping_failures=%d", requests.Load(), failures.Load(), fresh.Load(), reused.Load(), pingFailures.Load())
		})
	}
}
