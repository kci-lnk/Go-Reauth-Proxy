package proxy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go-reauth-proxy/pkg/grpc/pb"
)

func TestAuthenticatedBusinessProxyPreservesOrdinaryTrailersWithoutTraceLeakOnWire(t *testing.T) {
	for _, upstreamProtocol := range []int{1, 2} {
		for _, downstreamProtocol := range []int{1, 2} {
			for _, announced := range []bool{false, true} {
				for _, contentType := range []string{"text/plain", "text/event-stream", "application/octet-stream"} {
					name := fmt.Sprintf("upstream%d/downstream%d/announced=%t/%s", upstreamProtocol, downstreamProtocol, announced, contentType)
					t.Run(name, func(t *testing.T) {
						testAuthenticatedBusinessProxyTrailers(t, upstreamProtocol, downstreamProtocol, announced, contentType)
					})
				}
			}
		}
	}
}

func testAuthenticatedBusinessProxyTrailers(t *testing.T, upstreamProtocol, downstreamProtocol int, announced bool, contentType string) {
	t.Helper()
	traceNames := []string{traceIDHeader, "Traceparent", "B3", "X-B3-SpanId", "X-Custom-Trace-Token"}
	const payload = "authenticated business response\n"
	release := make(chan struct{})
	releaseUpstream := sync.OnceFunc(func() { close(release) })
	var actualUpstreamProtocol atomic.Int32
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		actualUpstreamProtocol.Store(int32(r.ProtoMajor))
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("X-Application-ID", "business-app")
		for _, name := range traceNames {
			w.Header().Set(name, "private-response-header")
		}
		if announced {
			w.Header().Set("Trailer", "Digest, X-Checksum, "+strings.Join(traceNames[:4], ", "))
		}
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		_, _ = io.WriteString(w, payload)
		w.(http.Flusher).Flush()
		// The client must receive this body before EOF. This guards both SSE
		// flushing and bounded binary coalescing against a buffering fix.
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		prefix := ""
		if !announced {
			prefix = http.TrailerPrefix
		}
		w.Header().Set(prefix+"Digest", "sha-256=ordinary-digest")
		w.Header().Set(prefix+"X-Checksum", "ordinary-checksum")
		for _, name := range traceNames[:4] {
			w.Header().Set(prefix+name, "private-trailer")
		}
		// Always include names discovered only when the body reaches EOF.
		w.Header().Set(http.TrailerPrefix+"X-Late-Checksum", "ordinary-late-checksum")
		w.Header().Set(http.TrailerPrefix+traceNames[4], "private-late-trailer")
	}))
	upstream.EnableHTTP2 = upstreamProtocol == 2
	if upstreamProtocol == 2 {
		upstream.StartTLS()
	} else {
		upstream.Start()
	}
	t.Cleanup(upstream.Close)

	var authorizations atomic.Int32
	bridge := testAuthBridge{
		supports: true,
		authorize: func(_ context.Context, request *pb.AuthorizeHttpRequest) (*pb.AuthorizeHttpResponse, error) {
			authorizations.Add(1)
			if !strings.Contains(request.GetContext().GetCookie(), authSessionCookieName+"="+combinedAuthTestCookieValue) {
				t.Error("authorization did not receive the synthetic session")
			}
			return successfulCombinedAuthResponse(request.GetMode(), pb.AuthCacheScope_AUTH_CACHE_SCOPE_NONE, pb.AuthCacheScope_AUTH_CACHE_SCOPE_NONE, nil), nil
		},
	}
	handler := newCombinedAuthTestHandler(upstream.URL, bridge, "host", 0)
	// Use a real transport trusted for this test server's TLS certificate.
	handler.proxyRoundTripper = upstream.Client().Transport
	gateway := httptest.NewUnstartedServer(handler)
	gateway.EnableHTTP2 = downstreamProtocol == 2
	if downstreamProtocol == 2 {
		gateway.StartTLS()
	} else {
		gateway.Start()
	}
	t.Cleanup(gateway.Close)
	t.Cleanup(releaseUpstream)
	client := gateway.Client()
	client.Timeout = 5 * time.Second
	request, err := http.NewRequest(http.MethodGet, gateway.URL+"/business/trailers", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "protected.example.test"
	request.AddCookie(&http.Cookie{Name: authSessionCookieName, Value: combinedAuthTestCookieValue})
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.ProtoMajor != downstreamProtocol {
		t.Fatalf("wire response status/protocol = %d/%s", response.StatusCode, response.Proto)
	}
	for _, name := range traceNames {
		if values := response.Header.Values(name); len(values) != 0 {
			t.Errorf("internal response header %s leaked: %q", name, values)
		}
		if _, exists := response.Trailer[http.CanonicalHeaderKey(name)]; exists {
			t.Errorf("internal trailer name %s was announced to the client", name)
		}
	}
	firstChunk := make([]byte, len(payload))
	if _, err := io.ReadFull(response.Body, firstChunk); err != nil || string(firstChunk) != payload {
		t.Fatalf("body was not delivered before upstream EOF: %q, error %v", firstChunk, err)
	}
	releaseUpstream()
	remaining, err := io.ReadAll(response.Body) // net/http exposes wire trailers after EOF.
	if err != nil || len(remaining) != 0 {
		t.Fatalf("unexpected trailing body = %q, error %v", remaining, err)
	}
	if authorizations.Load() != 1 {
		t.Fatalf("authorization calls = %d, want one successful protected-route check", authorizations.Load())
	}
	if got := actualUpstreamProtocol.Load(); got != int32(upstreamProtocol) {
		t.Fatalf("upstream protocol = HTTP/%d, want HTTP/%d", got, upstreamProtocol)
	}
	if response.Header.Get("X-Application-ID") != "business-app" {
		t.Fatal("ordinary application header was not preserved")
	}
	for name, want := range map[string]string{"Digest": "sha-256=ordinary-digest", "X-Checksum": "ordinary-checksum", "X-Late-Checksum": "ordinary-late-checksum"} {
		if got := response.Trailer.Get(name); got != want {
			t.Errorf("ordinary trailer %s = %q, want %q", name, got, want)
		}
	}
	for _, name := range traceNames {
		if values := response.Trailer.Values(name); len(values) != 0 {
			t.Errorf("internal trailer %s leaked after EOF: %q", name, values)
		}
	}
}
