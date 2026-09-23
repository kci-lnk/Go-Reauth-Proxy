package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go-reauth-proxy/pkg/grpc/pb"
)

func TestAuthenticatedBusinessProxyPreservesOrdinaryTrailersWithoutTraceLeakOnWire(t *testing.T) {
	traceNames := []string{traceIDHeader, "Traceparent", "B3", "X-B3-SpanId", "X-Custom-Trace-Token"}
	const payload = "authenticated business response\n"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-Application-ID", "business-app")
		for _, name := range traceNames {
			w.Header().Set(name, "private-response-header")
		}
		w.Header().Set("Trailer", "Digest, X-Checksum, "+strings.Join(traceNames[:4], ", "))
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush() // Force actual chunked framing before trailer values exist.
		_, _ = io.WriteString(w, payload)
		w.Header().Set("Digest", "sha-256=ordinary-digest")
		w.Header().Set("X-Checksum", "ordinary-checksum")
		for _, name := range traceNames[:4] {
			w.Header().Set(name, "private-announced-trailer")
		}
		// Also cover a trailer discovered only when the upstream body reaches EOF.
		w.Header().Set(http.TrailerPrefix+traceNames[4], "private-late-trailer")
	}))
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
	gateway := httptest.NewServer(newCombinedAuthTestHandler(upstream.URL, bridge, "host", 0))
	t.Cleanup(gateway.Close)
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
	if response.StatusCode != http.StatusOK || response.ProtoMajor != 1 {
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
	body, err := io.ReadAll(response.Body) // net/http exposes wire trailers after EOF.
	if err != nil || string(body) != payload {
		t.Fatalf("business body = %q, error %v", body, err)
	}
	if authorizations.Load() != 1 {
		t.Fatalf("authorization calls = %d, want one successful protected-route check", authorizations.Load())
	}
	if response.Header.Get("X-Application-ID") != "business-app" {
		t.Fatal("ordinary application header was not preserved")
	}
	for name, want := range map[string]string{"Digest": "sha-256=ordinary-digest", "X-Checksum": "ordinary-checksum"} {
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
