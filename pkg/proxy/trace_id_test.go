package proxy

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"sync"
	"testing"

	"go-reauth-proxy/pkg/models"
)

func TestNewRequestTraceIDFormatAndConcurrentUniqueness(t *testing.T) {
	const total = 512
	pattern := regexp.MustCompile(`^trc_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	ids := make(chan string, total)
	var workers sync.WaitGroup
	workers.Add(total)
	for range total {
		go func() {
			defer workers.Done()
			ids <- newRequestTraceID()
		}()
	}
	workers.Wait()
	close(ids)

	seen := make(map[string]struct{}, total)
	for traceID := range ids {
		if !pattern.MatchString(traceID) {
			t.Fatalf("trace id %q does not match the public format", traceID)
		}
		if _, exists := seen[traceID]; exists {
			t.Fatalf("duplicate trace id %q", traceID)
		}
		seen[traceID] = struct{}{}
	}
}

func TestServeHTTPForwardsGatewayTraceWithoutExposingTraceResponseHeaders(t *testing.T) {
	upstreamTrace := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamTrace <- r.Header.Get(traceIDHeader)
		w.Header().Set(traceIDHeader, "upstream-supplied")
		w.Header().Set("Traceparent", "00-upstream-parent")
		w.Header().Set("X-B3-SpanId", "upstream-span")
		w.Header().Set("X-Custom-Trace-Token", "upstream-token")
		w.Header().Set("X-Application-ID", "application-id")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	handler := &Handler{
		HostRules:      []models.HostRule{{Host: "app.example.test", Target: upstream.URL}},
		authCache:      newAuthStateCache(),
		preflightCache: newPreflightStateCache(),
	}
	handler.publishRequestSnapshotLocked()
	request := httptest.NewRequest(http.MethodGet, "http://app.example.test/health", nil)
	request.Header.Set(traceIDHeader, "trc_00000000-0000-4000-8000-000000000000")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	forwardedTrace := <-upstreamTrace
	if forwardedTrace == "" || forwardedTrace == "trc_00000000-0000-4000-8000-000000000000" {
		t.Fatalf("upstream trace id was not securely replaced: %q", forwardedTrace)
	}
	if values := recorder.Header().Values(traceIDHeader); len(values) != 0 {
		t.Fatalf("gateway trace response headers = %q, want none", values)
	}
	for _, name := range []string{"Traceparent", "X-B3-SpanId", "X-Custom-Trace-Token"} {
		if values := recorder.Header().Values(name); len(values) != 0 {
			t.Fatalf("%s response headers = %q, want none", name, values)
		}
	}
	if got := recorder.Header().Get("X-Application-ID"); got != "application-id" {
		t.Fatalf("unrelated response header = %q, want application-id", got)
	}
}

func TestServeHTTPErrorResponseDoesNotExposeGatewayTrace(t *testing.T) {
	handler := &Handler{
		authCache:      newAuthStateCache(),
		preflightCache: newPreflightStateCache(),
	}
	handler.publishRequestSnapshotLocked()
	request := httptest.NewRequest(http.MethodGet, "http://missing.example.test/not-found", nil)
	request.Header.Set(traceIDHeader, "client-supplied")
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if recorder.Code < http.StatusBadRequest {
		t.Fatalf("status = %d, want an error response", recorder.Code)
	}
	if values := recorder.Header().Values(traceIDHeader); len(values) != 0 {
		t.Fatalf("error response trace headers = %q, want none", values)
	}
}

func TestStripTraceResponseHeadersRemovesTracingTrailers(t *testing.T) {
	header := http.Header{
		"trailer":                 {"Digest, Traceparent", "X-B3-SpanId"},
		"traceparent":             {"00-upstream-parent"},
		http.TrailerPrefix + "B3": {"upstream-b3"},
		"Digest":                  {"sha-256=value"},
	}

	stripTraceResponseHeaders(header)

	if values := header["traceparent"]; len(values) != 0 {
		t.Fatalf("Traceparent headers = %q, want none", values)
	}
	if got := header["trailer"]; len(got) != 1 || got[0] != "Digest" {
		t.Fatalf("Trailer headers = %q, want [Digest]", got)
	}
	if values := header[http.TrailerPrefix+"B3"]; len(values) != 0 {
		t.Fatalf("B3 trailer values = %q, want none", values)
	}
	if got := header.Get("Digest"); got != "sha-256=value" {
		t.Fatalf("unrelated digest header = %q", got)
	}
}
