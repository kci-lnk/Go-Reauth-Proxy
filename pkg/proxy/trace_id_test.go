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

func TestServeHTTPOverwritesClientTraceAndForwardsGatewayTrace(t *testing.T) {
	upstreamTrace := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamTrace <- r.Header.Get(traceIDHeader)
		w.Header().Set(traceIDHeader, "upstream-supplied")
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

	responseTrace := recorder.Header().Get(traceIDHeader)
	if responseTrace == "" || responseTrace == "trc_00000000-0000-4000-8000-000000000000" {
		t.Fatalf("response trace id was not securely replaced: %q", responseTrace)
	}
	if forwarded := <-upstreamTrace; forwarded != responseTrace {
		t.Fatalf("upstream trace id = %q, response trace id = %q", forwarded, responseTrace)
	}
	if values := recorder.Header().Values(traceIDHeader); len(values) != 1 || values[0] != responseTrace {
		t.Fatalf("response trace headers = %q, want only gateway trace %q", values, responseTrace)
	}
}

func TestServeHTTPErrorResponseStillReturnsGatewayTrace(t *testing.T) {
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
	traceID := recorder.Header().Get(traceIDHeader)
	if traceID == "" || traceID == "client-supplied" {
		t.Fatalf("error response trace id was not securely replaced: %q", traceID)
	}
}
