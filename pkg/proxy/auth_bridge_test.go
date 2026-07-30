package proxy

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	"go-reauth-proxy/pkg/grpc/pb"
	"go-reauth-proxy/pkg/rpcbridge"
)

func testServerPort(t *testing.T, rawURL string) int {
	t.Helper()

	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}
	_, port, err := net.SplitHostPort(parsed.Host)
	if err != nil {
		t.Fatalf("split server host %q: %v", parsed.Host, err)
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		t.Fatalf("parse server port %q: %v", port, err)
	}
	return n
}

type testAuthBridge struct {
	supports  bool
	authorize func(context.Context, *pb.AuthorizeHttpRequest) (*pb.AuthorizeHttpResponse, error)
	verify    func(context.Context, *pb.VerifyAuthRequest) (*pb.VerifyAuthResponse, error)
	preflight func(context.Context, *pb.PreflightAuthRequest) (*pb.PreflightAuthResponse, error)
	stream    func(context.Context, *pb.VerifyStreamAuthRequest) (*pb.VerifyStreamAuthResponse, error)
}

func (b testAuthBridge) SupportsCapability(capability string) bool {
	return b.supports && capability == "authorize_http_v1"
}

func (b testAuthBridge) AuthorizeHTTP(ctx context.Context, in *pb.AuthorizeHttpRequest) (*pb.AuthorizeHttpResponse, error) {
	if b.authorize != nil {
		return b.authorize(ctx, in)
	}
	return &pb.AuthorizeHttpResponse{
		Preflight: &pb.PreflightAuthResponse{},
		Verify:    &pb.VerifyAuthResponse{Success: true, Status: http.StatusOK},
	}, nil
}

func setTestAuthBridge(t *testing.T, handler *Handler, bridge authBridgeClient) {
	t.Helper()

	handler.mu.Lock()
	defer handler.mu.Unlock()
	handler.authBridge = bridge
}

func (b testAuthBridge) VerifyAuth(ctx context.Context, in *pb.VerifyAuthRequest) (*pb.VerifyAuthResponse, error) {
	if b.verify != nil {
		return b.verify(ctx, in)
	}
	return &pb.VerifyAuthResponse{Success: true, Status: http.StatusOK}, nil
}

func (b testAuthBridge) PreflightAuth(ctx context.Context, in *pb.PreflightAuthRequest) (*pb.PreflightAuthResponse, error) {
	if b.preflight != nil {
		return b.preflight(ctx, in)
	}
	return &pb.PreflightAuthResponse{}, nil
}

func (b testAuthBridge) VerifyStreamAuth(ctx context.Context, in *pb.VerifyStreamAuthRequest) (*pb.VerifyStreamAuthResponse, error) {
	if b.stream != nil {
		return b.stream(ctx, in)
	}
	return &pb.VerifyStreamAuthResponse{
		Allowed:  false,
		Status:   http.StatusForbidden,
		Decision: "denied",
		Message:  "stream auth is not implemented by the test bridge",
	}, nil
}

func TestAuthBridgeFailureClassificationAndHTTPStatus(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		cause      string
		status     int
		retryAfter string
	}{
		{"unavailable", rpcbridge.ErrAuthBridgeUnavailable, "bridge_unavailable", http.StatusServiceUnavailable, "1"},
		{"queue full", rpcbridge.ErrAuthBridgeQueueFull, "queue_full", http.StatusServiceUnavailable, "1"},
		{"disconnected", rpcbridge.ErrAuthBridgeDisconnected, "disconnected", http.StatusServiceUnavailable, "1"},
		{"timeout", context.DeadlineExceeded, "timeout", http.StatusGatewayTimeout, ""},
		{"invalid response", rpcbridge.ErrAuthBridgeInvalidResponse, "invalid_response", http.StatusBadGateway, ""},
		{"internal", context.Canceled, "internal", http.StatusBadGateway, ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			failure := classifyAuthBridgeFailure(test.err)
			if failure.cause != test.cause || failure.status != test.status || failure.retryAfter != test.retryAfter {
				t.Fatalf("failure = %#v, want cause=%s status=%d retry=%q", failure, test.cause, test.status, test.retryAfter)
			}
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, "http://app.example.test/", nil)
			(&Handler{}).applyAuthCheckPlan(
				recorder,
				request,
				authCheckPlan{
					result:    authCheckResult{decision: "error"},
					errorPage: failure.errorPage(),
				},
				"203.0.113.1",
				"",
			)
			if recorder.Code != test.status {
				t.Fatalf("HTTP status = %d, want %d", recorder.Code, test.status)
			}
			if got := recorder.Header().Get("Retry-After"); got != test.retryAfter {
				t.Fatalf("Retry-After = %q, want %q", got, test.retryAfter)
			}
		})
	}
}
