package proxy

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"testing"

	"go-reauth-proxy/pkg/grpc/pb"
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
	verify    func(context.Context, *pb.VerifyAuthRequest) (*pb.VerifyAuthResponse, error)
	preflight func(context.Context, *pb.PreflightAuthRequest) (*pb.PreflightAuthResponse, error)
	stream    func(context.Context, *pb.VerifyStreamAuthRequest) (*pb.VerifyStreamAuthResponse, error)
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
