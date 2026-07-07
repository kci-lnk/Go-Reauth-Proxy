package rpcbridge

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"go-reauth-proxy/pkg/grpc/pb"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

func TestCheckInternalToken(t *testing.T) {
	t.Run("rejects empty configured token", func(t *testing.T) {
		err := CheckInternalToken(context.Background(), "")
		if status.Code(err) != codes.Unauthenticated {
			t.Fatalf("status = %v, want unauthenticated", status.Code(err))
		}
	})

	t.Run("rejects missing metadata", func(t *testing.T) {
		err := CheckInternalToken(context.Background(), "secret")
		if status.Code(err) != codes.Unauthenticated {
			t.Fatalf("status = %v, want unauthenticated", status.Code(err))
		}
	})

	t.Run("accepts internal metadata token", func(t *testing.T) {
		ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(InternalTokenMetadataKey, "secret"))
		if err := CheckInternalToken(ctx, "secret"); err != nil {
			t.Fatalf("CheckInternalToken with metadata token = %v, want nil", err)
		}
	})

	t.Run("accepts bearer token", func(t *testing.T) {
		ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer secret"))
		if err := CheckInternalToken(ctx, "secret"); err != nil {
			t.Fatalf("CheckInternalToken with bearer token = %v, want nil", err)
		}
	})

	t.Run("rejects invalid token", func(t *testing.T) {
		ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(InternalTokenMetadataKey, "wrong"))
		err := CheckInternalToken(ctx, "secret")
		if status.Code(err) != codes.Unauthenticated {
			t.Fatalf("status = %v, want unauthenticated", status.Code(err))
		}
	})
}

func TestResolveInternalToken(t *testing.T) {
	t.Run("uses explicit token", func(t *testing.T) {
		token, err := ResolveInternalToken(" explicit ")
		if err != nil {
			t.Fatalf("ResolveInternalToken returned error: %v", err)
		}
		if token != "explicit" {
			t.Fatalf("token = %q, want explicit", token)
		}
	})

	t.Run("requires a non-empty token", func(t *testing.T) {
		if _, err := ResolveInternalToken(" "); err != ErrInternalRPCTokenRequired {
			t.Fatalf("error = %v, want ErrInternalRPCTokenRequired", err)
		}
	})
}

func TestAuthBridgeGRPCRoundTrip(t *testing.T) {
	manager := NewAuthBridgeManager("secret")
	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	pb.RegisterAuthBridgeServiceServer(server, manager)
	go func() {
		_ = server.Serve(listener)
	}()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})

	conn, err := grpc.NewClient(
		"passthrough:///auth-bridge",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return listener.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
	})

	client := pb.NewAuthBridgeServiceClient(conn)
	streamCtx := metadata.NewOutgoingContext(
		context.Background(),
		metadata.Pairs(InternalTokenMetadataKey, "secret"),
	)
	stream, err := client.ConnectAuthBridge(streamCtx)
	if err != nil {
		t.Fatalf("ConnectAuthBridge: %v", err)
	}
	t.Cleanup(func() {
		_ = stream.CloseSend()
	})

	waitForConnectedBridge(t, manager)

	clientDone := make(chan error, 1)
	go func() {
		msg, err := stream.Recv()
		if err != nil {
			clientDone <- err
			return
		}
		if msg.GetVerifyAuthRequest() == nil {
			clientDone <- status.Errorf(codes.Internal, "received %T, want verify auth request", msg.GetPayload())
			return
		}
		clientDone <- stream.Send(&pb.AuthBridgeEnvelope{
			RequestId: msg.GetRequestId(),
			Payload: &pb.AuthBridgeEnvelope_VerifyAuthResponse{
				VerifyAuthResponse: &pb.VerifyAuthResponse{
					Success: true,
					Status:  200,
					Message: "ok",
				},
			},
		})
	}()

	resp, err := manager.VerifyAuth(context.Background(), &pb.VerifyAuthRequest{
		Context: &pb.AuthContext{ClientIp: "127.0.0.1"},
	})
	if err != nil {
		t.Fatalf("VerifyAuth: %v", err)
	}
	if !resp.GetSuccess() || resp.GetStatus() != 200 || resp.GetMessage() != "ok" {
		t.Fatalf("VerifyAuth response = %#v, want success status 200", resp)
	}
	select {
	case err := <-clientDone:
		if err != nil {
			t.Fatalf("bridge client response failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("bridge client did not handle request")
	}
}

func TestAuthBridgeRoundTripDoesNotHoldManagerLockDuringSend(t *testing.T) {
	manager := NewAuthBridgeManager("secret")
	stream := &blockingAuthBridgeStream{
		ctx:         context.Background(),
		sendStarted: make(chan struct{}),
		releaseSend: make(chan struct{}),
	}

	manager.attachStream(stream)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := manager.roundTrip(ctx, &pb.AuthBridgeEnvelope{
			Payload: &pb.AuthBridgeEnvelope_VerifyAuthRequest{
				VerifyAuthRequest: &pb.VerifyAuthRequest{},
			},
		})
		result <- err
	}()

	select {
	case <-stream.sendStarted:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("roundTrip did not start sending")
	}

	requestID := make(chan string, 1)
	go func() {
		manager.mu.Lock()
		defer manager.mu.Unlock()
		for id := range manager.pending {
			requestID <- id
			return
		}
	}()

	var id string
	select {
	case id = <-requestID:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("manager lock was blocked while stream.Send was in progress")
	}

	manager.dispatchResponse(&pb.AuthBridgeEnvelope{
		RequestId: id,
		Payload: &pb.AuthBridgeEnvelope_VerifyAuthResponse{
			VerifyAuthResponse: &pb.VerifyAuthResponse{Success: true, Status: 200},
		},
	})
	close(stream.releaseSend)

	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("roundTrip returned error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("roundTrip did not complete")
	}
}

func TestAuthBridgeDetachIgnoresReplacedStream(t *testing.T) {
	manager := NewAuthBridgeManager("secret")
	oldStream := &blockingAuthBridgeStream{ctx: context.Background()}
	newStream := &blockingAuthBridgeStream{ctx: context.Background()}

	oldActive := manager.attachStream(oldStream)
	oldPending := make(chan *pb.AuthBridgeEnvelope, 1)
	manager.mu.Lock()
	manager.pending["old"] = oldPending
	manager.mu.Unlock()

	newActive := manager.attachStream(newStream)
	select {
	case value := <-oldPending:
		if value != nil {
			t.Fatalf("old pending channel received %#v, want unavailable signal", value)
		}
	case <-time.After(time.Second):
		t.Fatal("old pending channel was not signaled on stream replacement")
	}

	newPending := make(chan *pb.AuthBridgeEnvelope, 1)
	manager.mu.Lock()
	manager.pending["new"] = newPending
	manager.mu.Unlock()

	manager.detachStream(oldActive)
	select {
	case value := <-newPending:
		t.Fatalf("new pending channel received %#v after old stream detach", value)
	default:
	}

	manager.detachStream(newActive)
	select {
	case value := <-newPending:
		if value != nil {
			t.Fatalf("new pending channel received %#v, want unavailable signal", value)
		}
	case <-time.After(time.Second):
		t.Fatal("new pending channel was not signaled on current stream detach")
	}
}

func TestAuthBridgeRoundTripHonorsContextWhileSendBlocked(t *testing.T) {
	manager := NewAuthBridgeManager("secret")
	stream := &blockingAuthBridgeStream{
		ctx:         context.Background(),
		sendStarted: make(chan struct{}),
		releaseSend: make(chan struct{}),
	}
	manager.attachStream(stream)

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := manager.roundTrip(ctx, &pb.AuthBridgeEnvelope{
			Payload: &pb.AuthBridgeEnvelope_VerifyAuthRequest{
				VerifyAuthRequest: &pb.VerifyAuthRequest{},
			},
		})
		result <- err
	}()

	select {
	case <-stream.sendStarted:
	case <-time.After(time.Second):
		t.Fatal("roundTrip did not start sending")
	}

	select {
	case err := <-result:
		if err != context.DeadlineExceeded {
			t.Fatalf("roundTrip error = %v, want context deadline exceeded", err)
		}
	case <-time.After(time.Second):
		t.Fatal("roundTrip did not respect context while Send was blocked")
	}

	newStream := &blockingAuthBridgeStream{ctx: context.Background()}
	attachDone := make(chan struct{})
	go func() {
		manager.attachStream(newStream)
		close(attachDone)
	}()
	select {
	case <-attachDone:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("new stream attach was blocked by the old stuck Send")
	}
	close(stream.releaseSend)
}

func TestAuthBridgeDispatchAfterUnavailableSignalDoesNotPanic(t *testing.T) {
	manager := NewAuthBridgeManager("secret")
	ch := make(chan *pb.AuthBridgeEnvelope, 1)
	manager.mu.Lock()
	manager.pending["request"] = ch
	manager.mu.Unlock()
	signalPendingUnavailable(map[string]chan *pb.AuthBridgeEnvelope{"request": ch})

	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("dispatchResponse panicked after unavailable signal: %v", recovered)
		}
	}()
	manager.dispatchResponse(&pb.AuthBridgeEnvelope{
		RequestId: "request",
		Payload: &pb.AuthBridgeEnvelope_VerifyAuthResponse{
			VerifyAuthResponse: &pb.VerifyAuthResponse{Success: true, Status: 200},
		},
	})
}

func waitForConnectedBridge(t *testing.T, manager *AuthBridgeManager) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		manager.mu.Lock()
		connected := manager.stream != nil
		manager.mu.Unlock()
		if connected {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("auth bridge did not connect")
}

type blockingAuthBridgeStream struct {
	grpc.ServerStream
	ctx             context.Context
	sendStarted     chan struct{}
	sendStartedOnce sync.Once
	releaseSend     chan struct{}
}

func (s *blockingAuthBridgeStream) Context() context.Context {
	if s.ctx == nil {
		return context.Background()
	}
	return s.ctx
}

func (s *blockingAuthBridgeStream) Send(*pb.AuthBridgeEnvelope) error {
	if s.sendStarted != nil {
		s.sendStartedOnce.Do(func() {
			close(s.sendStarted)
		})
	}
	if s.releaseSend != nil {
		<-s.releaseSend
	}
	return nil
}

func (s *blockingAuthBridgeStream) Recv() (*pb.AuthBridgeEnvelope, error) {
	return nil, io.EOF
}
