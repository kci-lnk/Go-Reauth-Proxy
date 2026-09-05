package rpcbridge

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"go-reauth-proxy/pkg/diagnostics"
	"go-reauth-proxy/pkg/grpc/pb"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

func BenchmarkAuthBridgePendingCompletion(b *testing.B) {
	for _, concurrency := range []int{1, 64, 256, 1024} {
		b.Run("Concurrent"+strconv.Itoa(concurrency)+"/ForcedShardCollision", func(b *testing.B) {
			manager := NewAuthBridgeManager("benchmark-token")
			requestIDs := authBridgeCollisionRequestIDs(manager, concurrency)
			benchmarkAuthBridgePendingCalls(b, manager, requestIDs)
		})
	}
}

func BenchmarkAuthBridgePendingCompletionDistributed(b *testing.B) {
	for _, concurrency := range []int{1, 64, 256, 1024} {
		b.Run("Concurrent"+strconv.Itoa(concurrency), func(b *testing.B) {
			manager := NewAuthBridgeManager("benchmark-token")
			requestIDs := make([]string, concurrency)
			for index := range requestIDs {
				requestIDs[index] = strconv.Itoa(index)
			}
			benchmarkAuthBridgePendingCalls(b, manager, requestIDs)
		})
	}
}

func benchmarkAuthBridgePendingCalls(b *testing.B, manager *AuthBridgeManager, requestIDs []string) {
	b.Helper()
	response := &pb.AuthBridgeEnvelope{Payload: &pb.AuthBridgeEnvelope_VerifyAuthResponse{
		VerifyAuthResponse: &pb.VerifyAuthResponse{Success: true, Status: http.StatusOK},
	}}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		calls := make([]*authBridgePendingCall, len(requestIDs))
		var ready sync.WaitGroup
		var completed sync.WaitGroup
		ready.Add(len(requestIDs))
		completed.Add(len(requestIDs))
		for index, requestID := range requestIDs {
			call := newAuthBridgePendingCall(nil)
			calls[index] = call
			shard := manager.pendingShard(requestID)
			shard.Lock()
			shard.calls[requestID] = call
			shard.Unlock()
			go func() {
				ready.Done()
				call.wait()
				completed.Done()
			}()
		}
		ready.Wait()
		for index, requestID := range requestIDs {
			manager.completePending(requestID, calls[index], response, nil)
		}
		completed.Wait()
	}
}

func authBridgeCollisionRequestIDs(manager *AuthBridgeManager, count int) []string {
	requestIDs := make([]string, 0, count)
	wanted := manager.pendingShard("benchmark-collision")
	for candidate := 0; len(requestIDs) < count; candidate++ {
		requestID := strconv.Itoa(candidate)
		if manager.pendingShard(requestID) == wanted {
			requestIDs = append(requestIDs, requestID)
		}
	}
	return requestIDs
}

func TestAuthBridgePendingCompletionNotifiesOnlyMatchingCall(t *testing.T) {
	manager := NewAuthBridgeManager("secret")
	requestIDs := authBridgeCollisionRequestIDs(manager, 2)
	first := newAuthBridgePendingCall(nil)
	second := newAuthBridgePendingCall(nil)
	shard := manager.pendingShard(requestIDs[0])
	shard.Lock()
	shard.calls[requestIDs[0]] = first
	shard.calls[requestIDs[1]] = second
	shard.Unlock()
	firstDone := waitForAuthBridgePendingCall(first)
	secondDone := waitForAuthBridgePendingCall(second)

	manager.completePending(requestIDs[0], first, &pb.AuthBridgeEnvelope{RequestId: requestIDs[0]}, nil)
	select {
	case <-firstDone:
	case <-time.After(time.Second):
		t.Fatal("matching pending call was not notified within one second")
	}
	select {
	case <-secondDone:
		t.Fatal("unrelated pending call in the same shard was notified")
	case <-time.After(10 * time.Millisecond):
	}

	manager.completePending(requestIDs[1], second, nil, context.Canceled)
	select {
	case <-secondDone:
	case <-time.After(time.Second):
		t.Fatal("second pending call was not notified within one second")
	}
}

func TestAuthBridgePendingCompletionBeforeWaitAndDuplicateIgnored(t *testing.T) {
	manager := NewAuthBridgeManager("secret")
	requestID := "completed-before-wait"
	call := newAuthBridgePendingCall(nil)
	shard := manager.pendingShard(requestID)
	shard.Lock()
	shard.calls[requestID] = call
	shard.Unlock()

	response := &pb.AuthBridgeEnvelope{RequestId: requestID}
	manager.completePending(requestID, call, response, nil)
	// A late cancellation or disconnect may try to complete the same call.
	// The shard identity check must make this a no-op rather than a second Done.
	manager.completePending(requestID, call, nil, context.Canceled)

	select {
	case <-waitForAuthBridgePendingCall(call):
	case <-time.After(time.Second):
		t.Fatal("completion that happened before Wait was lost")
	}
	if call.response != response || call.err != nil {
		t.Fatalf("completion result = (%p, %v), want (%p, nil)", call.response, call.err, response)
	}
}

func TestAuthBridgePendingResponseCancelRaceCompletesOnce(t *testing.T) {
	manager := NewAuthBridgeManager("secret")
	response := &pb.AuthBridgeEnvelope{RequestId: "response"}
	for index := range 1000 {
		requestID := "response-cancel-race-" + strconv.Itoa(index)
		call := newAuthBridgePendingCall(nil)
		shard := manager.pendingShard(requestID)
		shard.Lock()
		shard.calls[requestID] = call
		shard.Unlock()

		start := make(chan struct{})
		var competitors sync.WaitGroup
		competitors.Add(2)
		go func() {
			defer competitors.Done()
			<-start
			manager.completePending(requestID, call, response, nil)
		}()
		go func() {
			defer competitors.Done()
			<-start
			manager.completePending(requestID, call, nil, context.Canceled)
		}()
		close(start)
		competitors.Wait()

		select {
		case <-waitForAuthBridgePendingCall(call):
		case <-time.After(time.Second):
			t.Fatalf("iteration %d did not complete", index)
		}
		responseWon := call.response == response && call.err == nil
		cancelWon := call.response == nil && errors.Is(call.err, context.Canceled)
		if responseWon == cancelWon {
			t.Fatalf("iteration %d result = (%p, %v), want exactly one response or cancellation", index, call.response, call.err)
		}
		if manager.pendingMatches(requestID, call) {
			t.Fatalf("iteration %d left the completed call pending", index)
		}
	}
}

func waitForAuthBridgePendingCall(call *authBridgePendingCall) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		call.wait()
		close(done)
	}()
	return done
}

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
		metadata.Pairs(
			InternalTokenMetadataKey, "secret",
			AuthBridgeInstanceMetadataKey, "grpc-client",
			AuthBridgeCapabilityMetadataKey, CapabilityAuthorizeHTTPV1,
		),
	)
	stream, err := client.ConnectAuthBridge(streamCtx)
	if err != nil {
		t.Fatalf("ConnectAuthBridge: %v", err)
	}
	t.Cleanup(func() {
		_ = stream.CloseSend()
	})
	headerErr := make(chan error, 1)
	go func() {
		_, err := stream.Header()
		headerErr <- err
	}()
	select {
	case err := <-headerErr:
		if err != nil {
			t.Fatalf("auth bridge initial headers: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("auth bridge did not send initial headers from metadata handshake")
	}

	waitForConnectedBridge(t, manager)
	waitForCapability(t, manager, CapabilityAuthorizeHTTPV1)
	if err := stream.Send(&pb.AuthBridgeEnvelope{
		Payload: &pb.AuthBridgeEnvelope_Ready{Ready: &pb.AuthBridgeReady{
			InstanceId:   "grpc-client",
			Capabilities: []string{CapabilityAuthorizeHTTPV1},
		}},
	}); err != nil {
		t.Fatalf("send ready envelope: %v", err)
	}

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

	// A pre-metadata bridge must still become usable after receiving the
	// server headers. It starts with the capability-safe split-RPC fallback,
	// then its first body Ready envelope may advertise newer capabilities.
	if err := stream.CloseSend(); err != nil {
		t.Fatalf("close metadata bridge: %v", err)
	}
	waitForDisconnectedBridge(t, manager)
	legacyCtx := metadata.NewOutgoingContext(
		context.Background(),
		metadata.Pairs(InternalTokenMetadataKey, "secret"),
	)
	legacyStream, err := client.ConnectAuthBridge(legacyCtx)
	if err != nil {
		t.Fatalf("connect legacy auth bridge: %v", err)
	}
	t.Cleanup(func() { _ = legacyStream.CloseSend() })
	if _, err := legacyStream.Header(); err != nil {
		t.Fatalf("legacy auth bridge initial headers: %v", err)
	}
	readyCtx, readyCancel := context.WithTimeout(context.Background(), time.Second)
	defer readyCancel()
	if err := manager.WaitReady(readyCtx); err != nil {
		t.Fatalf("legacy auth bridge did not enter safe ready state: %v", err)
	}
	if manager.SupportsCapability(CapabilityAuthorizeHTTPV1) {
		t.Fatal("legacy auth bridge unexpectedly inherited a metadata capability")
	}
	if err := legacyStream.Send(&pb.AuthBridgeEnvelope{
		Payload: &pb.AuthBridgeEnvelope_Ready{Ready: &pb.AuthBridgeReady{
			InstanceId:   "legacy-client",
			Capabilities: []string{CapabilityAuthorizeHTTPV1},
		}},
	}); err != nil {
		t.Fatalf("send legacy ready envelope: %v", err)
	}
	waitForCapability(t, manager, CapabilityAuthorizeHTTPV1)
}

func TestAuthBridgeReadyCapabilitiesAndAuthorizeHTTP(t *testing.T) {
	manager := NewAuthBridgeManager("secret")
	stream := &blockingAuthBridgeStream{
		ctx:  context.Background(),
		sent: make(chan *pb.AuthBridgeEnvelope, 1),
	}
	active := manager.attachStream(stream)
	t.Cleanup(func() { manager.detachStream(active) })

	if manager.SupportsCapability(CapabilityAuthorizeHTTPV1) {
		t.Fatal("capability reported before ready envelope")
	}
	manager.handleIncoming(active, &pb.AuthBridgeEnvelope{
		Payload: &pb.AuthBridgeEnvelope_Ready{Ready: &pb.AuthBridgeReady{
			InstanceId:   "rust-1",
			Capabilities: []string{"", "  " + CapabilityAuthorizeHTTPV1 + "  ", "other"},
		}},
	})
	if !manager.SupportsCapability(CapabilityAuthorizeHTTPV1) {
		t.Fatal("authorize capability was not parsed from ready envelope")
	}
	if !manager.SupportsCapability("other") || manager.SupportsCapability("missing") {
		t.Fatal("capability snapshot did not match ready envelope")
	}

	result := make(chan struct {
		resp *pb.AuthorizeHttpResponse
		err  error
	}, 1)
	go func() {
		resp, err := manager.AuthorizeHTTP(context.Background(), &pb.AuthorizeHttpRequest{
			Context: &pb.AuthContext{ClientIp: "127.0.0.1"},
			Matched: true,
			Mode:    pb.HttpAuthMode_HTTP_AUTH_MODE_PREFLIGHT_AND_VERIFY,
		})
		result <- struct {
			resp *pb.AuthorizeHttpResponse
			err  error
		}{resp: resp, err: err}
	}()

	var request *pb.AuthBridgeEnvelope
	select {
	case request = <-stream.sent:
	case <-time.After(time.Second):
		t.Fatal("combined auth request was not sent")
	}
	if got := request.GetAuthorizeHttpRequest(); got == nil || !got.GetMatched() {
		t.Fatalf("request = %#v, want matched authorize HTTP request", request)
	}
	deadline := time.UnixMilli(request.GetDeadlineUnixMillis())
	if remaining := time.Until(deadline); remaining <= 0 || remaining > authBridgeRoundTripTimeout {
		t.Fatalf("request deadline remaining = %s, want (0, %s]", remaining, authBridgeRoundTripTimeout)
	}
	manager.dispatchResponse(active, &pb.AuthBridgeEnvelope{
		RequestId: request.GetRequestId(),
		Payload: &pb.AuthBridgeEnvelope_AuthorizeHttpResponse{
			AuthorizeHttpResponse: &pb.AuthorizeHttpResponse{
				Preflight:           &pb.PreflightAuthResponse{},
				Verify:              &pb.VerifyAuthResponse{Success: true, Status: 200},
				VerifyCacheScope:    pb.AuthCacheScope_AUTH_CACHE_SCOPE_HOST,
				PreflightCacheScope: pb.AuthCacheScope_AUTH_CACHE_SCOPE_EXACT_REQUEST,
			},
		},
	})

	select {
	case got := <-result:
		if got.err != nil {
			t.Fatalf("AuthorizeHTTP returned error: %v", got.err)
		}
		if !got.resp.GetVerify().GetSuccess() || got.resp.GetVerifyCacheScope() != pb.AuthCacheScope_AUTH_CACHE_SCOPE_HOST {
			t.Fatalf("AuthorizeHTTP response = %#v", got.resp)
		}
	case <-time.After(time.Second):
		t.Fatal("AuthorizeHTTP did not complete")
	}
}

func TestDeadlineOrDefaultUsesEarliestBudget(t *testing.T) {
	const fallback = 5 * time.Second

	shortContext, shortCancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer shortCancel()
	shortDeadline, _ := shortContext.Deadline()
	if got := deadlineOrDefault(shortContext, fallback); !got.Equal(shortDeadline) {
		t.Fatalf("short context deadline = %s, want %s", got, shortDeadline)
	}

	longContext, longCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer longCancel()
	started := time.Now()
	got := deadlineOrDefault(longContext, fallback)
	if got.Before(started.Add(fallback-time.Second)) || got.After(started.Add(fallback+time.Second)) {
		t.Fatalf("long context deadline = %s, want fallback near %s", got, started.Add(fallback))
	}
}

func TestAuthBridgeReadyChangeHookTracksHandshake(t *testing.T) {
	manager := NewAuthBridgeManager("secret")
	states := make(chan bool, 3)
	manager.SetReadyChangeHook(func(ready bool) { states <- ready })
	if ready := <-states; ready {
		t.Fatal("new manager reported ready")
	}
	active := &authBridgeStream{done: make(chan struct{})}
	manager.stream.Store(active)
	manager.handleIncoming(active, &pb.AuthBridgeEnvelope{
		Payload: &pb.AuthBridgeEnvelope_Ready{Ready: &pb.AuthBridgeReady{}},
	})
	if ready := <-states; !ready || !manager.IsReady() {
		t.Fatal("ready handshake was not published")
	}
	manager.detachStream(active)
	if ready := <-states; ready || manager.IsReady() {
		t.Fatal("bridge disconnect was not published")
	}
}

func TestAuthBridgeLegacyBridgeRejectsCombinedRequest(t *testing.T) {
	manager := NewAuthBridgeManager("secret")
	active := manager.attachStream(&blockingAuthBridgeStream{ctx: context.Background()})
	t.Cleanup(func() { manager.detachStream(active) })

	_, err := manager.AuthorizeHTTP(context.Background(), &pb.AuthorizeHttpRequest{})
	if !errors.Is(err, ErrAuthBridgeCapabilityUnsupported) {
		t.Fatalf("AuthorizeHTTP error = %v, want ErrAuthBridgeCapabilityUnsupported", err)
	}
}

func TestAuthBridgeLegacyRequestCompatibility(t *testing.T) {
	manager := NewAuthBridgeManager("secret")
	stream := &blockingAuthBridgeStream{
		ctx:  context.Background(),
		sent: make(chan *pb.AuthBridgeEnvelope, 1),
	}
	active := manager.attachStream(stream)
	t.Cleanup(func() { manager.detachStream(active) })

	tests := []struct {
		name     string
		call     func(context.Context) error
		respond  func(*pb.AuthBridgeEnvelope) *pb.AuthBridgeEnvelope
		validate func(*pb.AuthBridgeEnvelope) bool
	}{
		{
			name: "verify",
			call: func(ctx context.Context) error {
				resp, err := manager.VerifyAuth(ctx, &pb.VerifyAuthRequest{})
				if err == nil && (!resp.GetSuccess() || resp.GetStatus() != 200) {
					return errors.New("unexpected verify response")
				}
				return err
			},
			validate: func(msg *pb.AuthBridgeEnvelope) bool { return msg.GetVerifyAuthRequest() != nil },
			respond: func(msg *pb.AuthBridgeEnvelope) *pb.AuthBridgeEnvelope {
				return &pb.AuthBridgeEnvelope{RequestId: msg.GetRequestId(), Payload: &pb.AuthBridgeEnvelope_VerifyAuthResponse{VerifyAuthResponse: &pb.VerifyAuthResponse{Success: true, Status: 200}}}
			},
		},
		{
			name: "preflight",
			call: func(ctx context.Context) error {
				resp, err := manager.PreflightAuth(ctx, &pb.PreflightAuthRequest{})
				if err == nil && resp.GetDeny() {
					return errors.New("unexpected preflight response")
				}
				return err
			},
			validate: func(msg *pb.AuthBridgeEnvelope) bool { return msg.GetPreflightAuthRequest() != nil },
			respond: func(msg *pb.AuthBridgeEnvelope) *pb.AuthBridgeEnvelope {
				return &pb.AuthBridgeEnvelope{RequestId: msg.GetRequestId(), Payload: &pb.AuthBridgeEnvelope_PreflightAuthResponse{PreflightAuthResponse: &pb.PreflightAuthResponse{}}}
			},
		},
		{
			name: "stream",
			call: func(ctx context.Context) error {
				resp, err := manager.VerifyStreamAuth(ctx, &pb.VerifyStreamAuthRequest{})
				if err == nil && !resp.GetAllowed() {
					return errors.New("unexpected stream response")
				}
				return err
			},
			validate: func(msg *pb.AuthBridgeEnvelope) bool { return msg.GetVerifyStreamAuthRequest() != nil },
			respond: func(msg *pb.AuthBridgeEnvelope) *pb.AuthBridgeEnvelope {
				return &pb.AuthBridgeEnvelope{RequestId: msg.GetRequestId(), Payload: &pb.AuthBridgeEnvelope_VerifyStreamAuthResponse{VerifyStreamAuthResponse: &pb.VerifyStreamAuthResponse{Allowed: true, Status: 200}}}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := make(chan error, 1)
			go func() { result <- tt.call(context.Background()) }()
			var request *pb.AuthBridgeEnvelope
			select {
			case request = <-stream.sent:
			case <-time.After(time.Second):
				t.Fatal("legacy request was not sent")
			}
			if !tt.validate(request) {
				t.Fatalf("request payload = %T", request.GetPayload())
			}
			manager.dispatchResponse(active, tt.respond(request))
			select {
			case err := <-result:
				if err != nil {
					t.Fatalf("legacy call returned error: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("legacy call did not complete")
			}
		})
	}
}

func TestAuthBridgeRoundTripHonorsContextWhileWriterBlocked(t *testing.T) {
	manager := NewAuthBridgeManager("secret")
	stream := &blockingAuthBridgeStream{
		ctx:         context.Background(),
		sendStarted: make(chan struct{}),
		releaseSend: make(chan struct{}),
	}
	active := manager.attachStream(stream)
	t.Cleanup(func() {
		manager.detachStream(active)
		stream.release()
	})

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
	waitForPendingCount(t, manager, 0)
	if manager.stream.Load() != nil {
		t.Fatal("timed-out blocked Send left the auth bridge stream attached")
	}

	newStream := &blockingAuthBridgeStream{ctx: context.Background(), sent: make(chan *pb.AuthBridgeEnvelope, 1)}
	attachDone := make(chan struct{})
	var newActive *authBridgeStream
	go func() {
		newActive = manager.attachStream(newStream)
		close(attachDone)
	}()
	select {
	case <-attachDone:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("new stream attach was blocked by the old stuck Send")
	}
	manager.detachStream(newActive)
	stream.release()
}

func TestAuthBridgeCanceledSendThatUnblocksWithinGraceKeepsStream(t *testing.T) {
	manager := NewAuthBridgeManager("secret")
	stream := &blockingAuthBridgeStream{
		ctx:         context.Background(),
		sendStarted: make(chan struct{}),
		releaseSend: make(chan struct{}),
	}
	active := manager.attachStream(stream)
	t.Cleanup(func() {
		manager.detachStream(active)
		stream.release()
	})

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := manager.roundTrip(ctx, verifyEnvelope())
		result <- err
	}()
	select {
	case <-stream.sendStarted:
	case <-time.After(time.Second):
		t.Fatal("roundTrip did not start sending")
	}
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("roundTrip error = %v, want context canceled", err)
	}
	stream.release()
	deadline := time.Now().Add(time.Second)
	for active.sending.Load() != nil && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if active.sending.Load() != nil {
		t.Fatal("Send did not unblock")
	}
	time.Sleep(authBridgeCanceledSendGrace + 20*time.Millisecond)
	if manager.stream.Load() != active {
		t.Fatal("briefly blocked canceled Send detached a healthy auth bridge")
	}
}

func TestAuthBridgeBoundedWriterQueue(t *testing.T) {
	diagnostics.SetEnabled(true)
	t.Cleanup(func() { diagnostics.SetEnabled(false) })
	manager := NewAuthBridgeManager("secret")
	stream := &blockingAuthBridgeStream{
		ctx:         context.Background(),
		sendStarted: make(chan struct{}),
		releaseSend: make(chan struct{}),
	}
	active := manager.attachStream(stream)
	t.Cleanup(func() {
		manager.detachStream(active)
		stream.release()
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	results := make(chan error, authBridgeSendQueueSize+1)
	call := func() {
		_, err := manager.roundTrip(ctx, verifyEnvelope())
		results <- err
	}
	go call()
	select {
	case <-stream.sendStarted:
	case <-time.After(time.Second):
		t.Fatal("writer did not enter blocked Send")
	}
	for range authBridgeSendQueueSize {
		go call()
	}
	waitForQueueLength(t, active, authBridgeSendQueueSize)
	waitForAuthBridgeQueueDepth(t, uint64(authBridgeSendQueueSize))
	metrics := readAuthBridgeQueueMetrics(t)
	if metrics.Peak < uint64(authBridgeSendQueueSize) {
		t.Fatalf("auth bridge queue peak = %d, want at least %d", metrics.Peak, authBridgeSendQueueSize)
	}

	_, err := manager.roundTrip(context.Background(), verifyEnvelope())
	if !errors.Is(err, ErrAuthBridgeQueueFull) {
		t.Fatalf("overflow request error = %v, want ErrAuthBridgeQueueFull", err)
	}
	if got := len(active.sendQueue); got != authBridgeSendQueueSize {
		t.Fatalf("queue length = %d, want %d", got, authBridgeSendQueueSize)
	}
	if got := manager.inFlight.Load(); got != authBridgeSendQueueSize+1 {
		t.Fatalf("queue overflow leaked an admission slot: in flight = %d", got)
	}

	cancel()
	for range authBridgeSendQueueSize + 1 {
		select {
		case err := <-results:
			if !errors.Is(err, context.Canceled) && !errors.Is(err, ErrAuthBridgeUnavailable) {
				t.Fatalf("queued request error = %v, want context canceled or unavailable after stream detach", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("queued request did not observe cancellation")
		}
	}
	waitForPendingCount(t, manager, 0)
	stream.release()
	waitForAuthBridgeQueueDepth(t, 0)
	if got := manager.inFlight.Load(); got != 0 {
		t.Fatalf("canceled queue retained %d admission slots", got)
	}
}

func TestAuthBridgeReconnectFailsOnlyOldPendingRequests(t *testing.T) {
	manager := NewAuthBridgeManager("secret")
	oldStream := &blockingAuthBridgeStream{
		ctx:         context.Background(),
		sendStarted: make(chan struct{}),
		releaseSend: make(chan struct{}),
	}
	oldActive := manager.attachStream(oldStream)
	manager.handleIncoming(oldActive, &pb.AuthBridgeEnvelope{Payload: &pb.AuthBridgeEnvelope_Ready{Ready: &pb.AuthBridgeReady{Capabilities: []string{CapabilityAuthorizeHTTPV1}}}})

	oldResult := make(chan error, 1)
	go func() {
		_, err := manager.roundTrip(context.Background(), verifyEnvelope())
		oldResult <- err
	}()
	select {
	case <-oldStream.sendStarted:
	case <-time.After(time.Second):
		t.Fatal("old stream did not start sending")
	}

	newStream := &blockingAuthBridgeStream{ctx: context.Background(), sent: make(chan *pb.AuthBridgeEnvelope, 1)}
	newActive := manager.attachStream(newStream)
	t.Cleanup(func() {
		manager.detachStream(newActive)
		oldStream.release()
	})
	if manager.SupportsCapability(CapabilityAuthorizeHTTPV1) {
		t.Fatal("capabilities leaked across stream replacement")
	}
	select {
	case err := <-oldResult:
		if !errors.Is(err, ErrAuthBridgeDisconnected) {
			t.Fatalf("old request error = %v, want disconnected", err)
		}
	case <-time.After(time.Second):
		t.Fatal("old pending request was not failed on reconnect")
	}

	newResult := make(chan error, 1)
	go func() {
		_, err := manager.VerifyAuth(context.Background(), &pb.VerifyAuthRequest{})
		newResult <- err
	}()
	request := <-newStream.sent
	manager.detachStream(oldActive)
	manager.dispatchResponse(newActive, &pb.AuthBridgeEnvelope{
		RequestId: request.GetRequestId(),
		Payload:   &pb.AuthBridgeEnvelope_VerifyAuthResponse{VerifyAuthResponse: &pb.VerifyAuthResponse{Success: true, Status: 200}},
	})
	select {
	case err := <-newResult:
		if err != nil {
			t.Fatalf("new request failed after old detach: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("new request did not complete")
	}
	oldStream.release()
}

func TestAuthBridgeWaitReadyRequiresHandshake(t *testing.T) {
	manager := NewAuthBridgeManager("secret")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := manager.WaitReady(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("WaitReady without stream = %v, want deadline exceeded", err)
	}

	stream := &blockingAuthBridgeStream{
		ctx:  context.Background(),
		sent: make(chan *pb.AuthBridgeEnvelope, 1),
	}
	active := manager.attachStream(stream)
	t.Cleanup(func() { manager.detachStream(active) })
	ready := make(chan error, 1)
	go func() {
		ready <- manager.WaitReady(context.Background())
	}()
	manager.handleIncoming(active, &pb.AuthBridgeEnvelope{
		Payload: &pb.AuthBridgeEnvelope_Ready{
			Ready: &pb.AuthBridgeReady{Capabilities: []string{CapabilityAuthorizeHTTPV1}},
		},
	})
	select {
	case err := <-ready:
		if err != nil {
			t.Fatalf("WaitReady after handshake = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("WaitReady did not observe handshake")
	}
}

func waitForConnectedBridge(t *testing.T, manager *AuthBridgeManager) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if manager.stream.Load() != nil {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("auth bridge did not connect")
}

func waitForDisconnectedBridge(t *testing.T, manager *AuthBridgeManager) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if manager.stream.Load() == nil {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("auth bridge did not disconnect within one second")
}

func waitForCapability(t *testing.T, manager *AuthBridgeManager, capability string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if manager.SupportsCapability(capability) {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("auth bridge did not advertise capability %q", capability)
}

func waitForPendingCount(t *testing.T, manager *AuthBridgeManager, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		got := 0
		for i := range manager.pending {
			shard := &manager.pending[i]
			shard.Lock()
			got += len(shard.calls)
			shard.Unlock()
		}
		if got == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("pending request count did not reach %d", want)
}

func waitForQueueLength(t *testing.T, stream *authBridgeStream, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(stream.sendQueue) == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("writer queue length = %d, want %d", len(stream.sendQueue), want)
}

type authBridgeQueueMetrics struct {
	Depth uint64
	Peak  uint64
}

func readAuthBridgeQueueMetrics(t *testing.T) authBridgeQueueMetrics {
	t.Helper()
	recorder := httptest.NewRecorder()
	diagnostics.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/debug/metrics", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("diagnostics status = %d", recorder.Code)
	}
	var payload struct {
		Auth struct {
			Depth uint64 `json:"bridge_queue_depth"`
			Peak  uint64 `json:"bridge_queue_depth_peak"`
		} `json:"auth"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode diagnostics: %v", err)
	}
	return authBridgeQueueMetrics{Depth: payload.Auth.Depth, Peak: payload.Auth.Peak}
}

func waitForAuthBridgeQueueDepth(t *testing.T, want uint64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if got := readAuthBridgeQueueMetrics(t).Depth; got == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("auth bridge diagnostic queue depth = %d, want %d", readAuthBridgeQueueMetrics(t).Depth, want)
}

func verifyEnvelope() *pb.AuthBridgeEnvelope {
	return &pb.AuthBridgeEnvelope{
		Payload: &pb.AuthBridgeEnvelope_VerifyAuthRequest{VerifyAuthRequest: &pb.VerifyAuthRequest{}},
	}
}

type blockingAuthBridgeStream struct {
	grpc.ServerStream
	ctx             context.Context
	sendStarted     chan struct{}
	sendStartedOnce sync.Once
	releaseSend     chan struct{}
	releaseOnce     sync.Once
	sent            chan *pb.AuthBridgeEnvelope
}

func (s *blockingAuthBridgeStream) Context() context.Context {
	if s.ctx == nil {
		return context.Background()
	}
	return s.ctx
}

func (s *blockingAuthBridgeStream) Send(msg *pb.AuthBridgeEnvelope) error {
	if s.sendStarted != nil {
		s.sendStartedOnce.Do(func() {
			close(s.sendStarted)
		})
	}
	if s.releaseSend != nil {
		<-s.releaseSend
	}
	if s.sent != nil {
		s.sent <- msg
	}
	return nil
}

func (s *blockingAuthBridgeStream) Recv() (*pb.AuthBridgeEnvelope, error) {
	return nil, io.EOF
}

func (s *blockingAuthBridgeStream) release() {
	if s.releaseSend != nil {
		s.releaseOnce.Do(func() { close(s.releaseSend) })
	}
}
