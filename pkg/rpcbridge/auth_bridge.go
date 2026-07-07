package rpcbridge

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"go-reauth-proxy/pkg/grpc/pb"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const InternalTokenMetadataKey = "x-fn-knock-internal-rpc-token"

var (
	ErrAuthBridgeUnavailable     = errors.New("auth bridge is not connected")
	ErrInternalRPCTokenRequired  = errors.New("FN_KNOCK_INTERNAL_RPC_TOKEN must be set for internal gRPC")
	errInternalRPCTokenUnsetGRPC = status.Error(codes.Unauthenticated, "internal rpc token is not configured")
)

type AuthBridgeManager struct {
	pb.UnimplementedAuthBridgeServiceServer

	token string

	mu      sync.Mutex
	stream  *authBridgeStream
	pending map[string]chan *pb.AuthBridgeEnvelope
	nextID  uint64
}

type authBridgeStream struct {
	server   pb.AuthBridgeService_ConnectAuthBridgeServer
	sendMu   sync.Mutex
	done     chan struct{}
	doneOnce sync.Once
}

type authBridgeRecvResult struct {
	msg *pb.AuthBridgeEnvelope
	err error
}

func NewAuthBridgeManager(token string) *AuthBridgeManager {
	return &AuthBridgeManager{
		token:   strings.TrimSpace(token),
		pending: make(map[string]chan *pb.AuthBridgeEnvelope),
	}
}

func (m *AuthBridgeManager) ConnectAuthBridge(stream pb.AuthBridgeService_ConnectAuthBridgeServer) error {
	if err := CheckInternalToken(stream.Context(), m.token); err != nil {
		return err
	}

	active := m.attachStream(stream)

	defer func() {
		m.detachStream(active)
	}()

	recvCh := make(chan authBridgeRecvResult, 1)
	go active.recvLoop(recvCh)

	for {
		select {
		case <-active.done:
			return status.Error(codes.Unavailable, "auth bridge stream closed")
		case result := <-recvCh:
			if result.err == nil {
				m.dispatchResponse(result.msg)
				continue
			}
			if errors.Is(result.err, io.EOF) {
				return nil
			}
			return result.err
		}
	}
}

func (m *AuthBridgeManager) VerifyAuth(ctx context.Context, req *pb.VerifyAuthRequest) (*pb.VerifyAuthResponse, error) {
	msg, err := m.roundTrip(ctx, &pb.AuthBridgeEnvelope{
		Payload: &pb.AuthBridgeEnvelope_VerifyAuthRequest{VerifyAuthRequest: req},
	})
	if err != nil {
		return nil, err
	}
	resp := msg.GetVerifyAuthResponse()
	if resp == nil {
		return nil, fmt.Errorf("auth bridge returned %T for verify auth", msg.GetPayload())
	}
	return resp, nil
}

func (m *AuthBridgeManager) PreflightAuth(ctx context.Context, req *pb.PreflightAuthRequest) (*pb.PreflightAuthResponse, error) {
	msg, err := m.roundTrip(ctx, &pb.AuthBridgeEnvelope{
		Payload: &pb.AuthBridgeEnvelope_PreflightAuthRequest{PreflightAuthRequest: req},
	})
	if err != nil {
		return nil, err
	}
	resp := msg.GetPreflightAuthResponse()
	if resp == nil {
		return nil, fmt.Errorf("auth bridge returned %T for preflight auth", msg.GetPayload())
	}
	return resp, nil
}

func (m *AuthBridgeManager) VerifyStreamAuth(ctx context.Context, req *pb.VerifyStreamAuthRequest) (*pb.VerifyStreamAuthResponse, error) {
	msg, err := m.roundTrip(ctx, &pb.AuthBridgeEnvelope{
		Payload: &pb.AuthBridgeEnvelope_VerifyStreamAuthRequest{VerifyStreamAuthRequest: req},
	})
	if err != nil {
		return nil, err
	}
	resp := msg.GetVerifyStreamAuthResponse()
	if resp == nil {
		return nil, fmt.Errorf("auth bridge returned %T for stream auth", msg.GetPayload())
	}
	return resp, nil
}

func (m *AuthBridgeManager) roundTrip(ctx context.Context, msg *pb.AuthBridgeEnvelope) (*pb.AuthBridgeEnvelope, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithDeadline(ctx, deadlineOrDefault(ctx, 5*time.Second))
	defer cancel()

	m.mu.Lock()
	if m.stream == nil {
		m.mu.Unlock()
		return nil, ErrAuthBridgeUnavailable
	}
	requestID := m.nextRequestIDLocked()
	msg.RequestId = requestID
	ch := make(chan *pb.AuthBridgeEnvelope, 1)
	m.pending[requestID] = ch
	stream := m.stream
	m.mu.Unlock()

	cleanupPending := func() {
		m.mu.Lock()
		delete(m.pending, requestID)
		m.mu.Unlock()
	}

	m.mu.Lock()
	if m.stream != stream {
		delete(m.pending, requestID)
		m.mu.Unlock()
		return nil, ErrAuthBridgeUnavailable
	}
	m.mu.Unlock()
	if err := stream.send(ctx, msg); err != nil {
		cleanupPending()
		if errors.Is(err, context.DeadlineExceeded) {
			m.detachStream(stream)
		}
		return nil, err
	}
	defer cleanupPending()

	select {
	case resp := <-ch:
		if resp == nil {
			return nil, ErrAuthBridgeUnavailable
		}
		return resp, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *authBridgeStream) send(ctx context.Context, msg *pb.AuthBridgeEnvelope) error {
	done := make(chan error, 1)
	go func() {
		s.sendMu.Lock()
		defer s.sendMu.Unlock()
		select {
		case <-ctx.Done():
			done <- ctx.Err()
			return
		case <-s.done:
			done <- ErrAuthBridgeUnavailable
			return
		default:
		}
		done <- s.server.Send(msg)
	}()
	select {
	case err := <-done:
		return err
	case <-s.done:
		return ErrAuthBridgeUnavailable
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *authBridgeStream) recvLoop(recvCh chan<- authBridgeRecvResult) {
	for {
		msg, err := s.server.Recv()
		result := authBridgeRecvResult{msg: msg, err: err}
		select {
		case recvCh <- result:
		case <-s.done:
			return
		}
		if err != nil {
			return
		}
	}
}

func (s *authBridgeStream) close() {
	s.doneOnce.Do(func() {
		close(s.done)
	})
}

func (m *AuthBridgeManager) nextRequestIDLocked() string {
	m.nextID++
	return fmt.Sprintf("%d-%d", time.Now().UnixNano(), m.nextID)
}

func (m *AuthBridgeManager) dispatchResponse(msg *pb.AuthBridgeEnvelope) {
	if msg == nil || msg.RequestId == "" {
		return
	}
	m.mu.Lock()
	ch := m.pending[msg.RequestId]
	m.mu.Unlock()
	if ch == nil {
		return
	}
	select {
	case ch <- msg:
	default:
	}
}

func (m *AuthBridgeManager) attachStream(stream pb.AuthBridgeService_ConnectAuthBridgeServer) *authBridgeStream {
	active := &authBridgeStream{server: stream, done: make(chan struct{})}
	m.mu.Lock()
	previous := m.stream
	var pending map[string]chan *pb.AuthBridgeEnvelope
	if previous != nil {
		pending = m.pending
		m.pending = make(map[string]chan *pb.AuthBridgeEnvelope)
	}
	m.stream = active
	m.mu.Unlock()

	if previous != nil {
		previous.close()
	}
	signalPendingUnavailable(pending)
	return active
}

func (m *AuthBridgeManager) detachStream(stream *authBridgeStream) {
	m.mu.Lock()
	var pending map[string]chan *pb.AuthBridgeEnvelope
	if m.stream == stream {
		m.stream = nil
		pending = m.pending
		m.pending = make(map[string]chan *pb.AuthBridgeEnvelope)
	}
	m.mu.Unlock()

	stream.close()
	signalPendingUnavailable(pending)
}

func signalPendingUnavailable(pending map[string]chan *pb.AuthBridgeEnvelope) {
	for _, ch := range pending {
		select {
		case ch <- nil:
		default:
		}
	}
}

func CheckInternalToken(ctx context.Context, token string) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return errInternalRPCTokenUnsetGRPC
	}
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "missing internal rpc token")
	}
	for _, value := range md.Get(InternalTokenMetadataKey) {
		if internalTokenEqual(value, token) {
			return nil
		}
	}
	for _, value := range md.Get("authorization") {
		const prefix = "Bearer "
		if len(value) > len(prefix) && value[:len(prefix)] == prefix && internalTokenEqual(value[len(prefix):], token) {
			return nil
		}
	}
	return status.Error(codes.Unauthenticated, "invalid internal rpc token")
}

func ResolveInternalToken(primary string) (string, error) {
	if token := strings.TrimSpace(primary); token != "" {
		return token, nil
	}
	return "", ErrInternalRPCTokenRequired
}

func internalTokenEqual(got string, want string) bool {
	if got == "" || want == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func deadlineOrDefault(ctx context.Context, fallback time.Duration) time.Time {
	if deadline, ok := ctx.Deadline(); ok {
		return deadline
	}
	return time.Now().Add(fallback)
}
