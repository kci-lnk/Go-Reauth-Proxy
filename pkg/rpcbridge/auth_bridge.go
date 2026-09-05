package rpcbridge

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go-reauth-proxy/pkg/diagnostics"
	"go-reauth-proxy/pkg/grpc/pb"
	operationallog "go-reauth-proxy/pkg/logger"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	InternalTokenMetadataKey        = "x-fn-knock-internal-rpc-token"
	AuthBridgeInstanceMetadataKey   = "x-fn-knock-auth-bridge-instance-id"
	AuthBridgeCapabilityMetadataKey = "x-fn-knock-auth-bridge-capability"
	CapabilityAuthorizeHTTPV1       = "authorize_http_v1"
	CapabilitySubdomainRuleGrantV1  = "subdomain_rule_grant_v1"
	authBridgeSendQueueSize         = 256
	authBridgeInFlightLimit         = 1024
	authBridgePendingShardCount     = 64
	authBridgeRoundTripTimeout      = 5 * time.Second
	authBridgeCanceledSendGrace     = 100 * time.Millisecond
)

var (
	ErrAuthBridgeUnavailable           = errors.New("auth bridge is not connected")
	ErrAuthBridgeDisconnected          = errors.New("auth bridge disconnected")
	ErrAuthBridgeQueueFull             = errors.New("auth bridge request queue is full")
	ErrAuthBridgeInvalidResponse       = errors.New("auth bridge returned an invalid response")
	ErrAuthBridgeCapabilityUnsupported = errors.New("auth bridge capability is not supported")
	ErrInternalRPCTokenRequired        = errors.New("FN_KNOCK_INTERNAL_RPC_TOKEN must be set for internal gRPC")
	errInternalRPCTokenUnsetGRPC       = status.Error(codes.Unauthenticated, "internal rpc token is not configured")
)

type AuthBridgeManager struct {
	pb.UnimplementedAuthBridgeServiceServer

	token string

	stream        atomic.Pointer[authBridgeStream]
	readyOnChange atomic.Value
	readyNotify   chan struct{}
	nextID        atomic.Uint64
	pending       [authBridgePendingShardCount]authBridgePendingShard
	inFlight      atomic.Int64
	inFlightLimit int64
	readyMu       sync.Mutex
}

type authBridgeStream struct {
	server       pb.AuthBridgeService_ConnectAuthBridgeServer
	sendQueue    chan authBridgeOutboundRequest
	done         chan struct{}
	doneOnce     sync.Once
	capabilities atomic.Pointer[authBridgeCapabilities]
	sending      atomic.Pointer[authBridgeSending]
}

type authBridgeCapabilities struct {
	values map[string]struct{}
}

type authBridgeOutboundRequest struct {
	ctx       context.Context
	requestID string
	call      *authBridgePendingCall
	msg       *pb.AuthBridgeEnvelope
}

type authBridgeSending struct {
	requestID string
	call      *authBridgePendingCall
}

// authBridgePendingCall must only be passed by pointer after construction:
// newAuthBridgePendingCall initializes done before the call is published.
// stream is immutable; a non-nil stream also identifies an admitted call.
type authBridgePendingCall struct {
	stream   *authBridgeStream
	response *pb.AuthBridgeEnvelope
	err      error
	done     sync.WaitGroup
}

// A non-nil stream requires a successful reserveInFlight before construction.
// Production calls always have a stream. A nil stream is reserved for isolated
// completion tests/benchmarks that do not exercise admission. Reusing this
// immutable pointer avoids a separate flag that grows every pending allocation.
func newAuthBridgePendingCall(stream *authBridgeStream) *authBridgePendingCall {
	call := &authBridgePendingCall{stream: stream}
	// Add before the call is published in a pending shard. Every successful
	// removal from that shard performs exactly one Done, so the waiter has a
	// targeted completion signal without a separate heap object.
	call.done.Add(1)
	return call
}

func (c *authBridgePendingCall) wait() {
	c.done.Wait()
}

func (c *authBridgePendingCall) signal() {
	c.done.Done()
}

type authBridgePendingShard struct {
	sync.Mutex
	calls map[string]*authBridgePendingCall
}

type authBridgeRecvResult struct {
	msg *pb.AuthBridgeEnvelope
	err error
}

func NewAuthBridgeManager(token string) *AuthBridgeManager {
	m := &AuthBridgeManager{
		token:         strings.TrimSpace(token),
		readyNotify:   make(chan struct{}),
		inFlightLimit: authBridgeConfiguredInFlightLimit(),
	}
	var emptyReadyHook func(bool)
	m.readyOnChange.Store(emptyReadyHook)
	for i := range m.pending {
		shard := &m.pending[i]
		shard.calls = make(map[string]*authBridgePendingCall)
	}
	return m
}

// IsReady reports whether the currently active authenticated bridge completed
// metadata initialization or entered the capability-safe legacy fallback.
func (m *AuthBridgeManager) IsReady() bool {
	active := m.stream.Load()
	return active != nil && active.capabilities.Load() != nil && !active.isClosed()
}

// SetReadyChangeHook publishes Ready handshake transitions to process-level
// health reporting. The hook is immediately called with the current state.
func (m *AuthBridgeManager) SetReadyChangeHook(hook func(bool)) {
	if hook == nil {
		hook = func(bool) {}
	}
	m.readyOnChange.Store(hook)
	hook(m.IsReady())
}

func (m *AuthBridgeManager) notifyReadyChange(ready bool) {
	// Each transition wakes every waiter on the current generation. A single
	// queued notification can strand concurrent callers after readiness changes.
	m.readyMu.Lock()
	close(m.readyNotify)
	m.readyNotify = make(chan struct{})
	m.readyMu.Unlock()
	value := m.readyOnChange.Load()
	if hook, ok := value.(func(bool)); ok && hook != nil {
		hook(ready)
	}
}

// WaitReady blocks until a connected Rust bridge has completed initialization.
// Callers use this to keep public proxy listeners closed during startup while
// the internal gRPC control plane remains available.
func (m *AuthBridgeManager) WaitReady(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	for !m.IsReady() {
		m.readyMu.Lock()
		notify := m.readyNotify
		m.readyMu.Unlock()
		// Snapshot the generation before rechecking readiness, so a transition
		// between the fast check and subscription cannot become a missed wakeup.
		if m.IsReady() {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-notify:
		}
	}
	return nil
}

func (m *AuthBridgeManager) ConnectAuthBridge(stream pb.AuthBridgeService_ConnectAuthBridgeServer) error {
	if err := CheckInternalToken(stream.Context(), m.token); err != nil {
		return err
	}
	// Tonic does not guarantee that the request body is polled before the server
	// returns initial response headers. Current Rust clients therefore advertise
	// readiness in request metadata, which arrives with the HTTP/2 headers and
	// cannot race the first DATA frame. The body Ready envelope remains supported
	// for capability refreshes. A legacy client without capability metadata is
	// still safe to mark ready with an empty capability set: callers then use the
	// older split authorization RPCs instead of assuming newer bridge features.
	ready := authBridgeReadyFromMetadata(stream.Context())
	if ready == nil {
		ready = &pb.AuthBridgeReady{}
	}
	if err := stream.SendHeader(metadata.MD{}); err != nil {
		return status.Errorf(codes.Unavailable, "send auth bridge initial headers: %v", err)
	}

	active := m.attachStream(stream)
	defer func() {
		m.detachStream(active)
	}()
	m.handleIncoming(active, &pb.AuthBridgeEnvelope{
		Payload: &pb.AuthBridgeEnvelope_Ready{Ready: ready},
	})

	recvCh := make(chan authBridgeRecvResult, 1)
	go active.recvLoop(recvCh)

	for {
		select {
		case <-active.done:
			return status.Error(codes.Unavailable, "auth bridge stream closed")
		case result := <-recvCh:
			if result.err == nil {
				m.handleIncoming(active, result.msg)
				continue
			}
			if errors.Is(result.err, io.EOF) {
				return nil
			}
			return result.err
		}
	}
}

func authBridgeReadyFromMetadata(ctx context.Context) *pb.AuthBridgeReady {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil
	}
	values := md.Get(AuthBridgeCapabilityMetadataKey)
	capabilities := make([]string, 0, len(values))
	for _, value := range values {
		if capability := strings.TrimSpace(value); capability != "" {
			capabilities = append(capabilities, capability)
		}
	}
	if len(capabilities) == 0 {
		return nil
	}
	instanceID := ""
	if values := md.Get(AuthBridgeInstanceMetadataKey); len(values) > 0 {
		instanceID = strings.TrimSpace(values[0])
	}
	return &pb.AuthBridgeReady{InstanceId: instanceID, Capabilities: capabilities}
}

// SupportsCapability reports whether the currently connected bridge advertised
// capability in its most recent ready envelope.
func (m *AuthBridgeManager) SupportsCapability(capability string) bool {
	active := m.stream.Load()
	return active != nil && active.supportsCapability(capability)
}

// AuthorizeHTTP performs the combined HTTP preflight and verification request.
// Callers can use SupportsCapability to select this path without probing a
// legacy bridge; this method also rechecks the capability against the exact
// stream used for the request so a reconnect cannot send a new envelope to an
// older bridge.
func (m *AuthBridgeManager) AuthorizeHTTP(ctx context.Context, req *pb.AuthorizeHttpRequest) (*pb.AuthorizeHttpResponse, error) {
	active := m.stream.Load()
	if active == nil {
		return nil, ErrAuthBridgeUnavailable
	}
	if !active.supportsCapability(CapabilityAuthorizeHTTPV1) {
		return nil, ErrAuthBridgeCapabilityUnsupported
	}
	msg, err := m.roundTripOnStream(ctx, active, &pb.AuthBridgeEnvelope{
		Payload: &pb.AuthBridgeEnvelope_AuthorizeHttpRequest{AuthorizeHttpRequest: req},
	})
	if err != nil {
		return nil, err
	}
	resp := msg.GetAuthorizeHttpResponse()
	if resp == nil {
		return nil, fmt.Errorf("%w for authorize http", ErrAuthBridgeInvalidResponse)
	}
	return resp, nil
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
		return nil, fmt.Errorf("%w for verify auth", ErrAuthBridgeInvalidResponse)
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
		return nil, fmt.Errorf("%w for preflight auth", ErrAuthBridgeInvalidResponse)
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
		return nil, fmt.Errorf("%w for stream auth", ErrAuthBridgeInvalidResponse)
	}
	return resp, nil
}

func (m *AuthBridgeManager) roundTrip(ctx context.Context, msg *pb.AuthBridgeEnvelope) (*pb.AuthBridgeEnvelope, error) {
	return m.roundTripOnStream(ctx, nil, msg)
}

func (m *AuthBridgeManager) roundTripOnStream(ctx context.Context, expected *authBridgeStream, msg *pb.AuthBridgeEnvelope) (*pb.AuthBridgeEnvelope, error) {
	started := time.Now()
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithDeadline(ctx, deadlineOrDefault(ctx, authBridgeRoundTripTimeout))
	defer cancel()
	deadline, _ := ctx.Deadline()
	// Stamp the deadline before enqueueing. The Rust bridge must account for
	// time spent in this process's writer queue and in the gRPC transport rather
	// than starting a fresh timeout after it eventually receives the request.
	msg.DeadlineUnixMillis = deadline.UnixMilli()

	active := m.stream.Load()
	if active == nil || (expected != nil && active != expected) {
		return nil, ErrAuthBridgeUnavailable
	}
	diagnostics.RecordAuthBridgeRequest()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !m.reserveInFlight() {
		diagnostics.RecordAuthBridgeInFlightDrop()
		return nil, ErrAuthBridgeQueueFull
	}

	requestID := strconv.FormatUint(m.nextID.Add(1), 10)
	msg.RequestId = requestID
	call := newAuthBridgePendingCall(active)
	shard := m.pendingShard(requestID)
	shard.Lock()
	shard.calls[requestID] = call
	shard.Unlock()

	stopCancellation := context.AfterFunc(ctx, func() {
		ctxErr := ctx.Err()
		m.completePending(requestID, call, nil, ctxErr)
		m.recoverBlockedSend(active, requestID, call, ctxErr)
	})
	defer stopCancellation()

	if ctxErr := ctx.Err(); ctxErr != nil {
		m.completePending(requestID, call, nil, ctxErr)
		return nil, ctxErr
	}
	if m.stream.Load() != active || active.isClosed() {
		m.completePending(requestID, call, nil, ErrAuthBridgeUnavailable)
		return nil, ErrAuthBridgeUnavailable
	}

	if err := active.enqueue(m, authBridgeOutboundRequest{
		ctx:       ctx,
		requestID: requestID,
		call:      call,
		msg:       msg,
	}); err != nil {
		m.completePending(requestID, call, nil, err)
		return nil, err
	}

	call.wait()
	resp, err := call.response, call.err
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			operationallog.Diagnostic("WARN", "auth_bridge", "round_trip_timeout", "response_timeout", map[string]any{
				"duration_ms": time.Since(started).Milliseconds(),
				"queue_depth": len(active.sendQueue),
				"in_flight":   m.inFlight.Load(),
			})
		}
		return nil, err
	}
	return resp, nil
}

func (m *AuthBridgeManager) recoverBlockedSend(stream *authBridgeStream, requestID string, call *authBridgePendingCall, ctxErr error) {
	if stream == nil || !stream.isSending(requestID, call) {
		return
	}
	if errors.Is(ctxErr, context.DeadlineExceeded) {
		m.detachStream(stream)
		return
	}
	if !errors.Is(ctxErr, context.Canceled) {
		return
	}
	time.AfterFunc(authBridgeCanceledSendGrace, func() {
		if stream.isSending(requestID, call) {
			m.detachStream(stream)
		}
	})
}

func (s *authBridgeStream) enqueue(m *AuthBridgeManager, request authBridgeOutboundRequest) error {
	if err := request.ctx.Err(); err != nil {
		return err
	}
	select {
	case <-s.done:
		return ErrAuthBridgeUnavailable
	default:
	}
	select {
	case s.sendQueue <- request:
		m.observeQueueDepth(s)
		return nil
	case <-s.done:
		m.observeQueueDepth(s)
		return ErrAuthBridgeUnavailable
	case <-request.ctx.Done():
		m.observeQueueDepth(s)
		return request.ctx.Err()
	default:
		m.observeQueueDepth(s)
		diagnostics.RecordAuthBridgeQueueDrop()
		operationallog.Diagnostic("WARN", "auth_bridge", "queue_overflow", "send_queue_full", map[string]any{
			"queue_depth": len(s.sendQueue),
		})
		return ErrAuthBridgeQueueFull
	}
}

func (s *authBridgeStream) writerLoop(m *AuthBridgeManager) {
	for {
		select {
		case <-s.done:
			return
		case request := <-s.sendQueue:
			m.observeQueueDepth(s)
			if s.isClosed() || request.ctx.Err() != nil || !m.pendingMatches(request.requestID, request.call) {
				continue
			}
			sending := &authBridgeSending{requestID: request.requestID, call: request.call}
			s.sending.Store(sending)
			if s.isClosed() || request.ctx.Err() != nil || !m.pendingMatches(request.requestID, request.call) {
				s.sending.CompareAndSwap(sending, nil)
				continue
			}
			err := s.server.Send(request.msg)
			s.sending.CompareAndSwap(sending, nil)
			if err != nil {
				m.detachStream(s)
				return
			}
		}
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

func (s *authBridgeStream) isClosed() bool {
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}

func (s *authBridgeStream) isSending(requestID string, call *authBridgePendingCall) bool {
	current := s.sending.Load()
	return current != nil && current.requestID == requestID && current.call == call
}

func (s *authBridgeStream) setCapabilities(ready *pb.AuthBridgeReady) {
	values := make(map[string]struct{}, len(ready.GetCapabilities()))
	for _, capability := range ready.GetCapabilities() {
		capability = strings.TrimSpace(capability)
		if capability != "" {
			values[capability] = struct{}{}
		}
	}
	s.capabilities.Store(&authBridgeCapabilities{values: values})
}

func (s *authBridgeStream) supportsCapability(capability string) bool {
	capability = strings.TrimSpace(capability)
	if capability == "" {
		return false
	}
	snapshot := s.capabilities.Load()
	if snapshot == nil {
		return false
	}
	_, ok := snapshot.values[capability]
	return ok
}

func (m *AuthBridgeManager) handleIncoming(stream *authBridgeStream, msg *pb.AuthBridgeEnvelope) {
	if msg == nil {
		return
	}
	if ready := msg.GetReady(); ready != nil {
		stream.setCapabilities(ready)
		if m.stream.Load() == stream {
			m.notifyReadyChange(true)
			operationallog.Diagnostic("INFO", "auth_bridge", "ready", "handshake_completed", map[string]any{
				"status": "ready",
			})
		}
		return
	}
	m.dispatchResponse(stream, msg)
}

func (m *AuthBridgeManager) dispatchResponse(stream *authBridgeStream, msg *pb.AuthBridgeEnvelope) {
	if msg == nil || msg.RequestId == "" {
		return
	}
	shard := m.pendingShard(msg.RequestId)
	shard.Lock()
	call := shard.calls[msg.RequestId]
	if call != nil && call.stream == stream {
		delete(shard.calls, msg.RequestId)
		call.response = msg
		m.releaseInFlight(call)
		call.signal()
	}
	shard.Unlock()
}

func (m *AuthBridgeManager) attachStream(stream pb.AuthBridgeService_ConnectAuthBridgeServer) *authBridgeStream {
	active := &authBridgeStream{
		server:    stream,
		sendQueue: make(chan authBridgeOutboundRequest, authBridgeSendQueueSize),
		done:      make(chan struct{}),
	}
	previous := m.stream.Swap(active)
	m.notifyReadyChange(false)
	m.observeQueueDepth(active)
	go active.writerLoop(m)
	if previous == nil {
		operationallog.Diagnostic("INFO", "auth_bridge", "connected", "stream_attached", map[string]any{
			"status": "connected",
		})
	} else {
		operationallog.Diagnostic("WARN", "auth_bridge", "reconnected", "stream_replaced", map[string]any{
			"status": "connected",
		})
	}

	if previous != nil {
		previous.close()
		m.failPendingForStream(previous, ErrAuthBridgeDisconnected)
	}
	return active
}

func (m *AuthBridgeManager) detachStream(stream *authBridgeStream) {
	if m.stream.CompareAndSwap(stream, nil) {
		m.notifyReadyChange(false)
		diagnostics.ObserveAuthBridgeQueueDepth(0)
		operationallog.Diagnostic("WARN", "auth_bridge", "disconnected", "stream_closed", map[string]any{
			"status": "disconnected",
		})
		if active := m.stream.Load(); active != nil {
			m.observeQueueDepth(active)
		}
	}
	stream.close()
	m.failPendingForStream(stream, ErrAuthBridgeDisconnected)
}

func (m *AuthBridgeManager) observeQueueDepth(stream *authBridgeStream) {
	if m.stream.Load() != stream {
		return
	}
	diagnostics.ObserveAuthBridgeQueueDepth(uint64(len(stream.sendQueue)))
}

func (m *AuthBridgeManager) pendingShard(requestID string) *authBridgePendingShard {
	var hash uint64 = 14695981039346656037
	for i := 0; i < len(requestID); i++ {
		hash ^= uint64(requestID[i])
		hash *= 1099511628211
	}
	return &m.pending[hash&(authBridgePendingShardCount-1)]
}

func (m *AuthBridgeManager) pendingMatches(requestID string, want *authBridgePendingCall) bool {
	shard := m.pendingShard(requestID)
	shard.Lock()
	matches := shard.calls[requestID] == want
	shard.Unlock()
	return matches
}

func (m *AuthBridgeManager) completePending(requestID string, want *authBridgePendingCall, response *pb.AuthBridgeEnvelope, err error) {
	shard := m.pendingShard(requestID)
	shard.Lock()
	if shard.calls[requestID] == want {
		delete(shard.calls, requestID)
		want.response = response
		want.err = err
		m.releaseInFlight(want)
		want.signal()
	}
	shard.Unlock()
}

func (m *AuthBridgeManager) failPendingForStream(stream *authBridgeStream, err error) {
	for i := range m.pending {
		shard := &m.pending[i]
		shard.Lock()
		for requestID, call := range shard.calls {
			if call.stream == stream {
				delete(shard.calls, requestID)
				call.err = err
				m.releaseInFlight(call)
				call.signal()
			}
		}
		shard.Unlock()
	}
}

func authBridgeConfiguredInFlightLimit() int64 {
	const name = "FN_KNOCK_AUTH_BRIDGE_MAX_IN_FLIGHT"
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return authBridgeInFlightLimit
	}
	limit, err := strconv.ParseInt(value, 10, 64)
	if err != nil || limit < 1 {
		operationallog.Diagnostic("WARN", "auth_bridge", "invalid_config", name, nil)
		return authBridgeInFlightLimit
	}
	return limit
}

func (m *AuthBridgeManager) reserveInFlight() bool {
	limit := m.inFlightLimit
	if limit <= 0 {
		limit = authBridgeInFlightLimit
	}
	for {
		current := m.inFlight.Load()
		if current >= limit {
			return false
		}
		if m.inFlight.CompareAndSwap(current, current+1) {
			diagnostics.AddAuthBridgeInFlight(1)
			return true
		}
	}
}

// The successful pending-shard removal is the sole owner of releasing a slot.
// Late responses, cancellation and reconnects therefore cannot double-release.
// The immutable stream distinguishes admitted calls from nil-stream completion
// fixtures; it is not the once guard, which is the shard-locked map deletion.
func (m *AuthBridgeManager) releaseInFlight(call *authBridgePendingCall) {
	if call.stream != nil {
		m.releaseAdmittedInFlight()
	}
}

// Share the platform-specific atomic instruction sequences across response,
// cancellation and disconnect completion paths instead of expanding them in
// each caller. The caller still owns the shard lock and the unique map removal.
//
//go:noinline
func (m *AuthBridgeManager) releaseAdmittedInFlight() {
	m.inFlight.Add(-1)
	diagnostics.AddAuthBridgeInFlight(-1)
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
	fallbackDeadline := time.Now().Add(fallback)
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(fallbackDeadline) {
		return deadline
	}
	return fallbackDeadline
}
