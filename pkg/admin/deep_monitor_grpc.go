package admin

import (
	"context"
	"errors"
	"io"
	"time"

	"go-reauth-proxy/pkg/deepmonitor"
	"go-reauth-proxy/pkg/grpc/pb"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *GRPCServer) deepMonitor() (*deepmonitor.Manager, error) {
	if s == nil || s.admin == nil || s.admin.ProxyHandler == nil || s.admin.ProxyHandler.DeepMonitorManager() == nil {
		return nil, status.Error(codes.Unavailable, "deep monitor storage is unavailable")
	}
	return s.admin.ProxyHandler.DeepMonitorManager(), nil
}

func (s *GRPCServer) StartSession(ctx context.Context, req *pb.DeepMonitorStartRequest) (*pb.DeepMonitorSession, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	duration := time.Duration(req.GetDurationSeconds()) * time.Second
	result, err := s.admin.ProxyHandler.StartDeepMonitor(req.GetHost(), duration)
	if err != nil {
		return nil, deepMonitorStatus(err)
	}
	return result, nil
}

func (s *GRPCServer) ExtendSession(ctx context.Context, req *pb.DeepMonitorExtendRequest) (*pb.DeepMonitorSession, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	manager, err := s.deepMonitor()
	if err != nil {
		return nil, err
	}
	if req == nil || req.GetSessionId() == "" {
		return nil, status.Error(codes.InvalidArgument, "session_id is required")
	}
	result, extendErr := manager.Extend(req.GetSessionId(), time.Duration(req.GetDurationSeconds())*time.Second)
	if extendErr != nil {
		return nil, deepMonitorStatus(extendErr)
	}
	return result, nil
}

func (s *GRPCServer) StopSession(ctx context.Context, req *pb.DeepMonitorSessionRequest) (*pb.DeepMonitorSession, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	manager, err := s.deepMonitor()
	if err != nil {
		return nil, err
	}
	if req == nil || req.GetSessionId() == "" {
		return nil, status.Error(codes.InvalidArgument, "session_id is required")
	}
	result, stopErr := manager.Stop(req.GetSessionId(), "manual_stop")
	if stopErr != nil {
		return nil, deepMonitorStatus(stopErr)
	}
	return result, nil
}

func (s *GRPCServer) ListSessions(ctx context.Context, req *pb.DeepMonitorListRequest) (*pb.DeepMonitorSessionList, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	manager, err := s.deepMonitor()
	if err != nil {
		return nil, err
	}
	return &pb.DeepMonitorSessionList{Items: manager.List(req != nil && req.GetIncludeExpired())}, nil
}

func (s *GRPCServer) QueryEvents(ctx context.Context, req *pb.DeepMonitorQuery) (*pb.DeepMonitorQueryResult, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	manager, err := s.deepMonitor()
	if err != nil {
		return nil, err
	}
	if req == nil || req.GetSessionId() == "" {
		return nil, status.Error(codes.InvalidArgument, "session_id is required")
	}
	items, next, more, queryErr := manager.QueryFiltered(req.GetSessionId(), req.GetCursor(), int(req.GetLimit()), deepmonitor.QueryFilter{
		Type: req.GetType(), Search: req.GetSearch(), Direction: req.GetDirection(),
		Method: req.GetMethod(), Status: req.GetStatus(), ClientIP: req.GetClientIp(),
		Identity: req.GetIdentity(), Path: req.GetPath(),
	})
	if queryErr != nil {
		return nil, deepMonitorStatus(queryErr)
	}
	return &pb.DeepMonitorQueryResult{Items: items, NextCursor: next, HasMore: more}, nil
}

func (s *GRPCServer) GetEvent(ctx context.Context, req *pb.DeepMonitorEventRequest) (*pb.DeepMonitorEvent, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	manager, err := s.deepMonitor()
	if err != nil {
		return nil, err
	}
	if req == nil || req.GetSessionId() == "" || req.GetEventId() == "" {
		return nil, status.Error(codes.InvalidArgument, "session_id and event_id are required")
	}
	result, getErr := manager.GetEvent(req.GetSessionId(), req.GetEventId())
	if getErr != nil {
		return nil, deepMonitorStatus(getErr)
	}
	return result, nil
}

func (s *GRPCServer) WatchEvents(req *pb.DeepMonitorWatchRequest, stream pb.DeepMonitorService_WatchEventsServer) error {
	if err := s.checkToken(stream.Context()); err != nil {
		return err
	}
	manager, err := s.deepMonitor()
	if err != nil {
		return err
	}
	if req == nil || req.GetSessionId() == "" {
		return status.Error(codes.InvalidArgument, "session_id is required")
	}
	backlog, events, subscribeErr := manager.Subscribe(stream.Context(), req.GetSessionId(), req.GetAfterSequence())
	if subscribeErr != nil {
		return deepMonitorStatus(subscribeErr)
	}
	for _, item := range backlog {
		if err := stream.Send(item); err != nil {
			return err
		}
	}
	for {
		select {
		case item, ok := <-events:
			if !ok {
				return nil
			}
			if err := stream.Send(item); err != nil {
				return err
			}
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
	}
}

func (s *GRPCServer) StreamPayload(req *pb.DeepMonitorPayloadRequest, stream pb.DeepMonitorService_StreamPayloadServer) error {
	if err := s.checkToken(stream.Context()); err != nil {
		return err
	}
	manager, err := s.deepMonitor()
	if err != nil {
		return err
	}
	if req == nil || req.GetSessionId() == "" || req.GetEventId() == "" || req.GetPart() == "" {
		return status.Error(codes.InvalidArgument, "session_id, event_id and part are required")
	}
	file, total, contentType, openErr := manager.OpenPayload(req.GetSessionId(), req.GetEventId(), req.GetPart(), req.GetOffset())
	if openErr != nil {
		return deepMonitorStatus(openErr)
	}
	defer file.Close()
	offset := req.GetOffset()
	buffer := make([]byte, deepmonitor.PayloadChunkBytes)
	for {
		n, readErr := file.Read(buffer)
		if n > 0 {
			chunk := &pb.DeepMonitorPayloadChunk{Data: append([]byte(nil), buffer[:n]...), Offset: offset, TotalBytes: total, ContentType: contentType}
			offset += uint64(n)
			chunk.Eof = offset >= total
			if err := stream.Send(chunk); err != nil {
				return err
			}
		}
		if errors.Is(readErr, io.EOF) {
			if total == req.GetOffset() {
				return stream.Send(&pb.DeepMonitorPayloadChunk{Offset: offset, TotalBytes: total, Eof: true, ContentType: contentType})
			}
			return nil
		}
		if readErr != nil {
			return status.Error(codes.Internal, readErr.Error())
		}
	}
}

func (s *GRPCServer) StreamSessionArchive(req *pb.DeepMonitorSessionRequest, stream pb.DeepMonitorService_StreamSessionArchiveServer) error {
	if err := s.checkToken(stream.Context()); err != nil {
		return err
	}
	manager, err := s.deepMonitor()
	if err != nil {
		return err
	}
	if req == nil || req.GetSessionId() == "" {
		return status.Error(codes.InvalidArgument, "session_id is required")
	}
	archive, openErr := manager.OpenArchive(req.GetSessionId())
	if openErr != nil {
		return deepMonitorStatus(openErr)
	}
	defer archive.Close()
	buffer := make([]byte, deepmonitor.PayloadChunkBytes)
	offset := uint64(0)
	for {
		n, readErr := archive.Read(buffer)
		if n > 0 {
			chunk := &pb.DeepMonitorPayloadChunk{
				Data: append([]byte(nil), buffer[:n]...), Offset: offset,
				ContentType: "application/zip", Eof: errors.Is(readErr, io.EOF),
			}
			offset += uint64(n)
			if chunk.Eof {
				chunk.TotalBytes = offset
			}
			if err := stream.Send(chunk); err != nil {
				return err
			}
		}
		if errors.Is(readErr, io.EOF) {
			if n == 0 {
				return stream.Send(&pb.DeepMonitorPayloadChunk{
					Offset: offset, TotalBytes: offset, Eof: true, ContentType: "application/zip",
				})
			}
			return nil
		}
		if readErr != nil {
			return status.Error(codes.Internal, readErr.Error())
		}
	}
}

func (s *GRPCServer) DeleteSession(ctx context.Context, req *pb.DeepMonitorSessionRequest) (*pb.RpcStatus, error) {
	if err := s.checkToken(ctx); err != nil {
		return nil, err
	}
	manager, err := s.deepMonitor()
	if err != nil {
		return nil, err
	}
	if req == nil || req.GetSessionId() == "" {
		return nil, status.Error(codes.InvalidArgument, "session_id is required")
	}
	if err := manager.Delete(req.GetSessionId()); err != nil {
		return nil, deepMonitorStatus(err)
	}
	return rpcOK(), nil
}

func deepMonitorStatus(err error) error {
	switch {
	case errors.Is(err, deepmonitor.ErrNotFound), errors.Is(err, deepmonitor.ErrEventNotFound), errors.Is(err, deepmonitor.ErrPayloadNotFound):
		return status.Error(codes.NotFound, err.Error())
	case errors.Is(err, deepmonitor.ErrInvalidDuration):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, deepmonitor.ErrSessionActive), errors.Is(err, deepmonitor.ErrSessionExporting), errors.Is(err, deepmonitor.ErrSessionNotActive), errors.Is(err, deepmonitor.ErrHostAlreadyActive), errors.Is(err, deepmonitor.ErrTooManyActive):
		return status.Error(codes.FailedPrecondition, err.Error())
	default:
		return status.Error(codes.Internal, err.Error())
	}
}
