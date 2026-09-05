package proxy

import (
	"context"
	"go-reauth-proxy/pkg/gatewaylog"
	"strings"
)

func (h *Handler) FindLogEntryByTraceID(traceID string) (gatewaylog.TraceResult, error) {
	return h.FindLogEntryByTraceIDContext(context.Background(), traceID)
}

func (h *Handler) FindLogEntryByTraceIDContext(ctx context.Context, traceID string) (gatewaylog.TraceResult, error) {
	if h.gatewayLogManager == nil {
		return gatewaylog.TraceResult{TraceID: strings.TrimSpace(traceID)}, nil
	}
	return h.gatewayLogManager.FindByTraceIDContext(ctx, traceID)
}
