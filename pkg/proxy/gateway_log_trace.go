package proxy

import (
	"go-reauth-proxy/pkg/gatewaylog"
	"strings"
)

func (h *Handler) FindLogEntryByTraceID(traceID string) (gatewaylog.TraceResult, error) {
	if h.gatewayLogManager == nil {
		return gatewaylog.TraceResult{TraceID: strings.TrimSpace(traceID)}, nil
	}
	return h.gatewayLogManager.FindByTraceID(traceID)
}
