package proxy

import (
	"context"
	proxywaf "go-reauth-proxy/pkg/waf"
	"time"
)

func (h *Handler) WaitWAFEvents(ctx context.Context, timeout time.Duration) (bool, error) {
	return h.wafRuntime.WaitEvents(ctx, timeout)
}

func (h *Handler) LeaseWAFEvents(limit int) proxywaf.DrainResult {
	if h.wafRuntime == nil {
		return proxywaf.DrainResult{Events: []proxywaf.Event{}}
	}
	return h.wafRuntime.Lease(limit)
}

func (h *Handler) AcknowledgeWAFEventLease(leaseID string) proxywaf.DrainResult {
	if h.wafRuntime == nil {
		return proxywaf.DrainResult{Events: []proxywaf.Event{}}
	}
	return h.wafRuntime.AcknowledgeLease(leaseID)
}

func (h *Handler) ReleaseWAFEventLease(leaseID string) proxywaf.DrainResult {
	if h.wafRuntime == nil {
		return proxywaf.DrainResult{Events: []proxywaf.Event{}}
	}
	return h.wafRuntime.ReleaseLease(leaseID)
}
