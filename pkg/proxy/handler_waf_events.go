package proxy

import proxywaf "go-reauth-proxy/pkg/waf"

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
