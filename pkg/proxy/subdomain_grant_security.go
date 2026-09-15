package proxy

import (
	"context"
	"net/http"
	"time"

	"go-reauth-proxy/pkg/grpc/pb"
	"go-reauth-proxy/pkg/rpcbridge"
)

// inspectSubdomainGrantSecurityExemption is deliberately uncached and read-only.
// A cookie's presence is only a reason to ask Rust, never proof of authorization.
func (h *Handler) inspectSubdomainGrantSecurityExemption(r *http.Request, clientIP, accessMode string, backend routedBackend) bool {
	cookie, err := r.Cookie(advancedAuthGrantCookieName)
	if err != nil || cookie.Value == "" {
		return false
	}
	bridge := h.authBridgeManager()
	if bridge == nil || !bridge.SupportsCapability(rpcbridge.CapabilityInspectSubdomainGrantV1) ||
		!bridge.SupportsCapability(rpcbridge.CapabilityAuthorizeHTTPV1) {
		return false
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	result, err := bridge.AuthorizeHTTP(ctx, &pb.AuthorizeHttpRequest{
		Context: newRequestAuthContext(r, clientIP, accessMode, backend).proto(false),
		Mode:    pb.HttpAuthMode_HTTP_AUTH_MODE_INSPECT_SUBDOMAIN_GRANT,
	})
	return err == nil && result.GetSubdomainGrantSecurityExempt()
}
