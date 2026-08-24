package proxy

import (
	"net/http"
	"strings"

	"go-reauth-proxy/pkg/grpc/pb"
	"go-reauth-proxy/pkg/response"
)

func authResponseIsUnavailable(resp *pb.VerifyAuthResponse, responseHeaders http.Header, statusCode int) bool {
	if statusCode >= http.StatusInternalServerError || strings.EqualFold(strings.TrimSpace(resp.GetDecision()), "auth_unavailable") {
		return true
	}
	reason := strings.TrimSpace(resp.GetAccessDeniedReason())
	if reason == "" {
		reason = strings.TrimSpace(responseHeaders.Get(reauthAccessDeniedHeader))
	}
	return strings.EqualFold(reason, reauthServiceUnavailableReason)
}

func respondAuthServiceUnavailable(w http.ResponseWriter, r *http.Request, retryAfter string) {
	applyNoStoreCacheHeaders(w.Header())
	if retryAfter = strings.TrimSpace(retryAfter); retryAfter != "" {
		w.Header().Set("Retry-After", retryAfter)
	}
	response.HTML(w, r, http.StatusServiceUnavailable, authServiceUnavailableMessage, nil)
}
