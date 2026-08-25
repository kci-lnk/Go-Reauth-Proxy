package proxy

import (
	"context"
	stderrors "errors"
	"io"
	"net"
	"net/http"
	"strings"
	"syscall"

	"go-reauth-proxy/pkg/errors"
	"go-reauth-proxy/pkg/i18n"
	"go-reauth-proxy/pkg/models"
	"go-reauth-proxy/pkg/response"
)

const upstreamErrorClassHeader = "X-Fn-Knock-Upstream-Error-Class"

type upstreamFailure struct {
	code       int
	class      string
	retryAfter string
}

func classifyUpstreamFailure(err error) upstreamFailure {
	failure := upstreamFailure{
		code:  errors.CodeProxyBadGateway,
		class: "bad_gateway",
	}
	if err == nil {
		return failure
	}

	if stderrors.Is(err, context.DeadlineExceeded) {
		return upstreamFailure{code: errors.CodeProxyTimeout, class: "timeout"}
	}
	if stderrors.Is(err, context.Canceled) {
		return upstreamFailure{class: "request_canceled"}
	}
	var netErr net.Error
	if stderrors.As(err, &netErr) && netErr.Timeout() {
		return upstreamFailure{code: errors.CodeProxyTimeout, class: "timeout"}
	}

	var dnsErr *net.DNSError
	if stderrors.As(err, &dnsErr) {
		if dnsErr.IsTemporary {
			return upstreamFailure{
				code:       errors.CodeProxyUnavailable,
				class:      "dns_temporary",
				retryAfter: "1",
			}
		}
		return upstreamFailure{code: errors.CodeProxyBadGateway, class: "dns_error"}
	}

	message := strings.ToLower(err.Error())
	switch {
	case stderrors.Is(err, syscall.ECONNREFUSED),
		stderrors.Is(err, syscall.ENETUNREACH),
		stderrors.Is(err, syscall.EHOSTUNREACH),
		strings.Contains(message, "connection refused"),
		strings.Contains(message, "actively refused"),
		strings.Contains(message, "no route to host"),
		strings.Contains(message, "network is unreachable"),
		strings.Contains(message, "network unreachable"),
		strings.Contains(message, "host is down"):
		return upstreamFailure{
			code:       errors.CodeProxyUnavailable,
			class:      "connect_unavailable",
			retryAfter: "1",
		}
	case stderrors.Is(err, io.EOF), stderrors.Is(err, io.ErrUnexpectedEOF):
		return upstreamFailure{code: errors.CodeProxyBadGateway, class: "upstream_eof"}
	case stderrors.Is(err, syscall.ECONNRESET),
		stderrors.Is(err, syscall.EPIPE),
		strings.Contains(message, "connection reset"),
		strings.Contains(message, "broken pipe"),
		strings.Contains(message, "forcibly closed"):
		return upstreamFailure{code: errors.CodeProxyBadGateway, class: "upstream_reset"}
	default:
		return failure
	}
}

func upstreamUnavailableMessage(r *http.Request, cfg models.GatewayUnmatchedRouteConfig, err error, code int) string {
	normalized := models.NormalizeGatewayUnmatchedRouteConfig(cfg)
	message := errors.GetMessageForLocale(i18n.ResolveRequestLocale(r), code)
	if normalized.UpstreamErrorDetail == models.GatewayUpstreamErrorDetailMore && err != nil {
		return message + ": " + err.Error()
	}
	return message
}

func markUpstreamErrorClass(w http.ResponseWriter, class string) {
	for depth := 0; w != nil && depth < 16; depth++ {
		if trafficWriter, ok := w.(*trafficResponseWriter); ok {
			trafficWriter.upstreamErrorClass = class
			return
		}
		unwrapper, ok := w.(interface {
			Unwrap() http.ResponseWriter
		})
		if !ok {
			return
		}
		w = unwrapper.Unwrap()
	}
}

func (h *Handler) abortUpstreamConnectionIfConfigured(
	w http.ResponseWriter,
	cfg models.GatewayUnmatchedRouteConfig,
) bool {
	normalized := models.NormalizeGatewayUnmatchedRouteConfig(cfg)
	if normalized.UpstreamErrorDetail != models.GatewayUpstreamErrorDetailResetConnection {
		return false
	}
	markConnectionResetStatus(w)
	h.abortConnection(w)
	return true
}

func (h *Handler) handleUpstreamUnavailable(
	w http.ResponseWriter,
	r *http.Request,
	cfg models.GatewayUnmatchedRouteConfig,
	rules []models.Rule,
	authenticated bool,
	err error,
) {
	failure := classifyUpstreamFailure(err)
	markUpstreamErrorClass(w, failure.class)
	if failure.code == 0 {
		markConnectionResetStatus(w)
		return
	}
	if h.abortUpstreamConnectionIfConfigured(w, cfg) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set(upstreamErrorClassHeader, failure.class)
	if failure.retryAfter != "" {
		w.Header().Set("Retry-After", failure.retryAfter)
	}
	response.HTMLWithSelectLink(
		w,
		r,
		failure.code,
		upstreamUnavailableMessage(r, cfg, err, failure.code),
		rules,
		authenticated,
	)
}
