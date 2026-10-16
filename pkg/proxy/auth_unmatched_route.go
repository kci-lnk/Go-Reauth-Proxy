package proxy

import (
	"errors"
	"net/http"
	"strings"

	"go-reauth-proxy/pkg/models"
)

// Set only by the internal auth service's routing fallbacks, never by a
// matched endpoint returning a business-level 404.
const authRouteUnmatchedHeader = "X-Fn-Knock-Auth-Route-Unmatched"

var errAuthRouteUnmatched = errors.New("internal auth route unmatched")

// Run at the shared proxy response boundary, including after EOF when late
// trailers become available. A non-auth upstream must not expose this signal.
func stripAuthRouteUnmatchedHeaders(headers http.Header) {
	for name, values := range headers {
		if strings.EqualFold(name, authRouteUnmatchedHeader) ||
			strings.EqualFold(name, http.TrailerPrefix+authRouteUnmatchedHeader) {
			delete(headers, name)
		} else if strings.EqualFold(name, "Trailer") {
			var kept []string
			for _, value := range values {
				for _, trailer := range strings.Split(value, ",") {
					trailer = strings.TrimSpace(trailer)
					if trailer != "" && !strings.EqualFold(trailer, authRouteUnmatchedHeader) {
						kept = append(kept, trailer)
					}
				}
			}
			if len(kept) == 0 {
				delete(headers, name)
			} else {
				headers[name] = kept
			}
		}
	}
}

func checkAuthUnmatchedResponse(resp *http.Response, trustedAuthTarget bool, cfg models.GatewayUnmatchedRouteConfig) error {
	unmatched := resp.Header.Get(authRouteUnmatchedHeader) == "1"
	// This is an internal control signal, including when the setting is off.
	resp.Header.Del(authRouteUnmatchedHeader)
	if trustedAuthTarget && unmatched &&
		(resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed) &&
		cfg.Behavior == models.GatewayUnmatchedRouteBehaviorResetConnection {
		return errAuthRouteUnmatched
	}
	return nil
}

func (h *Handler) handleAuthUnmatchedError(w http.ResponseWriter, r *http.Request, err error) bool {
	if !errors.Is(err, errAuthRouteUnmatched) {
		return false
	}
	markConnectionResetStatus(w)
	// Preserve other requests on multiplexed connections, including HTTP/3.
	if r.ProtoMajor >= 2 {
		panic(http.ErrAbortHandler)
	}
	h.abortConnection(w)
	return true
}
