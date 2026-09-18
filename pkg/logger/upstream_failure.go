package logger

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// UpstreamFailure is the narrow exception to Diagnostic's no-request-data
// contract. Only failed upstream exchanges reach it. It records the configured
// origin and a generated trace ID, never URL paths, credentials, headers, bodies
// or arbitrary error text. The existing bounded queue, rotation and repeat
// limiter apply independently to each origin/route/failure combination.
func UpstreamFailure(target *url.URL, traceID, route, class string, err error) {
	runtime := diagnosticState.Load()
	if runtime == nil || runtime.closed.Load() || err == nil || errors.Is(err, context.Canceled) {
		return
	}
	switch route {
	case "host_rule", "host_location", "path_rule", "auth_proxy":
	default:
		return
	}
	switch class {
	case "timeout", "dns_temporary", "dns_error", "connect_unavailable", "upstream_eof", "upstream_reset", "bad_gateway":
	default:
		return
	}
	origin := upstreamOrigin(target)
	fields := map[string]any{"upstream_origin": origin, "route_type": route}
	if len(traceID) == 40 && strings.HasPrefix(traceID, "trc_") && strings.Trim(traceID[4:], "0123456789abcdef-") == "" {
		fields["trace_id"] = traceID
	}
	stage := "exchange"
	var op *net.OpError
	if errors.As(err, &op) {
		switch op.Op {
		case "dial", "read", "write":
			stage = op.Op
		}
		if addr, ok := op.Addr.(*net.TCPAddr); ok && addr != nil {
			fields["remote_address"] = net.JoinHostPort(addr.IP.String(), strconv.Itoa(addr.Port))
		}
	}
	var dns *net.DNSError
	if errors.As(err, &dns) {
		stage = "dns"
	}
	fields["stage"] = stage
	// Errno is machine-readable and cannot contain request secrets. Keep an
	// explicit portable label for the common connection failures as well.
	kind := class
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		kind = "connection_refused"
	case errors.Is(err, syscall.ENETUNREACH):
		kind = "network_unreachable"
	case errors.Is(err, syscall.EHOSTUNREACH):
		kind = "host_unreachable"
	case errors.Is(err, syscall.ECONNRESET):
		kind = "connection_reset"
	case errors.Is(err, syscall.EPIPE):
		kind = "broken_pipe"
	case errors.Is(err, io.ErrUnexpectedEOF):
		kind = "unexpected_eof"
	case errors.Is(err, io.EOF):
		kind = "eof"
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		fields["errno"] = uint64(errno)
	}
	fields["error_kind"] = kind
	now := time.Now()
	key := "upstream_failure\x00" + origin + "\x00" + route + "\x00" + class + "\x00" + stage + "\x00" + kind
	count, emit := runtime.aggregateRepeat(now, key)
	if !emit {
		return
	}
	if count > 1 {
		fields["count"] = count
	}
	record := diagnosticRecord{Time: now.UTC().Format(time.RFC3339Nano), Level: "WARN", Component: "proxy", Event: "upstream_failure", ReasonCode: class, Fields: fields}
	encoded, marshalErr := json.Marshal(record)
	if marshalErr == nil {
		runtime.enqueue("WARN", append(encoded, '\n'))
	}
}

func upstreamOrigin(target *url.URL) string {
	if target == nil || (target.Scheme != "http" && target.Scheme != "https") {
		return "unknown"
	}
	host := target.Hostname()
	if host == "" || len(host) > 253 {
		return "unknown"
	}
	for _, c := range host {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune(".-:_", c)) {
			return "unknown"
		}
	}
	port := target.Port()
	if port == "" {
		port = "80"
		if target.Scheme == "https" {
			port = "443"
		}
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return "unknown"
	}
	return target.Scheme + "://" + net.JoinHostPort(strings.ToLower(host), port)
}
