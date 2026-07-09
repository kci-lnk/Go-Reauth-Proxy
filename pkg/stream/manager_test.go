package stream

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"syscall"
	"testing"
)

var (
	streamBenchmarkStringSink string
	streamBenchmarkBoolSink   bool
	streamBenchmarkErrorSink  error
)

func TestLocalServiceURLMatchesLegacyFormat(t *testing.T) {
	tests := []struct {
		port int
		path string
	}{
		{port: 7999, path: "/api/auth/verify"},
		{port: 7999, path: "api/auth/verify"},
		{port: 1, path: "/"},
		{port: 65535, path: ""},
	}

	for _, tt := range tests {
		if got, want := localServiceURL(tt.port, tt.path), fmt.Sprintf("http://127.0.0.1:%d%s", tt.port, ensureLeadingSlash(tt.path)); got != want {
			t.Fatalf("localServiceURL(%d, %q) = %q, want %q", tt.port, tt.path, got, want)
		}
	}
}

func BenchmarkLocalServiceURL(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		streamBenchmarkStringSink = localServiceURL(7999, "/api/auth/verify")
	}
}

func BenchmarkLocalServiceURLOld(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		streamBenchmarkStringSink = fmt.Sprintf("http://127.0.0.1:%d%s", 7999, ensureLeadingSlash("/api/auth/verify"))
	}
}

func TestStreamErrorClassifiersMatchLegacyBehavior(t *testing.T) {
	tests := []error{
		nil,
		net.ErrClosed,
		errors.New("use of closed network connection"),
		errors.New("USE OF CLOSED NETWORK CONNECTION"),
		errors.New("read: connection reset by peer"),
		errors.New("write: BROKEN PIPE"),
		errors.New("listen tcp :8080: address already in use"),
		errors.New("LISTEN TCP :8080: ADDRESS ALREADY IN USE"),
		errors.New("permission denied"),
		fmt.Errorf("wrapped: %w", syscall.EADDRINUSE),
	}

	for _, err := range tests {
		t.Run(fmt.Sprint(err), func(t *testing.T) {
			gotRelay := normalizeRelayError(err) == nil
			wantRelay := normalizeRelayErrorLegacyForBenchmark(err) == nil
			if gotRelay != wantRelay {
				t.Fatalf("normalizeRelayError(%v) nil = %v, want legacy %v", err, gotRelay, wantRelay)
			}
			if got, want := isClosedConnErr(err), isClosedConnErrLegacyForBenchmark(err); got != want {
				t.Fatalf("isClosedConnErr(%v) = %v, want legacy %v", err, got, want)
			}
			if got, want := isAddrInUseErr(err), isAddrInUseErrLegacyForBenchmark(err); got != want {
				t.Fatalf("isAddrInUseErr(%v) = %v, want legacy %v", err, got, want)
			}
		})
	}
}

func BenchmarkNormalizeRelayErrorClosedMessage(b *testing.B) {
	err := errors.New("read tcp: USE OF CLOSED NETWORK CONNECTION")
	b.ReportAllocs()
	for b.Loop() {
		streamBenchmarkErrorSink = normalizeRelayError(err)
	}
}

func BenchmarkNormalizeRelayErrorClosedMessageOld(b *testing.B) {
	err := errors.New("read tcp: USE OF CLOSED NETWORK CONNECTION")
	b.ReportAllocs()
	for b.Loop() {
		streamBenchmarkErrorSink = normalizeRelayErrorLegacyForBenchmark(err)
	}
}

func BenchmarkIsClosedConnErrMessage(b *testing.B) {
	err := errors.New("read tcp: USE OF CLOSED NETWORK CONNECTION")
	b.ReportAllocs()
	for b.Loop() {
		streamBenchmarkBoolSink = isClosedConnErr(err)
	}
}

func BenchmarkIsClosedConnErrMessageOld(b *testing.B) {
	err := errors.New("read tcp: USE OF CLOSED NETWORK CONNECTION")
	b.ReportAllocs()
	for b.Loop() {
		streamBenchmarkBoolSink = isClosedConnErrLegacyForBenchmark(err)
	}
}

func BenchmarkIsAddrInUseErrMessage(b *testing.B) {
	err := errors.New("listen tcp :8080: ADDRESS ALREADY IN USE")
	b.ReportAllocs()
	for b.Loop() {
		streamBenchmarkBoolSink = isAddrInUseErr(err)
	}
}

func BenchmarkIsAddrInUseErrMessageOld(b *testing.B) {
	err := errors.New("listen tcp :8080: ADDRESS ALREADY IN USE")
	b.ReportAllocs()
	for b.Loop() {
		streamBenchmarkBoolSink = isAddrInUseErrLegacyForBenchmark(err)
	}
}

func normalizeRelayErrorLegacyForBenchmark(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return nil
	}

	errText := strings.ToLower(err.Error())
	if strings.Contains(errText, "use of closed network connection") ||
		strings.Contains(errText, "connection reset by peer") ||
		strings.Contains(errText, "broken pipe") {
		return nil
	}

	return err
}

func isClosedConnErrLegacyForBenchmark(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, net.ErrClosed) {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "use of closed network connection")
}

func isAddrInUseErrLegacyForBenchmark(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.EADDRINUSE) {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "address already in use")
}
