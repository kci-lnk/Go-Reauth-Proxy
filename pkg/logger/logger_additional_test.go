package logger

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type failingLoggerWriter struct{}

func (failingLoggerWriter) Write([]byte) (int, error) {
	return 0, errors.New("write failed")
}

func TestDailyFileWriterAppendsToTodayLog(t *testing.T) {
	dir := t.TempDir()
	writer := newDailyFileWriter(dir)
	t.Cleanup(func() { _ = writer.Close() })

	if _, err := writer.Write([]byte("first\n")); err != nil {
		t.Fatalf("write first line: %v", err)
	}
	if _, err := writer.Write([]byte("second\n")); err != nil {
		t.Fatalf("write second line: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, time.Now().Format(debugDateLayout)+".log"))
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	if string(data) != "first\nsecond\n" {
		t.Fatalf("unexpected log contents: %q", data)
	}
}

func TestDailyFileWriterEnsureDirFailsWhenBaseIsFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-dir")
	if err := os.WriteFile(path, []byte("file"), 0o644); err != nil {
		t.Fatalf("write marker file: %v", err)
	}
	writer := newDailyFileWriter(path)

	if _, err := writer.Write([]byte("line\n")); err == nil {
		t.Fatal("expected write to fail when base path is a file")
	}
}

func TestDailyFileWriterRotateReusesSameDateFile(t *testing.T) {
	writer := newDailyFileWriter(t.TempDir())
	t.Cleanup(func() { _ = writer.Close() })
	if err := writer.ensureDirLocked(); err != nil {
		t.Fatalf("ensure dir: %v", err)
	}
	now := time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)
	if err := writer.rotateLocked(now); err != nil {
		t.Fatalf("rotate first: %v", err)
	}
	first := writer.currentFile
	if err := writer.rotateLocked(now.Add(time.Hour)); err != nil {
		t.Fatalf("rotate same day: %v", err)
	}

	if writer.currentFile != first {
		t.Fatal("same-day rotate should reuse current file")
	}
}

func TestDailyFileWriterRotateOpensNewDateFile(t *testing.T) {
	dir := t.TempDir()
	writer := newDailyFileWriter(dir)
	t.Cleanup(func() { _ = writer.Close() })
	if err := writer.ensureDirLocked(); err != nil {
		t.Fatalf("ensure dir: %v", err)
	}
	if err := writer.rotateLocked(time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("rotate first: %v", err)
	}
	if err := writer.rotateLocked(time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("rotate second: %v", err)
	}

	if writer.currentDate != "2026-07-09" {
		t.Fatalf("current date = %q", writer.currentDate)
	}
	if _, err := os.Stat(filepath.Join(dir, "2026-07-08.log")); err != nil {
		t.Fatalf("missing first date log: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "2026-07-09.log")); err != nil {
		t.Fatalf("missing second date log: %v", err)
	}
}

func TestWarnOnceWriterForwardsSuccessfulWrites(t *testing.T) {
	var buf bytes.Buffer
	writer := warnOnceWriter{writer: &buf}

	n, err := writer.Write([]byte("ok"))

	if err != nil || n != 2 || buf.String() != "ok" {
		t.Fatalf("unexpected write result: n=%d err=%v buf=%q", n, err, buf.String())
	}
}

func TestWarnOnceWriterReturnsUnderlyingError(t *testing.T) {
	debugWarnedWrite.Store(false)
	writer := warnOnceWriter{writer: failingLoggerWriter{}}

	n, err := writer.Write([]byte("boom"))

	if err == nil || n != 0 {
		t.Fatalf("expected underlying write error, got n=%d err=%v", n, err)
	}
}

func TestAsyncWriterDropsWhenQueueIsFull(t *testing.T) {
	writer := &asyncWriter{
		writer: io.Discard,
		queue:  make(chan []byte, 1),
	}

	n, err := writer.Write([]byte("queued"))
	if err != nil || n != len("queued") {
		t.Fatalf("first Write() = %d, %v", n, err)
	}
	n, err = writer.Write([]byte("dropped"))
	if err != nil || n != len("dropped") {
		t.Fatalf("second Write() = %d, %v", n, err)
	}
	if got := writer.Dropped(); got != 1 {
		t.Fatalf("Dropped() = %d, want 1", got)
	}
}

func TestSetDebugLoggerNilWriterStillEnablesEvent(t *testing.T) {
	t.Cleanup(func() {
		setDebugLogger(false, io.Discard)
	})

	setDebugLogger(true, nil)

	if !DebugEnabled() {
		t.Fatal("debug logger should be enabled")
	}
	if event := DebugEvent("component", "event"); event == nil {
		t.Fatal("enabled debug event should not be nil")
	}
}

func TestDebugEventSanitizesComponentAndEvent(t *testing.T) {
	var buf bytes.Buffer
	t.Cleanup(func() {
		setDebugLogger(false, io.Discard)
		SetDebugAdminPortForRedaction(0)
	})

	setDebugLogger(true, &buf)
	DebugEvent("Authorization: Bearer secret", "Cookie: sid=secret").Send()

	got := buf.String()
	if strings.Contains(got, "Bearer secret") || strings.Contains(got, "sid=secret") {
		t.Fatalf("debug event leaked sensitive fields: %q", got)
	}
	if count := strings.Count(got, "[redacted]"); count < 2 {
		t.Fatalf("debug event missing redaction markers: %q", got)
	}
}

func TestSetDebugAdminPortForRedactionInvalidClearsPort(t *testing.T) {
	SetDebugAdminPortForRedaction(7996)
	SetDebugAdminPortForRedaction(70000)
	t.Cleanup(func() {
		SetDebugAdminPortForRedaction(0)
	})

	if got := SanitizePort(7996); got != 7996 {
		t.Fatalf("invalid admin port should clear redaction, got %#v", got)
	}
}

func TestNextDebugRequestIDIncrements(t *testing.T) {
	first := NextDebugRequestID()
	second := NextDebugRequestID()

	if first == second {
		t.Fatalf("request IDs should differ: %q", first)
	}
}

func TestSanitizeLogStringTrimsWhitespace(t *testing.T) {
	if got := SanitizeLogString("  ordinary message  "); got != "ordinary message" {
		t.Fatalf("sanitize log string = %q", got)
	}
}

func TestSanitizeLogStringRedactsAuthorizationMarker(t *testing.T) {
	if got := SanitizeLogString("upstream returned Authorization: Bearer secret"); got != "[redacted]" {
		t.Fatalf("authorization marker not redacted: %q", got)
	}
}

func TestSanitizeLogStringRedactsCookieMarker(t *testing.T) {
	if got := SanitizeLogString("Cookie: sid=secret"); got != "[redacted]" {
		t.Fatalf("cookie marker not redacted: %q", got)
	}
}

func TestSanitizeLogStringRedactsSetCookieMarker(t *testing.T) {
	if got := SanitizeLogString("Set-Cookie: sid=secret"); got != "[redacted]" {
		t.Fatalf("set-cookie marker not redacted: %q", got)
	}
}

func TestSanitizeLogStringRedactsLoopbackIPv6AdminPort(t *testing.T) {
	SetDebugAdminPortForRedaction(7996)
	t.Cleanup(func() {
		SetDebugAdminPortForRedaction(0)
	})

	got := SanitizeLogString("[::1]:7996")

	if strings.Contains(got, "7996") || !strings.Contains(got, "[admin-port]") {
		t.Fatalf("IPv6 admin port not redacted: %q", got)
	}
}

func TestSanitizeLogStringRedactsColonAdminPortFallback(t *testing.T) {
	SetDebugAdminPortForRedaction(7996)
	t.Cleanup(func() {
		SetDebugAdminPortForRedaction(0)
	})

	got := SanitizeLogString("203.0.113.10:7996")

	if strings.Contains(got, "7996") || !strings.Contains(got, "[admin-port]") {
		t.Fatalf("colon admin port fallback did not redact: %q", got)
	}
}

func TestSanitizeURLBlankReturnsEmpty(t *testing.T) {
	if got := SanitizeURL("   "); got != "" {
		t.Fatalf("blank URL sanitized to %q", got)
	}
}

func TestSanitizeURLRedactsSensitiveQueryNames(t *testing.T) {
	got := SanitizeURL("https://example.com/path?password=secret&api-key=key&ok=1")

	if strings.Contains(got, "secret") || strings.Contains(got, "api-key=key") {
		t.Fatalf("sensitive query leaked: %q", got)
	}
	if !strings.Contains(got, "ok=1") {
		t.Fatalf("non-sensitive query missing: %q", got)
	}
}

func TestSanitizeURLFallsBackToLogStringOnParseError(t *testing.T) {
	got := SanitizeURL("http://%zz")

	if got != "http://%zz" {
		t.Fatalf("unexpected parse-error fallback: %q", got)
	}
}

func TestSanitizeHeaderEmptyReturnsEmptyMap(t *testing.T) {
	got := SanitizeHeader(nil)

	if len(got) != 0 {
		t.Fatalf("empty header should return empty map: %#v", got)
	}
}

func TestSanitizeHeaderSkipsBlankHeaderName(t *testing.T) {
	got := SanitizeHeader(http.Header{" ": []string{"value"}})

	if len(got) != 0 {
		t.Fatalf("blank header name should be skipped: %#v", got)
	}
}

func TestSanitizeHeaderCanonicalizesHeaderNames(t *testing.T) {
	got := SanitizeHeader(http.Header{"x-custom-header": []string{"value"}})

	if values, ok := got["X-Custom-Header"].([]string); !ok || len(values) != 1 || values[0] != "value" {
		t.Fatalf("header not canonicalized: %#v", got)
	}
}

func TestSanitizeHeaderRedactsSessionHeader(t *testing.T) {
	got := SanitizeHeader(http.Header{"X-Session-Id": []string{"secret"}})

	if got["X-Session-Id"] != "[redacted]" {
		t.Fatalf("session header not redacted: %#v", got)
	}
}

func TestSanitizeHeaderSanitizesNonSensitiveValues(t *testing.T) {
	SetDebugAdminPortForRedaction(7996)
	t.Cleanup(func() {
		SetDebugAdminPortForRedaction(0)
	})

	got := SanitizeHeader(http.Header{"X-Upstream": []string{"localhost:7996"}})
	values := got["X-Upstream"].([]string)

	if strings.Contains(values[0], "7996") || !strings.Contains(values[0], "[admin-port]") {
		t.Fatalf("non-sensitive header value was not sanitized: %#v", got)
	}
}

func TestSanitizedHeaderNamesNilReturnsNil(t *testing.T) {
	if got := SanitizedHeaderNames(nil); got != nil {
		t.Fatalf("nil header names = %#v", got)
	}
}

func TestSanitizedHeaderNamesCanonicalizesAndSkipsBlank(t *testing.T) {
	got := SanitizedHeaderNames(http.Header{
		"x-api-key": []string{"secret"},
		" ":         []string{"skip"},
	})

	if len(got) != 1 || got[0] != "X-Api-Key" {
		t.Fatalf("unexpected header names: %#v", got)
	}
}

func TestIsSensitiveNameBlankFalse(t *testing.T) {
	if IsSensitiveName("   ") {
		t.Fatal("blank header name should not be sensitive")
	}
}

func TestIsSensitiveNameMatchesPasswordAlias(t *testing.T) {
	for _, name := range []string{"X-Password", "X-Passwd", "Client-Secret", "ApiKey", "Access-Key", "Private-Key"} {
		if !IsSensitiveName(name) {
			t.Fatalf("%q should be sensitive", name)
		}
	}
}

func TestContainsSensitiveHeaderMarkerIgnoresPlainText(t *testing.T) {
	if containsSensitiveHeaderMarker("authorization without colon") {
		t.Fatal("marker without colon should not be sensitive")
	}
}

func TestEqualFoldASCIIStringLengthMismatch(t *testing.T) {
	if equalFoldASCIIString("abc", "abcd") {
		t.Fatal("different lengths should not be equal")
	}
}

func TestEqualFoldASCIIStringCaseInsensitive(t *testing.T) {
	if !equalFoldASCIIString("AbC", "aBc") {
		t.Fatal("ASCII comparison should be case-insensitive")
	}
}

func TestContainsFoldASCIIStringEmptySearch(t *testing.T) {
	if !containsFoldASCIIString("abc", "") {
		t.Fatal("empty search string should match")
	}
}

func TestContainsFoldASCIIStringLongerSearchFalse(t *testing.T) {
	if containsFoldASCIIString("abc", "abcd") {
		t.Fatal("longer search should not match")
	}
}

func TestHasFoldASCIIPrefixCaseInsensitive(t *testing.T) {
	if !hasFoldASCIIPrefix("Content-Type", "content") {
		t.Fatal("prefix comparison should be case-insensitive")
	}
}

func TestLowerASCIIByteLeavesNonUppercase(t *testing.T) {
	if lowerASCIIByte('1') != '1' || lowerASCIIByte('z') != 'z' {
		t.Fatal("lowerASCIIByte changed non-uppercase byte")
	}
}

func TestParsePortValid(t *testing.T) {
	port, ok := parsePort(" 8080 ")

	if !ok || port != 8080 {
		t.Fatalf("parsePort = %d, %v", port, ok)
	}
}

func TestParsePortRejectsZero(t *testing.T) {
	if port, ok := parsePort("0"); ok || port != 0 {
		t.Fatalf("parsePort zero = %d, %v", port, ok)
	}
}

func TestParsePortRejectsTooLarge(t *testing.T) {
	if port, ok := parsePort("65536"); ok || port != 0 {
		t.Fatalf("parsePort too large = %d, %v", port, ok)
	}
}

func TestParsePortRejectsNonDigits(t *testing.T) {
	if port, ok := parsePort("80/tcp"); ok || port != 0 {
		t.Fatalf("parsePort non-digits = %d, %v", port, ok)
	}
}

func TestRedactStandaloneAdminPortUsesDigitBoundaries(t *testing.T) {
	got := redactStandaloneAdminPort("ports 7996 and 179960", "7996")

	if got != "ports [admin-port] and 179960" {
		t.Fatalf("unexpected standalone redaction: %q", got)
	}
}

func TestRedactStandaloneAdminPortReturnsOriginalWhenNoMatch(t *testing.T) {
	got := redactStandaloneAdminPort("port 8080", "7996")

	if got != "port 8080" {
		t.Fatalf("unexpected redaction: %q", got)
	}
}

func TestIsDigitBoundaryAtEdges(t *testing.T) {
	if !isDigitBoundary("123", -1) || !isDigitBoundary("123", 3) {
		t.Fatal("indexes outside string should be digit boundaries")
	}
}

func TestIsDigitBoundaryFalseForDigit(t *testing.T) {
	if isDigitBoundary("123", 1) {
		t.Fatal("digit should not be boundary")
	}
}

func TestIsLocalHostMatchesLoopbackIPv4(t *testing.T) {
	if !isLocalHost("127.0.0.1") {
		t.Fatal("127.0.0.1 should be local")
	}
}

func TestIsLocalHostMatchesBracketedIPv6(t *testing.T) {
	if !isLocalHost("[::1]") {
		t.Fatal("[::1] should be local")
	}
}

func TestIsLocalHostRejectsRemoteIP(t *testing.T) {
	if isLocalHost("203.0.113.10") {
		t.Fatal("remote address should not be local")
	}
}

func TestConsoleLoggingEnabledReadsEnvironment(t *testing.T) {
	t.Setenv(ConsoleLogEnv, "yes")

	if !ConsoleLoggingEnabled() {
		t.Fatal("console logging env should enable console logging")
	}
}
