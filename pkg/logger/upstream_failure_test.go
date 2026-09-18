package logger

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestUpstreamFailureDefaultLoggingAndRedaction(t *testing.T) {
	t.Cleanup(Setup)
	dir := t.TempDir()
	t.Setenv(DiagnosticLogDirEnv, dir)
	t.Setenv(ConsoleLogEnv, "0")
	t.Setenv(DebugLogEnv, "0")
	Setup()
	target, _ := url.Parse("https://user:password@backend.example/private?token=secret#fragment")
	failure := &net.OpError{Op: "dial", Net: "tcp", Addr: &net.TCPAddr{IP: net.ParseIP("192.0.2.4"), Port: 443}, Err: syscall.ECONNREFUSED}
	trace := "trc_12345678-1234-4234-8234-123456789abc"
	for i := 0; i < 20; i++ {
		UpstreamFailure(target, trace, "host_rule", "connect_unavailable", failure)
	}
	UpstreamFailure(target, trace, "host_rule", "bad_gateway", errors.New("password secret /private token=secret"))
	UpstreamFailure(target, trace, "host_rule", "timeout", context.Canceled)
	other, _ := url.Parse("http://another.example")
	UpstreamFailure(other, trace, "host_rule", "connect_unavailable", failure)
	FlushDiagnosticLogger()
	data, err := os.ReadFile(filepath.Join(dir, "gateway.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"password", "secret", "/private", "fragment", "user:"} {
		if strings.Contains(string(data), secret) {
			t.Fatalf("leaked %s: %s", secret, data)
		}
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 3 {
		t.Fatalf("want deduplicated failure, unknown error, independent origin: %s", data)
	}
	var record diagnosticRecord
	if err := json.Unmarshal([]byte(lines[0]), &record); err != nil {
		t.Fatal(err)
	}
	if record.Event != "upstream_failure" || record.ReasonCode != "connect_unavailable" {
		t.Fatalf("bad record: %+v", record)
	}
	for key, want := range map[string]string{"upstream_origin": "https://backend.example:443", "remote_address": "192.0.2.4:443", "stage": "dial", "error_kind": "connection_refused", "trace_id": trace} {
		if record.Fields[key] != want {
			t.Errorf("%s=%v want %s", key, record.Fields[key], want)
		}
	}
}

func TestUpstreamFailureDNSAndInvalidTrace(t *testing.T) {
	t.Cleanup(Setup)
	dir := t.TempDir()
	t.Setenv(DiagnosticLogDirEnv, dir)
	Setup()
	target, _ := url.Parse("http://backend.example")
	UpstreamFailure(target, "attacker-secret", "path_rule", "dns_temporary", &net.DNSError{Name: "secret", Err: "secret", IsTemporary: true})
	FlushDiagnosticLogger()
	data, err := os.ReadFile(filepath.Join(dir, "gateway.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var record diagnosticRecord
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatal(err)
	}
	if record.Fields["stage"] != "dns" || record.Fields["trace_id"] != nil || strings.Contains(string(data), "secret") {
		t.Fatalf("bad DNS record: %s", data)
	}
}

func TestUpstreamOrigin(t *testing.T) {
	for raw, want := range map[string]string{"https://name:secret@example.org/a?b=c": "https://example.org:443", "http://[::1]:7998/x": "http://[::1]:7998", "ftp://example.org": "unknown", "http://example.org:99999": "unknown"} {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if got := upstreamOrigin(u); got != want {
			t.Errorf("origin=%s want=%s", got, want)
		}
	}
}
