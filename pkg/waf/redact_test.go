package waf

import (
	"strings"
	"testing"
)

var wafRedactBenchmarkBoolSink bool
var wafRedactBenchmarkStringSink string

func TestIsSensitiveNameCaseInsensitive(t *testing.T) {
	tests := []string{
		"Authorization",
		"X-ApiKey",
		"session_id",
		"PASSWORD",
		"credential",
	}
	for _, name := range tests {
		if !isSensitiveName(name) {
			t.Fatalf("isSensitiveName(%q) = false, want true", name)
		}
	}
	if isSensitiveName("trace_id") {
		t.Fatal("isSensitiveName(\"trace_id\") = true, want false")
	}
}

func TestRedactRawQuery(t *testing.T) {
	got := redactRawQuery("ok=1&Token=secret&session_id=abc")
	for _, forbidden := range []string{"secret", "abc"} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("redactRawQuery leaked %q: %q", forbidden, got)
		}
	}
	for _, want := range []string{"Token=%5Bredacted%5D", "session_id=%5Bredacted%5D", "ok=1"} {
		if !strings.Contains(got, want) {
			t.Fatalf("redactRawQuery() = %q, want to contain %q", got, want)
		}
	}
}

func TestRedactRawQueryFallsBackForEncodedSensitiveNames(t *testing.T) {
	got := redactRawQuery("to%6ben=secret&ok=1")
	if strings.Contains(got, "secret") {
		t.Fatalf("redactRawQuery leaked encoded sensitive value: %q", got)
	}
	if !strings.Contains(got, "token=%5Bredacted%5D") {
		t.Fatalf("redactRawQuery() = %q, want decoded sensitive key redacted", got)
	}
}

func TestRedactRawQueryPreservesInvalidRawQuery(t *testing.T) {
	raw := "ok=1;token=secret"
	if got := redactRawQuery(raw); got != raw {
		t.Fatalf("redactRawQuery(%q) = %q, want raw query preserved", raw, got)
	}
}

func TestRedactRawQueryNoSensitiveFastPathPreservesRawQuery(t *testing.T) {
	raw := "b=2&a=1"
	if got := redactRawQuery(raw); got != raw {
		t.Fatalf("redactRawQuery(%q) = %q, want raw query preserved", raw, got)
	}
}

func BenchmarkIsSensitiveName(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		wafRedactBenchmarkBoolSink = isSensitiveName("X-Access-Token")
	}
}

func BenchmarkIsSensitiveNameOld(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		wafRedactBenchmarkBoolSink = isSensitiveNameOldForBenchmark("X-Access-Token")
	}
}

func BenchmarkRedactRawQuery(b *testing.B) {
	raw := "ok=1&Token=secret&session_id=abc&path=%2Fapp"

	b.ReportAllocs()
	for b.Loop() {
		wafRedactBenchmarkStringSink = redactRawQuery(raw)
	}
}

func BenchmarkRedactRawQueryFast(b *testing.B) {
	raw := "ok=1&Token=secret&session_id=abc&path=/app"

	b.ReportAllocs()
	for b.Loop() {
		wafRedactBenchmarkStringSink = redactRawQuery(raw)
	}
}

func BenchmarkRedactRawQueryNoSensitiveFast(b *testing.B) {
	raw := "ok=1&path=/app&trace_id=waf_123"

	b.ReportAllocs()
	for b.Loop() {
		wafRedactBenchmarkStringSink = redactRawQuery(raw)
	}
}

func isSensitiveNameOldForBenchmark(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return false
	}
	sensitiveParts := []string{
		"authorization",
		"cookie",
		"password",
		"passwd",
		"secret",
		"token",
		"session",
		"credential",
		"apikey",
		"api_key",
	}
	for _, part := range sensitiveParts {
		if strings.Contains(name, part) {
			return true
		}
	}
	return false
}
