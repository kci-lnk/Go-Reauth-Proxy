package proxy

import (
	"go-reauth-proxy/pkg/models"
	"net/url"
	"path"
	"strings"
	"testing"
)

func TestNormalizeForwardedHeadersTargetMatchesLegacyBehavior(t *testing.T) {
	tests := []string{
		"",
		"   ",
		"http://example.com",
		" HTTP://Example.COM:8080/base/../app?x=1#frag ",
		"ws://example.com/socket",
		"wss://example.com/socket",
		"https://user:pass@example.com/app",
		"https://example.com/a b",
		"https://example.com/a%2Fb",
		"https://[2001:db8::1]:8443/app/",
		"ftp://example.com",
		"/relative",
		"https://",
	}

	for _, rawTarget := range tests {
		t.Run(rawTarget, func(t *testing.T) {
			got, gotOK := normalizeForwardedHeadersTarget(rawTarget)
			want, wantOK := legacyNormalizeForwardedHeadersTargetForBenchmark(rawTarget)
			if got != want || gotOK != wantOK {
				t.Fatalf("normalizeForwardedHeadersTarget(%q) = %q, %v; want legacy %q, %v", rawTarget, got, gotOK, want, wantOK)
			}
		})
	}
}

func TestForwardedHeadersShouldOmitUsesNormalizedTargetKey(t *testing.T) {
	cfg := models.ForwardedHeadersConfig{
		Enabled:     true,
		OmitTargets: []string{"wss://example.com/socket?ignored=1"},
	}
	runtime := newForwardedHeadersConfig(cfg)
	target, err := url.Parse("https://example.com/socket?runtime=1#frag")
	if err != nil {
		t.Fatalf("parse target: %v", err)
	}

	if !runtime.shouldOmit(target) {
		t.Fatal("shouldOmit() = false, want true for normalized matching target")
	}
}

func BenchmarkNormalizeForwardedHeadersTargetURL(b *testing.B) {
	target, err := url.Parse("WSS://Example.COM:8443/base/../socket?x=1#frag")
	if err != nil {
		b.Fatalf("parse target: %v", err)
	}

	b.ReportAllocs()
	for b.Loop() {
		_, benchmarkHostSink, benchmarkBoolSink = normalizeForwardedHeadersTargetURL(target)
	}
}

func BenchmarkNormalizeForwardedHeadersTargetURLOld(b *testing.B) {
	target, err := url.Parse("WSS://Example.COM:8443/base/../socket?x=1#frag")
	if err != nil {
		b.Fatalf("parse target: %v", err)
	}

	b.ReportAllocs()
	for b.Loop() {
		_, benchmarkHostSink, benchmarkBoolSink = legacyNormalizeForwardedHeadersTargetURLForBenchmark(target)
	}
}

func BenchmarkForwardedHeadersShouldOmit(b *testing.B) {
	cfg := models.ForwardedHeadersConfig{
		Enabled:     true,
		OmitTargets: []string{"wss://example.com/socket?ignored=1"},
	}
	runtime := newForwardedHeadersConfig(cfg)
	target, err := url.Parse("https://example.com/socket?runtime=1#frag")
	if err != nil {
		b.Fatalf("parse target: %v", err)
	}

	b.ReportAllocs()
	for b.Loop() {
		benchmarkBoolSink = runtime.shouldOmit(target)
	}
}

func BenchmarkForwardedHeadersShouldOmitOld(b *testing.B) {
	normalized, ok := legacyNormalizeForwardedHeadersTargetForBenchmark("wss://example.com/socket?ignored=1")
	if !ok {
		b.Fatal("legacy target was not normalizable")
	}
	omitTargets := map[string]struct{}{normalized: {}}
	target, err := url.Parse("https://example.com/socket?runtime=1#frag")
	if err != nil {
		b.Fatalf("parse target: %v", err)
	}

	b.ReportAllocs()
	for b.Loop() {
		benchmarkBoolSink = legacyForwardedHeadersShouldOmitForBenchmark(true, omitTargets, target)
	}
}

func legacyNormalizeForwardedHeadersTargetForBenchmark(rawTarget string) (string, bool) {
	parsed, err := url.Parse(strings.TrimSpace(rawTarget))
	if err != nil {
		return "", false
	}

	_, normalized, ok := legacyNormalizeForwardedHeadersTargetURLForBenchmark(parsed)
	return normalized, ok
}

func legacyNormalizeForwardedHeadersTargetURLForBenchmark(target *url.URL) (*url.URL, string, bool) {
	if target == nil {
		return nil, "", false
	}

	normalized := *target
	normalized.Scheme = strings.ToLower(strings.TrimSpace(normalized.Scheme))
	switch normalized.Scheme {
	case "ws":
		normalized.Scheme = "http"
	case "wss":
		normalized.Scheme = "https"
	case "http", "https":
	default:
		return nil, "", false
	}

	if strings.TrimSpace(normalized.Host) == "" {
		return nil, "", false
	}

	normalized.User = nil
	normalized.RawQuery = ""
	normalized.Fragment = ""
	normalized.RawPath = ""
	normalized.Path = legacyCanonicalForwardedHeadersBasePathForBenchmark(normalized.Path)

	return &normalized, normalized.String(), true
}

func legacyForwardedHeadersShouldOmitForBenchmark(enabled bool, omitTargets map[string]struct{}, target *url.URL) bool {
	_, key, ok := legacyNormalizeForwardedHeadersTargetURLForBenchmark(target)
	if !ok || !enabled {
		return false
	}
	_, exists := omitTargets[key]
	return exists
}

func legacyCanonicalForwardedHeadersBasePathForBenchmark(rawPath string) string {
	rawPath = strings.TrimSpace(rawPath)
	if rawPath == "" || rawPath == "/" {
		return ""
	}

	cleaned := path.Clean(ensureLeadingSlash(rawPath))
	if cleaned == "." || cleaned == "/" {
		return ""
	}

	return cleaned
}
