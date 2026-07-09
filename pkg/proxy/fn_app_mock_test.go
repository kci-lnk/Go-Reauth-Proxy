package proxy

import (
	"net/http"
	"net/http/httptest"
	"path"
	"strings"
	"testing"
)

func TestIsFNAppRequestUsesUserAgentCaseInsensitively(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/trimcon", nil)
	req.Header.Set("User-Agent", "FN Client COM.TRIM.APP")

	if !isFNAppRequest(req) {
		t.Fatal("isFNAppRequest() = false, want true for FN App user agent")
	}
}

func TestIsFNAppRequestUsesRelayCookieCaseInsensitively(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/trimcon", nil)
	req.Header.Set("Cookie", "MODE=RELAY")

	if !isFNAppRequest(req) {
		t.Fatal("isFNAppRequest() = false, want true for relay cookie")
	}

	req.URL.Path = "/other"
	if isFNAppRequest(req) {
		t.Fatal("isFNAppRequest() = true for non-FN-App path, want false")
	}
}

func TestIsFNAppWebSocketRequestUsesConnectionHeaderCaseInsensitively(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/websocket", nil)
	req.Header.Set("Upgrade", "WebSocket")
	req.Header.Set("Connection", "keep-alive, Upgrade")

	if !isFNAppWebSocketRequest(req) {
		t.Fatal("isFNAppWebSocketRequest() = false, want true")
	}
}

func BenchmarkIsFNAppRequestUserAgent(b *testing.B) {
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/trimcon", nil)
	req.Header.Set("User-Agent", "FN Client COM.TRIM.APP")

	b.ReportAllocs()
	for b.Loop() {
		benchmarkBoolSink = isFNAppRequest(req)
	}
}

func BenchmarkIsFNAppRequestUserAgentOld(b *testing.B) {
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/trimcon", nil)
	req.Header.Set("User-Agent", "FN Client COM.TRIM.APP")

	b.ReportAllocs()
	for b.Loop() {
		benchmarkBoolSink = isFNAppRequestOldUserAgentForBenchmark(req)
	}
}

func isFNAppRequestOldUserAgentForBenchmark(r *http.Request) bool {
	if r == nil || r.URL == nil {
		return false
	}
	cleanPath := path.Clean(r.URL.Path)
	if cleanPath != "/trimcon" && cleanPath != "/websocket" {
		return false
	}
	userAgent := strings.ToLower(strings.TrimSpace(r.UserAgent()))
	return strings.Contains(userAgent, "com.trim.app") ||
		strings.Contains(userAgent, "com.trim.media") ||
		strings.Contains(userAgent, "dart:io") ||
		strings.Contains(userAgent, "flutter/")
}

func BenchmarkIsFNAppRequestRelayCookie(b *testing.B) {
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/trimcon", nil)
	req.Header.Set("Cookie", "theme=dark; MODE=RELAY")

	b.ReportAllocs()
	for b.Loop() {
		benchmarkBoolSink = isFNAppRequest(req)
	}
}

func BenchmarkIsFNAppRequestRelayCookieOld(b *testing.B) {
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/trimcon", nil)
	req.Header.Set("Cookie", "theme=dark; MODE=RELAY")

	b.ReportAllocs()
	for b.Loop() {
		benchmarkBoolSink = strings.Contains(strings.ToLower(req.Header.Get("Cookie")), strings.ToLower(fnAppRelayCookieValue))
	}
}

func BenchmarkIsFNAppWebSocketRequest(b *testing.B) {
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/websocket", nil)
	req.Header.Set("Upgrade", "WebSocket")
	req.Header.Set("Connection", "keep-alive, Upgrade")

	b.ReportAllocs()
	for b.Loop() {
		benchmarkBoolSink = isFNAppWebSocketRequest(req)
	}
}

func BenchmarkIsFNAppWebSocketRequestOldConnection(b *testing.B) {
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/websocket", nil)
	req.Header.Set("Upgrade", "WebSocket")
	req.Header.Set("Connection", "keep-alive, Upgrade")

	b.ReportAllocs()
	for b.Loop() {
		benchmarkBoolSink = strings.EqualFold(strings.TrimSpace(req.Header.Get("Upgrade")), "websocket") &&
			strings.Contains(strings.ToLower(req.Header.Get("Connection")), "upgrade")
	}
}
