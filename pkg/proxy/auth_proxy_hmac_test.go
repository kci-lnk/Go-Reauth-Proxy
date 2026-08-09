package proxy

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"go-reauth-proxy/pkg/models"
)

func TestInternalAuthProxyHeadersReplaceClientSignatureAndBindRequest(t *testing.T) {
	const secret = "gateway-only-hmac-secret"
	body := `{"target":"device-1"}`
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/api/auth/wol/targets/device-1/wake?audit=1", strings.NewReader(body))
	req.Header.Set("X-Timestamp", "client-controlled")
	req.Header.Set("X-Nonce", "client-controlled")
	req.Header.Set("X-Signature", "client-controlled")
	source := httptest.NewRequest(http.MethodPost, "https://auth.example.com/__auth__/api/auth/wol/targets/device-1/wake?audit=1", nil)
	target, err := url.Parse("http://127.0.0.1:7997/api/auth/wol/targets/device-1/wake")
	if err != nil {
		t.Fatal(err)
	}
	digestBytes := sha256.Sum256([]byte(body))
	digest := hex.EncodeToString(digestBytes[:])

	applyInternalAuthProxyHeaders(req, source, target, "203.0.113.10", models.AuthConfig{}, secret, digest)

	timestamp := req.Header.Get("X-Timestamp")
	nonce := req.Header.Get("X-Nonce")
	signature := req.Header.Get("X-Signature")
	if timestamp == "" || timestamp == "client-controlled" {
		t.Fatalf("timestamp was not replaced: %q", timestamp)
	}
	if len(nonce) != 32 || nonce == "client-controlled" {
		t.Fatalf("nonce was not replaced with 128 random bits: %q", nonce)
	}
	message := canonicalInternalAuthRequestMessage(
		http.MethodPost,
		"/api/auth/wol/targets/device-1/wake?audit=1",
		digest,
		timestamp,
		nonce,
	)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(message))
	want := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(signature), []byte(want)) {
		t.Fatalf("signature = %q, want %q", signature, want)
	}
}

func TestCanonicalInternalAuthRequestMessageMatchesRustContract(t *testing.T) {
	message := canonicalInternalAuthRequestMessage(
		"post",
		"/api/auth/wol/targets/device-1/wake?audit=1",
		"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
		"1700000000000",
		"0011223344556677",
	)
	want := strings.Join([]string{
		"fn-knock-v1",
		"POST",
		"/api/auth/wol/targets/device-1/wake?audit=1",
		"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
		"1700000000000",
		"0011223344556677",
	}, "\n")
	if message != want {
		t.Fatalf("canonical message = %q, want %q", message, want)
	}
}

func TestAuthProxyRequestBodyDigestRestoresBody(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "https://auth.example.com/__auth__/api/auth/login", strings.NewReader("request-body"))
	digest, err := authProxyRequestBodyDigest(req)
	if err != nil {
		t.Fatal(err)
	}
	wantBytes := sha256.Sum256([]byte("request-body"))
	if want := hex.EncodeToString(wantBytes[:]); digest != want {
		t.Fatalf("digest = %q, want %q", digest, want)
	}
	restored := make([]byte, len("request-body"))
	if _, err := req.Body.Read(restored); err != nil {
		t.Fatal(err)
	}
	if string(restored) != "request-body" {
		t.Fatalf("restored body = %q", restored)
	}
}

func TestAuthProxyRequestBodyDigestRejectsOversizedBody(t *testing.T) {
	req := httptest.NewRequest(
		http.MethodPost,
		"https://auth.example.com/__auth__/api/auth/login",
		strings.NewReader(strings.Repeat("x", maxSignedAuthRequestBodyBytes+1)),
	)
	if _, err := authProxyRequestBodyDigest(req); !errors.Is(err, errAuthProxyRequestBodyTooLarge) {
		t.Fatalf("error = %v, want errAuthProxyRequestBodyTooLarge", err)
	}
}

func TestAuthProxyRejectsCrossOriginMutations(t *testing.T) {
	tests := []struct {
		name   string
		origin string
		allow  bool
	}{
		{name: "missing origin for non-browser clients", allow: true},
		{name: "same origin", origin: "https://auth.example.com", allow: true},
		{name: "same origin explicit default port", origin: "https://auth.example.com:443", allow: true},
		{name: "cross origin", origin: "https://attacker.example.com", allow: false},
		{name: "opaque origin", origin: "null", allow: false},
		{name: "origin with query", origin: "https://auth.example.com?forged=1", allow: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "https://auth.example.com/__auth__/api/auth/wol/targets/device-1/wake", nil)
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			if got := authProxyOriginAllowed(req); got != tt.allow {
				t.Fatalf("authProxyOriginAllowed() = %v, want %v", got, tt.allow)
			}
		})
	}

	crossSiteWithoutOrigin := httptest.NewRequest(http.MethodPost, "https://auth.example.com/__auth__/api/auth/wol/targets/device-1/wake", nil)
	crossSiteWithoutOrigin.Header.Set("Sec-Fetch-Site", "cross-site")
	if authProxyOriginAllowed(crossSiteWithoutOrigin) {
		t.Fatal("cross-site browser mutation without Origin was allowed")
	}
}
