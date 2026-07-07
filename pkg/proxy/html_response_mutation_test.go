package proxy

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"go-reauth-proxy/pkg/grpc/pb"
	"go-reauth-proxy/pkg/models"
)

type trackingReadCloser struct {
	reader    *bytes.Reader
	readCount int
	closed    bool
}

func newTrackingReadCloser(body []byte) *trackingReadCloser {
	return &trackingReadCloser{reader: bytes.NewReader(body)}
}

func (rc *trackingReadCloser) Read(p []byte) (int, error) {
	rc.readCount++
	return rc.reader.Read(p)
}

func (rc *trackingReadCloser) Close() error {
	rc.closed = true
	return nil
}

func newHTMLMutationResponse(body []byte, contentType string, contentLength int64) (*http.Response, *trackingReadCloser) {
	rc := newTrackingReadCloser(body)
	resp := &http.Response{
		Header:        make(http.Header),
		Body:          rc,
		ContentLength: contentLength,
	}
	resp.Header.Set("Content-Type", contentType)
	if contentLength >= 0 {
		resp.Header.Set("Content-Length", strconv.FormatInt(contentLength, 10))
	}
	return resp, rc
}

func TestMaybeMutateHTMLProxyResponseSmallHTMLRewritesAndInjectsToolbar(t *testing.T) {
	body := []byte(`<html><body><a href="/login">login</a></body></html>`)
	resp, rc := newHTMLMutationResponse(body, "text/html; charset=utf-8", int64(len(body)))

	err := maybeMutateHTMLProxyResponse(resp, htmlResponseMutationOptions{
		rewrite:       true,
		rewritePrefix: "/app",
		toolbar:       true,
		toolbarHTML: func() string {
			return `<script>toolbar()</script>`
		},
		routeType: "test",
		routeKey:  "/app",
	})
	if err != nil {
		t.Fatalf("maybeMutateHTMLProxyResponse returned error: %v", err)
	}
	if !rc.closed {
		t.Fatal("original response body was not closed after mutation")
	}

	mutated, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read mutated response: %v", err)
	}
	bodyText := string(mutated)
	if !strings.Contains(bodyText, `href="/app/login"`) {
		t.Fatalf("mutated body did not rewrite absolute path: %s", bodyText)
	}
	if !strings.Contains(bodyText, `<script>toolbar()</script></body>`) {
		t.Fatalf("mutated body did not inject toolbar before body close: %s", bodyText)
	}
	if resp.ContentLength != int64(len(mutated)) {
		t.Fatalf("ContentLength = %d, want %d", resp.ContentLength, len(mutated))
	}
	if got := resp.Header.Get("Content-Length"); got != strconv.Itoa(len(mutated)) {
		t.Fatalf("Content-Length header = %q, want %d", got, len(mutated))
	}
}

func TestMaybeMutateHTMLProxyResponseSkipsNonHTMLWithoutReading(t *testing.T) {
	body := []byte(`{"ok":true}`)
	resp, rc := newHTMLMutationResponse(body, "application/json", int64(len(body)))

	err := maybeMutateHTMLProxyResponse(resp, htmlResponseMutationOptions{
		rewrite:       true,
		rewritePrefix: "/app",
		routeType:     "test",
		routeKey:      "/app",
	})
	if err != nil {
		t.Fatalf("maybeMutateHTMLProxyResponse returned error: %v", err)
	}
	if rc.readCount != 0 {
		t.Fatalf("readCount = %d, want 0 for non-HTML response", rc.readCount)
	}

	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read skipped response body: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("body changed after non-HTML skip")
	}
}

func TestMaybeMutateHTMLProxyResponseSkipsKnownLargeHTMLWithoutReading(t *testing.T) {
	body := []byte(`<html><body><a href="/asset">asset</a></body></html>`)
	resp, rc := newHTMLMutationResponse(body, "text/html", htmlProxyMutationBodyLimitBytes+1)

	err := maybeMutateHTMLProxyResponse(resp, htmlResponseMutationOptions{
		rewrite:       true,
		rewritePrefix: "/app",
		routeType:     "test",
		routeKey:      "/app",
	})
	if err != nil {
		t.Fatalf("maybeMutateHTMLProxyResponse returned error: %v", err)
	}
	if rc.readCount != 0 {
		t.Fatalf("readCount = %d, want 0 when Content-Length exceeds limit", rc.readCount)
	}

	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read skipped response body: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("body changed after known-large skip")
	}
}

func TestMaybeMutateHTMLProxyResponseUnknownLargeHTMLRestoresPreReadBytes(t *testing.T) {
	body := append([]byte(`<html><body><a href="/asset">asset</a>`), bytes.Repeat([]byte("x"), int(htmlProxyMutationBodyLimitBytes)+16)...)
	body = append(body, []byte(`</body></html>`)...)
	resp, _ := newHTMLMutationResponse(body, "text/html", -1)

	err := maybeMutateHTMLProxyResponse(resp, htmlResponseMutationOptions{
		rewrite:       true,
		rewritePrefix: "/app",
		routeType:     "test",
		routeKey:      "/app",
	})
	if err != nil {
		t.Fatalf("maybeMutateHTMLProxyResponse returned error: %v", err)
	}

	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read skipped unknown-large response body: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("unknown-large response body was not restored after pre-read")
	}
	if bytes.Contains(got, []byte(`href="/app/asset"`)) {
		t.Fatalf("unknown-large response body was rewritten despite exceeding limit")
	}
}

func TestPathRuleRewriteHTMLSkipsLargeHTMLBody(t *testing.T) {
	body := append([]byte(`<html><body><a href="/asset">asset</a>`), bytes.Repeat([]byte("x"), int(htmlProxyMutationBodyLimitBytes)+16)...)
	body = append(body, []byte(`</body></html>`)...)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		_, _ = w.Write(body)
	}))
	defer upstream.Close()

	handler := &Handler{
		Rules: []models.Rule{
			{
				Path:        "/app",
				Target:      upstream.URL,
				UseAuth:     false,
				RewriteHTML: true,
			},
		},
		authCache:      newAuthStateCache(),
		preflightCache: newPreflightStateCache(),
	}
	handler.publishRequestSnapshotLocked()

	req := httptest.NewRequest(http.MethodGet, "http://example.com/app/page", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	got := rec.Body.Bytes()
	if !bytes.Equal(got, body) {
		t.Fatalf("large HTML body changed; got len %d want len %d", len(got), len(body))
	}
	if bytes.Contains(got, []byte(`href="/app/asset"`)) {
		t.Fatalf("large HTML body was rewritten despite exceeding limit")
	}
}

func TestPublicHostRuleToolbarSkipsLargeHTMLBody(t *testing.T) {
	var verifyCalls int32
	bridge := testAuthBridge{
		verify: func(context.Context, *pb.VerifyAuthRequest) (*pb.VerifyAuthResponse, error) {
			atomic.AddInt32(&verifyCalls, 1)
			return &pb.VerifyAuthResponse{Success: true, Status: http.StatusOK}, nil
		},
	}

	body := append([]byte(`<!doctype html><html><body><main>public app</main>`), bytes.Repeat([]byte("x"), int(htmlProxyMutationBodyLimitBytes)+16)...)
	body = append(body, []byte(`</body></html>`)...)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		_, _ = w.Write(body)
	}))
	defer target.Close()

	handler := newPublicHostToolbarHandler(target.URL, bridge)
	req := httptest.NewRequest(http.MethodGet, "http://public.example.com/", nil)
	req.AddCookie(&http.Cookie{Name: authSessionCookieName, Value: "ok"})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := atomic.LoadInt32(&verifyCalls); got != 1 {
		t.Fatalf("verify calls = %d, want 1", got)
	}
	if got := rec.Body.Bytes(); !bytes.Equal(got, body) {
		t.Fatalf("large toolbar candidate body changed; got len %d want len %d", len(got), len(body))
	}
	if strings.Contains(rec.Body.String(), "reauth-proxy-toolbar") {
		t.Fatalf("large HTML response included toolbar despite exceeding limit")
	}
}
