package proxy

import (
	"bytes"
	"context"
	"errors"
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

type failingReadCloser struct {
	body []byte
	err  error
	read bool
}

type limitedReadCloser struct {
	reader *bytes.Reader
	limit  int
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

func (rc *failingReadCloser) Read(p []byte) (int, error) {
	if rc.read {
		return 0, rc.err
	}
	rc.read = true
	return copy(p, rc.body), rc.err
}

func (rc *failingReadCloser) Close() error {
	return nil
}

func (rc *limitedReadCloser) Read(p []byte) (int, error) {
	if len(p) > rc.limit {
		p = p[:rc.limit]
	}
	return rc.reader.Read(p)
}

func (rc *limitedReadCloser) Close() error { return nil }

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

func TestMaybeMutateHTMLProxyResponseToolbarOnlyStreamsBeforeBodyClose(t *testing.T) {
	body := []byte(`<html><body><main>app</main></body></html>`)
	resp, rc := newHTMLMutationResponse(body, "text/html", int64(len(body)))

	err := maybeMutateHTMLProxyResponse(resp, htmlResponseMutationOptions{
		toolbar: true,
		toolbarHTML: func() string {
			return `<script>toolbar()</script>`
		},
		routeType: "test",
		routeKey:  "app.example.com",
	})
	if err != nil {
		t.Fatalf("maybeMutateHTMLProxyResponse returned error: %v", err)
	}
	if rc.readCount != 0 {
		t.Fatalf("readCount = %d, want 0 before streamed body is read", rc.readCount)
	}
	if resp.ContentLength != -1 || resp.Header.Get("Content-Length") != "" {
		t.Fatalf("streamed toolbar response kept content length: field=%d header=%q", resp.ContentLength, resp.Header.Get("Content-Length"))
	}

	mutated, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read streamed mutated response: %v", err)
	}
	if bodyText := string(mutated); !strings.Contains(bodyText, `<main>app</main><script>toolbar()</script></body>`) {
		t.Fatalf("streamed toolbar was not injected before body close: %s", bodyText)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("close streamed body: %v", err)
	}
	if !rc.closed {
		t.Fatal("original response body was not closed through streaming wrapper")
	}
}

func TestMaybeMutateHTMLProxyResponseInvalidatesRepresentationValidators(t *testing.T) {
	body := []byte(`<html><body><main>app</main></body></html>`)
	resp, _ := newHTMLMutationResponse(body, "text/html", int64(len(body)))
	resp.StatusCode = http.StatusOK
	for name, value := range map[string]string{
		"ETag":           `"upstream"`,
		"Last-Modified":  "Wed, 21 Oct 2015 07:28:00 GMT",
		"Content-MD5":    "stale",
		"Digest":         "sha-256=stale",
		"Content-Digest": "sha-256=:stale:",
		"Repr-Digest":    "sha-256=:stale:",
		"Accept-Ranges":  "bytes",
	} {
		resp.Header.Set(name, value)
	}
	resp.Header.Set("Cache-Control", "public, max-age=3600")
	resp.Header.Set("Vary", "Accept-Language")

	err := maybeMutateHTMLProxyResponse(resp, htmlResponseMutationOptions{
		toolbar: true,
		toolbarHTML: func() string {
			return `<script>toolbar()</script>`
		},
	})
	if err != nil {
		t.Fatalf("maybeMutateHTMLProxyResponse returned error: %v", err)
	}
	for _, name := range []string{"ETag", "Last-Modified", "Content-MD5", "Digest", "Content-Digest", "Repr-Digest", "Accept-Ranges"} {
		if got := resp.Header.Get(name); got != "" {
			t.Fatalf("%s = %q, want empty", name, got)
		}
	}
	if got := resp.Header.Get("Cache-Control"); got != "public, max-age=3600" {
		t.Fatalf("Cache-Control = %q", got)
	}
	if got := resp.Header.Get("Vary"); got != "Accept-Language" {
		t.Fatalf("Vary = %q", got)
	}
}

func TestMaybeMutateHTMLProxyResponseSkipsNotModifiedAndPartialToolbarResponses(t *testing.T) {
	for _, status := range []int{http.StatusNotModified, http.StatusPartialContent} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			body := []byte(`<html><body>cached</body></html>`)
			resp, _ := newHTMLMutationResponse(body, "text/html", int64(len(body)))
			resp.StatusCode = status
			resp.Header.Set("ETag", `"cached"`)

			err := maybeMutateHTMLProxyResponse(resp, htmlResponseMutationOptions{
				toolbar: true,
				toolbarHTML: func() string {
					return `<script>toolbar()</script>`
				},
			})
			if err != nil {
				t.Fatalf("maybeMutateHTMLProxyResponse returned error: %v", err)
			}
			got, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("read response body: %v", err)
			}
			if !bytes.Equal(got, body) || resp.Header.Get("ETag") != `"cached"` {
				t.Fatalf("status %d response was mutated: body=%q headers=%#v", status, got, resp.Header)
			}
		})
	}
}

func TestMaybeMutateHTMLProxyResponseToolbarOnlyStreamsAcrossBodyCloseBoundary(t *testing.T) {
	prefix := "<html><body>" + strings.Repeat("x", htmlToolbarStreamChunkSize-len("<html><body>")-len("</"))
	body := []byte(prefix + `</body></html>`)
	resp, _ := newHTMLMutationResponse(body, "text/html", int64(len(body)))

	err := maybeMutateHTMLProxyResponse(resp, htmlResponseMutationOptions{
		toolbar: true,
		toolbarHTML: func() string {
			return `<script>toolbar()</script>`
		},
		routeType: "test",
		routeKey:  "app.example.com",
	})
	if err != nil {
		t.Fatalf("maybeMutateHTMLProxyResponse returned error: %v", err)
	}

	mutated, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read streamed mutated response: %v", err)
	}
	if bodyText := string(mutated); !strings.Contains(bodyText, `xxx<script>toolbar()</script></body>`) {
		t.Fatalf("streamed toolbar was not injected across body close boundary")
	}
}

func TestStreamingToolbarReadCloserHandlesOneByteChunks(t *testing.T) {
	body := []byte(`<!doctype html><HTML><BODY><main>app</main></BODY></HTML>`)
	source := &limitedReadCloser{reader: bytes.NewReader(body), limit: 1}
	rc := newStreamingToolbarReadCloser(source, `<script>toolbar()</script>`)

	mutated, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read one-byte chunks: %v", err)
	}
	if got := string(mutated); !strings.Contains(got, `<main>app</main><script>toolbar()</script></BODY>`) {
		t.Fatalf("toolbar was not injected across one-byte chunks: %s", got)
	}
}

func TestStreamingToolbarReadCloserDoesNotMutateOneByteNonHTMLChunks(t *testing.T) {
	body := []byte(`plain text that is not an html document`)
	source := &limitedReadCloser{reader: bytes.NewReader(body), limit: 1}
	rc := newStreamingToolbarReadCloser(source, `<script>toolbar()</script>`)

	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read one-byte non-HTML chunks: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("non-HTML body changed: got %q, want %q", got, body)
	}
}

func TestMaybeMutateHTMLProxyResponseToolbarOnlyStreamsAppendWithoutBodyClose(t *testing.T) {
	body := []byte(`<!doctype html><html><main>app</main>`)
	resp, _ := newHTMLMutationResponse(body, "text/html", -1)

	err := maybeMutateHTMLProxyResponse(resp, htmlResponseMutationOptions{
		toolbar: true,
		toolbarHTML: func() string {
			return `<script>toolbar()</script>`
		},
		routeType: "test",
		routeKey:  "app.example.com",
	})
	if err != nil {
		t.Fatalf("maybeMutateHTMLProxyResponse returned error: %v", err)
	}

	mutated, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read streamed mutated response: %v", err)
	}
	if bodyText := string(mutated); !strings.HasSuffix(bodyText, `<script>toolbar()</script>`) {
		t.Fatalf("streamed toolbar was not appended to HTML without body close: %s", bodyText)
	}
}

func TestMaybeMutateHTMLProxyResponseToolbarOnlyPreservesPendingOnReadError(t *testing.T) {
	readErr := errors.New("upstream read failed")
	body := []byte(`<html`)
	resp := &http.Response{
		Header:        make(http.Header),
		Body:          &failingReadCloser{body: body, err: readErr},
		ContentLength: -1,
	}
	resp.Header.Set("Content-Type", "text/html")

	err := maybeMutateHTMLProxyResponse(resp, htmlResponseMutationOptions{
		toolbar: true,
		toolbarHTML: func() string {
			return `<script>toolbar()</script>`
		},
		routeType: "test",
		routeKey:  "app.example.com",
	})
	if err != nil {
		t.Fatalf("maybeMutateHTMLProxyResponse returned error: %v", err)
	}

	got, err := io.ReadAll(resp.Body)
	if !errors.Is(err, readErr) {
		t.Fatalf("read error = %v, want %v", err, readErr)
	}
	if string(got) != string(body) {
		t.Fatalf("streamed body before read error = %q, want %q", string(got), string(body))
	}
}

func BenchmarkStreamingToolbarReadCloser2MiB(b *testing.B) {
	body := make([]byte, 0, 2*1024*1024)
	body = append(body, []byte(`<!doctype html><html><body>`)...)
	body = append(body, bytes.Repeat([]byte("x"), 2*1024*1024-len(body)-len(`</body></html>`))...)
	body = append(body, []byte(`</body></html>`)...)
	toolbar := `<script id="reauth-proxy-toolbar-loader">window.__REAUTH_PROXY_TOOLBAR_DATA__={};</script>`
	readBuffer := make([]byte, 32*1024)
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()

	for b.Loop() {
		rc := newStreamingToolbarReadCloser(io.NopCloser(bytes.NewReader(body)), toolbar)
		for {
			_, err := rc.Read(readBuffer)
			if err == io.EOF {
				break
			}
			if err != nil {
				b.Fatalf("read streamed toolbar body: %v", err)
			}
		}
		if err := rc.Close(); err != nil {
			b.Fatalf("close streamed toolbar body: %v", err)
		}
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

func TestPublicHostRuleToolbarStreamsLargeHTMLBody(t *testing.T) {
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
	got := rec.Body.String()
	if !strings.Contains(got, "reauth-proxy-toolbar") {
		t.Fatalf("large HTML response did not include streamed toolbar")
	}
	if !strings.Contains(got, `</main>`) || !strings.Contains(got, `</body></html>`) {
		t.Fatalf("large HTML response lost original markers")
	}
}
