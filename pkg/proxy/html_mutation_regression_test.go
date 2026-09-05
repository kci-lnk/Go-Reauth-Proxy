package proxy

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestToolbarInjectionRespectsHTMLContextsAcrossChunks(t *testing.T) {
	const toolbar = `<script>toolbar()</script>`
	for _, middle := range []string{
		`<script>const marker = "</body>";</script>`,
		`<SCRIPT data-x="</body>">const marker = '</BODY>';</SCRIPT>`,
		`<style>body::after { content: "</body>"; }</style>`,
		`<svg><![CDATA[ </body> </body> ]]></svg>`,
		`<svg><script><![CDATA[ const marker="</script></body>"; ]]></script></svg>`,
		`<svg/><script>const marker="<![CDATA[";</script>`,
		`<math><mtext><![CDATA[ </body> ]]></mtext></math>`,
		`<!DOCTYPE html PUBLIC "</body> </body>" "</body>">`,
		`<!-- </body><html> --><div>ok</div>`,
		`<!-- </body> --!><div>ok</div>`,
		`<textarea></body></textarea><title></body></title>`,
		`<xmp></body></xmp><iframe></body></iframe><noembed></body></noembed>`,
		`<noscript></body></noscript><noframes></body></noframes>`,
		`<div title="</body>" data-text='</body>'>ok</div>`,
		`<div data-unquoted=a'b>ok</div>`,
		`<template><template></body></template></body></template>`,
		`<script><!--<script>inner</script> const marker="</body>"; --></script>`,
	} {
		body := `<html><body>` + middle + `</body></html>`
		want := `<html><body>` + middle + toolbar + `</body></html>`
		t.Run(middle, func(t *testing.T) {
			for chunkSize := 1; chunkSize <= 24; chunkSize++ {
				rc := newStreamingToolbarReadCloser(&limitedReadCloser{reader: bytes.NewReader([]byte(body)), limit: chunkSize}, toolbar)
				got, err := io.ReadAll(rc)
				_ = rc.Close()
				if err != nil || string(got) != want {
					t.Fatalf("chunk %d: got %q, err %v, want %q", chunkSize, got, err, want)
				}
			}
			if got := string(injectToolbarIntoHTMLBytes([]byte(body), toolbar)); got != want {
				t.Fatalf("buffered injection = %q, want %q", got, want)
			}
		})
	}
}

func TestToolbarInjectionDoesNotAppendInsideUnterminatedContexts(t *testing.T) {
	for _, body := range []string{
		`<html><body><script>const marker="</body>";`,
		`<html><style>body { content: "</body>"; }`,
		`<html><!-- </body>`,
		`<html><div title="</body>`,
		`<html><template></body>`,
		`<html><plaintext></body>`,
		`<html><svg><![CDATA[ </body> </body>`,
		`<!-- <html> -->plain text`,
	} {
		rc := newStreamingToolbarReadCloser(io.NopCloser(strings.NewReader(body)), "TOOLBAR")
		got, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil || string(got) != body {
			t.Fatalf("streaming %q: got %q, error %v", body, got, err)
		}
		if got := string(injectToolbarIntoHTMLBytes([]byte(body), "TOOLBAR")); got != body {
			t.Fatalf("buffered %q: got %q", body, got)
		}
	}
}

func TestStreamingToolbarCombinesReadySegmentsWithoutWaitingForUpstream(t *testing.T) {
	reader, writer := io.Pipe()
	rc := newStreamingToolbarReadCloser(reader, "TOOLBAR")
	defer rc.Close()
	defer writer.Close()
	first := "<html><body>" + strings.Repeat("x", 128)
	second := strings.Repeat("y", 128)
	output := make(chan string, 1)
	errs := make(chan error, 1)
	go func() {
		for _, part := range []string{first, second} {
			if _, err := io.WriteString(writer, part); err != nil {
				errs <- err
				return
			}
		}
		// Deliberately leave the source open and idle after these two chunks.
	}()
	go func() {
		p := make([]byte, 4096)
		var got string
		for range 2 {
			n, err := rc.Read(p)
			if err != nil {
				errs <- err
				return
			}
			got += string(p[:n])
		}
		output <- got
	}()
	select {
	case got := <-output:
		want := first + second[:len(second)-htmlToolbarStreamTailBytes]
		if got != want {
			t.Fatalf("ready data = %q, want %q", got, want)
		}
	case err := <-errs:
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("Read waited for new upstream bytes instead of returning ready segments")
	}
}

func TestHTMLRewriteOutputBudgetAndExactAllocation(t *testing.T) {
	body := []byte(`<html><body>` + strings.Repeat(`<img src="/x">`, 20000) + `</body></html>`)
	prefix := "/" + strings.Repeat("p", 127)
	within := rewriteHTMLAbsolutePaths(body, prefix)
	if len(within) <= len(body) || len(within) != cap(within) {
		t.Fatalf("rewrite allocation: input=%d len=%d cap=%d", len(body), len(within), cap(within))
	}
	if got := rewriteHTMLAbsolutePaths(body, strings.Repeat("p", 1024)); !bytes.Equal(got, body) || &got[0] != &body[0] {
		t.Fatal("over-budget rewrite did not preserve the original body")
	}
	got := mutateHTMLProxyBody(body, true, strings.Repeat("p", 1024), "TOOLBAR")
	want := strings.Replace(string(body), "</body>", "TOOLBAR</body>", 1)
	if string(got) != want || len(got) != cap(got) {
		t.Fatal("over-budget paths prevented the independent bounded toolbar injection")
	}
}

func TestStreamingToolbarPreservesReadErrorAfterReadySegments(t *testing.T) {
	readErr := errors.New("upstream failed")
	body := []byte(`<html><body>` + strings.Repeat("x", 100))
	rc := newStreamingToolbarReadCloser(&failingReadCloser{body: body, err: readErr}, "TOOLBAR")
	defer rc.Close()
	got, err := io.ReadAll(rc)
	if !errors.Is(err, readErr) || !bytes.Equal(got, body) {
		t.Fatalf("got %q, err %v; want original body and upstream error", got, err)
	}
}

type toolbarClosingReadCloser struct {
	readStarted  chan struct{}
	closeStarted chan struct{}
	allowRead    chan struct{}
}

func (r *toolbarClosingReadCloser) Read(p []byte) (int, error) {
	close(r.readStarted)
	<-r.allowRead
	return copy(p, "<html><body>bytes returned while source closes"), io.ErrClosedPipe
}

func (r *toolbarClosingReadCloser) Close() error {
	close(r.closeStarted)
	return nil
}

func TestStreamingToolbarCloseWaitsForScratchOwnership(t *testing.T) {
	source := &toolbarClosingReadCloser{readStarted: make(chan struct{}), closeStarted: make(chan struct{}), allowRead: make(chan struct{})}
	rc := newStreamingToolbarReadCloser(source, "TOOLBAR")
	readDone := make(chan struct{})
	go func() {
		_, _ = rc.Read(make([]byte, 1024))
		close(readDone)
	}()
	<-source.readStarted
	closeDone := make(chan error, 1)
	go func() { closeDone <- rc.Close() }()
	<-source.closeStarted
	closedTooEarly := false
	select {
	case <-closeDone:
		closedTooEarly = true
	case <-time.After(20 * time.Millisecond):
	}
	close(source.allowRead)
	<-readDone
	if closedTooEarly {
		t.Fatal("Close returned the scratch buffer while upstream Read still owned it")
	}
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not finish after upstream Read returned")
	}
	if _, err := rc.Read(make([]byte, 1)); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("Read after Close = %v, want closed pipe", err)
	}
	if err := rc.Close(); err != nil {
		t.Fatalf("repeated Close: %v", err)
	}
}

func TestHTMLMutationPreservesCompressedReadErrors(t *testing.T) {
	for _, tc := range []struct {
		name       string
		encoder    func(io.Writer) io.WriteCloser
		trailerLen int
		checksum   error
	}{
		{name: "gzip", encoder: func(w io.Writer) io.WriteCloser { return gzip.NewWriter(w) }, trailerLen: 8, checksum: gzip.ErrChecksum},
		{name: "deflate", encoder: func(w io.Writer) io.WriteCloser { return zlib.NewWriter(w) }, trailerLen: 4, checksum: zlib.ErrChecksum},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := []byte("<html><body>" + strings.Repeat("data", 500))
			var compressed bytes.Buffer
			encoder := tc.encoder(&compressed)
			_, _ = encoder.Write(body)
			if err := encoder.Close(); err != nil {
				t.Fatal(err)
			}
			for _, truncated := range []bool{false, true} {
				encoded := bytes.Clone(compressed.Bytes())
				wantErr := tc.checksum
				if truncated {
					encoded = encoded[:len(encoded)-1]
					wantErr = io.ErrUnexpectedEOF
				} else {
					encoded[len(encoded)-tc.trailerLen] ^= 0xff
				}
				resp, source := newHTMLMutationResponse(encoded, "text/html", int64(len(encoded)))
				resp.StatusCode = http.StatusOK
				resp.Header.Set("Content-Encoding", tc.name)
				if err := maybeMutateHTMLProxyResponse(resp, htmlResponseMutationOptions{toolbar: true, toolbarHTML: func() string { return "TOOLBAR" }}); err != nil {
					t.Fatal(err)
				}
				got, err := io.ReadAll(resp.Body)
				if !errors.Is(err, wantErr) || !bytes.Equal(got, body) {
					t.Fatalf("truncated=%t: got %d bytes, error %v; want unchanged %d bytes and %v", truncated, len(got), err, len(body), wantErr)
				}
				if err := resp.Body.Close(); err != nil && !errors.Is(err, wantErr) {
					t.Fatal(err)
				}
				if !source.closed {
					t.Fatal("compressed source was not closed")
				}
			}
		})
	}
}

type htmlCompressedReadSignal struct {
	io.ReadCloser
	reads       int
	bodyStarted chan struct{}
}

func (r *htmlCompressedReadSignal) Read(p []byte) (int, error) {
	r.reads++
	if r.reads == 2 {
		close(r.bodyStarted)
	}
	return r.ReadCloser.Read(p)
}

func TestHTMLMutationCompressedReadCanBeCancelled(t *testing.T) {
	var compressed bytes.Buffer
	encoder := gzip.NewWriter(&compressed)
	_, _ = encoder.Write([]byte("<html><body>payload</body></html>"))
	_ = encoder.Close()
	reader, writer := io.Pipe()
	defer writer.Close()
	// Deliver only the fixed gzip header. The later body read must wait for
	// deflate data and be interrupted by Close, without closing its decoder
	// while that decoder is still executing Read.
	go func() { _, _ = writer.Write(compressed.Bytes()[:10]) }()
	source := &htmlCompressedReadSignal{ReadCloser: reader, bodyStarted: make(chan struct{})}
	resp := &http.Response{StatusCode: http.StatusOK, ContentLength: -1, Header: http.Header{"Content-Type": {"text/html"}, "Content-Encoding": {"gzip"}}, Body: source}
	if err := maybeMutateHTMLProxyResponse(resp, htmlResponseMutationOptions{toolbar: true, toolbarHTML: func() string { return "TOOLBAR" }}); err != nil {
		t.Fatal(err)
	}
	readDone := make(chan error, 1)
	go func() { _, err := io.ReadAll(resp.Body); readDone <- err }()
	select {
	case <-source.bodyStarted:
	case <-time.After(time.Second):
		_ = resp.Body.Close()
		t.Fatal("compressed body Read did not start")
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- resp.Body.Close() }()
	select {
	case err := <-closeDone:
		if err != nil && !errors.Is(err, io.ErrClosedPipe) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close failed to interrupt the compressed read")
	}
	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("cancelled compressed read lost its error")
		}
	case <-time.After(time.Second):
		t.Fatal("compressed read stayed blocked after Close")
	}
	if err := resp.Body.Close(); err != nil && !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("repeated Close: %v", err)
	}
}

func TestHTMLSmallRewriteBoundariesAndGrowth(t *testing.T) {
	boundaryBody := func(size int) []byte {
		const head = `<html><body><img src="/x">`
		const tail = `</body></html>`
		return []byte(head + strings.Repeat("x", size-len(head)-len(tail)) + tail)
	}
	for _, tc := range []struct {
		name   string
		body   []byte
		prefix string
	}{
		{name: "ordinary", body: makeRewriteBenchmarkHTML(256), prefix: "/app"},
		{name: "dense grows once", body: []byte(`<html><body>` + strings.Repeat(`<img src="/x">`, 4000) + `</body></html>`), prefix: "/long-prefix"},
		{name: "input boundary", body: boundaryBody(htmlSmallRewriteInputLimitBytes), prefix: "/app"},
		{name: "above input boundary", body: boundaryBody(htmlSmallRewriteInputLimitBytes + 1), prefix: "/app"},
		{name: "worst output fits", body: boundaryBody(htmlSmallRewriteInputLimitBytes), prefix: strings.Repeat("p", 18)},
		{name: "worst output exceeds small tier", body: boundaryBody(htmlSmallRewriteInputLimitBytes), prefix: strings.Repeat("p", 19)},
		{name: "inserted prefix is not rewritten", body: makeRewriteBenchmarkHTML(256), prefix: `/src="/`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, toolbar := range []string{"", "TOOLBAR"} {
				// The fixture's only ="/ candidates are supported attributes.
				// ReplaceAll does not reprocess the newly inserted prefix.
				want := strings.ReplaceAll(string(tc.body), `="/`, `="`+tc.prefix+`/`)
				if toolbar != "" {
					want = strings.TrimSuffix(want, "</body></html>") + toolbar + "</body></html>"
				}
				var got []byte
				allocations := testing.AllocsPerRun(10, func() {
					got = mutateHTMLProxyBody(tc.body, true, tc.prefix, toolbar)
				})
				if string(got) != want {
					t.Fatalf("toolbar=%q: rewritten output differs from expected bytes", toolbar)
				}
				if len(got) > htmlProxyMutationOutputLimitBytes || allocations > 2 {
					t.Fatalf("toolbar=%q: output=%d allocations=%.0f; want bounded output and at most one growth", toolbar, len(got), allocations)
				}
			}
		})
	}
}

func TestHTMLSmallRewriteWithoutMatchesDoesNotAllocate(t *testing.T) {
	body := []byte(`<html><body><img src="relative"><div data-other="/keep">unchanged</div></body></html>`)
	var got []byte
	allocations := testing.AllocsPerRun(10, func() {
		got = mutateHTMLProxyBody(body, true, "/app", "")
	})
	if allocations != 0 || len(got) != len(body) || &got[0] != &body[0] {
		t.Fatalf("unchanged body: allocations=%.0f, length=%d", allocations, len(got))
	}
}

func TestHTMLSmallRewritePreservesLiteralMatching(t *testing.T) {
	for _, tc := range []struct{ body, want string }{
		{`src="/href="/`, `src="/app/href="/app/`},
		{`other="/src="/`, `other="/src="/app/`},
		{`data-src="/x"`, `data-src="/app/x"`},
		{`SRC="/x" src ="/y" src='/z'`, `SRC="/x" src ="/y" src='/z'`},
		{`<base href="/">src="/`, `<base href="/app/">src="/app/`},
		{`<html></body><img src="/x">`, `<html>TOOLBAR</body><img src="/app/x">`},
	} {
		toolbar := ""
		if strings.Contains(tc.want, "TOOLBAR") {
			toolbar = "TOOLBAR"
		}
		got := mutateHTMLProxyBody([]byte(tc.body), true, "/app", toolbar)
		if string(got) != tc.want {
			t.Fatalf("input %q: got %q, want %q", tc.body, got, tc.want)
		}
	}
}
