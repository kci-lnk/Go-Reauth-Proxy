package proxy

import (
	"compress/gzip"
	"compress/zlib"
	"io"
	"net/http"
	"strings"
	"sync"
)

type decodedHTMLReadCloser struct {
	mu        sync.Mutex
	closeOnce sync.Once
	closeErr  error
	closed    bool
	decoder   io.ReadCloser
	source    io.Closer
}

func (rc *decodedHTMLReadCloser) Read(p []byte) (int, error) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	if rc.closed {
		return 0, io.ErrClosedPipe
	}
	return rc.decoder.Read(p)
}

func (rc *decodedHTMLReadCloser) Close() error {
	rc.closeOnce.Do(func() {
		// gzip/zlib Close is not safe alongside Read. Closing the upstream
		// source first wakes a blocked decoder without mutating its state.
		sourceErr := rc.source.Close()
		rc.mu.Lock()
		defer rc.mu.Unlock()
		rc.closed = true
		rc.closeErr = rc.decoder.Close()
		if rc.closeErr == nil {
			rc.closeErr = sourceErr
		}
	})
	return rc.closeErr
}

func decodeHTMLProxyResponseBody(resp *http.Response) (string, error) {
	if resp == nil || resp.Body == nil {
		return "", nil
	}

	encodingValues := resp.Header.Values("Content-Encoding")
	encoding := ""
	for _, value := range encodingValues {
		for _, item := range strings.Split(value, ",") {
			item = strings.ToLower(strings.TrimSpace(item))
			if item == "" {
				continue
			}
			if encoding != "" {
				return "unsupported_content_encoding", nil
			}
			encoding = item
		}
	}
	if encoding == "" || encoding == "identity" {
		return "", nil
	}

	source := resp.Body
	var (
		decoder io.ReadCloser
		err     error
	)
	switch encoding {
	case "gzip", "x-gzip":
		decoder, err = gzip.NewReader(source)
	case "deflate":
		decoder, err = zlib.NewReader(source)
	default:
		return "unsupported_content_encoding", nil
	}
	if err != nil {
		_ = source.Close()
		return "", err
	}

	resp.Body = &decodedHTMLReadCloser{decoder: decoder, source: source}
	resp.Uncompressed = true
	resp.ContentLength = -1
	resp.Header.Del("Content-Encoding")
	resp.Header.Del("Content-Length")
	invalidateMutatedHTMLRepresentationHeaders(resp.Header)
	return "", nil
}
