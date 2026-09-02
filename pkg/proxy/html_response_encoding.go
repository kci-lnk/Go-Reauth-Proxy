package proxy

import (
	"compress/gzip"
	"compress/zlib"
	"io"
	"net/http"
	"strings"
)

type decodedHTMLReadCloser struct {
	decoder io.ReadCloser
	source  io.Closer
}

func (rc *decodedHTMLReadCloser) Read(p []byte) (int, error) {
	return rc.decoder.Read(p)
}

func (rc *decodedHTMLReadCloser) Close() error {
	decoderErr := rc.decoder.Close()
	sourceErr := rc.source.Close()
	if decoderErr != nil {
		return decoderErr
	}
	return sourceErr
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
