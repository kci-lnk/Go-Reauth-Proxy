package proxy

import (
	"bytes"
	"io"
	"net/http"
	"strconv"

	"go-reauth-proxy/pkg/logger"
)

var (
	htmlRewriteHrefPattern   = []byte(`href="/`)
	htmlRewriteSrcPattern    = []byte(`src="/`)
	htmlRewriteActionPattern = []byte(`action="/`)
	htmlRewriteBasePattern   = []byte(`<base href="/">`)
	htmlRewriteSlashTail     = []byte(`/`)
	htmlRewriteBaseTail      = []byte(`/">`)
	htmlBodyCloseMarker      = []byte(`</body>`)
	htmlStartMarker          = []byte(`<html`)
	htmlHeadMarker           = []byte(`<head`)
	htmlBodyStartMarker      = []byte(`<body`)
	htmlDoctypeMarker        = []byte(`<!doctype`)
)

const (
	htmlProxyMutationBodyLimitBytes int64 = 2 * 1024 * 1024
	htmlToolbarStreamChunkSize            = 32 * 1024
	htmlToolbarStreamTailBytes            = len("<!doctype") - 1
	htmlToolbarStreamMaxSegments          = 5
)

var htmlToolbarStreamBufferPool = newProxyBufferPool(htmlToolbarStreamChunkSize)

type htmlResponseMutationOptions struct {
	rewrite       bool
	rewritePrefix string
	toolbar       bool
	toolbarHTML   func() string
	requestID     string
	routeType     string
	routeKey      string
}

type prependReadCloser struct {
	reader io.Reader
	closer io.Closer
}

func (rc *prependReadCloser) Read(p []byte) (int, error) {
	return rc.reader.Read(p)
}

func (rc *prependReadCloser) Close() error {
	if rc.closer == nil {
		return nil
	}
	return rc.closer.Close()
}

func maybeMutateHTMLProxyResponse(resp *http.Response, opts htmlResponseMutationOptions) error {
	if !opts.rewrite && !opts.toolbar {
		return nil
	}
	if resp == nil {
		logHTMLProxyMutation(opts, nil, "skipped", "no_response", 0, 0)
		return nil
	}
	if htmlProxyResponseMustNotHaveBody(resp) {
		logHTMLProxyMutation(opts, resp, "skipped", "no_response_body", 0, 0)
		return nil
	}
	if opts.toolbar && !toolbarResponseStatusAllowsInjection(resp.StatusCode) {
		opts.toolbar = false
		if !opts.rewrite {
			logHTMLProxyMutation(opts, resp, "skipped", "toolbar_status_not_ok", 0, 0)
			return nil
		}
	}
	if !isHTMLContentType(resp.Header.Get("Content-Type")) {
		logHTMLProxyMutation(opts, resp, "skipped", "not_html", 0, 0)
		return nil
	}
	if resp.Body == nil {
		logHTMLProxyMutation(opts, resp, "skipped", "no_body", 0, 0)
		return nil
	}
	if skipReason, err := decodeHTMLProxyResponseBody(resp); err != nil {
		return err
	} else if skipReason != "" {
		logHTMLProxyMutation(opts, resp, "skipped", skipReason, 0, 0)
		return nil
	}
	if opts.toolbar && !opts.rewrite {
		toolbarHTML := ""
		if opts.toolbarHTML != nil {
			toolbarHTML = opts.toolbarHTML()
		}
		if toolbarHTML == "" {
			logHTMLProxyMutation(opts, resp, "skipped", "empty_toolbar", 0, 0)
			return nil
		}
		resp.Body = newStreamingToolbarReadCloser(resp.Body, toolbarHTML)
		resp.ContentLength = -1
		resp.Header.Del("Content-Length")
		invalidateMutatedHTMLRepresentationHeaders(resp.Header)
		logHTMLProxyMutation(opts, resp, "streaming", "", 0, 0)
		return nil
	}

	bodyBytes, skipReason, err := readHTMLProxyMutationBody(resp, htmlProxyMutationBodyLimitBytes)
	if err != nil {
		return err
	}
	if skipReason != "" {
		logHTMLProxyMutation(opts, resp, "skipped", skipReason, 0, 0)
		return nil
	}

	originalLen := len(bodyBytes)
	toolbarHTML := ""
	if opts.toolbar {
		if opts.toolbarHTML != nil {
			toolbarHTML = opts.toolbarHTML()
		}
	}
	bodyBytes = mutateHTMLProxyBody(bodyBytes, opts.rewrite, opts.rewritePrefix, toolbarHTML)

	resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	resp.ContentLength = int64(len(bodyBytes))
	resp.Header.Set("Content-Length", strconv.Itoa(len(bodyBytes)))
	invalidateMutatedHTMLRepresentationHeaders(resp.Header)
	logHTMLProxyMutation(opts, resp, "applied", "", originalLen, len(bodyBytes))
	return nil
}

func invalidateMutatedHTMLRepresentationHeaders(headers http.Header) {
	if headers == nil {
		return
	}
	for _, name := range []string{
		"ETag",
		"Last-Modified",
		"Content-MD5",
		"Digest",
		"Content-Digest",
		"Repr-Digest",
		"Accept-Ranges",
	} {
		headers.Del(name)
	}
}

func readHTMLProxyMutationBody(resp *http.Response, limit int64) ([]byte, string, error) {
	if resp == nil || resp.Body == nil {
		return nil, "no_body", nil
	}
	if resp.ContentLength > limit {
		return nil, "content_length_exceeds_limit", nil
	}

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, "", err
	}
	if int64(len(bodyBytes)) > limit {
		resp.Body = &prependReadCloser{
			reader: io.MultiReader(bytes.NewReader(bodyBytes), resp.Body),
			closer: resp.Body,
		}
		return nil, "stream_exceeds_limit", nil
	}

	_ = resp.Body.Close()
	return bodyBytes, "", nil
}

func logHTMLProxyMutation(opts htmlResponseMutationOptions, resp *http.Response, outcome string, reason string, originalBytes int, mutatedBytes int) {
	if event := debugProxyEvent("html_response_mutation", opts.requestID); event != nil {
		contentLength := int64(-1)
		contentType := ""
		if resp != nil {
			contentLength = resp.ContentLength
			contentType = resp.Header.Get("Content-Type")
		}
		event.Str("route_type", opts.routeType).
			Str("route_key", logger.SanitizeLogString(opts.routeKey)).
			Str("outcome", outcome).
			Str("reason", reason).
			Bool("rewrite_html", opts.rewrite).
			Bool("toolbar", opts.toolbar).
			Str("content_type", logger.SanitizeLogString(contentType)).
			Int64("content_length", contentLength).
			Int64("limit_bytes", htmlProxyMutationBodyLimitBytes).
			Int("original_bytes", originalBytes).
			Int("mutated_bytes", mutatedBytes).
			Send()
	}
}

type toolbarStreamSegment struct {
	data   []byte
	text   string
	offset int
}

type streamingToolbarReadCloser struct {
	source  io.ReadCloser
	toolbar string
	scratch []byte

	pending     [htmlToolbarStreamTailBytes]byte
	emitPrefix  [htmlToolbarStreamTailBytes]byte
	pendingLen  int
	segments    [htmlToolbarStreamMaxSegments]toolbarStreamSegment
	segmentNext int
	segmentLen  int

	injected        bool
	sawHTML         bool
	readError       error
	scratchReleased bool
}

func newStreamingToolbarReadCloser(source io.ReadCloser, toolbarHTML string) io.ReadCloser {
	scratch := htmlToolbarStreamBufferPool.Get()
	if len(scratch) < htmlToolbarStreamChunkSize {
		scratch = make([]byte, htmlToolbarStreamChunkSize)
	}
	return &streamingToolbarReadCloser{
		source:  source,
		toolbar: toolbarHTML,
		scratch: scratch[:htmlToolbarStreamChunkSize],
	}
}

func (rc *streamingToolbarReadCloser) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		if n := rc.readSegments(p); n > 0 {
			return n, nil
		}
		if rc.readError != nil {
			rc.releaseScratch()
			return 0, rc.readError
		}
		rc.readMore()
	}
}

func (rc *streamingToolbarReadCloser) Close() error {
	if rc == nil {
		return nil
	}
	rc.releaseScratch()
	if rc.source == nil {
		return nil
	}
	source := rc.source
	rc.source = nil
	return source.Close()
}

func (rc *streamingToolbarReadCloser) releaseScratch() {
	if rc == nil || rc.scratchReleased {
		return
	}
	rc.scratchReleased = true
	if rc.scratch != nil {
		htmlToolbarStreamBufferPool.Put(rc.scratch)
		rc.scratch = nil
	}
}

func (rc *streamingToolbarReadCloser) readSegments(p []byte) int {
	for rc.segmentNext < rc.segmentLen {
		segment := &rc.segments[rc.segmentNext]
		var n int
		if segment.data != nil {
			n = copy(p, segment.data[segment.offset:])
			if segment.offset+n == len(segment.data) {
				rc.segmentNext++
			} else {
				segment.offset += n
			}
		} else {
			n = copy(p, segment.text[segment.offset:])
			if segment.offset+n == len(segment.text) {
				rc.segmentNext++
			} else {
				segment.offset += n
			}
		}
		if n > 0 {
			return n
		}
	}
	return 0
}

func (rc *streamingToolbarReadCloser) readMore() {
	rc.segmentNext = 0
	rc.segmentLen = 0
	if rc.source == nil {
		rc.finish()
		rc.readError = io.EOF
		return
	}

	n, err := rc.source.Read(rc.scratch)
	if n > 0 {
		rc.process(rc.scratch[:n])
	}
	if err == io.EOF {
		rc.finish()
		rc.readError = io.EOF
		return
	}
	if err != nil {
		rc.flushPending()
		rc.readError = err
	}
}

func (rc *streamingToolbarReadCloser) process(chunk []byte) {
	if rc.injected {
		rc.appendBytes(chunk)
		return
	}

	oldPendingLen := rc.pendingLen
	copy(rc.emitPrefix[:oldPendingLen], rc.pending[:oldPendingLen])
	oldPending := rc.emitPrefix[:oldPendingLen]
	if !rc.sawHTML && containsAnyHTMLMarkerAcrossChunks(oldPending, chunk) {
		rc.sawHTML = true
	}

	if idx := indexFoldASCIIChunks(oldPending, chunk, htmlBodyCloseMarker); idx >= 0 {
		rc.appendLogicalRange(oldPending, chunk, 0, idx)
		rc.appendString(rc.toolbar)
		rc.appendLogicalRange(oldPending, chunk, idx, len(oldPending)+len(chunk))
		rc.pendingLen = 0
		rc.injected = true
		return
	}

	totalLen := len(oldPending) + len(chunk)
	keepLen := min(totalLen, htmlToolbarStreamTailBytes)
	flushLen := totalLen - keepLen
	rc.appendLogicalRange(oldPending, chunk, 0, flushLen)
	rc.copyLogicalRangeToPending(oldPending, chunk, flushLen, totalLen)
}

func (rc *streamingToolbarReadCloser) appendLogicalRange(prefix []byte, chunk []byte, start int, end int) {
	if start >= end {
		return
	}
	if start < len(prefix) {
		prefixEnd := min(end, len(prefix))
		rc.appendBytes(prefix[start:prefixEnd])
	}
	if end > len(prefix) {
		chunkStart := max(0, start-len(prefix))
		rc.appendBytes(chunk[chunkStart : end-len(prefix)])
	}
}

func (rc *streamingToolbarReadCloser) copyLogicalRangeToPending(prefix []byte, chunk []byte, start int, end int) {
	rc.pendingLen = 0
	if start >= end {
		return
	}
	if start < len(prefix) {
		prefixEnd := min(end, len(prefix))
		rc.pendingLen += copy(rc.pending[rc.pendingLen:], prefix[start:prefixEnd])
	}
	if end > len(prefix) {
		chunkStart := max(0, start-len(prefix))
		rc.pendingLen += copy(rc.pending[rc.pendingLen:], chunk[chunkStart:end-len(prefix)])
	}
}

func (rc *streamingToolbarReadCloser) appendBytes(data []byte) {
	if len(data) == 0 {
		return
	}
	rc.segments[rc.segmentLen] = toolbarStreamSegment{data: data}
	rc.segmentLen++
}

func (rc *streamingToolbarReadCloser) appendString(text string) {
	if text == "" {
		return
	}
	rc.segments[rc.segmentLen] = toolbarStreamSegment{text: text}
	rc.segmentLen++
}

func (rc *streamingToolbarReadCloser) finish() {
	if rc.injected {
		return
	}
	rc.flushPending()
	if rc.sawHTML && rc.toolbar != "" {
		rc.appendString(rc.toolbar)
		rc.injected = true
	}
}

func (rc *streamingToolbarReadCloser) flushPending() {
	if rc.pendingLen == 0 {
		return
	}
	rc.appendBytes(rc.pending[:rc.pendingLen])
	rc.pendingLen = 0
}

func containsAnyHTMLMarkerAcrossChunks(prefix []byte, chunk []byte) bool {
	if containsAnyHTMLMarkerFoldASCII(chunk) {
		return true
	}
	if len(prefix) == 0 {
		return false
	}

	var boundary [htmlToolbarStreamTailBytes * 2]byte
	n := copy(boundary[:], prefix)
	n += copy(boundary[n:], chunk[:min(len(chunk), htmlToolbarStreamTailBytes)])
	return containsAnyHTMLMarkerFoldASCII(boundary[:n])
}

func indexFoldASCIIChunks(prefix []byte, chunk []byte, marker []byte) int {
	if idx := indexFoldASCII(prefix, marker); idx >= 0 {
		return idx
	}
	if len(prefix) > 0 && len(marker) > 1 {
		start := max(0, len(prefix)-len(marker)+1)
		totalLen := len(prefix) + len(chunk)
		for i := start; i < len(prefix) && i+len(marker) <= totalLen; i++ {
			matched := true
			for j := range marker {
				position := i + j
				var value byte
				if position < len(prefix) {
					value = prefix[position]
				} else {
					value = chunk[position-len(prefix)]
				}
				if lowerASCII(value) != lowerASCII(marker[j]) {
					matched = false
					break
				}
			}
			if matched {
				return i
			}
		}
	}
	if idx := indexFoldASCII(chunk, marker); idx >= 0 {
		return len(prefix) + idx
	}
	return -1
}

func mutateHTMLProxyBody(body []byte, rewrite bool, prefix string, toolbarHTML string) []byte {
	if len(body) == 0 {
		return body
	}
	if !rewrite || prefix == "" {
		return injectToolbarIntoHTMLBytes(body, toolbarHTML)
	}

	insertAt := -1
	appendToolbarAtEnd := false
	if toolbarHTML != "" {
		if idx := lastIndexFoldASCII(body, htmlBodyCloseMarker); idx >= 0 {
			insertAt = idx
		} else {
			appendToolbarAtEnd = containsAnyHTMLMarkerFoldASCII(body)
		}
	}

	var out []byte
	last := 0
	for i := 0; i < len(body); {
		if i == insertAt {
			if out == nil {
				out = make([]byte, 0, len(body)+len(toolbarHTML)+htmlRewriteExtraCapacity(len(body), len(prefix)))
			}
			out = append(out, body[last:i]...)
			out = append(out, toolbarHTML...)
			last = i
			insertAt = -1
			continue
		}

		oldLen, headLen, tail := htmlAbsolutePathReplacement(body[i:])
		if oldLen == 0 {
			i++
			continue
		}
		if out == nil {
			out = make([]byte, 0, len(body)+len(toolbarHTML)+htmlRewriteExtraCapacity(len(body), len(prefix)))
		}
		out = append(out, body[last:i]...)
		out = append(out, body[i:i+headLen]...)
		out = append(out, prefix...)
		out = append(out, tail...)
		i += oldLen
		last = i
	}

	if out == nil {
		if appendToolbarAtEnd {
			out = make([]byte, 0, len(body)+len(toolbarHTML))
			out = append(out, body...)
			out = append(out, toolbarHTML...)
			return out
		}
		return body
	}
	out = append(out, body[last:]...)
	if insertAt >= 0 {
		out = append(out, toolbarHTML...)
	}
	if appendToolbarAtEnd {
		out = append(out, toolbarHTML...)
	}
	return out
}

func rewriteHTMLAbsolutePaths(body []byte, prefix string) []byte {
	if len(body) == 0 || prefix == "" {
		return body
	}

	var out []byte
	last := 0
	for i := 0; i < len(body); {
		oldLen, headLen, tail := htmlAbsolutePathReplacement(body[i:])
		if oldLen == 0 {
			i++
			continue
		}
		if out == nil {
			out = make([]byte, 0, len(body)+htmlRewriteExtraCapacity(len(body), len(prefix)))
		}
		out = append(out, body[last:i]...)
		out = append(out, body[i:i+headLen]...)
		out = append(out, prefix...)
		out = append(out, tail...)
		i += oldLen
		last = i
	}
	if out == nil {
		return body
	}
	out = append(out, body[last:]...)
	return out
}

func htmlRewriteExtraCapacity(bodyLen int, prefixLen int) int {
	if prefixLen <= 0 {
		return 0
	}
	extra := prefixLen * 16
	if quarter := bodyLen / 4; quarter > extra {
		extra = quarter
	}
	if maxExtra := prefixLen * 1024; extra > maxExtra {
		extra = maxExtra
	}
	return extra
}

func htmlAbsolutePathReplacement(s []byte) (oldLen int, headLen int, tail []byte) {
	if len(s) == 0 {
		return 0, 0, nil
	}
	switch s[0] {
	case 'h':
		if bytes.HasPrefix(s, htmlRewriteHrefPattern) {
			return len(`href="/`), len(`href="`), htmlRewriteSlashTail
		}
	case 's':
		if bytes.HasPrefix(s, htmlRewriteSrcPattern) {
			return len(`src="/`), len(`src="`), htmlRewriteSlashTail
		}
	case 'a':
		if bytes.HasPrefix(s, htmlRewriteActionPattern) {
			return len(`action="/`), len(`action="`), htmlRewriteSlashTail
		}
	case '<':
		if bytes.HasPrefix(s, htmlRewriteBasePattern) {
			return len(`<base href="/">`), len(`<base href="`), htmlRewriteBaseTail
		}
	}
	return 0, 0, nil
}

func injectToolbarIntoHTMLBytes(body []byte, toolbarHTML string) []byte {
	if toolbarHTML == "" || len(body) == 0 {
		return body
	}

	if idx := lastIndexFoldASCII(body, htmlBodyCloseMarker); idx != -1 {
		out := make([]byte, 0, len(body)+len(toolbarHTML))
		out = append(out, body[:idx]...)
		out = append(out, toolbarHTML...)
		out = append(out, body[idx:]...)
		return out
	}

	if containsAnyHTMLMarkerFoldASCII(body) {
		return append(body, toolbarHTML...)
	}

	return body
}

func containsAnyHTMLMarkerFoldASCII(s []byte) bool {
	for i := 0; i < len(s); i++ {
		if s[i] != '<' {
			continue
		}
		remaining := s[i:]
		if equalFoldASCIIPrefix(remaining, htmlStartMarker) ||
			equalFoldASCIIPrefix(remaining, htmlHeadMarker) ||
			equalFoldASCIIPrefix(remaining, htmlBodyStartMarker) ||
			equalFoldASCIIPrefix(remaining, htmlDoctypeMarker) {
			return true
		}
	}
	return false
}

func equalFoldASCIIPrefix(s []byte, prefix []byte) bool {
	return len(s) >= len(prefix) && equalFoldASCIIBytes(s[:len(prefix)], prefix)
}

func lastIndexFoldASCII(s []byte, substr []byte) int {
	if len(substr) == 0 {
		return len(s)
	}
	if len(substr) > len(s) {
		return -1
	}
	for i := len(s) - len(substr); i >= 0; i-- {
		if equalFoldASCIIBytes(s[i:i+len(substr)], substr) {
			return i
		}
	}
	return -1
}

func indexFoldASCII(s []byte, substr []byte) int {
	if len(substr) == 0 {
		return 0
	}
	if len(substr) > len(s) {
		return -1
	}
	last := len(s) - len(substr)
	for i := 0; i <= last; i++ {
		if equalFoldASCIIBytes(s[i:i+len(substr)], substr) {
			return i
		}
	}
	return -1
}

func equalFoldASCIIBytes(a []byte, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if lowerASCII(a[i]) != lowerASCII(b[i]) {
			return false
		}
	}
	return true
}

func lowerASCII(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}
