package proxy

import (
	"bytes"
	"io"
	"net/http"
	"strconv"
	"sync"

	"go-reauth-proxy/pkg/logger"
)

var (
	htmlRewriteHrefPattern   = []byte(`href="/`)
	htmlRewriteSrcPattern    = []byte(`src="/`)
	htmlRewriteActionPattern = []byte(`action="/`)
	htmlRewriteBasePattern   = []byte(`<base href="/">`)
	htmlRewriteSlashTail     = []byte(`/`)
	htmlRewritePathCandidate = []byte(`="/`)
	htmlRewriteBaseTail      = []byte(`/">`)
	htmlBodyCloseMarker      = []byte(`</body>`)
	htmlStartMarker          = []byte(`<html`)
	htmlHeadMarker           = []byte(`<head`)
	htmlBodyStartMarker      = []byte(`<body`)
	htmlDoctypeMarker        = []byte(`<!doctype`)
)

const (
	htmlProxyMutationBodyLimitBytes int64 = 2 * 1024 * 1024
	// Bound expansion independently of the input limit. If rewriting would
	// exceed this budget, preserve the original paths and only add the toolbar.
	htmlProxyMutationOutputLimitBytes = 4 * 1024 * 1024
	htmlSmallRewriteInputLimitBytes   = 64 * 1024
	htmlSmallRewriteOutputLimitBytes  = 256 * 1024
	htmlToolbarStreamChunkSize        = 32 * 1024
	htmlToolbarStreamTailBytes        = 16
	htmlToolbarStreamMaxSegments      = 5
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
	// A range describes bytes in the original representation, including any
	// content encoding. Neither decoding nor rewriting a partial body can
	// preserve its Content-Range offsets.
	if resp.StatusCode == http.StatusPartialContent {
		logHTMLProxyMutation(opts, resp, "skipped", "partial_content", 0, 0)
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
	mu        sync.Mutex
	closeOnce sync.Once
	closeErr  error
	source    io.ReadCloser
	toolbar   string
	scratch   []byte

	pending     [htmlToolbarStreamTailBytes]byte
	emitPrefix  [htmlToolbarStreamTailBytes]byte
	pendingLen  int
	segments    [htmlToolbarStreamMaxSegments]toolbarStreamSegment
	segmentNext int
	segmentLen  int

	injected        bool
	lexer           htmlToolbarLexer
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
	rc.mu.Lock()
	defer rc.mu.Unlock()
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
	// Close the source before waiting for Read's lock so a blocked upstream
	// read is interrupted. Return the scratch buffer only after that read has
	// stopped using it; otherwise another response can acquire it too early.
	rc.closeOnce.Do(func() {
		if rc.source != nil {
			rc.closeErr = rc.source.Close()
		}
		rc.mu.Lock()
		defer rc.mu.Unlock()
		rc.readError = io.ErrClosedPipe
		clear(rc.segments[:])
		rc.segmentNext, rc.segmentLen, rc.pendingLen = 0, 0, 0
		rc.releaseScratch()
	})
	return rc.closeErr
}

func (rc *streamingToolbarReadCloser) releaseScratch() {
	if rc == nil || rc.scratchReleased {
		return
	}
	rc.scratchReleased = true
	rc.lexer.foreign = nil
	if rc.scratch != nil {
		htmlToolbarStreamBufferPool.Put(rc.scratch)
		rc.scratch = nil
	}
}

func (rc *streamingToolbarReadCloser) readSegments(p []byte) int {
	total := 0
	for rc.segmentNext < rc.segmentLen && len(p) > 0 {
		segment := &rc.segments[rc.segmentNext]
		var n int
		length := len(segment.text)
		if segment.data != nil {
			n = copy(p, segment.data[segment.offset:])
			length = len(segment.data)
		} else {
			n = copy(p, segment.text[segment.offset:])
		}
		segment.offset += n
		if segment.offset == length {
			*segment = toolbarStreamSegment{}
			rc.segmentNext++
		}
		total += n
		p = p[n:]
	}
	// Return all already prepared segments, but do not read upstream again
	// just to fill p: an upstream stream may pause indefinitely at this point.
	return total
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
	totalLen := len(oldPending) + len(chunk)
	keepLen := min(totalLen, htmlToolbarStreamTailBytes)
	flushLen := totalLen - keepLen
	if idx := rc.lexer.scan(oldPending, chunk, flushLen); idx >= 0 {
		rc.appendLogicalRange(oldPending, chunk, 0, idx)
		rc.appendString(rc.toolbar)
		rc.appendLogicalRange(oldPending, chunk, idx, len(oldPending)+len(chunk))
		rc.pendingLen = 0
		rc.injected = true
		return
	}

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
	if idx := rc.lexer.scan(nil, rc.pending[:rc.pendingLen], rc.pendingLen); idx >= 0 {
		rc.appendBytes(rc.pending[:idx])
		rc.appendString(rc.toolbar)
		rc.appendBytes(rc.pending[idx:rc.pendingLen])
		rc.pendingLen = 0
		rc.injected = true
		return
	}
	rc.flushPending()
	if rc.lexer.canAppend() && rc.toolbar != "" {
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

func mutateHTMLProxyBody(body []byte, rewrite bool, prefix string, toolbarHTML string) []byte {
	if len(body) == 0 {
		return body
	}
	insertAt := -1
	if toolbarHTML != "" {
		insertAt = htmlToolbarInsertionOffset(body)
	}
	outputLen := len(body)
	if insertAt >= 0 {
		if len(toolbarHTML) > htmlProxyMutationOutputLimitBytes-outputLen {
			return body
		}
		outputLen += len(toolbarHTML)
	}

	// Count before allocating: repeated absolute paths can amplify a bounded
	// input many times when the route prefix is long. Skip the whole rewrite
	// on overflow so a page never contains a mixture of rewritten paths.
	rewrite = rewrite && prefix != ""
	if rewrite {
		// Every match consumes at least len(`src="/`) input bytes. For small
		// pages this upper bound proves safety without counting every match
		// first. Keep the common short-prefix path a single lazy-copy pass.
		maxMatches := len(body) / len(htmlRewriteSrcPattern)
		if len(body) <= htmlSmallRewriteInputLimitBytes && maxMatches > 0 &&
			outputLen <= htmlSmallRewriteOutputLimitBytes &&
			len(prefix) <= (htmlSmallRewriteOutputLimitBytes-outputLen)/maxMatches {
			return mutateSmallHTMLProxyBody(body, prefix, toolbarHTML, insertAt, outputLen, outputLen+maxMatches*len(prefix))
		}
		// Each replacement adds exactly len(prefix), including <base>, whose
		// href also occurs in this non-overlapping count. bytes.Count avoids
		// a second byte-by-byte rewrite pass solely to size the allocation.
		matches := bytes.Count(body, htmlRewriteHrefPattern) + bytes.Count(body, htmlRewriteSrcPattern) + bytes.Count(body, htmlRewriteActionPattern)
		if matches == 0 || matches > (htmlProxyMutationOutputLimitBytes-outputLen)/len(prefix) {
			rewrite = false
		} else {
			outputLen += matches * len(prefix)
		}
	}
	if outputLen == len(body) {
		return body
	}

	out := make([]byte, 0, outputLen)
	if !rewrite {
		out = append(out, body[:insertAt]...)
		out = append(out, toolbarHTML...)
		return append(out, body[insertAt:]...)
	}
	last := 0
	for i := 0; i < len(body); {
		if i == insertAt {
			out = append(out, body[last:i]...)
			out = append(out, toolbarHTML...)
			last = i
		}
		oldLen, headLen, tail := 0, 0, []byte(nil)
		if rewrite {
			oldLen, headLen, tail = htmlAbsolutePathReplacement(body[i:])
		}
		if oldLen == 0 {
			i++
			continue
		}
		out = append(out, body[last:i]...)
		out = append(out, body[i:i+headLen]...)
		out = append(out, prefix...)
		out = append(out, tail...)
		i += oldLen
		last = i
	}
	out = append(out, body[last:]...)
	if insertAt == len(body) {
		out = append(out, toolbarHTML...)
	}
	return out
}

// mutateSmallHTMLProxyBody is used only after a worst-case bound proves its
// output fits the small-page budget. If the initial estimate is insufficient,
// count the unprocessed suffix once and resize exactly; subsequent appends
// cannot trigger repeated geometric growth.
func mutateSmallHTMLProxyBody(body []byte, prefix, toolbarHTML string, insertAt, outputLen, maxOutputLen int) []byte {
	extra := min(max(len(prefix)*16, len(body)/4), len(prefix)*1024)
	initialCapacity := min(outputLen+extra, maxOutputLen)
	var out []byte
	last := 0
	for cursor := 0; ; {
		slash := nextHTMLAbsolutePathSlash(body, cursor)
		if slash < 0 {
			break
		}
		if out == nil {
			out = make([]byte, 0, initialCapacity)
		}
		if outputLen+len(prefix) > cap(out) {
			// The current insertion is already known; count only later ones.
			suffix := body[slash+1:]
			remaining := bytes.Count(suffix, htmlRewriteHrefPattern) + bytes.Count(suffix, htmlRewriteSrcPattern) + bytes.Count(suffix, htmlRewriteActionPattern)
			next := make([]byte, len(out), outputLen+(remaining+1)*len(prefix))
			copy(next, out)
			out = next
		}
		outputLen += len(prefix)
		if insertAt >= last && insertAt <= slash {
			out = append(out, body[last:insertAt]...)
			out = append(out, toolbarHTML...)
			last = insertAt
			insertAt = -1
		}
		out = append(out, body[last:slash]...)
		out = append(out, prefix...)
		last = slash
		cursor = slash + 1
	}
	if out == nil {
		if insertAt < 0 {
			return body
		}
		out = make([]byte, 0, outputLen)
	}
	if insertAt >= last {
		out = append(out, body[last:insertAt]...)
		out = append(out, toolbarHTML...)
		last = insertAt
	}
	return append(out, body[last:]...)
}

// All supported replacements, including <base href="/">, insert the prefix
// immediately before a slash following =". Search that common suffix directly
// so ordinary text and unrelated markup need no per-byte rewrite dispatch.
func nextHTMLAbsolutePathSlash(body []byte, cursor int) int {
	for cursor < len(body) {
		index := bytes.Index(body[cursor:], htmlRewritePathCandidate)
		if index < 0 {
			return -1
		}
		equal := cursor + index
		if equal >= 4 && string(body[equal-4:equal]) == "href" ||
			equal >= 3 && string(body[equal-3:equal]) == "src" ||
			equal >= 6 && string(body[equal-6:equal]) == "action" {
			return equal + 2
		}
		cursor = equal + len(htmlRewritePathCandidate)
	}
	return -1
}

func rewriteHTMLAbsolutePaths(body []byte, prefix string) []byte {
	return mutateHTMLProxyBody(body, true, prefix, "")
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
	return mutateHTMLProxyBody(body, false, "", toolbarHTML)
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
