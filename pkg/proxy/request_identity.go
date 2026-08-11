package proxy

import (
	"net/http"
	"strings"

	"golang.org/x/net/http/httpguts"
)

const proxyPathCookieName = "__proxy_path"
const defaultCookieMaxNum = 3000
const canonicalCookieIdentityStackPairs = 8

type canonicalCookiePair struct {
	name  string
	value string
}

func canonicalCookieIdentity(r *http.Request) string {
	if r == nil {
		return ""
	}

	headers := r.Header.Values("Cookie")
	if len(headers) == 0 || !cookieHeaderValuesWithinDefaultLimit(headers) {
		return ""
	}

	var stackPairs [canonicalCookieIdentityStackPairs]canonicalCookiePair
	pairs := stackPairs[:0]
	for _, header := range headers {
		pairs = appendCanonicalCookieIdentityPairs(pairs, header)
	}
	if len(pairs) == 0 {
		return ""
	}
	if len(pairs) == 1 {
		return pairs[0].name + "=" + pairs[0].value
	}

	sortCanonicalCookiePairs(pairs)

	var b strings.Builder
	b.Grow(canonicalCookieIdentitySize(pairs))
	for i, pair := range pairs {
		if i > 0 {
			b.WriteByte(';')
		}
		b.WriteString(pair.name)
		b.WriteByte('=')
		b.WriteString(pair.value)
	}
	return b.String()
}

func canonicalCookieIdentityKey(r *http.Request) (string, bool) {
	if r == nil {
		return "", false
	}

	headers := r.Header.Values("Cookie")
	if len(headers) == 0 || !cookieHeaderValuesWithinDefaultLimit(headers) {
		return "", false
	}

	var stackPairs [canonicalCookieIdentityStackPairs]canonicalCookiePair
	pairs := stackPairs[:0]
	for _, header := range headers {
		pairs = appendCanonicalCookieIdentityPairs(pairs, header)
	}
	if len(pairs) == 0 {
		return "", false
	}

	var stack [authCacheHashBufferSize]byte
	buf := stack[:0]
	buf = append(buf, identitySourceCookiePrefix...)
	if len(pairs) == 1 {
		buf = appendCanonicalCookiePairBytes(buf, pairs[0])
	} else {
		sortCanonicalCookiePairs(pairs)
		buf = appendCanonicalCookiePairsBytes(buf, pairs)
	}
	return sha256HexBytes(buf), true
}

func appendCanonicalCookiePairsBytes(buf []byte, pairs []canonicalCookiePair) []byte {
	for i, pair := range pairs {
		if i > 0 {
			buf = append(buf, ';')
		}
		buf = appendCanonicalCookiePairBytes(buf, pair)
	}
	return buf
}

func appendCanonicalCookieIdentityPairs(pairs []canonicalCookiePair, header string) []canonicalCookiePair {
	for {
		part, rest, more := strings.Cut(header, ";")
		name, value, ok := parseCanonicalCookiePart(strings.TrimSpace(part))
		if ok && name != proxyPathCookieName && value != "" {
			pairs = append(pairs, canonicalCookiePair{name: name, value: value})
		}
		if !more {
			return pairs
		}
		header = rest
	}
}

func appendCanonicalCookiePairBytes(buf []byte, pair canonicalCookiePair) []byte {
	buf = append(buf, pair.name...)
	buf = append(buf, '=')
	buf = append(buf, pair.value...)
	return buf
}

func sortCanonicalCookiePairs(pairs []canonicalCookiePair) {
	for i := 1; i < len(pairs); i++ {
		pair := pairs[i]
		j := i - 1
		for ; j >= 0 && canonicalCookiePairLess(pair, pairs[j]); j-- {
			pairs[j+1] = pairs[j]
		}
		pairs[j+1] = pair
	}
}

func canonicalCookiePairLess(a, b canonicalCookiePair) bool {
	if a.name == b.name {
		return a.value < b.value
	}
	return a.name < b.name
}

func parseCanonicalCookiePart(part string) (string, string, bool) {
	if part == "" {
		return "", "", false
	}
	name, rawValue, _ := strings.Cut(part, "=")
	name = strings.TrimSpace(name)
	if name == "" || !httpguts.ValidHeaderFieldName(name) {
		return "", "", false
	}
	value, ok := parseCanonicalCookieValue(rawValue)
	if !ok {
		return "", "", false
	}
	return name, value, true
}

func parseCanonicalCookieValue(raw string) (string, bool) {
	if len(raw) > 1 && raw[0] == '"' && raw[len(raw)-1] == '"' {
		raw = raw[1 : len(raw)-1]
	}
	for i := 0; i < len(raw); i++ {
		if !validCanonicalCookieValueByte(raw[i]) {
			return "", false
		}
	}
	return raw, true
}

func validCanonicalCookieValueByte(b byte) bool {
	return 0x20 <= b && b < 0x7f && b != '"' && b != ';' && b != '\\'
}

func cookieHeaderValuesWithinDefaultLimit(headers []string) bool {
	if len(headers) == 0 {
		return true
	}
	totalLen := 0
	for _, header := range headers {
		totalLen += len(header)
	}
	if totalLen+len(headers) <= defaultCookieMaxNum {
		return true
	}

	count := 0
	for _, header := range headers {
		count += strings.Count(header, ";") + 1
		if count > defaultCookieMaxNum {
			return false
		}
	}
	return true
}

func canonicalCookieIdentitySize(pairs []canonicalCookiePair) int {
	if len(pairs) == 0 {
		return 0
	}
	size := len(pairs) - 1
	for _, pair := range pairs {
		size += len(pair.name) + 1 + len(pair.value)
	}
	return size
}

func activeIdentityKey(r *http.Request, clientIP string) string {
	if cookieKey, ok := canonicalCookieIdentityKey(r); ok {
		return cookieKey
	} else if auth := r.Header.Get("Authorization"); auth != "" {
		return activeIdentityKeyFromParts(identitySourceAuthPrefix, auth)
	} else if clientIP != "" {
		return activeIdentityKeyFromParts(identitySourceIPPrefix, clientIP)
	} else {
		return ""
	}
}

func activeIdentityKeyFromSource(src string) string {
	if strings.TrimSpace(src) == "" {
		return ""
	}
	return sha256HexString(src)
}

func activeIdentityKeyFromClientIP(clientIP string) string {
	clientIP = strings.TrimSpace(clientIP)
	if clientIP == "" {
		return ""
	}
	return activeIdentityKeyFromParts(identitySourceIPPrefix, clientIP)
}
