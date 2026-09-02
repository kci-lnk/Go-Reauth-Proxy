package proxy

import "strings"

func equalFoldASCIIString(a string, b string) bool {
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

func containsFoldASCIIString(value string, search string) bool {
	if search == "" {
		return true
	}
	if len(search) > len(value) {
		return false
	}
	first := lowerASCII(search[0])
	last := len(value) - len(search)
	for i := 0; i <= last; i++ {
		if lowerASCII(value[i]) != first {
			continue
		}
		if hasFoldASCIIPrefixString(value[i:], search) {
			return true
		}
	}
	return false
}

func containsFoldString(value string, search string) bool {
	if search == "" {
		return true
	}
	if isASCIIString(value) && isASCIIString(search) {
		return containsFoldASCIIString(value, search)
	}
	return strings.Contains(strings.ToLower(value), strings.ToLower(search))
}

func isASCIIString(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] >= 0x80 {
			return false
		}
	}
	return true
}

func hasFoldASCIIPrefixString(value string, prefix string) bool {
	if len(prefix) > len(value) {
		return false
	}
	for i := 1; i < len(prefix); i++ {
		if lowerASCII(value[i]) != lowerASCII(prefix[i]) {
			return false
		}
	}
	return true
}

func isHTMLContentType(contentType string) bool {
	mediaType := strings.TrimSpace(contentType)
	if separator := strings.IndexByte(mediaType, ';'); separator >= 0 {
		mediaType = strings.TrimSpace(mediaType[:separator])
	}
	return equalFoldASCIIString(mediaType, "text/html")
}

func lowerASCIIString(value string) string {
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c >= 0x80 || (c >= 'A' && c <= 'Z') {
			return strings.ToLower(value)
		}
	}
	return value
}

func isASCIISpace(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', '\f', '\v':
		return true
	default:
		return false
	}
}
