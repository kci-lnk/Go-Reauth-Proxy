package response

import (
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"html/template"
	"io/fs"
	"mime"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	WebsiteIconPathPrefix   = "/__assets__/website_icon."
	maxWebsiteIconBytes     = 1024 * 1024
	maxWebsiteIconPathBytes = 512
	derivedIconPathSuffix   = ".img"
)

//go:embed static/favicon/*
var faviconFS embed.FS

// faviconFiles maps URL paths to embedded file paths
var faviconFiles = map[string]string{
	"/__assets__/favicon/favicon-16x16.png":          "static/favicon/favicon-16x16.png",
	"/__assets__/favicon/favicon-32x32.png":          "static/favicon/favicon-32x32.png",
	"/__assets__/favicon/apple-touch-icon.png":       "static/favicon/apple-touch-icon.png",
	"/__assets__/favicon/android-chrome-192x192.png": "static/favicon/android-chrome-192x192.png",
	"/__assets__/favicon/android-chrome-512x512.png": "static/favicon/android-chrome-512x512.png",
	"/__assets__/favicon/site.webmanifest":           "static/favicon/site.webmanifest",
}

var (
	inlinePageIconDataURL = embeddedFaviconDataURL("/__assets__/favicon/favicon-32x32.png")
	inlinePageLogoDataURL = embeddedFaviconDataURL("/__assets__/favicon/android-chrome-192x192.png")
)

func embeddedFaviconDataURL(path string) template.URL {
	embeddedPath, ok := faviconFiles[path]
	if !ok {
		return ""
	}
	data, err := fs.ReadFile(faviconFS, embeddedPath)
	if err != nil {
		return ""
	}
	contentType := mime.TypeByExtension(filepath.Ext(embeddedPath))
	if contentType == "" || !strings.HasPrefix(contentType, "image/") {
		return ""
	}
	return template.URL("data:" + contentType + ";base64," + base64.StdEncoding.EncodeToString(data))
}

// IsFaviconPath checks if the given URL path is a favicon-related static file.
func IsFaviconPath(path string) bool {
	_, ok := faviconFiles[path]
	return ok
}

// ServeFavicon serves the favicon file for the given URL path.
func ServeFavicon(w http.ResponseWriter, r *http.Request) {
	embeddedPath, ok := faviconFiles[r.URL.Path]
	if !ok {
		http.NotFound(w, r)
		return
	}

	data, err := fs.ReadFile(faviconFS, embeddedPath)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	ext := filepath.Ext(embeddedPath)
	contentType := mime.TypeByExtension(ext)
	if contentType == "" {
		if strings.HasSuffix(embeddedPath, ".webmanifest") {
			contentType = "application/manifest+json"
		} else {
			contentType = "application/octet-stream"
		}
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Write(data)
}

// ServeWebsiteIcon serves the matched HostRule favicon without requiring an
// authenticated proxy session. Invalid or missing icon data falls back to the
// embedded fn-knock icon so the URL remains usable for every mapped website.
func ServeWebsiteIcon(w http.ResponseWriter, r *http.Request, favicon string) {
	serveWebsiteIcon(w, r, favicon, false)
}

// ServeContentAddressedWebsiteIcon serves an automatically derived icon path
// with immutable caching. It verifies the request path against the favicon
// content before enabling the long-lived policy.
func ServeContentAddressedWebsiteIcon(w http.ResponseWriter, r *http.Request, favicon string) {
	derivedPath := EffectiveWebsiteIconPath("", favicon)
	serveWebsiteIcon(w, r, favicon, derivedPath != "" && r.URL.Path == derivedPath)
}

func serveWebsiteIcon(w http.ResponseWriter, r *http.Request, favicon string, immutable bool) {
	contentType, data, ok := decodeWebsiteIconDataURL(favicon)
	if !ok {
		contentType = "image/png"
		data, _ = fs.ReadFile(faviconFS, faviconFiles["/__assets__/favicon/favicon-32x32.png"])
	}

	hash := sha256.Sum256(data)
	etag := `"` + hex.EncodeToString(hash[:]) + `"`
	w.Header().Set("Content-Type", contentType)
	cacheControl := "public, max-age=300, stale-while-revalidate=86400"
	if immutable {
		cacheControl = "public, max-age=31536000, immutable"
	}
	w.Header().Set("Cache-Control", cacheControl)
	w.Header().Set("Cross-Origin-Resource-Policy", "cross-origin")
	w.Header().Set("ETag", etag)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if contentType == "image/svg+xml" {
		w.Header().Set("Content-Security-Policy", "default-src 'none'; sandbox")
	}
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	if r.Method == http.MethodHead {
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		return
	}
	_, _ = w.Write(data)
}

// EffectiveWebsiteIconPath returns a short per-host asset path for a favicon.
// Configured opaque paths are preserved; otherwise valid image data receives
// a deterministic content-addressed path so toolbar payloads never need to
// repeat the Base64 image itself.
func EffectiveWebsiteIconPath(configuredPath string, favicon string) string {
	if configuredPath = normalizeWebsiteIconPath(configuredPath); configuredPath != "" {
		return configuredPath
	}
	favicon = strings.TrimSpace(favicon)
	if _, _, ok := validateBase64ImageDataURL(favicon, maxWebsiteIconBytes); !ok {
		return ""
	}
	digest := sha256.Sum256([]byte(favicon))
	return WebsiteIconPathPrefix + hex.EncodeToString(digest[:]) + derivedIconPathSuffix
}

func normalizeWebsiteIconPath(value string) string {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, WebsiteIconPathPrefix) || len(value) > maxWebsiteIconPathBytes {
		return ""
	}
	name := strings.TrimPrefix(value, WebsiteIconPathPrefix)
	if name == "" || !isASCIIAlphaNumeric(name[0]) {
		return ""
	}
	for i := 0; i < len(name); i++ {
		char := name[i]
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || char == '.' || char == '_' || char == '-' {
			continue
		}
		return ""
	}
	return value
}

func isASCIIAlphaNumeric(char byte) bool {
	return (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9')
}

func decodeWebsiteIconDataURL(value string) (string, []byte, bool) {
	contentType, encoded, ok := validateBase64ImageDataURL(value, maxWebsiteIconBytes)
	if !ok {
		return "", nil, false
	}
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", nil, false
	}
	return contentType, data, true
}

// validateBase64ImageDataURL validates a Base64-only image data URL and
// applies its limit to the decoded image bytes rather than to the encoded
// transport representation. This keeps every Base64 favicon consumer on the
// same size contract without allocating a decoded copy during toolbar renders.
func validateBase64ImageDataURL(value string, maxDecodedBytes int) (string, string, bool) {
	value = strings.TrimSpace(value)
	metadata, encoded, ok := strings.Cut(value, ",")
	if !ok || len(metadata) < len("data:") || !strings.EqualFold(metadata[:len("data:")], "data:") {
		return "", "", false
	}
	metadataBody := metadata[len("data:"):]
	firstSeparator := strings.IndexByte(metadataBody, ';')
	lastSeparator := strings.LastIndexByte(metadataBody, ';')
	if firstSeparator < 1 ||
		lastSeparator != firstSeparator ||
		!strings.EqualFold(strings.TrimSpace(metadataBody[lastSeparator+1:]), "base64") {
		return "", "", false
	}
	contentType, ok := normalizeImageDataURLContentType(metadataBody[:firstSeparator])
	if !ok {
		return "", "", false
	}
	decodedBytes, ok := strictBase64DecodedLen(encoded)
	if !ok || decodedBytes == 0 || maxDecodedBytes < 1 || decodedBytes > maxDecodedBytes {
		return "", "", false
	}
	return contentType, encoded, true
}

func strictBase64DecodedLen(encoded string) (int, bool) {
	if len(encoded) == 0 || len(encoded)%4 != 0 {
		return 0, false
	}

	padding := 0
	if encoded[len(encoded)-1] == '=' {
		padding++
		if len(encoded) > 1 && encoded[len(encoded)-2] == '=' {
			padding++
		}
	}
	dataEnd := len(encoded) - padding
	for index := 0; index < dataEnd; index++ {
		if _, ok := base64AlphabetValue(encoded[index]); !ok {
			return 0, false
		}
	}
	for index := dataEnd; index < len(encoded); index++ {
		if encoded[index] != '=' {
			return 0, false
		}
	}
	lastValue, _ := base64AlphabetValue(encoded[dataEnd-1])
	if (padding == 2 && lastValue&0x0f != 0) || (padding == 1 && lastValue&0x03 != 0) {
		return 0, false
	}

	return len(encoded)/4*3 - padding, true
}

func base64AlphabetValue(value byte) (byte, bool) {
	switch {
	case value >= 'A' && value <= 'Z':
		return value - 'A', true
	case value >= 'a' && value <= 'z':
		return value - 'a' + 26, true
	case value >= '0' && value <= '9':
		return value - '0' + 52, true
	case value == '+':
		return 62, true
	case value == '/':
		return 63, true
	default:
		return 0, false
	}
}

func normalizeImageDataURLContentType(value string) (string, bool) {
	value = strings.TrimSpace(value)
	for _, allowed := range [...]string{
		"image/avif",
		"image/gif",
		"image/jpeg",
		"image/png",
		"image/svg+xml",
		"image/vnd.microsoft.icon",
		"image/webp",
		"image/x-icon",
	} {
		if strings.EqualFold(value, allowed) {
			return allowed, true
		}
	}
	return "", false
}
