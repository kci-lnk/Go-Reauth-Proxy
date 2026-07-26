package response

import (
	"embed"
	"encoding/base64"
	"html/template"
	"io/fs"
	"mime"
	"net/http"
	"path/filepath"
	"strings"
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
