package response

import (
	"bytes"
	"net/http"
	"path"
	"time"
)

const toolbarAssetCacheControl = "public,max-age=31536000,immutable"

// ToolbarAssetPath returns the content-addressed URL of the toolbar runtime.
func ToolbarAssetPath() string {
	return toolbarAssetPath
}

// IsToolbarAssetPath reports whether path names the current toolbar runtime.
func IsToolbarAssetPath(requestPath string) bool {
	return requestPath == toolbarAssetPath
}

// ServeToolbarAsset serves the immutable, content-addressed toolbar runtime.
func ServeToolbarAsset(w http.ResponseWriter, r *http.Request) {
	if r == nil || r.URL == nil {
		http.Error(w, "404 page not found", http.StatusNotFound)
		return
	}
	if !IsToolbarAssetPath(r.URL.Path) {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", toolbarAssetCacheControl)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.ServeContent(w, r, path.Base(toolbarAssetPath), time.Time{}, bytes.NewReader(toolbarRuntime))
}
