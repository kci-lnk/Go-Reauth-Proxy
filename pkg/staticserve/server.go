package staticserve

import (
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"go-reauth-proxy/pkg/models"
)

const (
	publicFileCacheControl  = "public, max-age=0, must-revalidate"
	privateFileCacheControl = "private, no-store"
	generatedCacheControl   = "private, no-store"
)

type Options struct {
	Private        bool
	ProtectedPaths []string
}

type Server struct {
	readme *readmeRenderer
}

func New() *Server {
	return &Server{readme: newReadmeRenderer()}
}

var defaultServer = New()

func Serve(w http.ResponseWriter, r *http.Request, targetType string, cfg *models.StaticServeConfig, options Options) {
	defaultServer.Serve(w, r, targetType, cfg, options)
}

func (s *Server) Serve(w http.ResponseWriter, r *http.Request, targetType string, cfg *models.StaticServeConfig, options Options) {
	if w == nil || r == nil || r.URL == nil {
		return
	}
	if r.URL.RawPath != "" {
		decodedPath, err := url.PathUnescape(r.URL.RawPath)
		if err != nil || decodedPath != r.URL.Path || hasEncodedPathSeparatorOrControl(r.URL.RawPath) {
			writeError(w, r, http.StatusNotFound, "Not found")
			return
		}
	}
	// Gateway-owned endpoints are resolved before host mappings, but keep the
	// static package fail-closed as a second boundary. This also prevents a
	// future caller from accidentally exposing a user-created /__... file.
	if strings.HasPrefix(r.URL.Path, "/__") {
		writeError(w, r, http.StatusNotFound, "Not found")
		return
	}
	normalizedTargetType := models.NormalizeHostRuleTargetType(targetType)
	if normalizedTargetType == models.HostRuleTargetTypeFile && r.URL.Path != "/" {
		writeError(w, r, http.StatusNotFound, "Not found")
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeError(w, r, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	normalized, err := NormalizeConfig(targetType, cfg, options.ProtectedPaths...)
	if err != nil {
		writeRootUnavailable(w, r)
		return
	}
	resolvedPath, err := resolveConfiguredStaticPath(normalized.Path, options.ProtectedPaths...)
	if err != nil {
		writeRootUnavailable(w, r)
		return
	}
	normalized.Path = resolvedPath

	switch normalizedTargetType {
	case models.HostRuleTargetTypeFile:
		s.serveFileMapping(w, r, normalized, options)
	case models.HostRuleTargetTypeDirectory:
		s.serveDirectoryMapping(w, r, normalized, options)
	default:
		writeRootUnavailable(w, r)
	}
}

func (s *Server) serveFileMapping(w http.ResponseWriter, r *http.Request, cfg *models.StaticServeConfig, options Options) {
	if r.URL.Path != "/" {
		writeError(w, r, http.StatusNotFound, "Not found")
		return
	}

	root, err := openStaticDirectoryRoot(filepath.Dir(cfg.Path), options.ProtectedPaths...)
	if err != nil {
		writeRootUnavailable(w, r)
		return
	}
	defer root.Close()

	file, err := openRootFileForRead(root, filepath.Base(cfg.Path))
	if err != nil {
		writeRootUnavailable(w, r)
		return
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		writeRootUnavailable(w, r)
		return
	}
	serveOpenedFile(w, r, file, info, filepath.Base(cfg.Path), options.Private)
}

func (s *Server) serveDirectoryMapping(w http.ResponseWriter, r *http.Request, cfg *models.StaticServeConfig, options Options) {
	root, err := openStaticDirectoryRoot(cfg.Path, options.ProtectedPaths...)
	if err != nil {
		writeRootUnavailable(w, r)
		return
	}
	defer root.Close()

	name, ok := requestRootName(r.URL.Path)
	if !ok {
		writeError(w, r, http.StatusNotFound, "Not found")
		return
	}
	target, err := openRootFileForRead(root, name)
	if err != nil {
		if name == "." {
			writeRootUnavailable(w, r)
		} else {
			writeError(w, r, http.StatusNotFound, "Not found")
		}
		return
	}
	defer target.Close()
	info, err := target.Stat()
	if err != nil {
		if name == "." {
			writeRootUnavailable(w, r)
		} else {
			writeError(w, r, http.StatusNotFound, "Not found")
		}
		return
	}

	if info.Mode().IsRegular() {
		if strings.HasSuffix(r.URL.Path, "/") {
			redirectCanonicalPath(w, r, strings.TrimSuffix(r.URL.Path, "/"))
			return
		}
		serveOpenedFile(w, r, target, info, path.Base(name), options.Private)
		return
	}
	if !info.IsDir() {
		writeError(w, r, http.StatusNotFound, "Not found")
		return
	}
	if !strings.HasSuffix(r.URL.Path, "/") {
		redirectCanonicalPath(w, r, r.URL.Path+"/")
		return
	}

	for _, indexName := range cfg.IndexFiles {
		indexPath := joinRootName(name, indexName)
		indexFile, openErr := openRootFileForRead(root, indexPath)
		if openErr != nil {
			continue
		}
		indexInfo, statErr := indexFile.Stat()
		if statErr == nil && indexInfo.Mode().IsRegular() {
			serveOpenedFile(w, r, indexFile, indexInfo, indexName, options.Private)
			indexFile.Close()
			return
		}
		indexFile.Close()
	}

	if !cfg.DirectoryListing.Enabled {
		writeError(w, r, http.StatusNotFound, "Not found")
		return
	}
	s.serveDirectoryListing(w, r, root, target, name, cfg)
}

func requestRootName(requestPath string) (string, bool) {
	if requestPath == "" || requestPath[0] != '/' || !strings.HasPrefix(requestPath, "/") {
		return "", false
	}
	if requestPath == "/" {
		return ".", true
	}
	trimmed := strings.TrimSuffix(strings.TrimPrefix(requestPath, "/"), "/")
	if trimmed == "" {
		return "", false
	}
	components := strings.Split(trimmed, "/")
	for _, component := range components {
		if !safeVisibleName(component) {
			return "", false
		}
	}
	return strings.Join(components, "/"), true
}

func joinRootName(directory, name string) string {
	if directory == "." {
		return name
	}
	return directory + "/" + name
}

func serveOpenedFile(w http.ResponseWriter, r *http.Request, file *os.File, info os.FileInfo, displayName string, private bool) {
	contentType := mime.TypeByExtension(strings.ToLower(filepath.Ext(displayName)))
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("ETag", weakFileETag(info))
	if private {
		w.Header().Set("Cache-Control", privateFileCacheControl)
	} else {
		w.Header().Set("Cache-Control", publicFileCacheControl)
	}
	http.ServeContent(w, r, displayName, validFileModTime(info.ModTime()), file)
}

func weakFileETag(info os.FileInfo) string {
	if info == nil {
		return `W/"0-0"`
	}
	return fmt.Sprintf(`W/"%x-%x"`, info.ModTime().UnixNano(), info.Size())
}

func redirectCanonicalPath(w http.ResponseWriter, r *http.Request, requestPath string) {
	next := &url.URL{Path: requestPath, RawQuery: r.URL.RawQuery}
	w.Header().Set("Cache-Control", generatedCacheControl)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.Redirect(w, r, next.RequestURI(), http.StatusMovedPermanently)
}

func writeRootUnavailable(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Retry-After", "5")
	writeError(w, r, http.StatusServiceUnavailable, "Static source unavailable")
}

func writeError(w http.ResponseWriter, r *http.Request, status int, message string) {
	body := message + "\n"
	w.Header().Set("Cache-Control", generatedCacheControl)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	if r == nil || r.Method == http.MethodHead {
		return
	}
	_, _ = io.WriteString(w, body)
}

func validFileModTime(value time.Time) time.Time {
	if value.IsZero() || value.Before(time.Unix(0, 0)) {
		return time.Time{}
	}
	return value
}
