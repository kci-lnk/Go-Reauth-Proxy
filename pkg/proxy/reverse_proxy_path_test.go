package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"go-reauth-proxy/pkg/models"
)

func TestBuildReverseProxyRoutePath(t *testing.T) {
	tests := []struct {
		name        string
		targetPath  string
		requestPath string
		stripPath   bool
		pathPrefix  string
		want        string
	}{
		{
			name:        "keeps full request path without target path",
			requestPath: "/api/http/send_group_msg",
			pathPrefix:  "/api/http",
			want:        "/api/http/send_group_msg",
		},
		{
			name:        "strips matched path to target root",
			targetPath:  "/",
			requestPath: "/api/http/send_group_msg",
			stripPath:   true,
			pathPrefix:  "/api/http",
			want:        "/send_group_msg",
		},
		{
			name:        "strips matched path under target base path",
			targetPath:  "/base/",
			requestPath: "/api/http/send_group_msg",
			stripPath:   true,
			pathPrefix:  "/api/http",
			want:        "/base/send_group_msg",
		},
		{
			name:        "keeps full request path under target base path",
			targetPath:  "/base",
			requestPath: "/api/http/send_group_msg",
			pathPrefix:  "/api/http",
			want:        "/base/api/http/send_group_msg",
		},
		{
			name:        "strips exact match to root",
			targetPath:  "/",
			requestPath: "/api/http",
			stripPath:   true,
			pathPrefix:  "/api/http",
			want:        "/",
		},
		{
			name:        "strips exact match under target base path",
			targetPath:  "/base/",
			requestPath: "/api/http",
			stripPath:   true,
			pathPrefix:  "/api/http",
			want:        "/base/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildReverseProxyRoutePath(tt.targetPath, tt.requestPath, tt.stripPath, tt.pathPrefix)
			if got != tt.want {
				t.Fatalf("buildReverseProxyRoutePath() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuildHostReverseProxyEntryPath(t *testing.T) {
	tests := []struct {
		name        string
		targetPath  string
		requestPath string
		want        string
	}{
		{
			name:        "maps root request to exact target entry path",
			targetPath:  "/p",
			requestPath: "/",
			want:        "/p",
		},
		{
			name:        "preserves exact entry path request",
			targetPath:  "/p",
			requestPath: "/p",
			want:        "/p",
		},
		{
			name:        "preserves request below entry path",
			targetPath:  "/p",
			requestPath: "/p/assets/app.js",
			want:        "/p/assets/app.js",
		},
		{
			name:        "preserves explicit target trailing slash for root request",
			targetPath:  "/p/",
			requestPath: "/",
			want:        "/p/",
		},
		{
			name:        "does not prepend entry path to sibling route",
			targetPath:  "/p",
			requestPath: "/photo",
			want:        "/photo",
		},
		{
			name:        "preserves origin login route outside entry path",
			targetPath:  "/p",
			requestPath: "/login",
			want:        "/login",
		},
		{
			name:        "preserves origin assets outside entry path",
			targetPath:  "/p",
			requestPath: "/assets/app.js",
			want:        "/assets/app.js",
		},
		{
			name:        "preserves request path without target path",
			requestPath: "/assets/app.js",
			want:        "/assets/app.js",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildHostReverseProxyEntryPath(tt.targetPath, tt.requestPath)
			if got != tt.want {
				t.Fatalf("buildHostReverseProxyEntryPath() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuildHostReverseProxyPathModes(t *testing.T) {
	tests := []struct {
		name        string
		targetPath  string
		requestPath string
		mode        string
		want        string
	}{
		{
			name:        "entry mode preserves a non-root request",
			targetPath:  "/webdav",
			requestPath: "/floccus/bookmarks.xbel",
			mode:        models.HostTargetPathModeEntry,
			want:        "/floccus/bookmarks.xbel",
		},
		{
			name:        "missing mode remains backward compatible",
			targetPath:  "/webdav",
			requestPath: "/floccus/bookmarks.xbel",
			want:        "/floccus/bookmarks.xbel",
		},
		{
			name:        "prefix mode mounts a non-root request",
			targetPath:  "/webdav",
			requestPath: "/floccus/bookmarks.xbel",
			mode:        models.HostTargetPathModePrefix,
			want:        "/webdav/floccus/bookmarks.xbel",
		},
		{
			name:        "prefix mode preserves the target trailing slash",
			targetPath:  "/webdav/",
			requestPath: "/",
			mode:        models.HostTargetPathModePrefix,
			want:        "/webdav/",
		},
		{
			name:        "prefix mode without a target path is unchanged",
			requestPath: "/floccus/bookmarks.xbel",
			mode:        models.HostTargetPathModePrefix,
			want:        "/floccus/bookmarks.xbel",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildHostReverseProxyPath(tt.targetPath, tt.requestPath, tt.mode)
			if got != tt.want {
				t.Fatalf("buildHostReverseProxyPath() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestApplyHostReverseProxyPathPreservesEscapedResourcePaths(t *testing.T) {
	targetURL, err := url.Parse("http://127.0.0.1:8080/webdav%2Froot")
	if err != nil {
		t.Fatalf("parse target URL: %v", err)
	}
	incomingURL, err := url.Parse("/folder%2Fname/%E6%B5%8B%E8%AF%95%20file.txt")
	if err != nil {
		t.Fatalf("parse incoming URL: %v", err)
	}
	out := &url.URL{}

	applyHostReverseProxyPath(
		out,
		targetURL,
		incomingURL,
		models.HostTargetPathModePrefix,
	)

	if want := "/webdav/root/folder/name/测试 file.txt"; out.Path != want {
		t.Fatalf("Path = %q, want %q", out.Path, want)
	}
	if want := "/webdav%2Froot/folder%2Fname/%E6%B5%8B%E8%AF%95%20file.txt"; out.RawPath != want {
		t.Fatalf("RawPath = %q, want %q", out.RawPath, want)
	}
	if want := "/webdav%2Froot/folder%2Fname/%E6%B5%8B%E8%AF%95%20file.txt"; out.RequestURI() != want {
		t.Fatalf("RequestURI() = %q, want %q", out.RequestURI(), want)
	}

	entryOut := &url.URL{}
	applyHostReverseProxyPath(
		entryOut,
		targetURL,
		incomingURL,
		models.HostTargetPathModeEntry,
	)
	if want := "/folder%2Fname/%E6%B5%8B%E8%AF%95%20file.txt"; entryOut.RequestURI() != want {
		t.Fatalf("entry RequestURI() = %q, want %q", entryOut.RequestURI(), want)
	}

	targetWithEscapedTrailingSlash, err := url.Parse("http://127.0.0.1:8080/webdav%2F")
	if err != nil {
		t.Fatalf("parse target URL with escaped trailing slash: %v", err)
	}
	trailingSlashOut := &url.URL{}
	applyHostReverseProxyPath(
		trailingSlashOut,
		targetWithEscapedTrailingSlash,
		&url.URL{Path: "/file.txt"},
		models.HostTargetPathModePrefix,
	)
	if want := "/webdav%2Ffile.txt"; trailingSlashOut.RequestURI() != want {
		t.Fatalf("escaped trailing slash RequestURI() = %q, want %q", trailingSlashOut.RequestURI(), want)
	}
}

func TestHostRuleTargetPathActsAsEntryPath(t *testing.T) {
	type upstreamRequest struct {
		path    string
		query   string
		referer string
	}
	seen := make(chan upstreamRequest, 3)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- upstreamRequest{
			path:    r.URL.Path,
			query:   r.URL.RawQuery,
			referer: r.Header.Get("Referer"),
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	handler := newHostLocationTestHandler(models.HostRule{
		Host:   "photos.example.com",
		Target: upstream.URL + "/p",
	})

	tests := []struct {
		name        string
		requestURL  string
		referer     string
		wantPath    string
		wantQuery   string
		wantReferer string
	}{
		{
			name:       "root uses target entry path",
			requestURL: "http://photos.example.com/",
			wantPath:   "/p",
		},
		{
			name:       "application resource keeps its emitted path",
			requestURL: "http://photos.example.com/p/assets/app.js?v=1",
			wantPath:   "/p/assets/app.js",
			wantQuery:  "v=1",
		},
		{
			name:        "login route remains at origin root",
			requestURL:  "http://photos.example.com/login?redirect_uri=http%3A%2F%2Fphotos.example.com%2Fp%2F",
			referer:     "http://photos.example.com/p/",
			wantPath:    "/login",
			wantQuery:   "redirect_uri=http%3A%2F%2Fphotos.example.com%2Fp%2F",
			wantReferer: upstream.URL + "/p/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.requestURL, nil)
			if tt.referer != "" {
				req.Header.Set("Referer", tt.referer)
			}
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
			}
			got := <-seen
			if got.path != tt.wantPath {
				t.Fatalf("upstream path = %q, want %q", got.path, tt.wantPath)
			}
			if got.query != tt.wantQuery {
				t.Fatalf("upstream query = %q, want %q", got.query, tt.wantQuery)
			}
			if got.referer != tt.wantReferer {
				t.Fatalf("upstream referer = %q, want %q", got.referer, tt.wantReferer)
			}
		})
	}
}

func TestHostRuleTargetPathPrefixMountsWebDAVRequests(t *testing.T) {
	type upstreamRequest struct {
		method     string
		path       string
		query      string
		requestURI string
		referer    string
	}
	seen := make(chan upstreamRequest, 4)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- upstreamRequest{
			method:     r.Method,
			path:       r.URL.Path,
			query:      r.URL.RawQuery,
			requestURI: r.RequestURI,
			referer:    r.Header.Get("Referer"),
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	handler := newHostLocationTestHandler(models.HostRule{
		Host:           "dav.example.com",
		Target:         upstream.URL + "/webdav",
		TargetPathMode: models.HostTargetPathModePrefix,
	})

	tests := []struct {
		name        string
		method      string
		requestURL  string
		referer     string
		wantPath    string
		wantQuery   string
		wantURI     string
		wantReferer string
	}{
		{
			name:       "WebDAV root is mounted below target path",
			method:     "PROPFIND",
			requestURL: "http://dav.example.com/",
			wantPath:   "/webdav/",
			wantURI:    "/webdav/",
		},
		{
			name:       "WebDAV collection is mounted below target path",
			method:     "MKCOL",
			requestURL: "http://dav.example.com/floccus",
			wantPath:   "/webdav/floccus",
			wantURI:    "/webdav/floccus",
		},
		{
			name:        "WebDAV resource preserves method query and rewritten referer",
			method:      http.MethodPut,
			requestURL:  "http://dav.example.com/floccus/bookmarks.xbel.lock?rev=2",
			referer:     "http://dav.example.com/floccus/",
			wantPath:    "/webdav/floccus/bookmarks.xbel.lock",
			wantQuery:   "rev=2",
			wantURI:     "/webdav/floccus/bookmarks.xbel.lock?rev=2",
			wantReferer: upstream.URL + "/webdav/floccus/",
		},
		{
			name:        "encoded WebDAV resource keeps its escaped slash",
			method:      http.MethodGet,
			requestURL:  "http://dav.example.com/floccus/folder%2Fname.txt",
			referer:     "http://dav.example.com/floccus/folder%2Fname.txt",
			wantPath:    "/webdav/floccus/folder/name.txt",
			wantURI:     "/webdav/floccus/folder%2Fname.txt",
			wantReferer: upstream.URL + "/webdav/floccus/folder%2Fname.txt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.requestURL, nil)
			if tt.referer != "" {
				req.Header.Set("Referer", tt.referer)
			}
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
			}
			got := <-seen
			if got.method != tt.method {
				t.Fatalf("upstream method = %q, want %q", got.method, tt.method)
			}
			if got.path != tt.wantPath {
				t.Fatalf("upstream path = %q, want %q", got.path, tt.wantPath)
			}
			if got.query != tt.wantQuery {
				t.Fatalf("upstream query = %q, want %q", got.query, tt.wantQuery)
			}
			if got.requestURI != tt.wantURI {
				t.Fatalf("upstream RequestURI = %q, want %q", got.requestURI, tt.wantURI)
			}
			if got.referer != tt.wantReferer {
				t.Fatalf("upstream referer = %q, want %q", got.referer, tt.wantReferer)
			}
		})
	}
}

func TestPathRuleProxyStripsMatchedPathToTargetRoot(t *testing.T) {
	var gotPath string
	var gotQuery string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	handler := &Handler{
		Rules: []models.Rule{
			{
				Path:      "/api/http",
				Target:    upstream.URL + "/",
				StripPath: true,
			},
		},
		authCache:      newAuthStateCache(),
		preflightCache: newPreflightStateCache(),
	}
	handler.publishRequestSnapshotLocked()

	req := httptest.NewRequest(http.MethodPost, "http://gateway.test/api/http/send_group_msg?group_id=1", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	if gotPath != "/send_group_msg" {
		t.Fatalf("upstream path = %q, want /send_group_msg", gotPath)
	}
	if gotQuery != "group_id=1" {
		t.Fatalf("upstream query = %q, want group_id=1", gotQuery)
	}
}

func TestHostLocationProxyStripsMatchedPathUnderTargetBasePath(t *testing.T) {
	var gotPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	handler := newHostLocationTestHandler(models.HostRule{
		Host:   "app.example.com",
		Target: "http://127.0.0.1:8080",
		Locations: []models.HostLocation{
			{
				Path:      "/api/http",
				Match:     models.HostLocationMatchPrefix,
				Action:    models.HostLocationActionProxy,
				Target:    upstream.URL + "/base/",
				StripPath: true,
			},
		},
	})

	req := httptest.NewRequest(http.MethodPost, "http://app.example.com/api/http/send_group_msg", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	if gotPath != "/base/send_group_msg" {
		t.Fatalf("upstream path = %q, want /base/send_group_msg", gotPath)
	}
}
