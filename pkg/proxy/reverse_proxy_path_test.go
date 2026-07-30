package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
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
