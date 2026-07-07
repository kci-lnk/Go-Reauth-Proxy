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
