package staticserve

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"go-reauth-proxy/pkg/models"
)

func FuzzStaticDirectoryNeverEscapesRoot(f *testing.F) {
	workspace := f.TempDir()
	rootPath := filepath.Join(workspace, "public")
	outsidePath := filepath.Join(workspace, "outside")
	if err := os.Mkdir(rootPath, 0o755); err != nil {
		f.Fatal(err)
	}
	if err := os.Mkdir(outsidePath, 0o755); err != nil {
		f.Fatal(err)
	}
	const outsideMarker = "FUZZ-OUTSIDE-STATIC-ROOT-SECRET"
	if err := os.WriteFile(filepath.Join(outsidePath, "secret.txt"), []byte(outsideMarker), 0o600); err != nil {
		f.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootPath, "safe.txt"), []byte("safe"), 0o600); err != nil {
		f.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Symlink("../outside", filepath.Join(rootPath, "escape")); err != nil {
			f.Fatal(err)
		}
	}

	for _, seed := range []string{
		"/safe.txt", "/../outside/secret.txt", "/%2e%2e/outside/secret.txt",
		"/escape/secret.txt", "/%2F..%2Foutside", "/%5C..%5Coutside",
		"//escape/secret.txt", "/.hidden", "/%00", "/%252e%252e/outside/secret.txt",
	} {
		f.Add(seed)
	}
	cfg := &models.StaticServeConfig{Path: rootPath, DirectoryListing: models.StaticDirectoryListingConfig{Enabled: true}}
	f.Fuzz(func(t *testing.T, requestTarget string) {
		if len(requestTarget) == 0 || len(requestTarget) > 2048 || !strings.HasPrefix(requestTarget, "/") {
			return
		}
		parsed, err := url.ParseRequestURI(requestTarget)
		if err != nil || parsed.Path == "" {
			return
		}
		request := httptest.NewRequest(http.MethodGet, "http://static.example/", nil)
		request.URL.Path = parsed.Path
		request.URL.RawPath = parsed.RawPath
		request.URL.RawQuery = parsed.RawQuery
		request.RequestURI = requestTarget
		recorder := httptest.NewRecorder()
		Serve(recorder, request, models.HostRuleTargetTypeDirectory, cfg, Options{})
		if strings.Contains(recorder.Body.String(), outsideMarker) {
			t.Fatalf("request target %q escaped static root: status=%d body=%q", requestTarget, recorder.Code, recorder.Body.String())
		}
		for name, values := range recorder.Header() {
			for _, value := range values {
				if strings.Contains(value, workspace) || strings.Contains(value, outsideMarker) {
					t.Fatalf("request target %q leaked filesystem data in %s: %q", requestTarget, name, value)
				}
			}
		}
	})
}

func FuzzRequestRootNameIsAlwaysLocalAndVisible(f *testing.F) {
	for _, seed := range []string{"/", "/index.html", "/a/b/", "/../x", "//x", "/.git/config", "/a\\b", "/a\x00b"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, requestPath string) {
		if len(requestPath) > 4096 {
			return
		}
		name, ok := requestRootName(requestPath)
		if !ok {
			return
		}
		if name == "." {
			if requestPath != "/" {
				t.Fatalf("requestRootName(%q) accepted root as %q", requestPath, name)
			}
			return
		}
		if !visibleRootRelativeName(name) || filepath.IsAbs(filepath.FromSlash(name)) {
			t.Fatalf("requestRootName(%q) returned unsafe name %q", requestPath, name)
		}
		for _, component := range strings.Split(name, "/") {
			if !safeVisibleName(component) {
				t.Fatalf("requestRootName(%q) returned unsafe component %q", requestPath, component)
			}
		}
	})
}
