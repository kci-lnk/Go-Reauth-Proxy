package staticserve

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"go-reauth-proxy/pkg/models"
)

// These tests deliberately exercise the HTTP-facing boundary instead of only
// testing path helpers. They are regressions for traversal families commonly
// catalogued under CWE-22/CWE-23/CWE-35 and for symlink race variants of
// CWE-59. A response is never allowed to contain outsideMarker.
func TestSecurityTraversalPayloadsOverHTTP(t *testing.T) {
	workspace := t.TempDir()
	rootPath := filepath.Join(workspace, "public")
	if err := os.Mkdir(rootPath, 0o755); err != nil {
		t.Fatal(err)
	}
	const outsideMarker = "OUTSIDE-STATIC-ROOT-SECRET"
	mustWriteFile(t, filepath.Join(workspace, "outside.txt"), outsideMarker)
	mustWriteFile(t, filepath.Join(rootPath, "safe.txt"), "safe")

	server := newStaticSecurityHTTPServer(t, rootPath, false)
	client := server.Client()
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}

	payloads := []string{
		"/../outside.txt",
		"/%2e%2e/outside.txt",
		"/%2E%2e/%2e%2E/outside.txt",
		"/%2e%2e%2foutside.txt",
		"/%2e%2e%5coutside.txt",
		"/%252e%252e/outside.txt",
		"/%252e%252e%252foutside.txt",
		"/safe/%2e%2e/%2e%2e/outside.txt",
		"//../outside.txt",
		"/safe\\..\\outside.txt",
		"/safe%5c..%5coutside.txt",
		"/%00outside.txt",
		"/%2500outside.txt",
		"/%c0%ae%c0%ae/outside.txt",
		"/%ff/outside.txt",
	}
	for _, payload := range payloads {
		t.Run(url.PathEscape(payload), func(t *testing.T) {
			response, err := client.Get(server.URL + payload)
			if err != nil {
				t.Fatalf("GET %q: %v", payload, err)
			}
			body := readSecurityResponse(t, response)
			if response.StatusCode != http.StatusNotFound {
				t.Fatalf("GET %q = %d, want 404; body=%q", payload, response.StatusCode, body)
			}
			assertNoStaticSecretLeak(t, response, body, workspace, outsideMarker)
		})
	}
}

// CVE-2026-55677 covers encoded slash/backslash routing inconsistencies. The
// static boundary must validate net/http's once-decoded URL.Path and must not
// apply a second percent-unescape before opening a rooted name.
func TestCVE202655677EncodedSeparatorsAreDecodedExactlyOnce(t *testing.T) {
	workspace := t.TempDir()
	rootPath := filepath.Join(workspace, "public")
	if err := os.Mkdir(rootPath, 0o755); err != nil {
		t.Fatal(err)
	}
	const outsideMarker = "CVE-2026-55677-OUTSIDE"
	mustWriteFile(t, filepath.Join(workspace, "outside.txt"), outsideMarker)
	mustWriteFile(t, filepath.Join(rootPath, "encoded%2Fname.txt"), "literal-percent-slash")
	mustWriteFile(t, filepath.Join(rootPath, "encoded%5Cname.txt"), "literal-percent-backslash")
	if err := os.Mkdir(filepath.Join(rootPath, "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	mustWriteFile(t, filepath.Join(rootPath, "nested", "exists.txt"), "must-not-cross-encoded-separator")

	server := newStaticSecurityHTTPServer(t, rootPath, false)
	client := server.Client()
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }

	blocked := []string{
		"/safe%2F..%2F..%2Foutside.txt",
		"/safe%5C..%5C..%5Coutside.txt",
		"/%2F..%2Foutside.txt",
		"/%5C..%5Coutside.txt",
		"/encoded%2Fname.txt",
		"/encoded%5Cname.txt",
		"/nested%2Fexists.txt",
	}
	for _, requestPath := range blocked {
		response, err := client.Get(server.URL + requestPath)
		if err != nil {
			t.Fatalf("GET %q: %v", requestPath, err)
		}
		body := readSecurityResponse(t, response)
		if response.StatusCode != http.StatusNotFound {
			t.Errorf("GET %q = %d %q, want 404", requestPath, response.StatusCode, body)
		}
		assertNoStaticSecretLeak(t, response, body, outsideMarker, workspace)
	}

	allowedLiteralNames := map[string]string{
		"/encoded%252Fname.txt": "literal-percent-slash",
		"/encoded%255Cname.txt": "literal-percent-backslash",
	}
	for requestPath, wantBody := range allowedLiteralNames {
		response, err := client.Get(server.URL + requestPath)
		if err != nil {
			t.Fatalf("GET %q: %v", requestPath, err)
		}
		body := readSecurityResponse(t, response)
		if response.StatusCode != http.StatusOK || body != wantBody {
			t.Errorf("GET %q = %d %q, want once-decoded literal file %q", requestPath, response.StatusCode, body, wantBody)
		}
	}
}

// CVE-2026-39822 is a regression guard for an os.Root escape involving a
// final symlink plus a trailing slash. Even if the link points to a directory,
// neither the link itself nor a child beneath it may escape the configured root.
func TestCVE202639822FinalSymlinkWithTrailingSlashCannotEscapeRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation normally requires elevated privileges on Windows")
	}
	workspace := t.TempDir()
	rootPath := filepath.Join(workspace, "public")
	outsidePath := filepath.Join(workspace, "outside")
	if err := os.Mkdir(rootPath, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(outsidePath, 0o755); err != nil {
		t.Fatal(err)
	}
	const outsideMarker = "CVE-2026-39822-OUTSIDE"
	mustWriteFile(t, filepath.Join(outsidePath, "secret.txt"), outsideMarker)
	if err := os.Symlink("../outside", filepath.Join(rootPath, "link")); err != nil {
		t.Fatal(err)
	}
	cfg := listingConfig(rootPath, false)
	for _, requestPath := range []string{"/link/", "/link/secret.txt"} {
		response := serveRequest(t, models.HostRuleTargetTypeDirectory, cfg, http.MethodGet, requestPath, nil, Options{})
		if response.Code != http.StatusNotFound || strings.Contains(response.Body.String(), outsideMarker) {
			t.Errorf("GET %q = %d %q, want non-leaking 404", requestPath, response.Code, response.Body.String())
		}
	}
}

func TestSecurityDoubleSlashPathCannotCreateSchemeRelativeRedirect(t *testing.T) {
	rootPath := t.TempDir()
	if err := os.Mkdir(filepath.Join(rootPath, "dir"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, requestPath := range []string{"//dir", "///dir", "//evil.example"} {
		response := serveRequest(t, models.HostRuleTargetTypeDirectory, listingConfig(rootPath, false), http.MethodGet, requestPath, nil, Options{})
		if response.Code >= 300 && response.Code < 400 {
			t.Fatalf("GET %q produced unsafe redirect %d Location=%q", requestPath, response.Code, response.Header().Get("Location"))
		}
		if location := response.Header().Get("Location"); strings.HasPrefix(location, "//") {
			t.Fatalf("GET %q produced scheme-relative Location %q", requestPath, location)
		}
	}
}

func TestSecurityGatewayInternalNamespaceIsNeverServed(t *testing.T) {
	rootPath := t.TempDir()
	for _, name := range []string{"__select__", "__auth__", "__assets__", "__custom"} {
		if err := os.Mkdir(filepath.Join(rootPath, name), 0o755); err != nil {
			t.Fatal(err)
		}
		mustWriteFile(t, filepath.Join(rootPath, name, "secret.txt"), "must-not-be-static")
	}
	cfg := listingConfig(rootPath, false)
	for _, requestPath := range []string{
		"/__select__/secret.txt",
		"/__auth__/secret.txt",
		"/__assets__/secret.txt",
		"/__custom/secret.txt",
		"/%5f%5fauth%5f%5f/secret.txt",
	} {
		response := serveRequest(t, models.HostRuleTargetTypeDirectory, cfg, http.MethodGet, requestPath, nil, Options{})
		if response.Code != http.StatusNotFound || strings.Contains(response.Body.String(), "must-not-be-static") {
			t.Errorf("GET %q = %d %q, want fail-closed 404", requestPath, response.Code, response.Body.String())
		}
	}
	listing := serveRequest(t, models.HostRuleTargetTypeDirectory, cfg, http.MethodGet, "/", nil, Options{})
	if listing.Code != http.StatusOK {
		t.Fatalf("root listing = %d %q", listing.Code, listing.Body.String())
	}
	if strings.Contains(listing.Body.String(), "__auth__") || strings.Contains(listing.Body.String(), "__assets__") {
		t.Fatal("gateway-internal namespace was exposed in directory listing")
	}
}

func TestSecurityURLRawPathCannotOverrideValidatedPath(t *testing.T) {
	workspace := t.TempDir()
	rootPath := filepath.Join(workspace, "public")
	if err := os.Mkdir(rootPath, 0o755); err != nil {
		t.Fatal(err)
	}
	const outsideMarker = "RAWPATH-OUTSIDE-SECRET"
	mustWriteFile(t, filepath.Join(workspace, "outside.txt"), outsideMarker)
	mustWriteFile(t, filepath.Join(rootPath, "safe.txt"), "safe")

	cases := []struct {
		name       string
		path       string
		rawPath    string
		wantStatus int
		wantBody   string
	}{
		{
			name:       "mismatched malicious RawPath fails closed",
			path:       "/safe.txt",
			rawPath:    "/%2e%2e/outside.txt",
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "valid encoded RawPath for safe Path",
			path:       "/safe.txt",
			rawPath:    "/%73afe.txt",
			wantStatus: http.StatusOK,
			wantBody:   "safe",
		},
		{
			name:       "safe RawPath cannot disguise traversing Path",
			path:       "/../outside.txt",
			rawPath:    "/safe.txt",
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "safe RawPath cannot disguise hidden Path",
			path:       "/.secret",
			rawPath:    "/safe.txt",
			wantStatus: http.StatusNotFound,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "http://static.example/", nil)
			request.URL.Path = testCase.path
			request.URL.RawPath = testCase.rawPath
			request.RequestURI = testCase.rawPath
			recorder := httptest.NewRecorder()
			Serve(recorder, request, models.HostRuleTargetTypeDirectory, listingConfig(rootPath, false), Options{})
			if recorder.Code != testCase.wantStatus || (testCase.wantBody != "" && recorder.Body.String() != testCase.wantBody) {
				t.Fatalf("response = %d %q, want %d %q", recorder.Code, recorder.Body.String(), testCase.wantStatus, testCase.wantBody)
			}
			if strings.Contains(recorder.Body.String(), outsideMarker) {
				t.Fatal("RawPath request escaped static root")
			}
		})
	}
}

func TestSecurityDotItemsBlockedThroughDirectEncodedAndSymlinkPaths(t *testing.T) {
	rootPath := t.TempDir()
	mustWriteFile(t, filepath.Join(rootPath, ".env"), "hidden-env")
	if err := os.MkdirAll(filepath.Join(rootPath, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	mustWriteFile(t, filepath.Join(rootPath, ".git", "config"), "hidden-git-config")
	if err := os.MkdirAll(filepath.Join(rootPath, "visible", ".nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	mustWriteFile(t, filepath.Join(rootPath, "visible", ".nested", "secret.txt"), "nested-hidden")

	for linkName, target := range map[string]string{
		"env-alias":      ".env",
		"git-alias":      ".git",
		"hidden-chain-1": "hidden-chain-2",
		"hidden-chain-2": ".env",
	} {
		if err := os.Symlink(target, filepath.Join(rootPath, linkName)); err != nil {
			if runtime.GOOS == "windows" {
				t.Skipf("symlink unavailable: %v", err)
			}
			t.Fatal(err)
		}
	}

	cfg := listingConfig(rootPath, false)
	paths := []string{
		"/.env",
		"/%2eenv",
		"/.git/config",
		"/%2egit/config",
		"/visible/.nested/secret.txt",
		"/visible/%2enested/secret.txt",
		"/env-alias",
		"/git-alias/config",
		"/hidden-chain-1",
	}
	for _, requestPath := range paths {
		response := serveRequest(t, models.HostRuleTargetTypeDirectory, cfg, http.MethodGet, requestPath, nil, Options{})
		if response.Code != http.StatusNotFound {
			t.Errorf("GET %q = %d %q, want 404", requestPath, response.Code, response.Body.String())
		}
	}

	for _, requestPath := range []string{"/", "/visible/"} {
		response := serveRequest(t, models.HostRuleTargetTypeDirectory, cfg, http.MethodGet, requestPath, nil, Options{})
		body := response.Body.String()
		for _, forbidden := range []string{".env", ".git", ".nested", "env-alias", "git-alias", "hidden-chain"} {
			if strings.Contains(body, forbidden) {
				t.Errorf("listing %q exposed hidden item or alias %q: %s", requestPath, forbidden, body)
			}
		}
	}
}

func TestSecurityVisibleRootContainedSymlinksRemainAccessible(t *testing.T) {
	rootPath := t.TempDir()
	if err := os.Mkdir(filepath.Join(rootPath, "content"), 0o755); err != nil {
		t.Fatal(err)
	}
	mustWriteFile(t, filepath.Join(rootPath, "content", "file.txt"), "visible-symlink-body")
	for name, target := range map[string]string{
		"file-alias":      "content/file.txt",
		"directory-alias": "content",
		"chain-1":         "chain-2",
		"chain-2":         "content/file.txt",
	} {
		if err := os.Symlink(target, filepath.Join(rootPath, name)); err != nil {
			if runtime.GOOS == "windows" {
				t.Skipf("symlink unavailable: %v", err)
			}
			t.Fatal(err)
		}
	}
	cfg := listingConfig(rootPath, false)
	for _, requestPath := range []string{"/file-alias", "/directory-alias/file.txt", "/chain-1"} {
		response := serveRequest(t, models.HostRuleTargetTypeDirectory, cfg, http.MethodGet, requestPath, nil, Options{})
		if response.Code != http.StatusOK || response.Body.String() != "visible-symlink-body" {
			t.Errorf("GET %q = %d %q, want accessible contained symlink", requestPath, response.Code, response.Body.String())
		}
	}
	listing := serveRequest(t, models.HostRuleTargetTypeDirectory, cfg, http.MethodGet, "/", nil, Options{})
	for _, expected := range []string{"file-alias", "directory-alias", "chain-1"} {
		if !strings.Contains(listing.Body.String(), expected) {
			t.Errorf("root-contained symlink %q missing from listing", expected)
		}
	}
}

func TestSecurityIndexSymlinkCannotAliasHiddenFile(t *testing.T) {
	rootPath := t.TempDir()
	mustWriteFile(t, filepath.Join(rootPath, ".secret-index"), "hidden-index-body")
	if err := os.Symlink(".secret-index", filepath.Join(rootPath, "index.html")); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlink unavailable: %v", err)
		}
		t.Fatal(err)
	}
	cfg := &models.StaticServeConfig{Path: rootPath, IndexFiles: []string{"index.html"}}
	response := serveRequest(t, models.HostRuleTargetTypeDirectory, cfg, http.MethodGet, "/", nil, Options{})
	if response.Code != http.StatusNotFound || strings.Contains(response.Body.String(), "hidden-index-body") {
		t.Fatalf("hidden index alias = %d %q, want 404", response.Code, response.Body.String())
	}
}

func TestSecurityVisibleIndexSymlinkRemainsAccessible(t *testing.T) {
	rootPath := t.TempDir()
	mustWriteFile(t, filepath.Join(rootPath, "home.html"), "visible-index-body")
	if err := os.Symlink("home.html", filepath.Join(rootPath, "index.html")); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlink unavailable: %v", err)
		}
		t.Fatal(err)
	}
	cfg := &models.StaticServeConfig{Path: rootPath, IndexFiles: []string{"index.html"}}
	response := serveRequest(t, models.HostRuleTargetTypeDirectory, cfg, http.MethodGet, "/", nil, Options{})
	if response.Code != http.StatusOK || response.Body.String() != "visible-index-body" {
		t.Fatalf("visible index alias = %d %q", response.Code, response.Body.String())
	}
}

func TestSecuritySymlinkVisibilityForReadmeAndFileMapping(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation normally requires elevated privileges on Windows")
	}
	t.Run("README visible target renders", func(t *testing.T) {
		rootPath := t.TempDir()
		mustWriteFile(t, filepath.Join(rootPath, "VISIBLE.md"), "# Visible README marker\n")
		if err := os.Symlink("VISIBLE.md", filepath.Join(rootPath, "README.md")); err != nil {
			t.Fatal(err)
		}
		response := serveRequest(t, models.HostRuleTargetTypeDirectory, listingConfig(rootPath, true), http.MethodGet, "/", nil, Options{})
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Visible README marker") {
			t.Fatalf("visible README alias = %d %q", response.Code, response.Body.String())
		}
	})
	t.Run("README hidden target is omitted", func(t *testing.T) {
		rootPath := t.TempDir()
		mustWriteFile(t, filepath.Join(rootPath, ".hidden-readme"), "# HIDDEN-README-SECRET\n")
		if err := os.Symlink(".hidden-readme", filepath.Join(rootPath, "README.md")); err != nil {
			t.Fatal(err)
		}
		response := serveRequest(t, models.HostRuleTargetTypeDirectory, listingConfig(rootPath, true), http.MethodGet, "/", nil, Options{})
		if response.Code != http.StatusOK || strings.Contains(response.Body.String(), "HIDDEN-README-SECRET") {
			t.Fatalf("hidden README alias = %d %q", response.Code, response.Body.String())
		}
	})
	t.Run("file mapping visible target serves", func(t *testing.T) {
		rootPath := t.TempDir()
		visible := filepath.Join(rootPath, "visible.txt")
		alias := filepath.Join(rootPath, "alias.txt")
		mustWriteFile(t, visible, "visible-file-body")
		if err := os.Symlink("visible.txt", alias); err != nil {
			t.Fatal(err)
		}
		response := serveRequest(t, models.HostRuleTargetTypeFile, &models.StaticServeConfig{Path: alias}, http.MethodGet, "/", nil, Options{})
		if response.Code != http.StatusOK || response.Body.String() != "visible-file-body" {
			t.Fatalf("visible file alias = %d %q", response.Code, response.Body.String())
		}
	})
	t.Run("file mapping hidden target is unavailable", func(t *testing.T) {
		rootPath := t.TempDir()
		hidden := filepath.Join(rootPath, ".hidden.txt")
		alias := filepath.Join(rootPath, "alias.txt")
		mustWriteFile(t, hidden, "HIDDEN-FILE-MAPPING-SECRET")
		if err := os.Symlink(".hidden.txt", alias); err != nil {
			t.Fatal(err)
		}
		response := serveRequest(t, models.HostRuleTargetTypeFile, &models.StaticServeConfig{Path: alias}, http.MethodGet, "/", nil, Options{})
		if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), "HIDDEN-FILE-MAPPING-SECRET") {
			t.Fatalf("hidden file alias = %d %q", response.Code, response.Body.String())
		}
	})
}

func TestSecurityMultilevelSymlinkResolutionStaysInsideRoot(t *testing.T) {
	workspace := t.TempDir()
	rootPath := filepath.Join(workspace, "public")
	outsidePath := filepath.Join(workspace, "outside")
	if err := os.MkdirAll(filepath.Join(rootPath, "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(outsidePath, 0o755); err != nil {
		t.Fatal(err)
	}
	mustWriteFile(t, filepath.Join(rootPath, "nested", "inside.txt"), "inside")
	mustWriteFile(t, filepath.Join(outsidePath, "secret.txt"), "outside-secret")

	links := map[string]string{
		"inside-level-1":  "inside-level-2",
		"inside-level-2":  "nested/inside.txt",
		"escape-file":     "../outside/secret.txt",
		"escape-dir":      "../outside",
		"escape-chain-1":  "escape-chain-2",
		"escape-chain-2":  "../outside/secret.txt",
		"absolute-inside": filepath.Join(rootPath, "nested", "inside.txt"),
		"cycle-a":         "cycle-b",
		"cycle-b":         "cycle-a",
	}
	for name, target := range links {
		if err := os.Symlink(target, filepath.Join(rootPath, name)); err != nil {
			if runtime.GOOS == "windows" {
				t.Skipf("symlink unavailable: %v", err)
			}
			t.Fatal(err)
		}
	}

	cfg := listingConfig(rootPath, false)
	inside := serveRequest(t, models.HostRuleTargetTypeDirectory, cfg, http.MethodGet, "/inside-level-1", nil, Options{})
	if inside.Code != http.StatusOK || inside.Body.String() != "inside" {
		t.Fatalf("contained symlink chain = %d %q", inside.Code, inside.Body.String())
	}
	for _, requestPath := range []string{
		"/escape-file",
		"/escape-dir/secret.txt",
		"/escape-chain-1",
		"/absolute-inside",
		"/cycle-a",
	} {
		response := serveRequest(t, models.HostRuleTargetTypeDirectory, cfg, http.MethodGet, requestPath, nil, Options{})
		if response.Code != http.StatusNotFound || strings.Contains(response.Body.String(), "outside-secret") {
			t.Errorf("GET %q = %d %q, want non-leaking 404", requestPath, response.Code, response.Body.String())
		}
	}
	listing := serveRequest(t, models.HostRuleTargetTypeDirectory, cfg, http.MethodGet, "/", nil, Options{})
	for _, forbidden := range []string{"escape-file", "escape-dir", "escape-chain-1", "absolute-inside", "cycle-a"} {
		if strings.Contains(listing.Body.String(), forbidden) {
			t.Errorf("listing exposed invalid symlink %q", forbidden)
		}
	}
}

func TestSecuritySymlinkSwapRaceNeverEscapesRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation normally requires elevated privileges on Windows")
	}
	workspace := t.TempDir()
	rootPath := filepath.Join(workspace, "public")
	outsidePath := filepath.Join(workspace, "outside")
	if err := os.Mkdir(rootPath, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(outsidePath, 0o755); err != nil {
		t.Fatal(err)
	}
	mustWriteFile(t, filepath.Join(rootPath, "inside.txt"), "inside")
	const outsideMarker = "SYMLINK-RACE-OUTSIDE-SECRET"
	mustWriteFile(t, filepath.Join(outsidePath, "secret.txt"), outsideMarker)
	linkPath := filepath.Join(rootPath, "flip")
	if err := os.Symlink("inside.txt", linkPath); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	workerDone := make(chan struct{})
	var ready sync.WaitGroup
	ready.Add(1)
	go func() {
		defer close(workerDone)
		ready.Done()
		for iteration := 0; ; iteration++ {
			select {
			case <-ctx.Done():
				return
			default:
			}
			target := "inside.txt"
			if iteration%2 == 1 {
				target = "../outside/secret.txt"
			}
			staging := filepath.Join(rootPath, fmt.Sprintf(".flip-stage-%d", iteration%2))
			_ = os.Remove(staging)
			if err := os.Symlink(target, staging); err != nil {
				errCh <- err
				return
			}
			if err := os.Rename(staging, linkPath); err != nil {
				errCh <- err
				return
			}
		}
	}()
	ready.Wait()

	cfg := &models.StaticServeConfig{Path: rootPath}
	for iteration := 0; iteration < 1000; iteration++ {
		response := serveRequest(t, models.HostRuleTargetTypeDirectory, cfg, http.MethodGet, "/flip", nil, Options{})
		if strings.Contains(response.Body.String(), outsideMarker) {
			cancel()
			t.Fatalf("iteration %d escaped root: %d %q", iteration, response.Code, response.Body.String())
		}
		if response.Code != http.StatusOK && response.Code != http.StatusNotFound {
			cancel()
			t.Fatalf("iteration %d returned unexpected status %d", iteration, response.Code)
		}
	}
	cancel()
	select {
	case err := <-errCh:
		t.Fatal(err)
	case <-workerDone:
	case <-time.After(time.Second):
		t.Fatal("symlink swap worker did not stop")
	}
}

func TestSecuritySymlinkSwapRaceNeverExposesHiddenTarget(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation normally requires elevated privileges on Windows")
	}
	rootPath := t.TempDir()
	mustWriteFile(t, filepath.Join(rootPath, "inside.txt"), "inside")
	const hiddenMarker = "SYMLINK-RACE-HIDDEN-SECRET"
	mustWriteFile(t, filepath.Join(rootPath, ".hidden.txt"), hiddenMarker)
	linkPath := filepath.Join(rootPath, "flip")
	if err := os.Symlink("inside.txt", linkPath); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	workerDone := make(chan struct{})
	go func() {
		defer close(workerDone)
		for iteration := 0; ; iteration++ {
			select {
			case <-ctx.Done():
				return
			default:
			}
			target := "inside.txt"
			if iteration%2 == 1 {
				target = ".hidden.txt"
			}
			staging := filepath.Join(rootPath, fmt.Sprintf(".hidden-flip-stage-%d", iteration%2))
			_ = os.Remove(staging)
			if err := os.Symlink(target, staging); err != nil {
				errCh <- err
				return
			}
			if err := os.Rename(staging, linkPath); err != nil {
				errCh <- err
				return
			}
		}
	}()

	cfg := &models.StaticServeConfig{Path: rootPath}
	for iteration := 0; iteration < 1000; iteration++ {
		response := serveRequest(t, models.HostRuleTargetTypeDirectory, cfg, http.MethodGet, "/flip", nil, Options{})
		if strings.Contains(response.Body.String(), hiddenMarker) {
			cancel()
			t.Fatalf("iteration %d exposed hidden target: %d %q", iteration, response.Code, response.Body.String())
		}
		if response.Code != http.StatusOK && response.Code != http.StatusNotFound {
			cancel()
			t.Fatalf("iteration %d returned unexpected status %d", iteration, response.Code)
		}
	}
	cancel()
	select {
	case err := <-errCh:
		t.Fatal(err)
	case <-workerDone:
	case <-time.After(time.Second):
		t.Fatal("hidden symlink swap worker did not stop")
	}
}

func TestSecurityMaliciousFilenamesAreEscapedOrHidden(t *testing.T) {
	rootPath := t.TempDir()
	visibleAttackName := `"><img src=x onerror=alert(1)>.txt`
	hiddenNames := []string{
		"line\nbreak.txt",
		"tab\tbreak.txt",
		"bidi-\u202ehtml.txt",
		"zero-\u200bwidth.txt",
	}
	if runtime.GOOS == "windows" {
		// Win32 rejects markup delimiters and ASCII control characters before
		// the listing code sees them. Keep coverage for HTML escaping and
		// Unicode format-character filtering with valid NTFS names.
		visibleAttackName = "visible&markup.txt"
		hiddenNames = hiddenNames[2:]
	}
	mustWriteFile(t, filepath.Join(rootPath, visibleAttackName), "safe-file-body")
	for _, hiddenName := range hiddenNames {
		mustWriteFile(t, filepath.Join(rootPath, hiddenName), "control-name")
	}

	cfg := listingConfig(rootPath, false)
	listing := serveRequest(t, models.HostRuleTargetTypeDirectory, cfg, http.MethodGet, "/", nil, Options{})
	if listing.Code != http.StatusOK {
		t.Fatalf("listing = %d %q", listing.Code, listing.Body.String())
	}
	body := listing.Body.String()
	if runtime.GOOS == "windows" {
		if strings.Contains(body, visibleAttackName) || !strings.Contains(body, "visible&amp;markup.txt") {
			t.Fatalf("render-sensitive filename was not escaped: %s", body)
		}
	} else {
		if strings.Contains(body, `<img src=x`) || strings.Contains(body, `href=\"\"><img`) {
			t.Fatalf("malicious filename became markup: %s", body)
		}
		if !strings.Contains(body, "&lt;img") {
			t.Fatalf("escaped malicious filename missing: %s", body)
		}
	}
	for _, forbidden := range []string{"line\nbreak", "tab\tbreak", "\u202e", "\u200b"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("control/format filename %q was listed", forbidden)
		}
	}

	requestPath := "/" + url.PathEscape(visibleAttackName)
	fileResponse := serveRequest(t, models.HostRuleTargetTypeDirectory, cfg, http.MethodGet, requestPath, nil, Options{})
	if fileResponse.Code != http.StatusOK || fileResponse.Body.String() != "safe-file-body" {
		t.Fatalf("escaped safe filename = %d %q", fileResponse.Code, fileResponse.Body.String())
	}
	for _, unsafePath := range []string{"/line%0abreak.txt", "/tab%09break.txt", "/bidi-%E2%80%AEhtml.txt", "/zero-%E2%80%8Bwidth.txt"} {
		response := serveRequest(t, models.HostRuleTargetTypeDirectory, cfg, http.MethodGet, unsafePath, nil, Options{})
		if response.Code != http.StatusNotFound {
			t.Errorf("unsafe filename %q = %d, want 404", unsafePath, response.Code)
		}
	}
}

func TestSecurityReadmeXSSAndExternalResourcesAreRemoved(t *testing.T) {
	rootPath := t.TempDir()
	readme := `# Security

<script>alert(1)</script>
<iframe src="https://evil.example/frame"></iframe>
<form action="https://evil.example/submit"><input autofocus onfocus="alert(1)"></form>
<svg><a xlink:href="javascript:alert(1)"><text>bad</text></a></svg>

![http](http://evil.example/a.png)
![https](https://evil.example/a.png)
![protocol-relative](//evil.example/a.png)
![data](data:image/svg+xml;base64,PHN2Zz4=)
![javascript](javascript:alert(1))
![file](file:///etc/passwd)
![backslash](\\evil.example\a.png)
![encoded-slashes](%2f%2fevil.example%2fa.png)
![encoded-backslashes](%5c%5cevil.example%5ca.png)
![encoded-control](images%0aevil.example.png)
![local](./images/local.png?version=1#fragment)
![root](/assets/local.png)

[external](https://example.com/)
[javascript](javascript:alert(1))
<a href="https://example.com" onclick="alert(1)">raw link</a>
`
	mustWriteFile(t, filepath.Join(rootPath, "README.md"), readme)
	response := serveRequest(t, models.HostRuleTargetTypeDirectory, listingConfig(rootPath, true), http.MethodGet, "/", nil, Options{})
	if response.Code != http.StatusOK {
		t.Fatalf("listing = %d %q", response.Code, response.Body.String())
	}
	body := strings.ToLower(renderedReadmeHTML(response.Body.String()))
	for _, forbidden := range []string{
		"<script", "<iframe", "<form", "<input", "<svg", "onfocus", "onclick", "xlink:",
		"evil.example", "data:image", "javascript:", "file:///", "srcset=",
	} {
		if strings.Contains(body, forbidden) {
			t.Errorf("README output contains forbidden %q: %s", forbidden, body)
		}
	}
	for _, allowed := range []string{`src="./images/local.png?version=1#fragment"`, `src="/assets/local.png"`} {
		if !strings.Contains(body, allowed) {
			t.Errorf("README lost allowed same-origin image %q: %s", allowed, body)
		}
	}
	if !strings.Contains(body, `rel="nofollow noopener noreferrer"`) {
		t.Errorf("README external link lacks mandatory rel: %s", body)
	}
	if got := response.Header().Get("Content-Security-Policy"); got != listingPageCSP || strings.Contains(got, "data:") || strings.Contains(got, "http:") {
		t.Errorf("unsafe README CSP %q", got)
	}
}

func TestSecurityInvalidOrOversizedReadmeIsOmitted(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		content []byte
	}{
		{name: "invalid UTF-8", content: []byte{'#', ' ', 0xff, 0xfe}},
		{name: "over one MiB", content: []byte("# " + strings.Repeat("a", MaxReadmeBytes))},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			rootPath := t.TempDir()
			if err := os.WriteFile(filepath.Join(rootPath, "README.md"), testCase.content, 0o644); err != nil {
				t.Fatal(err)
			}
			response := serveRequest(t, models.HostRuleTargetTypeDirectory, listingConfig(rootPath, true), http.MethodGet, "/", nil, Options{})
			if response.Code != http.StatusOK {
				t.Fatalf("listing = %d %q", response.Code, response.Body.String())
			}
			if strings.Contains(response.Body.String(), `<article class="readme"`) {
				t.Fatalf("invalid README was rendered")
			}
		})
	}
}

func TestSecurityErrorsNeverDiscloseFilesystemPaths(t *testing.T) {
	workspace := t.TempDir()
	rootPath := filepath.Join(workspace, "sensitive-static-path")
	missingFile := filepath.Join(rootPath, "missing-secret-file.txt")
	configurations := []struct {
		name       string
		targetType string
		cfg        *models.StaticServeConfig
		path       string
		options    Options
	}{
		{name: "missing directory root", targetType: models.HostRuleTargetTypeDirectory, cfg: &models.StaticServeConfig{Path: rootPath}, path: "/"},
		{name: "missing file root", targetType: models.HostRuleTargetTypeFile, cfg: &models.StaticServeConfig{Path: missingFile}, path: "/"},
		{name: "protected configured root", targetType: models.HostRuleTargetTypeDirectory, cfg: &models.StaticServeConfig{Path: rootPath}, path: "/", options: Options{ProtectedPaths: []string{rootPath}}},
	}
	for _, testCase := range configurations {
		t.Run(testCase.name, func(t *testing.T) {
			response := serveRequest(t, testCase.targetType, testCase.cfg, http.MethodGet, testCase.path, nil, testCase.options)
			if response.Code != http.StatusServiceUnavailable {
				t.Fatalf("response = %d %q, want 503", response.Code, response.Body.String())
			}
			assertRecorderDoesNotContain(t, response, workspace, rootPath, missingFile, filepath.Base(rootPath), filepath.Base(missingFile))
		})
	}

	existing := t.TempDir()
	response := serveRequest(t, models.HostRuleTargetTypeDirectory, listingConfig(existing, false), http.MethodGet, "/missing-file.txt", nil, Options{})
	if response.Code != http.StatusNotFound {
		t.Fatalf("missing child = %d %q", response.Code, response.Body.String())
	}
	assertRecorderDoesNotContain(t, response, existing, "missing-file.txt")
}

func TestSecurityCanceledHTTPRequestStopsListingWithoutResponse(t *testing.T) {
	rootPath := t.TempDir()
	for index := 0; index < 128; index++ {
		mustWriteFile(t, filepath.Join(rootPath, fmt.Sprintf("file-%03d.txt", index)), "x")
	}
	request := httptest.NewRequest(http.MethodGet, "http://static.example/", nil)
	ctx, cancel := context.WithCancel(request.Context())
	cancel()
	request = request.WithContext(ctx)
	recorder := httptest.NewRecorder()
	Serve(recorder, request, models.HostRuleTargetTypeDirectory, listingConfig(rootPath, false), Options{})
	if recorder.Body.Len() != 0 || len(recorder.Header()) != 0 {
		t.Fatalf("canceled request wrote response: headers=%v body=%q", recorder.Header(), recorder.Body.String())
	}
}

func TestSecurityDirectoryScanLimitFailsClosedAtBoundary(t *testing.T) {
	rootPath := t.TempDir()
	for index := 0; index < 4; index++ {
		mustWriteFile(t, filepath.Join(rootPath, fmt.Sprintf("file-%d.txt", index)), "x")
	}
	openDirectory := func(t *testing.T, path string) (*os.Root, *os.File) {
		t.Helper()
		root, err := os.OpenRoot(path)
		if err != nil {
			t.Fatal(err)
		}
		directory, err := openRootFileForRead(root, ".")
		if err != nil {
			_ = root.Close()
			t.Fatal(err)
		}
		return root, directory
	}

	root, directory := openDirectory(t, rootPath)
	_, _, _, err := scanDirectoryPageWithLimits(context.Background(), root, directory, ".", nil, 3, 10)
	_ = directory.Close()
	_ = root.Close()
	if !errors.Is(err, errDirectoryTooLarge) {
		t.Fatalf("raw scan beyond limit error = %v, want errDirectoryTooLarge", err)
	}

	root, directory = openDirectory(t, rootPath)
	_, _, _, err = scanDirectoryPageWithLimits(context.Background(), root, directory, ".", nil, 10, 3)
	_ = directory.Close()
	_ = root.Close()
	if !errors.Is(err, errDirectoryTooLarge) {
		t.Fatalf("visible scan beyond limit error = %v, want errDirectoryTooLarge", err)
	}

	root, directory = openDirectory(t, rootPath)
	candidates, _, _, err := scanDirectoryPageWithLimits(context.Background(), root, directory, ".", nil, 4, 4)
	_ = directory.Close()
	_ = root.Close()
	if err != nil || len(candidates) != 4 {
		t.Fatalf("scan at exact raw and visible limits = %d candidates, err=%v", len(candidates), err)
	}

	filteredRoot := t.TempDir()
	for index := 0; index < 3; index++ {
		mustWriteFile(t, filepath.Join(filteredRoot, fmt.Sprintf(".hidden-%d", index)), "x")
	}
	mustWriteFile(t, filepath.Join(filteredRoot, "visible.txt"), "x")
	root, directory = openDirectory(t, filteredRoot)
	_, _, _, err = scanDirectoryPageWithLimits(context.Background(), root, directory, ".", nil, 3, 10)
	_ = directory.Close()
	_ = root.Close()
	if !errors.Is(err, errDirectoryTooLarge) {
		t.Fatalf("filtered entries bypassed raw scan limit: err=%v", err)
	}

	root, directory = openDirectory(t, filteredRoot)
	candidates, _, _, err = scanDirectoryPageWithLimits(context.Background(), root, directory, ".", nil, 4, 1)
	_ = directory.Close()
	_ = root.Close()
	if err != nil || len(candidates) != 1 || candidates[0].key.name != "visible.txt" {
		t.Fatalf("filtered scan at exact limits = %#v, err=%v", candidates, err)
	}

	if MaxDirectoryScannedEntries != 1_000_000 || MaxDirectoryVisibleEntries != 1_000_000 {
		t.Fatalf("production scan limits = raw %d, visible %d; want 1,000,000 each", MaxDirectoryScannedEntries, MaxDirectoryVisibleEntries)
	}
}

func TestSecurityInvalidCursorPayloadsAreRejected(t *testing.T) {
	rootPath := t.TempDir()
	mustWriteFile(t, filepath.Join(rootPath, "visible.txt"), "x")
	malformedPayloads := []string{
		"not-base64!",
		strings.Repeat("A", 513),
		base64.RawURLEncoding.EncodeToString([]byte{2, 0, 'x'}),
		base64.RawURLEncoding.EncodeToString([]byte{0, 2, 'x'}),
		base64.RawURLEncoding.EncodeToString([]byte{0, 0, '.', '.'}),
		base64.RawURLEncoding.EncodeToString([]byte{0, 0, '.', 'h', 'i', 'd', 'd', 'e', 'n'}),
		base64.RawURLEncoding.EncodeToString(append([]byte{0, 0}, []byte("bad/name")...)),
		base64.RawURLEncoding.EncodeToString(append([]byte{0, 0}, []byte("bad\\name")...)),
		base64.RawURLEncoding.EncodeToString(append([]byte{0, 0}, 0xff)),
	}
	for _, cursor := range malformedPayloads {
		response := serveRequest(t, models.HostRuleTargetTypeDirectory, listingConfig(rootPath, false), http.MethodGet, "/?cursor="+url.QueryEscape(cursor), nil, Options{})
		if response.Code != http.StatusBadRequest || response.Body.String() != "Invalid directory cursor\n" {
			t.Errorf("cursor %q = %d %q, want 400", cursor, response.Code, response.Body.String())
		}
	}
	for _, rawQuery := range []string{
		"cursor=%zz",
		"cursor",
		"cursor=",
		"cursor=&cursor=",
		"cursor=QQ&cursor=Qg",
	} {
		response := serveRequest(t, models.HostRuleTargetTypeDirectory, listingConfig(rootPath, false), http.MethodGet, "/?"+rawQuery, nil, Options{})
		if response.Code != http.StatusBadRequest || response.Body.String() != "Invalid directory cursor\n" {
			t.Errorf("raw query %q = %d %q, want 400", rawQuery, response.Code, response.Body.String())
		}
	}
}

func newStaticSecurityHTTPServer(t *testing.T, rootPath string, renderReadme bool) *httptest.Server {
	t.Helper()
	cfg := listingConfig(rootPath, renderReadme)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		Serve(w, r, models.HostRuleTargetTypeDirectory, cfg, Options{})
	}))
	t.Cleanup(server.Close)
	return server
}

func readSecurityResponse(t *testing.T, response *http.Response) string {
	t.Helper()
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func assertNoStaticSecretLeak(t *testing.T, response *http.Response, body string, values ...string) {
	t.Helper()
	for _, value := range values {
		if value == "" {
			continue
		}
		if strings.Contains(body, value) {
			t.Errorf("response body disclosed %q: %q", value, body)
		}
		for name, headerValues := range response.Header {
			for _, headerValue := range headerValues {
				if strings.Contains(headerValue, value) {
					t.Errorf("response header %s disclosed %q: %q", name, value, headerValue)
				}
			}
		}
	}
}

func assertRecorderDoesNotContain(t *testing.T, response *httptest.ResponseRecorder, values ...string) {
	t.Helper()
	for _, value := range values {
		if value == "" {
			continue
		}
		if strings.Contains(response.Body.String(), value) {
			t.Errorf("response body disclosed %q: %q", value, response.Body.String())
		}
		for name, headerValues := range response.Header() {
			for _, headerValue := range headerValues {
				if strings.Contains(headerValue, value) {
					t.Errorf("response header %s disclosed %q: %q", name, value, headerValue)
				}
			}
		}
	}
}
