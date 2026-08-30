package staticserve

import (
	"context"
	"errors"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"go-reauth-proxy/pkg/models"
)

func TestSingleFileMappingHTTPBehavior(t *testing.T) {
	directory := t.TempDir()
	filePath := filepath.Join(directory, "asset.txt")
	content := "0123456789"
	mustWriteFile(t, filePath, content)
	cfg := &models.StaticServeConfig{Path: filePath}

	get := serveRequest(t, models.HostRuleTargetTypeFile, cfg, http.MethodGet, "/", nil, Options{})
	if get.Code != http.StatusOK || get.Body.String() != content {
		t.Fatalf("GET = %d %q, want 200 %q", get.Code, get.Body.String(), content)
	}
	if got := get.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/plain") {
		t.Fatalf("Content-Type = %q, want text/plain", got)
	}
	if got := get.Header().Get("Cache-Control"); got != publicFileCacheControl {
		t.Fatalf("Cache-Control = %q", got)
	}
	if got := get.Header().Get("ETag"); !strings.HasPrefix(got, `W/"`) {
		t.Fatalf("ETag = %q, want weak validator", got)
	}

	head := serveRequest(t, models.HostRuleTargetTypeFile, cfg, http.MethodHead, "/", nil, Options{})
	if head.Code != http.StatusOK || head.Body.Len() != 0 {
		t.Fatalf("HEAD = %d body=%q", head.Code, head.Body.String())
	}
	if head.Header().Get("Content-Length") != strconv.Itoa(len(content)) {
		t.Fatalf("HEAD Content-Length = %q", head.Header().Get("Content-Length"))
	}

	rangeHeaders := http.Header{"Range": []string{"bytes=2-5"}}
	partial := serveRequest(t, models.HostRuleTargetTypeFile, cfg, http.MethodGet, "/", rangeHeaders, Options{})
	if partial.Code != http.StatusPartialContent || partial.Body.String() != "2345" {
		t.Fatalf("range = %d %q", partial.Code, partial.Body.String())
	}
	if partial.Header().Get("Content-Range") != "bytes 2-5/10" {
		t.Fatalf("Content-Range = %q", partial.Header().Get("Content-Range"))
	}

	conditional := serveRequest(t, models.HostRuleTargetTypeFile, cfg, http.MethodGet, "/", http.Header{
		"If-None-Match": []string{get.Header().Get("ETag")},
	}, Options{})
	if conditional.Code != http.StatusNotModified || conditional.Body.Len() != 0 {
		t.Fatalf("conditional = %d %q", conditional.Code, conditional.Body.String())
	}

	notFound := serveRequest(t, models.HostRuleTargetTypeFile, cfg, http.MethodGet, "/anything", nil, Options{})
	if notFound.Code != http.StatusNotFound {
		t.Fatalf("non-root file request = %d, want 404", notFound.Code)
	}
	method := serveRequest(t, models.HostRuleTargetTypeFile, cfg, http.MethodPost, "/", nil, Options{})
	if method.Code != http.StatusMethodNotAllowed || method.Header().Get("Allow") != "GET, HEAD" {
		t.Fatalf("POST = %d Allow=%q", method.Code, method.Header().Get("Allow"))
	}
	nonRootMethod := serveRequest(t, models.HostRuleTargetTypeFile, cfg, http.MethodPost, "/anything", nil, Options{})
	if nonRootMethod.Code != http.StatusNotFound || nonRootMethod.Header().Get("Allow") != "" {
		t.Fatalf("POST non-root = %d Allow=%q, want 404 without Allow", nonRootMethod.Code, nonRootMethod.Header().Get("Allow"))
	}

	private := serveRequest(t, models.HostRuleTargetTypeFile, cfg, http.MethodGet, "/", nil, Options{Private: true})
	if private.Header().Get("Cache-Control") != privateFileCacheControl {
		t.Fatalf("private Cache-Control = %q", private.Header().Get("Cache-Control"))
	}
}

func TestDirectoryRedirectIndexAndListingDisabled(t *testing.T) {
	directory := t.TempDir()
	mustWriteFile(t, filepath.Join(directory, "index.html"), "first")
	mustWriteFile(t, filepath.Join(directory, "index.htm"), "second")
	if err := os.Mkdir(filepath.Join(directory, "docs"), 0o755); err != nil {
		t.Fatal(err)
	}
	mustWriteFile(t, filepath.Join(directory, "docs", "index.htm"), "docs")
	cfg := &models.StaticServeConfig{
		Path:       directory,
		IndexFiles: []string{"index.htm", "index.html"},
	}

	redirect := serveRequest(t, models.HostRuleTargetTypeDirectory, cfg, http.MethodGet, "/docs", nil, Options{})
	if redirect.Code != http.StatusMovedPermanently || redirect.Header().Get("Location") != "/docs/" {
		t.Fatalf("redirect = %d Location=%q", redirect.Code, redirect.Header().Get("Location"))
	}
	index := serveRequest(t, models.HostRuleTargetTypeDirectory, cfg, http.MethodGet, "/", nil, Options{})
	if index.Code != http.StatusOK || index.Body.String() != "second" {
		t.Fatalf("ordered index = %d %q", index.Code, index.Body.String())
	}

	withoutIndex := t.TempDir()
	mustWriteFile(t, filepath.Join(withoutIndex, "visible.txt"), "body")
	disabled := serveRequest(t, models.HostRuleTargetTypeDirectory, &models.StaticServeConfig{Path: withoutIndex}, http.MethodGet, "/", nil, Options{})
	if disabled.Code != http.StatusNotFound {
		t.Fatalf("listing disabled = %d, want 404", disabled.Code)
	}
}

func TestDirectoryListingSortEscapingAndHeaders(t *testing.T) {
	directory := t.TempDir()
	for _, name := range []string{"zDir", "ADir"} {
		if err := os.Mkdir(filepath.Join(directory, name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"b.txt", "a.txt", "Z.txt", `.hidden`, "evil\"><script>.txt", "a?#%.txt"} {
		mustWriteFile(t, filepath.Join(directory, name), name)
	}
	cfg := listingConfig(directory, false)
	response := serveRequest(t, models.HostRuleTargetTypeDirectory, cfg, http.MethodGet, "/", nil, Options{})
	if response.Code != http.StatusOK {
		t.Fatalf("listing = %d %q", response.Code, response.Body.String())
	}
	body := response.Body.String()
	assertOrdered(t, body, ">ADir/</a>", ">zDir/</a>", ">a.txt</a>", ">a?#%.txt</a>", ">b.txt</a>", ">Z.txt</a>")
	if strings.Contains(body, `>.hidden</a>`) || strings.Contains(body, `evil"><script>.txt`) {
		t.Fatalf("unsafe/hidden filename leaked into listing: %s", body)
	}
	if !strings.Contains(body, "evil&#34;&gt;&lt;script&gt;.txt") {
		t.Fatalf("escaped filename missing: %s", body)
	}
	if !strings.Contains(body, "a%3F%23%25.txt") {
		t.Fatalf("URL-escaped filename missing: %s", body)
	}
	if got := response.Header().Get("Content-Security-Policy"); got != listingPageCSP || strings.Contains(got, "data:") {
		t.Fatalf("CSP = %q", got)
	}
	if response.Header().Get("Cache-Control") != generatedCacheControl {
		t.Fatalf("listing cache = %q", response.Header().Get("Cache-Control"))
	}

	head := serveRequest(t, models.HostRuleTargetTypeDirectory, cfg, http.MethodHead, "/", nil, Options{})
	if head.Code != http.StatusOK || head.Body.Len() != 0 || head.Header().Get("Content-Length") == "" {
		t.Fatalf("listing HEAD = %d body=%q length=%q", head.Code, head.Body.String(), head.Header().Get("Content-Length"))
	}
}

func TestDirectoryListingBidirectionalCursorAndReadmeOnEveryPage(t *testing.T) {
	directory := t.TempDir()
	for index := 0; index < 205; index++ {
		mustWriteFile(t, filepath.Join(directory, "file-"+strconv.Itoa(1000+index)+".txt"), "x")
	}
	mustWriteFile(t, filepath.Join(directory, "README.md"), "# Repeated README\n")
	cfg := listingConfig(directory, true)

	first := serveRequest(t, models.HostRuleTargetTypeDirectory, cfg, http.MethodGet, "/", nil, Options{})
	firstBody := first.Body.String()
	if strings.Contains(firstBody, "Previous page") || !strings.Contains(firstBody, "Next page") || !strings.Contains(firstBody, "Repeated README") {
		t.Fatalf("unexpected first page navigation/README")
	}
	next := pageLink(t, firstBody, "next")
	second := serveRequest(t, models.HostRuleTargetTypeDirectory, cfg, http.MethodGet, next, nil, Options{})
	secondBody := second.Body.String()
	if !strings.Contains(secondBody, "Previous page") || !strings.Contains(secondBody, "Next page") || !strings.Contains(secondBody, "Repeated README") {
		t.Fatalf("unexpected second page navigation/README")
	}
	previous := pageLink(t, secondBody, "prev")
	back := serveRequest(t, models.HostRuleTargetTypeDirectory, cfg, http.MethodGet, previous, nil, Options{})
	if strings.Contains(back.Body.String(), "Previous page") || !strings.Contains(back.Body.String(), "file-1000.txt") {
		t.Fatalf("previous cursor did not return to first page")
	}

	third := serveRequest(t, models.HostRuleTargetTypeDirectory, cfg, http.MethodGet, pageLink(t, secondBody, "next"), nil, Options{})
	if !strings.Contains(third.Body.String(), "Previous page") || strings.Contains(third.Body.String(), "Next page") || !strings.Contains(third.Body.String(), "Repeated README") {
		t.Fatalf("unexpected final page navigation/README")
	}
}

func TestDotTraversalAndRootedSymlinks(t *testing.T) {
	directory := t.TempDir()
	mustWriteFile(t, filepath.Join(directory, ".secret"), "hidden")
	inside := filepath.Join(directory, "inside")
	if err := os.Mkdir(inside, 0o755); err != nil {
		t.Fatal(err)
	}
	mustWriteFile(t, filepath.Join(inside, "ok.txt"), "inside")
	outsideDir := t.TempDir()
	mustWriteFile(t, filepath.Join(outsideDir, "outside.txt"), "outside")
	if err := os.Symlink("inside/ok.txt", filepath.Join(directory, "inside-link.txt")); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlink unavailable: %v", err)
		}
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outsideDir, "outside.txt"), filepath.Join(directory, "outside-link.txt")); err != nil {
		t.Fatal(err)
	}
	cfg := listingConfig(directory, false)

	insideResponse := serveRequest(t, models.HostRuleTargetTypeDirectory, cfg, http.MethodGet, "/inside-link.txt", nil, Options{})
	if insideResponse.Code != http.StatusOK || insideResponse.Body.String() != "inside" {
		t.Fatalf("root-contained symlink = %d %q", insideResponse.Code, insideResponse.Body.String())
	}
	for _, requestPath := range []string{"/.secret", "/../outside.txt", "/%2e%2e/outside.txt", `/inside\\ok.txt`, "/outside-link.txt"} {
		response := serveRequest(t, models.HostRuleTargetTypeDirectory, cfg, http.MethodGet, requestPath, nil, Options{})
		if response.Code != http.StatusNotFound {
			t.Fatalf("request %q = %d, want 404", requestPath, response.Code)
		}
	}
	listing := serveRequest(t, models.HostRuleTargetTypeDirectory, cfg, http.MethodGet, "/", nil, Options{})
	if strings.Contains(listing.Body.String(), ".secret") || strings.Contains(listing.Body.String(), "outside-link") {
		t.Fatalf("hidden or escaping symlink was listed")
	}
}

func TestReadmeSanitizationAndSameOriginImages(t *testing.T) {
	directory := t.TempDir()
	readme := `# Safe title

<script>alert(1)</script>

![local](images/logo.png)
![root](/assets/logo.png)
![internal](/__auth__/api/auth/logout)
![nested-internal](images/__private/track.png)
![encoded-internal](/%5f%5fauth__/api/auth/logout)
![external](https://evil.example/track.png)
![protocol-relative](//evil.example/track.png)
![data](data:image/png;base64,AAAA)

[external link](https://example.com)
[bad link](javascript:alert(1))

<img src="x" onerror="alert(1)">
`
	mustWriteFile(t, filepath.Join(directory, "README.md"), readme)
	cfg := listingConfig(directory, true)
	response := serveRequest(t, models.HostRuleTargetTypeDirectory, cfg, http.MethodGet, "/", nil, Options{})
	body := renderedReadmeHTML(response.Body.String())
	for _, forbidden := range []string{"<script", "onerror", "evil.example/track", "data:image", "javascript:"} {
		if strings.Contains(strings.ToLower(body), strings.ToLower(forbidden)) {
			t.Fatalf("README contains forbidden %q: %s", forbidden, body)
		}
	}
	if !strings.Contains(body, `src="images/logo.png"`) || !strings.Contains(body, `src="/assets/logo.png"`) {
		t.Fatalf("same-origin README images missing: %s", body)
	}
	for _, forbiddenSource := range []string{"/__auth__/api/auth/logout", "images/__private/track.png", "/%5f%5fauth__/api/auth/logout"} {
		if strings.Contains(strings.ToLower(body), strings.ToLower(forbiddenSource)) {
			t.Fatalf("README internal image source survived %q: %s", forbiddenSource, body)
		}
	}
	if !strings.Contains(body, `rel="nofollow noopener noreferrer"`) {
		t.Fatalf("external link safety relation missing: %s", body)
	}
}

func TestRootUnavailableAndChildNotFound(t *testing.T) {
	directory := t.TempDir()
	cfg := listingConfig(directory, false)
	if err := os.Remove(directory); err != nil {
		t.Fatal(err)
	}
	root := serveRequest(t, models.HostRuleTargetTypeDirectory, cfg, http.MethodGet, "/", nil, Options{})
	if root.Code != http.StatusServiceUnavailable || root.Header().Get("Retry-After") == "" {
		t.Fatalf("lost root = %d Retry-After=%q", root.Code, root.Header().Get("Retry-After"))
	}

	existing := t.TempDir()
	child := serveRequest(t, models.HostRuleTargetTypeDirectory, listingConfig(existing, false), http.MethodGet, "/missing.txt", nil, Options{})
	if child.Code != http.StatusNotFound {
		t.Fatalf("missing child = %d, want 404", child.Code)
	}
	missingFile := serveRequest(t, models.HostRuleTargetTypeFile, &models.StaticServeConfig{Path: filepath.Join(existing, "missing.txt")}, http.MethodGet, "/", nil, Options{})
	if missingFile.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing single file = %d, want 503", missingFile.Code)
	}
}

func TestProbePathAndProtectedPaths(t *testing.T) {
	directory := t.TempDir()
	filePath := filepath.Join(directory, "file.txt")
	mustWriteFile(t, filePath, "ok")

	fileProbe := ProbePath(models.HostRuleTargetTypeFile, filePath)
	if !fileProbe.Exists || !fileProbe.Readable || fileProbe.ActualType != models.HostRuleTargetTypeFile || fileProbe.NormalizedPath != filepath.Clean(filePath) || fileProbe.ErrorCode != "" {
		t.Fatalf("file probe = %#v", fileProbe)
	}
	mismatch := ProbePath(models.HostRuleTargetTypeDirectory, filePath)
	if !mismatch.Exists || mismatch.ErrorCode != ProbeErrorTypeMismatch || mismatch.ActualType != models.HostRuleTargetTypeFile {
		t.Fatalf("mismatch probe = %#v", mismatch)
	}
	missing := ProbePath(models.HostRuleTargetTypeFile, filepath.Join(directory, "missing.txt"))
	if missing.Exists || missing.ErrorCode != ProbeErrorNotFound {
		t.Fatalf("missing probe = %#v", missing)
	}
	protected := ProbePath(models.HostRuleTargetTypeDirectory, directory, filepath.Join(directory, "runtime"))
	if protected.ErrorCode != ProbeErrorProtectedPath {
		t.Fatalf("protected ancestor probe = %#v", protected)
	}
}

func TestNormalizeStaticConfigBoundaries(t *testing.T) {
	root := t.TempDir()
	hidden := filepath.Join(root, ".secret")
	if _, err := NormalizeConfig(models.HostRuleTargetTypeDirectory, &models.StaticServeConfig{Path: hidden}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("hidden directory error = %v", err)
	}
	if _, err := NormalizeConfig(models.HostRuleTargetTypeDirectory, &models.StaticServeConfig{Path: string(filepath.Separator)}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("filesystem root error = %v", err)
	}
	emptyIndexes, err := NormalizeConfig(models.HostRuleTargetTypeDirectory, &models.StaticServeConfig{Path: root})
	if err != nil || len(emptyIndexes.IndexFiles) != 0 {
		t.Fatalf("empty index list normalized to %#v, err=%v", emptyIndexes, err)
	}
	tooLong := strings.Repeat("a", 256)
	if _, err := NormalizeConfig(models.HostRuleTargetTypeDirectory, &models.StaticServeConfig{Path: root, IndexFiles: []string{tooLong}}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("long index error = %v", err)
	}
	tooMany := make([]string, MaxIndexFiles+1)
	for index := range tooMany {
		tooMany[index] = "index-" + strconv.Itoa(index) + ".html"
	}
	if _, err := NormalizeConfig(models.HostRuleTargetTypeDirectory, &models.StaticServeConfig{Path: root, IndexFiles: tooMany}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("too many indexes error = %v", err)
	}
}

func TestDirectoryScanHonorsCancellation(t *testing.T) {
	directoryPath := t.TempDir()
	mustWriteFile(t, filepath.Join(directoryPath, "file.txt"), "x")
	root, err := os.OpenRoot(directoryPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	directory, err := root.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, _, err = scanDirectoryPage(ctx, root, directory, ".", nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("scan error = %v, want context.Canceled", err)
	}
}

func listingConfig(path string, renderReadme bool) *models.StaticServeConfig {
	return &models.StaticServeConfig{
		Path: path,
		DirectoryListing: models.StaticDirectoryListingConfig{
			Enabled:      true,
			RenderReadme: renderReadme,
		},
	}
}

func serveRequest(t *testing.T, targetType string, cfg *models.StaticServeConfig, method, requestPath string, headers http.Header, options Options) *httptest.ResponseRecorder {
	t.Helper()
	requestURL := "http://static.example" + requestPath
	request := httptest.NewRequest(method, requestURL, nil)
	for name, values := range headers {
		for _, value := range values {
			request.Header.Add(name, value)
		}
	}
	recorder := httptest.NewRecorder()
	Serve(recorder, request, targetType, cfg, options)
	return recorder
}

func mustWriteFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, time.Unix(1_700_000_000, 0), time.Unix(1_700_000_000, 0)); err != nil {
		t.Fatal(err)
	}
}

func assertOrdered(t *testing.T, body string, values ...string) {
	t.Helper()
	position := -1
	for _, value := range values {
		next := strings.Index(body, value)
		if next < 0 || next <= position {
			t.Fatalf("%q is missing or out of order in %s", value, body)
		}
		position = next
	}
}

func pageLink(t *testing.T, body, relation string) string {
	t.Helper()
	pattern := regexp.MustCompile(`rel="` + regexp.QuoteMeta(relation) + `" href="([^"]+)"`)
	match := pattern.FindStringSubmatch(body)
	if len(match) != 2 {
		t.Fatalf("%s link missing", relation)
	}
	value := html.UnescapeString(match[1])
	parsed, err := url.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	return "/" + "?" + parsed.RawQuery
}

func renderedReadmeHTML(body string) string {
	start := strings.Index(body, `<article class="readme"`)
	if start < 0 {
		return ""
	}
	end := strings.Index(body[start:], `</article>`)
	if end < 0 {
		return body[start:]
	}
	return body[start : start+end+len(`</article>`)]
}
