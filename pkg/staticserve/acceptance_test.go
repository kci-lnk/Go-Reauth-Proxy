package staticserve

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"go-reauth-proxy/pkg/models"
)

func TestFileResponseValidatorsMIMEAndHTMLAreTransparent(t *testing.T) {
	directory := t.TempDir()
	unknownPath := filepath.Join(directory, "download.fnkunknown")
	mustWriteFile(t, unknownPath, "opaque")
	unknown := serveRequest(t, models.HostRuleTargetTypeFile, &models.StaticServeConfig{Path: unknownPath}, http.MethodGet, "/", nil, Options{})
	if unknown.Code != http.StatusOK {
		t.Fatalf("unknown extension status = %d, body=%q", unknown.Code, unknown.Body.String())
	}
	if got := unknown.Header().Get("Content-Type"); got != "application/octet-stream" {
		t.Fatalf("unknown extension Content-Type = %q", got)
	}
	if got := unknown.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("X-Content-Type-Options = %q", got)
	}
	lastModified := unknown.Header().Get("Last-Modified")
	if lastModified == "" {
		t.Fatal("file response omitted Last-Modified")
	}
	conditional := serveRequest(t, models.HostRuleTargetTypeFile, &models.StaticServeConfig{Path: unknownPath}, http.MethodGet, "/", http.Header{
		"If-Modified-Since": []string{lastModified},
	}, Options{})
	if conditional.Code != http.StatusNotModified || conditional.Body.Len() != 0 {
		t.Fatalf("If-Modified-Since response = %d %q", conditional.Code, conditional.Body.String())
	}

	htmlBody := "<!doctype html><html><body><main>user bytes</main></body></html>"
	htmlPath := filepath.Join(directory, "page.html")
	mustWriteFile(t, htmlPath, htmlBody)
	htmlResponse := serveRequest(t, models.HostRuleTargetTypeFile, &models.StaticServeConfig{Path: htmlPath}, http.MethodGet, "/", nil, Options{})
	if htmlResponse.Code != http.StatusOK || htmlResponse.Body.String() != htmlBody {
		t.Fatalf("HTML response = %d %q", htmlResponse.Code, htmlResponse.Body.String())
	}
	if got := htmlResponse.Header().Get("Content-Security-Policy"); got != "" {
		t.Fatalf("user HTML unexpectedly received listing CSP %q", got)
	}
	for _, injected := range []string{"fn-knock-toolbar", "__toolbar__", "<script"} {
		if strings.Contains(htmlResponse.Body.String(), injected) {
			t.Fatalf("user HTML was modified with %q: %s", injected, htmlResponse.Body.String())
		}
	}
}

func TestDirectoryRedirectPreservesQueryAndRootTypeChangesFailClosed(t *testing.T) {
	root := t.TempDir()
	docs := filepath.Join(root, "docs")
	if err := os.Mkdir(docs, 0o755); err != nil {
		t.Fatal(err)
	}
	redirect := serveRequest(t, models.HostRuleTargetTypeDirectory, listingConfig(root, false), http.MethodGet, "/docs?x=1&x=2", nil, Options{})
	if redirect.Code != http.StatusMovedPermanently || redirect.Header().Get("Location") != "/docs/?x=1&x=2" {
		t.Fatalf("redirect = %d Location=%q", redirect.Code, redirect.Header().Get("Location"))
	}

	directoryTarget := filepath.Join(t.TempDir(), "root")
	if err := os.Mkdir(directoryTarget, 0o755); err != nil {
		t.Fatal(err)
	}
	directoryConfig := listingConfig(directoryTarget, false)
	if err := os.Remove(directoryTarget); err != nil {
		t.Fatal(err)
	}
	mustWriteFile(t, directoryTarget, "wrong type")
	wrongDirectory := serveRequest(t, models.HostRuleTargetTypeDirectory, directoryConfig, http.MethodGet, "/", nil, Options{})
	if wrongDirectory.Code != http.StatusServiceUnavailable || strings.Contains(wrongDirectory.Body.String(), directoryTarget) {
		t.Fatalf("changed directory root = %d %q", wrongDirectory.Code, wrongDirectory.Body.String())
	}

	fileParent := t.TempDir()
	fileTarget := filepath.Join(fileParent, "asset.txt")
	mustWriteFile(t, fileTarget, "file")
	fileConfig := &models.StaticServeConfig{Path: fileTarget}
	if err := os.Remove(fileTarget); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(fileTarget, 0o755); err != nil {
		t.Fatal(err)
	}
	wrongFile := serveRequest(t, models.HostRuleTargetTypeFile, fileConfig, http.MethodGet, "/", nil, Options{})
	if wrongFile.Code != http.StatusServiceUnavailable || strings.Contains(wrongFile.Body.String(), fileTarget) {
		t.Fatalf("changed file root = %d %q", wrongFile.Code, wrongFile.Body.String())
	}
}

func TestDirectoryPaginationToleratesMutation(t *testing.T) {
	root := t.TempDir()
	for index := 0; index < DefaultPageSize+25; index++ {
		mustWriteFile(t, filepath.Join(root, "entry-"+formatPaddedIndex(index)+".txt"), "x")
	}
	cfg := listingConfig(root, false)
	first := serveRequest(t, models.HostRuleTargetTypeDirectory, cfg, http.MethodGet, "/", nil, Options{})
	if first.Code != http.StatusOK {
		t.Fatalf("first page = %d %q", first.Code, first.Body.String())
	}
	next := pageLink(t, first.Body.String(), "next")
	if err := os.Remove(filepath.Join(root, "entry-000.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(root, "entry-110.txt"), filepath.Join(root, "entry-050a.txt")); err != nil {
		t.Fatal(err)
	}
	mustWriteFile(t, filepath.Join(root, "entry-999.txt"), "new")
	second := serveRequest(t, models.HostRuleTargetTypeDirectory, cfg, http.MethodGet, next, nil, Options{})
	if second.Code != http.StatusOK {
		t.Fatalf("page after directory mutation = %d %q", second.Code, second.Body.String())
	}
	if strings.Contains(second.Body.String(), root) || !strings.Contains(second.Body.String(), `<table class="listing-table">`) {
		t.Fatalf("mutated page leaked root or was malformed: %s", second.Body.String())
	}
}

func TestReadmeIsResolvedPerDirectoryAndFailuresAreOptional(t *testing.T) {
	root := t.TempDir()
	child := filepath.Join(root, "child")
	if err := os.Mkdir(child, 0o755); err != nil {
		t.Fatal(err)
	}
	mustWriteFile(t, filepath.Join(root, "README.md"), "# Root README\n")
	mustWriteFile(t, filepath.Join(child, "README.md"), "# Child README\n")
	cfg := listingConfig(root, true)
	rootPage := serveRequest(t, models.HostRuleTargetTypeDirectory, cfg, http.MethodGet, "/", nil, Options{})
	if rootPage.Code != http.StatusOK || !strings.Contains(rootPage.Body.String(), "Root README") || strings.Contains(rootPage.Body.String(), "Child README") {
		t.Fatalf("root README selection = %d %q", rootPage.Code, rootPage.Body.String())
	}
	childPage := serveRequest(t, models.HostRuleTargetTypeDirectory, cfg, http.MethodGet, "/child/", nil, Options{})
	if childPage.Code != http.StatusOK || !strings.Contains(childPage.Body.String(), "Child README") || strings.Contains(childPage.Body.String(), "Root README") {
		t.Fatalf("child README selection = %d %q", childPage.Code, childPage.Body.String())
	}

	readmePath := filepath.Join(child, "README.md")
	if err := os.Chmod(readmePath, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(readmePath, 0o644) })
	optional := serveRequest(t, models.HostRuleTargetTypeDirectory, cfg, http.MethodGet, "/child/", nil, Options{})
	if optional.Code != http.StatusOK {
		t.Fatalf("unreadable README broke listing: %d %q", optional.Code, optional.Body.String())
	}
	if runtime.GOOS != "windows" && os.Geteuid() != 0 && strings.Contains(optional.Body.String(), "Child README") {
		t.Fatal("unreadable README was unexpectedly rendered")
	}
}

func formatPaddedIndex(index int) string {
	return fmt.Sprintf("%03d", index)
}
