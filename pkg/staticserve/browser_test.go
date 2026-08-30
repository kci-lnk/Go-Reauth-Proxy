package staticserve

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"go-reauth-proxy/pkg/models"
)

func TestBrowsePathFiltersUnsafeEntriesAndAppliesProtectedPathStates(t *testing.T) {
	root := t.TempDir()
	mustMakeBrowseDir(t, filepath.Join(root, "safe"))
	mustWriteBrowseFile(t, filepath.Join(root, "asset.txt"), "asset")
	mustMakeBrowseDir(t, filepath.Join(root, ".hidden"))
	internalPath := filepath.Join(root, "__internal")
	mustMakeBrowseDir(t, filepath.Join(internalPath, "private-child"))
	protectedParent := filepath.Join(root, "vault-parent")
	protectedPath := filepath.Join(protectedParent, "secret")
	mustMakeBrowseDir(t, protectedPath)

	safeLinkCreated := false
	if err := os.Symlink("safe", filepath.Join(root, "safe-link")); err != nil {
		if !errors.Is(err, os.ErrPermission) {
			t.Fatal(err)
		}
	} else {
		safeLinkCreated = true
	}
	outside := t.TempDir()
	_ = os.Symlink(outside, filepath.Join(root, "outside-link"))
	_ = os.Symlink(filepath.Join("vault-parent", "secret"), filepath.Join(root, "protected-link"))
	_ = os.Symlink(".hidden", filepath.Join(root, "hidden-link"))
	internalLinkCreated := false
	if err := os.Symlink("__internal", filepath.Join(root, "internal-link")); err != nil {
		if !errors.Is(err, os.ErrPermission) {
			t.Fatal(err)
		}
	} else {
		internalLinkCreated = true
	}

	result := BrowsePath(context.Background(), models.HostRuleTargetTypeDirectory, root, "", protectedPath)
	if result.ErrorCode != "" {
		t.Fatalf("BrowsePath() error = %q", result.ErrorCode)
	}
	if result.CurrentPath == nil || *result.CurrentPath != filepath.Clean(root) {
		t.Fatalf("current path = %#v, want %q", result.CurrentPath, filepath.Clean(root))
	}
	if result.CurrentSelectable {
		t.Fatal("a strict ancestor of a protected path must not be selectable")
	}
	if result.SelectedPath != nil || result.Platform != browsePlatform() {
		t.Fatalf("unexpected selected path/platform: %#v %q", result.SelectedPath, result.Platform)
	}
	if len(result.Breadcrumbs) == 0 || result.Breadcrumbs[0].Name != string(filepath.Separator) || result.Breadcrumbs[len(result.Breadcrumbs)-1].Path != filepath.Clean(root) {
		t.Fatalf("breadcrumbs = %#v", result.Breadcrumbs)
	}

	entries := browseEntriesByName(result.Entries)
	if _, ok := entries[".hidden"]; ok {
		t.Fatal("hidden directory was exposed")
	}
	if _, ok := entries["__internal"]; ok {
		t.Fatal("internal directory was exposed")
	}
	for _, hidden := range []string{"outside-link", "protected-link", "hidden-link", "internal-link"} {
		if _, ok := entries[hidden]; ok {
			t.Errorf("unsafe symlink %q was exposed", hidden)
		}
	}
	if safe := entries["safe"]; !safe.Navigable || !safe.Selectable || safe.EntryType != models.HostRuleTargetTypeDirectory {
		t.Errorf("safe directory = %#v", safe)
	}
	if file := entries["asset.txt"]; file.Navigable || file.Selectable || file.EntryType != models.HostRuleTargetTypeFile || file.SizeBytes == nil || *file.SizeBytes != 5 || file.ModifiedAt == nil {
		t.Errorf("directory-mode file = %#v", file)
	}
	if ancestor := entries["vault-parent"]; !ancestor.Navigable || ancestor.Selectable || ancestor.EntryType != models.HostRuleTargetTypeDirectory {
		t.Errorf("protected ancestor = %#v", ancestor)
	}
	if safeLinkCreated {
		safeLink, ok := entries["safe-link"]
		if !ok || !safeLink.Navigable || !safeLink.Selectable {
			t.Errorf("safe in-tree symlink = %#v, present = %v", safeLink, ok)
		}
	}

	insideAncestor := BrowsePath(context.Background(), models.HostRuleTargetTypeDirectory, protectedParent, "", protectedPath)
	if insideAncestor.ErrorCode != "" {
		t.Fatalf("browse protected ancestor error = %q", insideAncestor.ErrorCode)
	}
	if _, ok := browseEntriesByName(insideAncestor.Entries)["secret"]; ok {
		t.Fatal("protected directory itself was exposed from its parent")
	}
	protected := BrowsePath(context.Background(), models.HostRuleTargetTypeDirectory, protectedPath, "", protectedPath)
	assertBrowseFailureOnly(t, protected, BrowseErrorProtectedPath)
	if internalLinkCreated {
		internalAlias := BrowsePath(context.Background(), models.HostRuleTargetTypeDirectory, filepath.Join(root, "internal-link"), "")
		assertBrowseFailureOnly(t, internalAlias, BrowseErrorInvalidPath)
	}
}

func TestBrowsePathFileModeSelectsAFileAndListsItsParent(t *testing.T) {
	root := t.TempDir()
	filePath := filepath.Join(root, "selected.txt")
	mustWriteBrowseFile(t, filePath, "selected")
	mustMakeBrowseDir(t, filepath.Join(root, "folder"))

	result := BrowsePath(context.Background(), models.HostRuleTargetTypeFile, filePath, "")
	if result.ErrorCode != "" {
		t.Fatalf("BrowsePath() error = %q", result.ErrorCode)
	}
	if result.CurrentPath == nil || *result.CurrentPath != filepath.Clean(root) || result.SelectedPath == nil || *result.SelectedPath != filepath.Clean(filePath) {
		t.Fatalf("file selection paths = current %#v selected %#v", result.CurrentPath, result.SelectedPath)
	}
	if result.CurrentSelectable {
		t.Fatal("a current directory is never selectable in file mode")
	}
	entries := browseEntriesByName(result.Entries)
	if file := entries["selected.txt"]; !file.Selectable || file.Navigable || file.EntryType != models.HostRuleTargetTypeFile {
		t.Fatalf("selected file entry = %#v", file)
	}
	if directory := entries["folder"]; directory.Selectable || !directory.Navigable || directory.EntryType != models.HostRuleTargetTypeDirectory {
		t.Fatalf("file-mode directory entry = %#v", directory)
	}

	notDirectory := BrowsePath(context.Background(), models.HostRuleTargetTypeDirectory, filePath, "")
	assertBrowseFailureOnly(t, notDirectory, BrowseErrorNotDirectory)
}

func TestBrowsePathPaginationIsStableAndCursorIsBound(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"z-directory", "A-directory"} {
		mustMakeBrowseDir(t, filepath.Join(root, name))
	}
	for index := 0; index < 203; index++ {
		mustWriteBrowseFile(t, filepath.Join(root, fmt.Sprintf("file-%03d.txt", index)), "x")
	}

	first := BrowsePath(context.Background(), models.HostRuleTargetTypeFile, root, "")
	if first.ErrorCode != "" || len(first.Entries) != BrowsePageSize || first.PreviousCursor != "" || first.NextCursor == "" {
		t.Fatalf("first page = error %q entries %d prev %q next %q", first.ErrorCode, len(first.Entries), first.PreviousCursor, first.NextCursor)
	}
	if first.Entries[0].Name != "A-directory" || first.Entries[1].Name != "z-directory" || first.Entries[2].Name != "file-000.txt" {
		t.Fatalf("first page ordering starts %#v", first.Entries[:3])
	}
	assertBrowseEntriesSorted(t, first.Entries)

	second := BrowsePath(context.Background(), models.HostRuleTargetTypeFile, root, first.NextCursor)
	if second.ErrorCode != "" || len(second.Entries) != BrowsePageSize || second.PreviousCursor == "" || second.NextCursor == "" {
		t.Fatalf("second page = error %q entries %d prev %q next %q", second.ErrorCode, len(second.Entries), second.PreviousCursor, second.NextCursor)
	}
	assertBrowseEntriesSorted(t, second.Entries)
	back := BrowsePath(context.Background(), models.HostRuleTargetTypeFile, root, second.PreviousCursor)
	if back.ErrorCode != "" || len(back.Entries) != len(first.Entries) {
		t.Fatalf("previous page = error %q entries %d", back.ErrorCode, len(back.Entries))
	}
	for index := range first.Entries {
		if back.Entries[index].Path != first.Entries[index].Path {
			t.Fatalf("round-trip page differs at %d: %q != %q", index, back.Entries[index].Path, first.Entries[index].Path)
		}
	}

	otherRoot := t.TempDir()
	assertBrowseFailureOnly(t, BrowsePath(context.Background(), models.HostRuleTargetTypeFile, otherRoot, first.NextCursor), BrowseErrorInvalidCursor)
	assertBrowseFailureOnly(t, BrowsePath(context.Background(), models.HostRuleTargetTypeDirectory, root, first.NextCursor), BrowseErrorInvalidCursor)
	assertBrowseFailureOnly(t, BrowsePath(context.Background(), models.HostRuleTargetTypeFile, root, strings.Repeat("a", MaxBrowseCursorBytes+1)), BrowseErrorInvalidCursor)
	assertBrowseFailureOnly(t, BrowsePath(context.Background(), models.HostRuleTargetTypeFile, root, first.NextCursor+"\n"), BrowseErrorInvalidCursor)
	tampered := []byte(first.NextCursor)
	if tampered[len(tampered)/2] == 'A' {
		tampered[len(tampered)/2] = 'B'
	} else {
		tampered[len(tampered)/2] = 'A'
	}
	assertBrowseFailureOnly(t, BrowsePath(context.Background(), models.HostRuleTargetTypeFile, root, string(tampered)), BrowseErrorInvalidCursor)
}

func TestBrowsePathRejectsInvalidMissingAndUnsupportedTargets(t *testing.T) {
	root := t.TempDir()
	tests := []struct {
		name       string
		targetType string
		path       string
		want       string
	}{
		{name: "relative", targetType: models.HostRuleTargetTypeFile, path: "relative", want: BrowseErrorInvalidPath},
		{name: "backslash", targetType: models.HostRuleTargetTypeFile, path: root + `\\child`, want: BrowseErrorInvalidPath},
		{name: "missing", targetType: models.HostRuleTargetTypeFile, path: filepath.Join(root, "missing"), want: BrowseErrorNotFound},
		{name: "unsupported target", targetType: models.HostRuleTargetTypeProxy, path: root, want: BrowseErrorUnsupportedType},
	}
	for _, testCase := range tests {
		if runtime.GOOS == "windows" && testCase.name == "backslash" {
			continue
		}
		t.Run(testCase.name, func(t *testing.T) {
			assertBrowseFailureOnly(t, BrowsePath(context.Background(), testCase.targetType, testCase.path, ""), testCase.want)
		})
	}
}

func TestBrowsePathEmptyPOSIXPathOpensFilesystemRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows uses a virtual local-drive root")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result := BrowsePath(ctx, models.HostRuleTargetTypeDirectory, "", "")
	if result.ErrorCode != "" {
		t.Fatalf("BrowsePath(empty) error = %q", result.ErrorCode)
	}
	if result.Platform != "posix" || result.CurrentPath == nil || *result.CurrentPath != "/" || result.ParentPath != nil || result.CurrentSelectable {
		t.Fatalf("root result = %#v", result)
	}
	if len(result.Breadcrumbs) != 1 || result.Breadcrumbs[0] != (BrowseBreadcrumb{Name: "/", Path: "/"}) {
		t.Fatalf("root breadcrumbs = %#v", result.Breadcrumbs)
	}
}

func TestBrowsePathPreservesVisiblePOSIXWhitespace(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Win32 normalizes trailing spaces and the shared name policy rejects them")
	}
	root := t.TempDir()
	pathValue := filepath.Join(root, " visible whitespace ")
	mustMakeBrowseDir(t, pathValue)
	result := BrowsePath(context.Background(), models.HostRuleTargetTypeDirectory, pathValue, "")
	if result.ErrorCode != "" || result.CurrentPath == nil || *result.CurrentPath != pathValue || !result.CurrentSelectable {
		t.Fatalf("whitespace path result = %#v", result)
	}
	if got := result.Breadcrumbs[len(result.Breadcrumbs)-1].Name; got != " visible whitespace " {
		t.Fatalf("breadcrumb name = %q", got)
	}
}

func TestScanBrowseDirectoryPageHonorsProductionLimits(t *testing.T) {
	rootPath := t.TempDir()
	for _, name := range []string{"one", "two", "three"} {
		mustWriteBrowseFile(t, filepath.Join(rootPath, name), name)
	}
	root, err := openBrowseDirectoryRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	directory, err := openRootFileForRead(root, ".")
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	_, _, _, err = scanBrowseDirectoryPageWithLimits(context.Background(), root, directory, rootPath, models.HostRuleTargetTypeFile, nil, 2, 2)
	if !errors.Is(err, errDirectoryTooLarge) {
		t.Fatalf("scan error = %v, want errDirectoryTooLarge", err)
	}
}

func TestBrowseProtectionClassifiesAncestorExactAndDescendant(t *testing.T) {
	root := t.TempDir()
	protected := filepath.Join(root, "secret")
	mustMakeBrowseDir(t, filepath.Join(protected, "child"))
	if got := browseProtection(root, protected); got != browseProtectionAncestor {
		t.Fatalf("ancestor state = %v", got)
	}
	if got := browseProtection(protected, protected); got != browseProtectionHidden {
		t.Fatalf("exact state = %v", got)
	}
	if got := browseProtection(filepath.Join(protected, "child"), protected); got != browseProtectionHidden {
		t.Fatalf("descendant state = %v", got)
	}
	if got := browseProtection(filepath.Join(root, "sibling"), protected); got != browseProtectionNormal {
		t.Fatalf("sibling state = %v", got)
	}
}

func assertBrowseFailureOnly(t *testing.T, result BrowseResult, wantCode string) {
	t.Helper()
	if result.ErrorCode != wantCode {
		t.Fatalf("error code = %q, want %q; result %#v", result.ErrorCode, wantCode, result)
	}
	if result.CurrentPath != nil || result.ParentPath != nil || result.SelectedPath != nil || result.CurrentSelectable || len(result.Breadcrumbs) != 0 || len(result.Entries) != 0 || result.PreviousCursor != "" || result.NextCursor != "" {
		t.Fatalf("failure leaked browse fields: %#v", result)
	}
	if result.Platform != "posix" && result.Platform != "windows" {
		t.Fatalf("failure platform = %q", result.Platform)
	}
}

func assertBrowseEntriesSorted(t *testing.T, entries []BrowseEntry) {
	t.Helper()
	for index := 1; index < len(entries); index++ {
		previous := newListingKey(entries[index-1].EntryType == models.HostRuleTargetTypeDirectory, entries[index-1].Name)
		current := newListingKey(entries[index].EntryType == models.HostRuleTargetTypeDirectory, entries[index].Name)
		if compareListingKeys(previous, current) >= 0 {
			t.Fatalf("entries out of order at %d: %q then %q", index, entries[index-1].Name, entries[index].Name)
		}
	}
}

func browseEntriesByName(entries []BrowseEntry) map[string]BrowseEntry {
	result := make(map[string]BrowseEntry, len(entries))
	for _, entry := range entries {
		result[entry.Name] = entry
	}
	return result
}

func mustMakeBrowseDir(t *testing.T, pathValue string) {
	t.Helper()
	if err := os.MkdirAll(pathValue, 0o755); err != nil {
		t.Fatal(err)
	}
}

func mustWriteBrowseFile(t *testing.T, pathValue, contents string) {
	t.Helper()
	if err := os.WriteFile(pathValue, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
}
