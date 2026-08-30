//go:build !windows

package staticserve

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"go-reauth-proxy/pkg/models"
	"golang.org/x/sys/unix"
)

func TestBrowsePathHidesFIFOAndSocketEntries(t *testing.T) {
	root, err := os.MkdirTemp("/tmp", "fn-knock-browse-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if err := unix.Mkfifo(filepath.Join(root, "pipe"), 0o600); err != nil {
		t.Fatal(err)
	}
	socketPath := filepath.Join(root, "socket")
	socket, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(socket)
	if err := unix.Bind(socket, &unix.SockaddrUnix{Name: socketPath}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(socketPath) })

	result := BrowsePath(context.Background(), models.HostRuleTargetTypeFile, root, "")
	if result.ErrorCode != "" {
		t.Fatalf("BrowsePath() error = %q", result.ErrorCode)
	}
	entries := browseEntriesByName(result.Entries)
	if _, ok := entries["pipe"]; ok {
		t.Fatal("FIFO was exposed")
	}
	if _, ok := entries["socket"]; ok {
		t.Fatal("socket was exposed")
	}
	assertBrowseFailureOnly(t, BrowsePath(context.Background(), models.HostRuleTargetTypeFile, filepath.Join(root, "pipe"), ""), BrowseErrorUnsupportedType)
	assertBrowseFailureOnly(t, BrowsePath(context.Background(), models.HostRuleTargetTypeFile, socketPath, ""), BrowseErrorUnsupportedType)
}

func TestBrowsePathClassifiesDirectoryPermissionFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can bypass directory permission bits")
	}
	root := t.TempDir()
	blocked := filepath.Join(root, "blocked")
	if err := os.Mkdir(blocked, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(blocked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(blocked, 0o700) })
	result := BrowsePath(context.Background(), models.HostRuleTargetTypeDirectory, blocked, "")
	assertBrowseFailureOnly(t, result, BrowseErrorPermissionDenied)
}

func TestBrowseDirectoryRootFailsClosedWhenPathIsSwappedToProtectedSymlink(t *testing.T) {
	parent := t.TempDir()
	browsePath := filepath.Join(parent, "browse")
	movedPath := filepath.Join(parent, "moved")
	protectedPath := filepath.Join(parent, "protected")
	if err := os.Mkdir(browsePath, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(protectedPath, 0o700); err != nil {
		t.Fatal(err)
	}
	pathPolicy := newBrowsePathPolicy(protectedPath)
	root, err := openBrowseDirectoryRootAfterPreopen(browsePath, func() {
		if renameErr := os.Rename(browsePath, movedPath); renameErr != nil {
			t.Fatalf("rename browsable directory: %v", renameErr)
		}
		if symlinkErr := os.Symlink(protectedPath, browsePath); symlinkErr != nil {
			t.Fatalf("replace browse path with protected symlink: %v", symlinkErr)
		}
	}, pathPolicy)
	if root != nil {
		_ = root.Close()
		t.Fatal("browser root opened after its path was swapped to a protected symlink")
	}
	if err == nil {
		t.Fatal("browser root swap returned no error")
	}
}

func TestBrowsePathRejectsDirectOutOfTreeAndProtectedSymlinks(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	protected := filepath.Join(root, "protected")
	if err := os.Mkdir(protected, 0o700); err != nil {
		t.Fatal(err)
	}
	outLink := filepath.Join(root, "outside-link")
	protectedLink := filepath.Join(root, "protected-link")
	if err := os.Symlink(outside, outLink); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(protected, protectedLink); err != nil {
		t.Fatal(err)
	}
	assertBrowseFailureOnly(t, BrowsePath(context.Background(), models.HostRuleTargetTypeDirectory, outLink, ""), BrowseErrorInvalidPath)
	assertBrowseFailureOnly(t, BrowsePath(context.Background(), models.HostRuleTargetTypeDirectory, protectedLink, "", protected), BrowseErrorProtectedPath)
}
