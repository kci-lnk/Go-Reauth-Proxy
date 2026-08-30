package staticserve

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

var errUnsafeRootTarget = errors.New("rooted file target is unsafe")

type rootedFileOpener interface {
	Name() string
	Lstat(name string) (os.FileInfo, error)
	OpenFile(name string, flag int, perm os.FileMode) (*os.File, error)
}

type staticDirectoryRoot struct {
	*os.Root
	pinned      *os.File
	visibleName string
}

func (root *staticDirectoryRoot) Name() string {
	if root == nil {
		return ""
	}
	return root.visibleName
}

func (root *staticDirectoryRoot) Close() error {
	if root == nil {
		return nil
	}
	var rootErr, pinnedErr error
	if root.Root != nil {
		rootErr = root.Root.Close()
		root.Root = nil
	}
	if root.pinned != nil {
		pinnedErr = root.pinned.Close()
		root.pinned = nil
	}
	return errors.Join(rootErr, pinnedErr)
}

// openStaticDirectoryRoot performs a non-blocking, directory-only pre-open and
// constructs os.Root from that pinned descriptor on Unix. Opening the original
// pathname again would reintroduce an unbounded FIFO race because os.OpenRoot
// checks the mode only after a blocking O_RDONLY open.
func openStaticDirectoryRoot(pathValue string, protectedPaths ...string) (*staticDirectoryRoot, error) {
	return openStaticDirectoryRootAfterPreopen(pathValue, nil, protectedPaths...)
}

func openStaticDirectoryRootAfterPreopen(pathValue string, afterPreopen func(), protectedPaths ...string) (*staticDirectoryRoot, error) {
	return openStaticDirectoryRootWithValidator(pathValue, afterPreopen, func(resolvedPath string) error {
		return ValidateProtectedPath(resolvedPath, protectedPaths...)
	})
}

// openStaticDirectoryRootWithValidator keeps the descriptor-pinning and
// identity checks shared by serving and administrative browsing while letting
// each caller apply its own resolved-path policy. Serving rejects both sides of
// every protected-path overlap; browsing additionally needs to traverse a
// protected directory's strict ancestors without ever selecting them.
func openStaticDirectoryRootWithValidator(pathValue string, afterPreopen func(), validateResolvedPath func(string) error) (*staticDirectoryRoot, error) {
	preopened, err := preopenStaticDirectory(pathValue)
	if err != nil {
		return nil, err
	}
	preopenedOwned := true
	defer func() {
		if preopenedOwned {
			_ = preopened.Close()
		}
	}()
	preopenedInfo, err := preopened.Stat()
	if err != nil || !preopenedInfo.IsDir() {
		return nil, errUnsafeRootTarget
	}
	if afterPreopen != nil {
		afterPreopen()
	}

	osRoot, err := openRootFromPinnedDirectory(pathValue, preopened)
	if err != nil {
		return nil, err
	}
	root := &staticDirectoryRoot{Root: osRoot, pinned: preopened, visibleName: pathValue}
	preopenedOwned = false
	openedDirectory, err := openRootFileForRead(root, ".")
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	openedInfo, statErr := openedDirectory.Stat()
	_ = openedDirectory.Close()
	if statErr != nil || !openedInfo.IsDir() || !os.SameFile(preopenedInfo, openedInfo) {
		_ = root.Close()
		return nil, errUnsafeRootTarget
	}
	// Re-evaluate protected paths after the rooted handle has been established.
	// This closes the Windows junction/reparse-point race between the earlier
	// config resolution and os.OpenRoot. SameFile above binds this spelling to
	// the pinned directory; after this check all request opens use that handle.
	resolvedOpenedRoot, err := filepath.EvalSymlinks(filepath.Clean(pathValue))
	if err != nil {
		_ = root.Close()
		return nil, errUnsafeRootTarget
	}
	resolvedInfo, err := os.Stat(resolvedOpenedRoot)
	if err != nil || !os.SameFile(openedInfo, resolvedInfo) {
		_ = root.Close()
		return nil, errUnsafeRootTarget
	}
	if validateResolvedPath != nil {
		if err := validateResolvedPath(resolvedOpenedRoot); err != nil {
			_ = root.Close()
			return nil, err
		}
	}
	return root, nil
}

// openRootFileForRead prevents a FIFO or device-like entry from blocking the
// request goroutine before its mode can be inspected. O_NONBLOCK is a no-op for
// ordinary files and directories; non-Unix platforms use flag 0.
func openRootFileForRead(root rootedFileOpener, name string) (*os.File, error) {
	if root == nil || !visibleRootRelativeName(name) {
		return nil, errUnsafeRootTarget
	}
	// Avoid touching a known device, socket, or FIFO at all. The opened handle
	// is still checked below because a local writer may replace the entry after
	// this advisory Lstat; O_NONBLOCK prevents that race from hanging on a FIFO.
	entryInfo, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	entryMode := entryInfo.Mode()
	if !entryMode.IsRegular() && !entryMode.IsDir() && entryMode&os.ModeSymlink == 0 {
		return nil, errUnsafeRootTarget
	}
	file, err := root.OpenFile(name, os.O_RDONLY|staticOpenNonblock, 0)
	if err != nil {
		return nil, err
	}
	if err := validateOpenedRootTarget(root, name, file); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func visibleRootRelativeName(name string) bool {
	if name == "." {
		return true
	}
	if name == "" || filepath.IsAbs(filepath.FromSlash(name)) {
		return false
	}
	for _, component := range strings.Split(name, "/") {
		if !safeVisibleName(component) {
			return false
		}
	}
	return true
}

// validateOpenedRootTarget binds the opened descriptor to a visible resolved
// path. os.Root already prevents root escape; the independent checks here add
// the product policy that dot-items must not become reachable through visible
// symlink aliases. SameFile closes the TOCTOU gap between opening and resolving:
// if a symlink changes during validation, the descriptor and resolved target no
// longer identify the same object and the request fails closed.
func validateOpenedRootTarget(root rootedFileOpener, name string, opened *os.File) error {
	if root == nil || opened == nil {
		return errUnsafeRootTarget
	}
	resolvedRoot, err := filepath.EvalSymlinks(filepath.Clean(root.Name()))
	if err != nil {
		return errUnsafeRootTarget
	}
	resolvedTarget, err := filepath.EvalSymlinks(filepath.Join(root.Name(), filepath.FromSlash(name)))
	if err != nil {
		return errUnsafeRootTarget
	}
	relative, err := filepath.Rel(resolvedRoot, resolvedTarget)
	if err != nil || filepath.IsAbs(relative) || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		return errUnsafeRootTarget
	}
	if relative != "." {
		for _, component := range strings.Split(relative, string(os.PathSeparator)) {
			if !safeVisibleName(component) {
				return errUnsafeRootTarget
			}
		}
	}
	openedInfo, err := opened.Stat()
	if err != nil {
		return errUnsafeRootTarget
	}
	resolvedInfo, err := os.Stat(resolvedTarget)
	if err != nil || !os.SameFile(openedInfo, resolvedInfo) {
		return errUnsafeRootTarget
	}
	return nil
}
