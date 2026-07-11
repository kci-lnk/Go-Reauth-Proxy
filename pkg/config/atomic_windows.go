//go:build windows

package config

import "golang.org/x/sys/windows"

func platformAtomicRename(oldPath string, newPath string) error {
	oldPtr, err := windows.UTF16PtrFromString(oldPath)
	if err != nil {
		return err
	}
	newPtr, err := windows.UTF16PtrFromString(newPath)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(
		oldPtr,
		newPtr,
		windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH,
	)
}

// Windows does not expose POSIX directory fsync semantics. MOVEFILE_WRITE_THROUGH
// above flushes the replacement before MoveFileEx returns.
func syncParentDirectory(string) error { return nil }
