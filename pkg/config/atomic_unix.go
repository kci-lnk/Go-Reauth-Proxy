//go:build !windows

package config

import "os"

func platformAtomicRename(oldPath string, newPath string) error {
	return os.Rename(oldPath, newPath)
}

func syncParentDirectory(dir string) error {
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	if err := directory.Sync(); err != nil {
		_ = directory.Close()
		return err
	}
	return directory.Close()
}
