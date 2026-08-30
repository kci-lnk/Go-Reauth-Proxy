//go:build !(aix || android || darwin || dragonfly || freebsd || illumos || ios || linux || netbsd || openbsd || solaris)

package staticserve

import "os"

func preopenStaticDirectory(pathValue string) (*os.File, error) {
	info, err := os.Lstat(pathValue)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errUnsafeRootTarget
	}
	file, err := os.Open(pathValue)
	if err != nil {
		return nil, err
	}
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.IsDir() || !os.SameFile(info, openedInfo) {
		_ = file.Close()
		return nil, errUnsafeRootTarget
	}
	return file, nil
}

func openRootFromPinnedDirectory(pathValue string, _ *os.File) (*os.Root, error) {
	return os.OpenRoot(pathValue)
}
