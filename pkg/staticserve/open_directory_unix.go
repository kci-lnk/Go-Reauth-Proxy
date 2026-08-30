//go:build aix || android || darwin || dragonfly || freebsd || illumos || ios || linux || netbsd || openbsd || solaris

package staticserve

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func preopenStaticDirectory(pathValue string) (*os.File, error) {
	fd, err := unix.Open(
		pathValue,
		unix.O_RDONLY|unix.O_NONBLOCK|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), pathValue)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errUnsafeRootTarget
	}
	return file, nil
}

func openRootFromPinnedDirectory(_ string, pinned *os.File) (*os.Root, error) {
	if pinned == nil {
		return nil, errUnsafeRootTarget
	}
	fd := pinned.Fd()
	for _, descriptorPath := range []string{
		fmt.Sprintf("/proc/self/fd/%d", fd),
		fmt.Sprintf("/dev/fd/%d", fd),
	} {
		root, err := os.OpenRoot(descriptorPath)
		if err == nil {
			return root, nil
		}
	}
	// Do not fall back to opening the original pathname: doing so would restore
	// the FIFO swap race this descriptor bridge is designed to remove.
	return nil, errUnsafeRootTarget
}
