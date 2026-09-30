package logger

import (
	"errors"
	"syscall"

	"golang.org/x/sys/windows"
)

// Winsock reports WSA errors rather than Go's portable errno constants.
func matchesSocketErrno(err error, code syscall.Errno) bool {
	if errors.Is(err, code) {
		return true
	}
	switch code {
	case syscall.ECONNREFUSED:
		return errors.Is(err, windows.WSAECONNREFUSED)
	case syscall.ENETUNREACH:
		return errors.Is(err, windows.WSAENETUNREACH)
	case syscall.EHOSTUNREACH:
		return errors.Is(err, windows.WSAEHOSTUNREACH)
	case syscall.ECONNRESET:
		return errors.Is(err, windows.WSAECONNRESET)
	default:
		return false
	}
}
