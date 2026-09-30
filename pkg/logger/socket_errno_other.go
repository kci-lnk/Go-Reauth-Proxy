//go:build !windows

package logger

import (
	"errors"
	"syscall"
)

func matchesSocketErrno(err error, code syscall.Errno) bool {
	return errors.Is(err, code)
}
