package logger

import (
	"net"
	"os"
	"syscall"
	"testing"

	"golang.org/x/sys/windows"
)

func TestMatchesWinsockErrno(t *testing.T) {
	for _, pair := range []struct{ portable, native syscall.Errno }{
		{syscall.ECONNREFUSED, windows.WSAECONNREFUSED},
		{syscall.ENETUNREACH, windows.WSAENETUNREACH},
		{syscall.EHOSTUNREACH, windows.WSAEHOSTUNREACH},
		{syscall.ECONNRESET, windows.WSAECONNRESET},
	} {
		for _, code := range []syscall.Errno{pair.portable, pair.native} {
			err := &net.OpError{Op: "dial", Net: "tcp", Err: &os.SyscallError{Syscall: "connectex", Err: code}}
			if !matchesSocketErrno(err, pair.portable) {
				t.Errorf("wrapped errno %d did not match %d", code, pair.portable)
			}
			if matchesSocketErrno(err, syscall.EINVAL) {
				t.Errorf("wrapped errno %d matched unrelated EINVAL", code)
			}
		}
	}
}
