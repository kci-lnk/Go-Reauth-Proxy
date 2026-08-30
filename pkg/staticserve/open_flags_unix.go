//go:build aix || android || darwin || dragonfly || freebsd || illumos || ios || linux || netbsd || openbsd || solaris

package staticserve

import "syscall"

const staticOpenNonblock = syscall.O_NONBLOCK
