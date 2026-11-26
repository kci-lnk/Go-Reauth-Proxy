//go:build !windows

package main

import "syscall"

const listenAddressInUse = syscall.EADDRINUSE
