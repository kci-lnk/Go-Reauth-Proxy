//go:build !windows

package main

import (
	"log"
	"syscall"
)

func raiseNoFileLimit() {
	target := syscall.Rlimit{
		Cur: targetNoFileLimit,
		Max: targetNoFileLimit,
	}
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &target); err == nil {
		log.Printf("Raised RLIMIT_NOFILE to soft=%d hard=%d", targetNoFileLimit, targetNoFileLimit)
		return
	} else {
		targetErr := err
		var inherited syscall.Rlimit
		if getErr := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &inherited); getErr == nil && inherited.Cur < inherited.Max {
			fallback := syscall.Rlimit{Cur: inherited.Max, Max: inherited.Max}
			if setErr := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &fallback); setErr == nil {
				log.Printf(
					"Failed to set RLIMIT_NOFILE to %d; raised soft limit to inherited hard limit %d instead: %v",
					targetNoFileLimit,
					inherited.Max,
					targetErr,
				)
				return
			}
		}
		log.Printf("Failed to set RLIMIT_NOFILE to %d: %v", targetNoFileLimit, targetErr)
	}
}
