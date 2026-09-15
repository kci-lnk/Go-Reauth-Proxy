package main

import (
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// configureTransparentHugePages runs before loading configuration and compiling
// WAF rules. Small Go heaps can otherwise retain inflated RSS when khugepaged
// fills in pages that the runtime has already released. Changing GODEBUG here
// would be too late: the runtime reads disablethp during its own initialization.
// The prctl applies to the process's shared address space, including Go threads;
// it is also inherited by child processes. It does not change host THP settings.
func configureTransparentHugePages() error {
	if !disableTransparentHugePages(os.Getenv("GODEBUG")) {
		return nil
	}
	return unix.Prctl(unix.PR_SET_THP_DISABLE, 1, 0, 0, 0)
}

func disableTransparentHugePages(godebug string) bool {
	disable := true
	// Match the runtime's startup parsing: the last valid integer wins.
	// Explicit disablethp=0 opts out without undoing an inherited OS policy.
	for _, setting := range strings.Split(godebug, ",") {
		key, value, ok := strings.Cut(setting, "=")
		if !ok || key != "disablethp" {
			continue
		}
		if n, err := strconv.ParseInt(value, 10, 32); err == nil {
			disable = n != 0
		}
	}
	return disable
}
