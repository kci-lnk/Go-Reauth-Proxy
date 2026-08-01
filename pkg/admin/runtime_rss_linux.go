//go:build linux

package admin

import (
	"os"
	"strconv"
	"strings"
)

func currentProcessRSSBytes() uint64 {
	raw, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(raw))
	if len(fields) < 2 {
		return 0
	}
	residentPages, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return 0
	}
	return residentPages * uint64(os.Getpagesize())
}
