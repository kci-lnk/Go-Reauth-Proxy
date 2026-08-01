//go:build windows

package admin

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var getProcessMemoryInfo = windows.NewLazySystemDLL("psapi.dll").NewProc("GetProcessMemoryInfo")

type processMemoryCounters struct {
	Cb                         uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
}

func currentProcessRSSBytes() uint64 {
	process, err := windows.GetCurrentProcess()
	if err != nil {
		return 0
	}
	var counters processMemoryCounters
	counters.Cb = uint32(unsafe.Sizeof(counters))
	ok, _, _ := getProcessMemoryInfo.Call(
		uintptr(process),
		uintptr(unsafe.Pointer(&counters)),
		uintptr(counters.Cb),
	)
	if ok == 0 {
		return 0
	}
	return uint64(counters.WorkingSetSize)
}
