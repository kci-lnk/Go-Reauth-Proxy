//go:build darwin

package admin

import (
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	procInfoCallPIDInfo = 2
	procPIDTaskInfo     = 4
)

type procTaskInfo struct {
	VirtualSize      uint64
	ResidentSize     uint64
	TotalUser        uint64
	TotalSystem      uint64
	ThreadsUser      uint64
	ThreadsSystem    uint64
	Policy           int32
	Faults           int32
	Pageins          int32
	CopyOnWriteFault int32
	MessagesSent     int32
	MessagesReceived int32
	SyscallsMach     int32
	SyscallsUnix     int32
	ContextSwitches  int32
	ThreadCount      int32
	RunningCount     int32
	Priority         int32
}

func currentProcessRSSBytes() uint64 {
	var info procTaskInfo
	size := unsafe.Sizeof(info)
	written, _, errno := unix.Syscall6(
		unix.SYS_PROC_INFO,
		procInfoCallPIDInfo,
		uintptr(os.Getpid()),
		procPIDTaskInfo,
		0,
		uintptr(unsafe.Pointer(&info)),
		size,
	)
	if errno != 0 || written != size {
		return 0
	}
	return info.ResidentSize
}
