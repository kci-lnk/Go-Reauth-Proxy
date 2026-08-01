//go:build !darwin && !linux && !windows

package admin

func currentProcessRSSBytes() uint64 {
	return 0
}
