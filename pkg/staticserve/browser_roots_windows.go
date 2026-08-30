//go:build windows

package staticserve

import (
	"strings"

	"golang.org/x/sys/windows"
)

func browseDriveRoots() ([]string, error) {
	mask, err := windows.GetLogicalDrives()
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, 26)
	for index := 0; index < 26; index++ {
		if mask&(1<<index) == 0 {
			continue
		}
		root := string(rune('A'+index)) + `:\`
		rootUTF16, err := windows.UTF16PtrFromString(root)
		if err != nil {
			continue
		}
		switch windows.GetDriveType(rootUTF16) {
		case windows.DRIVE_FIXED, windows.DRIVE_REMOVABLE, windows.DRIVE_RAMDISK:
			result = append(result, root)
		}
	}
	return result, nil
}

func validWindowsDriveRoot(value string) bool {
	if len(value) != 3 || value[1:] != `:\` {
		return false
	}
	letter := strings.ToUpper(value[:1])[0]
	return letter >= 'A' && letter <= 'Z'
}
