//go:build !windows

package staticserve

func browseDriveRoots() ([]string, error) {
	return nil, nil
}

func validWindowsDriveRoot(string) bool {
	return false
}
