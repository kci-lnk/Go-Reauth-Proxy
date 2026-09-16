// Package testutil supplies filesystem fixtures for integration tests.
package testutil

import (
	"os"
	"runtime"
	"testing"
)

// StaticDir keeps Windows public-content fixtures outside LOCALAPPDATA, which
// the production policy deliberately protects. Do not clear protected roots.
func StaticDir(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "windows" {
		return t.TempDir()
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(cwd, "static-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	})
	return dir
}
