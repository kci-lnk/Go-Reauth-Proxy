package main

import (
	"os"
	"os/exec"
	"testing"

	"golang.org/x/sys/unix"
)

// Use child processes so a test cannot change the test runner's memory policy.
// Query the kernel after applying the policy, rather than only testing parsing.
func TestTransparentHugePages(t *testing.T) {
	if os.Getenv("GO_REPROXY_TEST_THP_CHILD") == "1" {
		before, err := unix.PrctlRetInt(unix.PR_GET_THP_DISABLE, 0, 0, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		original := os.Getenv("GODEBUG")
		if err := configureTransparentHugePages(); err != nil {
			t.Fatal(err)
		}
		after, err := unix.PrctlRetInt(unix.PR_GET_THP_DISABLE, 0, 0, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		want := 1
		if os.Getenv("GO_REPROXY_TEST_THP_OPT_OUT") == "1" {
			want = before
		}
		if after != want {
			t.Fatalf("kernel THP disable flag = %d, want %d", after, want)
		}
		if os.Getenv("GODEBUG") != original {
			t.Fatal("changed unrelated runtime settings")
		}
		return
	}

	for _, tc := range []struct {
		name    string
		godebug string
		optOut  bool
	}{
		{"default", "", false},
		{"unrelated", "http2client=0", false},
		{"explicit_enable", "disablethp=1", false},
		{"explicit_opt_out", "http2client=0,disablethp=0", true},
		{"last_opt_out", "disablethp=1,disablethp=0", true},
		{"last_enable", "disablethp=0,disablethp=1", false},
		{"invalid_default", "disablethp=invalid", false},
		{"invalid_after_opt_out", "disablethp=0,disablethp=invalid", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := disableTransparentHugePages(tc.godebug); got == tc.optOut {
				t.Fatalf("disableTransparentHugePages(%q) = %v", tc.godebug, got)
			}
			t.Setenv("GODEBUG", tc.godebug)
			t.Setenv("GO_REPROXY_TEST_THP_CHILD", "1")
			optOut := "0"
			if tc.optOut {
				optOut = "1"
			}
			t.Setenv("GO_REPROXY_TEST_THP_OPT_OUT", optOut)
			cmd := exec.Command(os.Args[0], "-test.run=^TestTransparentHugePages$")
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("THP subprocess: %v\n%s", err, output)
			}
		})
	}
}
