package version

// Version and Commit are variables so release builds can inject the exact
// bundle identity with -ldflags -X. Development builds retain useful values.
var (
	Version = "2.1.1"
	Commit  = "unknown"
)

const ControlAPIVersion uint32 = 2
