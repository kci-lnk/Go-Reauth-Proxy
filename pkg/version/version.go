package version

// Version and Commit are variables so release builds can inject the exact
// bundle identity with -ldflags -X. Development builds retain useful values.
var (
	Version = "2.4.3"
	Commit  = "unknown"
)
