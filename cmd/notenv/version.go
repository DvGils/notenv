package main

import "fmt"

// Build metadata. These defaults apply to local `go build`/`go install`; at
// release time they are overridden via -ldflags (GoReleaser sets main.version,
// main.commit, and main.date).
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func versionString() string {
	return fmt.Sprintf("notenv %s (commit %s, built %s)", version, commit, date)
}
