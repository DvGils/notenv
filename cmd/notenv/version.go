package main

import (
	"fmt"
	"runtime/debug"
)

// Build metadata. GoReleaser stamps these via -ldflags at release time. For
// other builds they stay empty and versionString falls back to the module
// version and VCS stamps that Go embeds in every binary.
var (
	version = ""
	commit  = ""
	date    = ""
)

func versionString() string {
	v, c, d := version, commit, date

	// No -ldflags (e.g. `go install ...@v0.1.0`, `go build`): recover what we
	// can from the embedded build info. Main.Version is the module version
	// ("v0.1.0" when installed by version, "(devel)" for a local checkout);
	// the vcs.* settings are present for builds from a Git checkout.
	if v == "" || c == "" || d == "" {
		if bi, ok := debug.ReadBuildInfo(); ok {
			if v == "" && bi.Main.Version != "" {
				v = bi.Main.Version
			}
			for _, s := range bi.Settings {
				switch s.Key {
				case "vcs.revision":
					if c == "" {
						c = s.Value
					}
				case "vcs.time":
					if d == "" {
						d = s.Value
					}
				}
			}
		}
	}

	if v == "" {
		v = "dev"
	}
	if c == "" {
		c = "none"
	}
	if d == "" {
		d = "unknown"
	}
	return fmt.Sprintf("notenv %s (commit %s, built %s)", v, c, d)
}
