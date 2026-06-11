package main

import (
	"runtime/debug"
	"strings"
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
	// ("v0.1.0" when installed by version, a VCS-derived version like
	// "v0.3.0+dirty" for a local checkout); the vcs.* settings are present only
	// for a build from a Git checkout, so a `go install pkg@version` build has
	// no commit or date to show.
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

	return renderVersion(v, c, d)
}

// renderVersion formats the resolved build metadata. It shows only the detail it
// actually has, so a build with no embedded commit/date (e.g. `go install
// pkg@version`) prints just the version instead of "none"/"unknown" noise.
func renderVersion(v, c, d string) string {
	if v == "" {
		v = "dev"
	}
	if len(c) > 12 {
		c = c[:12] // short commit hash; a dirty tree already shows in the version
	}
	var detail []string
	if c != "" {
		detail = append(detail, "commit "+c)
	}
	if d != "" {
		detail = append(detail, "built "+d)
	}
	if len(detail) == 0 {
		return "notenv " + v
	}
	return "notenv " + v + " (" + strings.Join(detail, ", ") + ")"
}
