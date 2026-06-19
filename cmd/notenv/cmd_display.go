package main

import (
	"fmt"
	"strings"
	"time"
	"unicode"
)

// sanitizeDisplay renders user-authored text (a description) safe for a terminal
// and for the tab-separated inspect output. Descriptions are stored faithfully
// (see internal/secrets) and are not gated like values, so they may carry
// control bytes; rendering each as a visible escape stops a description from
// breaking the column layout or injecting a terminal escape sequence when
// printed (e.g. a teammate's booby-trapped description shown by `secret inspect`).
// Structured (--json) output is left faithful: encoding/json escapes control
// bytes in its own text, and a machine consumer should receive the real value.
func sanitizeDisplay(s string) string {
	if !strings.ContainsFunc(s, unicode.IsControl) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if unicode.IsControl(r) {
				fmt.Fprintf(&b, `\x%02x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	return b.String()
}

// modifiedLabel renders a write's advisory wall-clock timestamp for humans; a
// zero TS is a write that predates timestamps.
func modifiedLabel(ts int64) string {
	if ts == 0 {
		return "-"
	}
	return time.Unix(ts, 0).Local().Format("2006-01-02 15:04")
}
