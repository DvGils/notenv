// Package ui is notenv's hand-rolled terminal UI: ANSI styling, prompts,
// an arrow-key select, and a spinner. Built on x/term raw mode, which is
// already a dependency, so it adds zero new supply-chain surface.
//
// Styling honors NO_COLOR and TERM=dumb and disables itself off-TTY.
// All human-facing output goes to stderr; stdout stays reserved for data.
package ui

import (
	"fmt"
	"os"

	"golang.org/x/term"
)

var styled = func() bool {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	return term.IsTerminal(int(os.Stderr.Fd()))
}()

func style(code, s string) string {
	if !styled {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func Bold(s string) string   { return style("1", s) }
func Dim(s string) string    { return style("2", s) }
func Red(s string) string    { return style("31", s) }
func Green(s string) string  { return style("32", s) }
func Yellow(s string) string { return style("33", s) }
func Cyan(s string) string   { return style("36", s) }

// Status lines: a colored glyph + message on stderr.

func Successf(format string, a ...any) {
	fmt.Fprintln(os.Stderr, Green("✓"), fmt.Sprintf(format, a...))
}
func Failf(format string, a ...any) { fmt.Fprintln(os.Stderr, Red("✗"), fmt.Sprintf(format, a...)) }
func Warnf(format string, a ...any) {
	fmt.Fprintln(os.Stderr, Yellow("⚠"), fmt.Sprintf(format, a...))
}
func Infof(format string, a ...any) { fmt.Fprintln(os.Stderr, Dim("→"), fmt.Sprintf(format, a...)) }
func Notef(format string, a ...any) { fmt.Fprintln(os.Stderr, Dim("•"), fmt.Sprintf(format, a...)) }
