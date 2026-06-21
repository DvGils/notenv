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
	"strings"

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

// Substep reports a completed sub-step of a phase: a dim, indented check kept
// subordinate to its Heading and the final summary, so the eye lands on those
// rather than on each internal step.
func Substep(format string, a ...any) {
	fmt.Fprintln(os.Stderr, Dim("  ✓ "+fmt.Sprintf(format, a...)))
}

// Structural output for multi-step flows (setup): a phase Heading, an unadorned
// Plainf line for a summary body, and a Rule to frame it. These carry no status
// glyph, so a block built from them reads as one unit instead of a stack of
// equally-weighted status lines.

// Heading prints a blank line then a bold section title, opening a phase.
func Heading(format string, a ...any) {
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, Bold(fmt.Sprintf(format, a...)))
}

// Plainf prints one unadorned line to stderr (no glyph), for the body of a
// summary block where the status vocabulary would only add noise.
func Plainf(format string, a ...any) {
	fmt.Fprintln(os.Stderr, fmt.Sprintf(format, a...))
}

// Rule prints a dim horizontal rule, used to delimit a summary block.
func Rule() {
	fmt.Fprintln(os.Stderr, Dim(strings.Repeat("─", 56)))
}
