package ui

import (
	"strings"
	"testing"
)

// renderMenu must separate lines with newlines, never terminate with one, or
// the menu scrolls the terminal at the bottom of the screen and the redraw
// drifts (printing a fresh menu per keypress).
func TestRenderMenuNoTrailingNewline(t *testing.T) {
	var b strings.Builder
	opts := []Option{{Label: "one"}, {Label: "two", Detail: "second"}, {Label: "three"}}
	renderMenu(&b, "pick", opts, 1)
	out := b.String()

	if strings.HasSuffix(out, "\n") {
		t.Fatal("renderMenu output must not end with a newline")
	}
	// One separator between each of the label + len(opts) rows.
	if got := strings.Count(out, "\r\n"); got != len(opts) {
		t.Fatalf("got %d newline separators, want %d", got, len(opts))
	}
	for _, want := range []string{"one", "two", "three", "second"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q", want)
		}
	}
}
