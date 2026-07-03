package ui

import (
	"fmt"
	"io"
	"os"
	"strconv"

	"golang.org/x/term"
)

// Option is one selectable entry; Detail renders dimmed after the label.
type Option struct {
	Label  string
	Detail string
}

// keyAction is the meaning of a key press in the picker.
type keyAction int

const (
	keyNone keyAction = iota
	keyConfirm
	keyCancel
	keyUp
	keyDown
)

// decodeKey maps a raw read from the terminal to an action. Arrow keys
// arrive as the 3-byte escape sequence ESC [ A/B; single bytes cover the
// vi-style and control keys.
func decodeKey(b []byte) keyAction {
	if len(b) == 3 && b[0] == 0x1b && b[1] == '[' {
		switch b[2] {
		case 'A':
			return keyUp
		case 'B':
			return keyDown
		}
		return keyNone
	}
	if len(b) != 1 {
		return keyNone
	}
	switch b[0] {
	case '\r', '\n':
		return keyConfirm
	case 3, 'q', 27: // Ctrl-C, q, bare Esc
		return keyCancel
	case 'k':
		return keyUp
	case 'j':
		return keyDown
	}
	return keyNone
}

// renderMenu draws the option list with the cursor row highlighted. Lines are
// separated by newlines rather than terminated by them, so the cursor finishes
// on the last option's row, not a blank line below it. That stops the terminal
// from scrolling when the menu sits at the bottom of the screen (which would
// otherwise throw off the cursor-up redraw and print a new menu each keypress).
// Each line is cleared with \x1b[2K so a shorter redraw leaves no stale text.
func renderMenu(out io.Writer, label string, options []Option, cursor int) {
	fmt.Fprint(out, "\x1b[2K"+question(label, ""))
	for i, opt := range options {
		line := "  " + opt.Label
		if i == cursor {
			line = Cyan("› " + opt.Label)
		}
		if opt.Detail != "" {
			line += "  " + Dim(opt.Detail)
		}
		fmt.Fprint(out, "\r\n\x1b[2K"+line)
	}
}

// Select renders an arrow-key picker on the controlling terminal and
// returns the chosen index. Keys: up/down (or k/j), Enter to choose,
// Esc/q/Ctrl-C to cancel (returns ErrCanceled). Without a usable raw-mode
// terminal it falls back to a numbered prompt.
func Select(label string, options []Option) (int, error) {
	if len(options) == 0 {
		return -1, fmt.Errorf("select %q: no options", label)
	}
	f, err := tty()
	if err != nil {
		return -1, err
	}
	if f != os.Stdin {
		defer func() { _ = f.Close() }()
	}

	fd := int(f.Fd())
	previous, err := term.MakeRaw(fd)
	if err != nil {
		return selectNumbered(label, options)
	}
	defer func() { _ = term.Restore(fd, previous) }()

	out := os.Stderr
	fmt.Fprint(out, "\x1b[?25l")       // hide cursor
	defer fmt.Fprint(out, "\x1b[?25h") // show cursor

	cursor := 0
	// After renderMenu the cursor sits on the last option's row. moveTop
	// returns to the start of the menu (label row, column 0); wipe also erases
	// the menu from there to the end of the screen.
	moveTop := func() { fmt.Fprintf(out, "\x1b[%dA\r", len(options)) }
	wipe := func() { moveTop(); fmt.Fprint(out, "\x1b[0J") }

	renderMenu(out, label, options, cursor)
	buf := make([]byte, 3)
	for {
		n, err := f.Read(buf)
		if err != nil {
			wipe()
			return -1, err
		}
		switch decodeKey(buf[:n]) {
		case keyConfirm:
			wipe()
			_ = term.Restore(fd, previous)
			fmt.Fprintln(out, question(label, "")+options[cursor].Label)
			return cursor, nil
		case keyCancel:
			wipe()
			return -1, ErrCanceled
		case keyUp:
			cursor = (cursor + len(options) - 1) % len(options)
		case keyDown:
			cursor = (cursor + 1) % len(options)
		default:
			continue
		}
		moveTop()
		renderMenu(out, label, options, cursor)
	}
}

// selectNumbered is the no-raw-mode fallback: print the list, read a number.
func selectNumbered(label string, options []Option) (int, error) {
	for i, opt := range options {
		line := fmt.Sprintf("  %d) %s", i+1, opt.Label)
		if opt.Detail != "" {
			line += "  " + Dim(opt.Detail)
		}
		fmt.Fprintln(os.Stderr, line)
	}
	answer, err := Input(label, "1-"+strconv.Itoa(len(options)))
	if err != nil {
		return -1, err
	}
	choice, err := strconv.Atoi(answer)
	if err != nil || choice < 1 || choice > len(options) {
		return -1, fmt.Errorf("invalid choice %q", answer)
	}
	return choice - 1, nil
}
