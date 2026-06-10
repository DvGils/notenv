package ui

import (
	"fmt"
	"os"
	"strconv"

	"golang.org/x/term"
)

// Option is one selectable entry; Detail renders dimmed after the label.
type Option struct {
	Label  string
	Detail string
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
		defer f.Close()
	}

	fd := int(f.Fd())
	previous, err := term.MakeRaw(fd)
	if err != nil {
		return selectNumbered(label, options)
	}
	defer term.Restore(fd, previous)

	out := os.Stderr
	fmt.Fprint(out, "\x1b[?25l")       // hide cursor
	defer fmt.Fprint(out, "\x1b[?25h") // show cursor

	cursor := 0
	render := func() {
		fmt.Fprint(out, question(label, "")+"\r\n")
		for i, opt := range options {
			line := "  " + opt.Label
			if i == cursor {
				line = Cyan("› " + opt.Label)
			}
			if opt.Detail != "" {
				line += "  " + Dim(opt.Detail)
			}
			fmt.Fprint(out, "\x1b[2K"+line+"\r\n")
		}
	}
	rewind := func() { fmt.Fprintf(out, "\x1b[%dA", len(options)+1) }
	clear := func() {
		fmt.Fprintf(out, "\x1b[%dA\x1b[J", len(options)+1) // wipe the menu
	}

	render()
	buf := make([]byte, 3)
	for {
		n, err := f.Read(buf)
		if err != nil {
			clear()
			return -1, err
		}
		key := buf[:n]
		switch {
		case n == 1 && (key[0] == '\r' || key[0] == '\n'):
			clear()
			term.Restore(fd, previous)
			fmt.Fprintln(out, question(label, "")+options[cursor].Label)
			return cursor, nil
		case n == 1 && (key[0] == 3 || key[0] == 'q' || key[0] == 27): // Ctrl-C, q, bare Esc
			clear()
			return -1, ErrCanceled
		case n == 1 && key[0] == 'k', n == 3 && key[2] == 'A': // up
			cursor = (cursor + len(options) - 1) % len(options)
		case n == 1 && key[0] == 'j', n == 3 && key[2] == 'B': // down
			cursor = (cursor + 1) % len(options)
		default:
			continue
		}
		rewind()
		render()
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
