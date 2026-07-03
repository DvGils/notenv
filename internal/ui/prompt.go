package ui

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

// ErrCanceled is returned when the user aborts a prompt (Esc, q, Ctrl-C).
var ErrCanceled = errors.New("canceled")

// tty opens the controlling terminal for interaction, preferring /dev/tty
// so prompts work even when stdin/stdout are pipes.
func tty() (*os.File, error) {
	if f, err := os.Open("/dev/tty"); err == nil {
		return f, nil
	}
	if term.IsTerminal(int(os.Stdin.Fd())) {
		return os.Stdin, nil
	}
	return nil, errors.New("interactive prompt needs a terminal; pass the value with a flag instead")
}

// Interactive reports whether prompts are possible at all.
func Interactive() bool {
	if f, err := os.Open("/dev/tty"); err == nil {
		_ = f.Close()
		return true
	}
	return term.IsTerminal(int(os.Stdin.Fd()))
}

func question(label, hint string) string {
	q := Cyan("?") + " " + Bold(label)
	if hint != "" {
		q += " " + Dim("("+hint+")")
	}
	return q + " " + Dim("›") + " "
}

// Input reads one echoed line; empty input returns def.
func Input(label, def string) (string, error) {
	in, err := tty()
	if err != nil {
		return "", err
	}
	if in != os.Stdin {
		defer func() { _ = in.Close() }()
	}
	fmt.Fprint(os.Stderr, question(label, def))
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil {
		return "", err
	}
	if value := strings.TrimSpace(line); value != "" {
		return value, nil
	}
	return def, nil
}

// Confirm asks a yes/no question.
func Confirm(label string, def bool) (bool, error) {
	hint := "y/N"
	if def {
		hint = "Y/n"
	}
	answer, err := Input(label, hint)
	if err != nil {
		return false, err
	}
	switch strings.ToLower(answer) {
	case "y", "yes":
		return true, nil
	case "n", "no":
		return false, nil
	default:
		return def, nil
	}
}
