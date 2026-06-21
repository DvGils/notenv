package ui

import (
	"fmt"
	"os"
	"time"
)

var frames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// Spin runs fn while animating a spinner on stderr, then reports the
// outcome as a success or failure status line. Off-TTY it degrades to plain lines.
func Spin(label string, fn func() error) error { return spin(label, false, fn) }

// SpinSub is Spin rendered as a sub-step of a phase: dim and indented while
// running, and it leaves a dim Substep line on success instead of a top-level
// status, so a phase's individual steps stay subordinate to its Heading. A
// failure still surfaces at full weight.
func SpinSub(label string, fn func() error) error { return spin(label, true, fn) }

func spin(label string, sub bool, fn func() error) error {
	if !styled {
		if !sub {
			Infof("%s…", label)
		}
		return report(label, sub, fn())
	}

	done := make(chan error, 1)
	go func() { done <- fn() }()

	ticker := time.NewTicker(80 * time.Millisecond)
	defer ticker.Stop()
	for i := 0; ; i++ {
		select {
		case err := <-done:
			fmt.Fprint(os.Stderr, "\r\x1b[2K")
			return report(label, sub, err)
		case <-ticker.C:
			frame := frames[i%len(frames)]
			if sub {
				fmt.Fprintf(os.Stderr, "\r\x1b[2K  %s %s", Dim(frame), Dim(label))
			} else {
				fmt.Fprintf(os.Stderr, "\r\x1b[2K%s %s", Cyan(frame), label)
			}
		}
	}
}

func report(label string, sub bool, err error) error {
	if err != nil {
		Failf("%s", label)
		return err
	}
	if sub {
		Substep("%s", label)
	} else {
		Successf("%s", label)
	}
	return nil
}
