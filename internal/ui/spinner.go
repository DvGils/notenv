package ui

import (
	"fmt"
	"os"
	"time"
)

var frames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// Spin runs fn while animating a spinner on stderr, then reports the
// outcome as a success or failure status line. Off-TTY it degrades to plain lines.
func Spin(label string, fn func() error) error {
	if !styled {
		Infof("%s…", label)
		return report(label, fn())
	}

	done := make(chan error, 1)
	go func() { done <- fn() }()

	ticker := time.NewTicker(80 * time.Millisecond)
	defer ticker.Stop()
	for i := 0; ; i++ {
		select {
		case err := <-done:
			fmt.Fprint(os.Stderr, "\r\x1b[2K")
			return report(label, err)
		case <-ticker.C:
			fmt.Fprintf(os.Stderr, "\r\x1b[2K%s %s", Cyan(frames[i%len(frames)]), label)
		}
	}
}

func report(label string, err error) error {
	if err != nil {
		Failf("%s", label)
		return err
	}
	Successf("%s", label)
	return nil
}
