// Package runner executes the child process with secrets in its
// environment: exec, stream stdio, propagate exit code.
// Plaintext exists only in the child's env for its lifetime; Masker
// additionally scrubs the values from captured output.
package runner

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"
)

// waitDelay bounds how long Wait blocks on the child's stdout/stderr pipes
// after the child itself has exited. The pipes only exist when a non-file
// writer (a Masker) is interposed; a grandchild that inherited them and
// outlives the child would otherwise hold Wait open forever.
const waitDelay = 10 * time.Second

// StartError reports that the child process never ran (the command was not
// found, not executable, or the spawn itself failed) — as opposed to an error
// after a successful start. Callers map the distinction to exit codes.
type StartError struct{ Err error }

func (e *StartError) Error() string { return e.Err.Error() }
func (e *StartError) Unwrap() error { return e.Err }

// Run executes argv with the given environment, wiring stdin through (nil
// reads as empty — for callers whose own stdin belongs to a protocol) and
// streaming the child's output to stdout/stderr (pass os.Stdout/os.Stderr for
// a direct wire, or Maskers to scrub captured output — the caller flushes
// those after Run returns), forwarding termination signals to the child. It
// returns the child's exit code (128+signal if the child was killed by a
// signal); a child that never started is a *StartError.
func Run(argv []string, env []string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = env
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.WaitDelay = waitDelay

	if err := cmd.Start(); err != nil {
		return -1, &StartError{Err: fmt.Errorf("exec %s: %w", argv[0], err)}
	}

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case sig := <-signals:
				_ = cmd.Process.Signal(sig)
			case <-done:
				return
			}
		}
	}()

	err := cmd.Wait()
	close(done)
	signal.Stop(signals)

	if errors.Is(err, exec.ErrWaitDelay) {
		// The child itself exited; only a lingering pipe holder (a grandchild
		// that inherited stdout) was cut loose. Report the child's real exit.
		err = nil
	}
	if err == nil {
		return exitCode(cmd.ProcessState), nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exitCode(exit.ProcessState), nil
	}
	return -1, err
}

func exitCode(state *os.ProcessState) int {
	if ws, ok := state.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int(ws.Signal())
	}
	return state.ExitCode()
}
