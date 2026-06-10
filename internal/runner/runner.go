// Package runner executes the child process with secrets in its
// environment: exec, stream stdio, propagate exit code.
// Plaintext exists only in the child's env for its lifetime.
package runner

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
)

// Run executes argv with the given environment, wiring the parent's stdio
// through and forwarding termination signals to the child. It returns the
// child's exit code (128+signal if the child was killed by a signal).
func Run(argv []string, env []string) (int, error) {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return -1, fmt.Errorf("exec %s: %w", argv[0], err)
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

	if err == nil {
		return 0, nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		if ws, ok := exit.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return 128 + int(ws.Signal()), nil
		}
		return exit.ExitCode(), nil
	}
	return -1, err
}
