//go:build !windows

package main

import (
	"errors"
	"syscall"
)

// pidAlive reports whether a process with this PID exists. Signal 0 performs the
// permission/existence check without delivering a signal: nil means it exists and
// is ours, EPERM means it exists but is owned by another user (still alive),
// ESRCH means it is gone.
func pidAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}
