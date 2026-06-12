//go:build windows

package local

import (
	"os"

	"golang.org/x/sys/windows"
)

// lockExclusive takes an exclusive lock on path via LockFileEx, blocking
// until it is available, and returns the release. The lock belongs to the
// handle, so the kernel releases it when the process dies: no stale lock can
// outlive its holder.
func lockExclusive(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	ol := new(windows.Overlapped)
	if err := windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, ol); err != nil {
		_ = f.Close()
		return nil, err
	}
	return func() {
		_ = windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, ol)
		_ = f.Close()
	}, nil
}
