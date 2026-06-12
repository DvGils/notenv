//go:build unix

package local

import (
	"os"

	"golang.org/x/sys/unix"
)

// lockExclusive takes an exclusive advisory lock on path, blocking until it
// is available, and returns the release. flock locks belong to the open file
// description, so the kernel releases them when the process dies (no stale
// lock can outlive its holder), and two calls in one process exclude each
// other because each opens its own descriptor.
func lockExclusive(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, err
	}
	return func() {
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
		_ = f.Close()
	}, nil
}
