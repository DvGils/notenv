//go:build linux

package keyring

import (
	"time"

	"golang.org/x/sys/unix"
)

// kernelCache stores master keys as "user"-type keys in the kernel's
// per-UID user keyring. Keys live in kernel memory only, are shared across
// the user's processes (prompt once per login session), and the kernel
// enforces the TTL.
type kernelCache struct{}

func newCache() Cache { return kernelCache{} }

func keyDesc(scope string) string { return "notenv:" + scope }

func (kernelCache) Get(scope string) (string, bool) {
	id, err := unix.KeyctlSearch(unix.KEY_SPEC_USER_KEYRING, "user", keyDesc(scope), 0)
	if err != nil {
		return "", false
	}
	size, err := unix.KeyctlBuffer(unix.KEYCTL_READ, id, nil, 0)
	if err != nil || size <= 0 {
		return "", false
	}
	buf := make([]byte, size)
	n, err := unix.KeyctlBuffer(unix.KEYCTL_READ, id, buf, 0)
	if err != nil {
		return "", false
	}
	return string(buf[:n]), true
}

func (kernelCache) Store(scope, masterKey string, ttl time.Duration) error {
	if ttl <= 0 {
		return nil
	}
	id, err := unix.AddKey("user", keyDesc(scope), []byte(masterKey), unix.KEY_SPEC_USER_KEYRING)
	if err != nil {
		return err
	}
	_, err = unix.KeyctlInt(unix.KEYCTL_SET_TIMEOUT, id, int(ttl.Seconds()), 0, 0)
	if err != nil {
		// A key that cannot be expired must not linger: drop it and skip caching.
		_, _ = unix.KeyctlInt(unix.KEYCTL_INVALIDATE, id, 0, 0, 0)
		return err
	}
	return nil
}

func (kernelCache) Drop(scope string) {
	id, err := unix.KeyctlSearch(unix.KEY_SPEC_USER_KEYRING, "user", keyDesc(scope), 0)
	if err != nil {
		return
	}
	_, _ = unix.KeyctlInt(unix.KEYCTL_INVALIDATE, id, 0, 0, 0)
}
