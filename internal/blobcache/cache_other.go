//go:build !linux

package blobcache

import "time"

// macOS and Windows cache the master key (Keychain/DPAPI), but there is no
// RAM-backed, session-scoped store to hold ciphertext blobs that a logout or
// reboot reliably reclaims, so blob caching stays Linux-only by design. Here it
// is a no-op: reads pay the network round-trip, while the key prompt is still
// spared by the platform key cache.
func newCache(time.Duration) Cache { return disabled{} }

// Clear is a no-op where there is no cache.
func Clear() (int, error) { return 0, nil }
