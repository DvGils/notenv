//go:build !linux

package blobcache

import "time"

// No RAM-backed, session-scoped store is wired yet on macOS/Windows, and the
// invariant is to cache the blob only where the key is cached; their key
// caches (Keychain/DPAPI) are not built either. So caching is a no-op here:
// reads pay the network round-trip, exactly as the key prompt happens every
// time today. Lands together with the platform key cache.
func newCache(time.Duration) Cache { return disabled{} }

// Clear is a no-op where there is no cache.
func Clear() (int, error) { return 0, nil }
