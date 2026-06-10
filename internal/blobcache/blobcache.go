// Package blobcache is a session-scoped cache of encrypted namespace blobs,
// so a warm `notenv run` needs no network round-trip.
//
// It is the storage-side twin of the keyring master-key cache, and obeys the
// same invariant: the blob is only cached on a platform that also caches the
// key, with matching lifecycles. On Linux that means tmpfs (XDG_RUNTIME_DIR)
// paired with the kernel keyring, both RAM-backed and both gone on
// logout/reboot, so encrypted secrets never linger on persistent disk. Other
// platforms get a no-op cache until their key cache lands (macOS Keychain or
// Windows DPAPI).
//
// Only ciphertext is ever cached, which is useless without the key.
package blobcache

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// Cache stores encrypted blobs keyed by (scope, namespace), where scope is
// the storage base (config.CacheScope). Implementations must store only
// ciphertext and never on persistent disk.
type Cache interface {
	// Get returns the cached ciphertext for a blob, if present and fresh.
	Get(scope, namespace string) ([]byte, bool)
	// Put caches ciphertext best-effort.
	Put(scope, namespace string, ciphertext []byte) error
	// Drop invalidates a cached blob.
	Drop(scope, namespace string)
}

// New returns this platform's cache. A non-positive ttl disables caching
// (every Get misses), as does the absence of a suitable RAM-backed store.
func New(ttl time.Duration) Cache {
	if ttl <= 0 {
		return disabled{}
	}
	return newCache(ttl)
}

// disabled is the no-op cache: used when caching is off, the TTL is
// non-positive, or the platform has no RAM-backed ephemeral store.
type disabled struct{}

func (disabled) Get(string, string) ([]byte, bool) { return nil, false }
func (disabled) Put(string, string, []byte) error  { return nil }
func (disabled) Drop(string, string)               {}

// keyFor derives the on-disk filename for a blob. scope is already
// length-prefixed (unambiguous); the NUL separator keeps (scope, namespace)
// from aliasing. Hashed so storage names never leak into the cache dir.
func keyFor(scope, namespace string) string {
	sum := sha256.Sum256([]byte(scope + "\x00" + namespace))
	return hex.EncodeToString(sum[:]) + ".age"
}
