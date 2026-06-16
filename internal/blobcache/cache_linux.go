//go:build linux

package blobcache

import (
	"os"
	"path/filepath"
	"time"

	"github.com/DvGils/notenv/internal/runtimedir"
)

// fsCache stores blobs as files under XDG_RUNTIME_DIR (/run/user/UID). The dir is
// verified to be RAM-backed (tmpfs/ramfs), owner-only, before use, so cached
// ciphertext never reaches persistent disk and cannot outlive the login session,
// no matter when notenv is next run. If it cannot be verified, caching is
// disabled rather than fall back to real disk (see blobDir).
type fsCache struct {
	dir string
	ttl time.Duration
}

// ramBacked verifies a candidate runtime dir; a test seam so the round-trip tests
// can exercise fsCache on an ordinary temp dir that is not actually tmpfs.
var ramBacked = runtimedir.IsRAMBacked

// blobDir returns the tmpfs cache directory and whether one is available. It is
// available only when XDG_RUNTIME_DIR is set and verified RAM-backed; otherwise
// caching is refused rather than land ciphertext on persistent disk.
func blobDir() (string, bool) {
	runtime := os.Getenv("XDG_RUNTIME_DIR")
	if runtime == "" || !ramBacked(runtime) {
		return "", false // no verified RAM-backed dir, refuse to cache on real disk
	}
	return filepath.Join(runtime, "notenv", "blobs"), true
}

func newCache(ttl time.Duration) Cache {
	dir, ok := blobDir()
	if !ok {
		return disabled{}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return disabled{}
	}
	c := fsCache{dir: dir, ttl: ttl}
	c.sweep() // opportunistic: every invocation removes expired entries
	return c
}

// Clear removes every cached blob on this machine and returns the count.
// Works regardless of TTL/config (housekeeping / machine handoff).
func Clear() (int, error) {
	dir, ok := blobDir()
	if !ok {
		return 0, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	removed := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if os.Remove(filepath.Join(dir, e.Name())) == nil {
			removed++
		}
	}
	return removed, nil
}

func (c fsCache) path(scope, namespace string) string {
	return filepath.Join(c.dir, keyFor(scope, namespace))
}

func (c fsCache) Get(scope, namespace string) ([]byte, bool) {
	p := c.path(scope, namespace)
	info, err := os.Stat(p)
	if err != nil {
		return nil, false
	}
	if c.expired(info.ModTime()) {
		_ = os.Remove(p)
		return nil, false
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, false
	}
	return data, true
}

func (c fsCache) Put(scope, namespace string, ciphertext []byte) error {
	// Write to a temp file in the same dir, then rename, so a reader never
	// sees a half-written blob.
	tmp, err := os.CreateTemp(c.dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename succeeds
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(ciphertext); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, c.path(scope, namespace))
}

func (c fsCache) Drop(scope, namespace string) {
	_ = os.Remove(c.path(scope, namespace))
}

func (c fsCache) expired(mod time.Time) bool {
	return time.Since(mod) > c.ttl
}

// sweep deletes every expired entry (and any leaked temp file, which has no
// future mtime and so ages out the same way). Bounds in-session lifetime to
// the TTL even if a blob's own namespace is never read again.
func (c fsCache) sweep() {
	entries, err := os.ReadDir(c.dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if c.expired(info.ModTime()) {
			_ = os.Remove(filepath.Join(c.dir, e.Name()))
		}
	}
}
