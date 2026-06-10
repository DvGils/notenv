//go:build linux

package keyring

import (
	"testing"
	"time"
)

// Exercises the real kernel keyring: store, hit, drop, miss.
// Uses a test-only namespace so it never collides with real cached
// passphrases, and drops it again on the way out.
func TestKernelCacheRoundTrip(t *testing.T) {
	c := newCache()
	const ns = "notenv-test-roundtrip"
	t.Cleanup(func() { c.Drop(ns) })

	if _, ok := c.Get(ns); ok {
		t.Fatal("unexpected cache hit before Store")
	}
	if err := c.Store(ns, "hunter2", time.Minute); err != nil {
		t.Skipf("kernel keyring unavailable in this environment: %v", err)
	}
	got, ok := c.Get(ns)
	if !ok || got != "hunter2" {
		t.Fatalf("Get = %q, %v; want hunter2, true", got, ok)
	}
	c.Drop(ns)
	if _, ok := c.Get(ns); ok {
		t.Fatal("cache hit after Drop")
	}
}

func TestKernelCacheZeroTTLDoesNotStore(t *testing.T) {
	c := newCache()
	const ns = "notenv-test-zerottl"
	t.Cleanup(func() { c.Drop(ns) })

	if err := c.Store(ns, "hunter2", 0); err != nil {
		t.Fatalf("Store with zero TTL should be a no-op, got %v", err)
	}
	if _, ok := c.Get(ns); ok {
		t.Fatal("zero TTL must not cache")
	}
}
