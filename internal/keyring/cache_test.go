package keyring

import (
	"testing"
	"time"
)

// The cache conformance set runs against whatever newCache returns on this
// platform: kernel keyring on Linux, Keychain on macOS, DPAPI on Windows,
// the null cache elsewhere. An environment without a usable store (a locked
// CI keychain) skips rather than fails; the null cache passes trivially
// (every Get is a miss and Store is a no-op).

func TestCacheRoundTrip(t *testing.T) {
	c := newCache()
	const ns = "notenv-test-roundtrip"
	t.Cleanup(func() { c.Drop(ns) })

	if _, ok := c.Get(ns); ok {
		t.Fatal("unexpected cache hit before Store")
	}
	if err := c.Store(ns, "hunter2", time.Minute); err != nil {
		t.Skipf("platform key store unavailable in this environment: %v", err)
	}
	got, ok := c.Get(ns)
	if cacheIsNull {
		if ok {
			t.Fatal("the null cache must never hit")
		}
		return
	}
	if !ok || got != "hunter2" {
		t.Fatalf("Get = %q, %v; want hunter2, true", got, ok)
	}
	c.Drop(ns)
	if _, ok := c.Get(ns); ok {
		t.Fatal("cache hit after Drop")
	}
}

func TestCacheZeroTTLDoesNotStore(t *testing.T) {
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

// TestCacheTTLExpires: an entry past its TTL is a miss. The kernel keyring
// enforces the deadline itself; the native stores enforce it lazily on read.
// Either way, the contract observable here is the same: expired means gone.
func TestCacheTTLExpires(t *testing.T) {
	c := newCache()
	if cacheIsNull {
		t.Skip("null cache has nothing to expire")
	}
	const ns = "notenv-test-expiry"
	t.Cleanup(func() { c.Drop(ns) })

	if err := c.Store(ns, "hunter2", time.Second); err != nil {
		t.Skipf("platform key store unavailable in this environment: %v", err)
	}
	if _, ok := c.Get(ns); !ok {
		t.Fatal("entry must be readable inside its TTL")
	}
	time.Sleep(1500 * time.Millisecond)
	if got, ok := c.Get(ns); ok {
		t.Fatalf("entry must expire after its TTL, got %q", got)
	}
	if _, ok := c.Get(ns); ok {
		t.Fatal("an expired entry must stay gone")
	}
}
