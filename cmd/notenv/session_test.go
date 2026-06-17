package main

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/DvGils/notenv/internal/config"
	"github.com/DvGils/notenv/internal/crypto"
)

func TestNoCacheLeaseRoundTrip(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())

	if noCacheLeaseActive() {
		t.Fatal("lease reported active before any was taken")
	}
	release, err := takeNoCacheLease()
	if err != nil {
		t.Fatalf("takeNoCacheLease: %v", err)
	}
	if !noCacheLeaseActive() {
		t.Fatal("lease not active after takeNoCacheLease")
	}
	release()
	if noCacheLeaseActive() {
		t.Fatal("lease still active after release")
	}
}

func TestNoCacheLeaseStaleMarkersRemoved(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())

	dir, err := noCacheLeaseDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// A dead-PID marker and a stray non-PID file: neither is a live holder.
	for _, name := range []string{"999999999", "not-a-pid"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if noCacheLeaseActive() {
		t.Fatal("a lease dir with only dead/stray markers reported active")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("stale lease dir was not cleaned up (err=%v)", err)
	}
}

// TestNoCacheLeaseRefcountSurvivesConcurrentRelease guards the refcount: a second
// concurrent handoff must keep the lease alive when the first releases. The second
// supervisor is stood in for by our parent process, which is guaranteed alive.
func TestNoCacheLeaseRefcountSurvivesConcurrentRelease(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())

	release, err := takeNoCacheLease() // this process: holder one
	if err != nil {
		t.Fatal(err)
	}
	dir, err := noCacheLeaseDir()
	if err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(dir, strconv.Itoa(os.Getppid())) // holder two (live)
	if err := os.WriteFile(other, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	release() // holder one ends; holder two is still live
	if !noCacheLeaseActive() {
		t.Fatal("lease dropped after one of two concurrent holders released (refcount broken)")
	}

	if err := os.Remove(other); err != nil { // holder two ends
		t.Fatal(err)
	}
	if noCacheLeaseActive() {
		t.Fatal("lease still active after all holders released")
	}
}

func TestSessionGuard(t *testing.T) {
	const scopeE = "1::local:/tmp/ephemeral"
	const scopeReal = "2:b2:notenv"

	// No session: every scope is allowed.
	t.Setenv(sessionEnv, "")
	if err := sessionGuard(scopeReal); err != nil {
		t.Fatalf("with no session, sessionGuard(%q) = %v, want nil", scopeReal, err)
	}

	// In a session: only the ephemeral scope unlocks.
	t.Setenv(sessionEnv, scopeE)
	if err := sessionGuard(scopeE); err != nil {
		t.Fatalf("in session, sessionGuard(ephemeral) = %v, want nil", err)
	}
	if err := sessionGuard(scopeReal); err == nil {
		t.Fatal("in session, sessionGuard(real vault) = nil, want a refusal")
	}
}

// fakeCache records Store calls so a test can assert caching was suppressed.
type fakeCache struct {
	stored map[string]string
}

func (c *fakeCache) Get(scope string) (string, bool) { v, ok := c.stored[scope]; return v, ok }
func (c *fakeCache) Store(scope, key string, _ time.Duration) error {
	if c.stored == nil {
		c.stored = map[string]string{}
	}
	c.stored[scope] = key
	return nil
}
func (c *fakeCache) Drop(scope string) { delete(c.stored, scope) }

func TestCacheMasterSkipsWhileHandoffLeased(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())

	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	_, mk, err := crypto.NewRecipientHeader(id.Recipient(), "test")
	if err != nil {
		t.Fatal(err)
	}

	// No lease: the master is cached.
	cache := &fakeCache{}
	cacheMaster(cache, "1::local:/srv/vault", mk, time.Hour)
	if _, ok := cache.Get("1::local:/srv/vault"); !ok {
		t.Fatal("master was not cached with no lease in force")
	}

	// Lease held: caching is suppressed for EVERY scope, not just the handed-off
	// one (the lease is global), so a sibling vault unlocked mid-session stays cold.
	release, err := takeNoCacheLease()
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	for _, scope := range []string{"1::local:/srv/vault", "2:b2:other"} {
		c := &fakeCache{}
		cacheMaster(c, scope, mk, time.Hour)
		if _, ok := c.Get(scope); ok {
			t.Fatalf("master for %q was cached while a no-cache lease was held", scope)
		}
	}
}

// TestDropAllCachedMasters: handoff clears every vault this machine has cached, so
// no sibling master is left in the agent-readable per-uid keyring.
func TestDropAllCachedMasters(t *testing.T) {
	isolateConfig(t)
	scopes := []string{"1::local:/srv/a", "2:b2:b"}
	for _, s := range scopes { // a cached master implies a pin; AcceptNamespace pins
		if err := config.AcceptNamespace(s, "ns"); err != nil {
			t.Fatal(err)
		}
	}
	cache := &fakeCache{stored: map[string]string{scopes[0]: "ka", scopes[1]: "kb"}}
	dropAllCachedMasters(cache)
	for _, s := range scopes {
		if _, ok := cache.Get(s); ok {
			t.Fatalf("pinned scope %q was not dropped from the cache", s)
		}
	}
}
