package main

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/DvGils/notenv/internal/crypto"
)

func TestLeaseRoundTrip(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	const scope = "1::local:/srv/vault"

	if leaseActive(scope) {
		t.Fatal("scope is leased before any lease was taken")
	}
	release, err := takeLease(scope)
	if err != nil {
		t.Fatalf("takeLease: %v", err)
	}
	if !leaseActive(scope) {
		t.Fatal("scope is not leased after takeLease")
	}
	// A different scope is unaffected.
	if leaseActive("1::local:/srv/other") {
		t.Fatal("an unrelated scope is reported leased")
	}
	release()
	if leaseActive(scope) {
		t.Fatal("scope is still leased after release")
	}
}

func TestLeaseStaleMarkersRemoved(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	const scope = "1::local:/srv/dead"

	dir, err := leaseDir(scope)
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
	if leaseActive(scope) {
		t.Fatal("a lease dir with only dead/stray markers reported active")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("stale lease dir was not cleaned up (err=%v)", err)
	}
}

// TestLeaseRefcountSurvivesConcurrentRelease guards the v0.19.1 fix: a second
// concurrent handoff of the same source vault must keep the lease alive when the
// first releases. The second supervisor is stood in for by our parent process,
// which is guaranteed to be alive.
func TestLeaseRefcountSurvivesConcurrentRelease(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	const scope = "1::local:/srv/shared"

	release, err := takeLease(scope) // this process: holder one
	if err != nil {
		t.Fatal(err)
	}
	dir, err := leaseDir(scope)
	if err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(dir, strconv.Itoa(os.Getppid())) // holder two (live)
	if err := os.WriteFile(other, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	release() // holder one ends; holder two is still live
	if !leaseActive(scope) {
		t.Fatal("lease dropped after one of two concurrent holders released (refcount broken)")
	}

	if err := os.Remove(other); err != nil { // holder two ends
		t.Fatal(err)
	}
	if leaseActive(scope) {
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

func TestCacheMasterSkipsWhenLeased(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	const scope = "1::local:/srv/vault"

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
	cacheMaster(cache, scope, mk, time.Hour)
	if _, ok := cache.Get(scope); !ok {
		t.Fatal("master was not cached with no lease in force")
	}

	// Lease held: caching is suppressed.
	release, err := takeLease(scope)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	cache2 := &fakeCache{}
	cacheMaster(cache2, scope, mk, time.Hour)
	if _, ok := cache2.Get(scope); ok {
		t.Fatal("master was cached while a no-cache lease was held")
	}
}
