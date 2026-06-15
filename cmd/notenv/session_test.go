package main

import (
	"os"
	"path/filepath"
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
	dir := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", dir)

	cases := map[string]string{
		"1::local:/garbage": "not-a-pid", // unreadable content
		"1::local:/deadpid": "999999999", // a PID no process holds
	}
	for scope, content := range cases {
		marker, err := leaseMarker(scope)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(marker), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(marker, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if leaseActive(scope) {
			t.Fatalf("scope %q with stale marker %q reported active", scope, content)
		}
		if _, err := os.Stat(marker); !os.IsNotExist(err) {
			t.Errorf("stale marker for %q was not removed (err=%v)", scope, err)
		}
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
