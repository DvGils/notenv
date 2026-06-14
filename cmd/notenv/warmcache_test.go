package main

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/DvGils/notenv/internal/crypto"
	"github.com/DvGils/notenv/internal/secrets"
)

// mapBlobCache is an in-memory blobcache.Cache for the warm-path tests (the real
// one is tmpfs/keyring-backed and a no-op off Linux).
type mapBlobCache struct{ m map[string][]byte }

func newMapBlobCache() *mapBlobCache { return &mapBlobCache{m: map[string][]byte{}} }

func (c *mapBlobCache) Get(scope, ns string) ([]byte, bool) {
	v, ok := c.m[scope+"\x00"+ns]
	return v, ok
}
func (c *mapBlobCache) Put(scope, ns string, b []byte) error {
	c.m[scope+"\x00"+ns] = b
	return nil
}
func (c *mapBlobCache) Drop(scope, ns string) { delete(c.m, scope+"\x00"+ns) }

func warmApp(t *testing.T) (*app, *mapBlobCache, *crypto.MasterKey) {
	t.Helper()
	mk, err := crypto.GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	blobs := newMapBlobCache()
	a := &app{namespace: "proj", cache: newMapCache(), blobs: blobs, cacheScope: "scope"}
	a.cache.Store(a.cacheScope, mk.String(), time.Hour)
	return a, blobs, mk
}

// TestWarmCacheRoundTrip: a cached state reads back identically.
func TestWarmCacheRoundTrip(t *testing.T) {
	a, _, mk := warmApp(t)
	state := &secrets.State{Secrets: map[string]string{"K": "v"}, Meta: map[string]secrets.Meta{}}

	a.cacheState(mk, state)
	got, ok := a.cachedSecrets()
	if !ok {
		t.Fatal("a freshly cached state must read back")
	}
	if got.secrets["K"] != "v" {
		t.Fatalf("K = %q, want v", got.secrets["K"])
	}
}

// TestWarmCacheRejectsForgedEntry is the S5 guard: age encryption is to the
// master's PUBLIC recipient (exposed in the cleartext header), so an attacker who
// can write the cache dir can plant a blob that decrypts cleanly. The
// master-keyed MAC, which that attacker cannot forge, must make the warm path
// reject it and fall through to the authenticated read.
func TestWarmCacheRejectsForgedEntry(t *testing.T) {
	a, blobs, mk := warmApp(t)

	// A fully decode-able forged payload (encrypted to the master's recipient,
	// which models an attacker who only has the public key), but with a MAC the
	// attacker could not have computed without the master's secret material.
	evil, err := encodePayload(&secrets.State{Secrets: map[string]string{"K": "attacker"}, Meta: map[string]secrets.Meta{}})
	if err != nil {
		t.Fatal(err)
	}
	forged, err := mk.Encrypt(evil)
	if err != nil {
		t.Fatal(err)
	}
	env, err := json.Marshal(cacheEnvelope{MAC: "forged-not-a-real-mac", Sealed: forged})
	if err != nil {
		t.Fatal(err)
	}
	_ = blobs.Put(a.cacheScope, a.namespace, env)

	if _, ok := a.cachedSecrets(); ok {
		t.Fatal("a cache entry whose MAC is not the master's must be rejected, even though it decrypts")
	}
}

// TestWarmCacheRejectsTamperedEntry: flipping a byte of a legitimately cached
// ciphertext breaks its MAC, so the warm path rejects it.
func TestWarmCacheRejectsTamperedEntry(t *testing.T) {
	a, blobs, mk := warmApp(t)
	a.cacheState(mk, &secrets.State{Secrets: map[string]string{"K": "v"}, Meta: map[string]secrets.Meta{}})

	raw, _ := blobs.Get(a.cacheScope, a.namespace)
	var env cacheEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	env.Sealed[0] ^= 0xFF
	tampered, _ := json.Marshal(env)
	_ = blobs.Put(a.cacheScope, a.namespace, tampered)

	if _, ok := a.cachedSecrets(); ok {
		t.Fatal("a tampered cache entry must be rejected")
	}
}
