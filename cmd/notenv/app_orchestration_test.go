package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/DvGils/notenv/internal/backend/memstore"
	"github.com/DvGils/notenv/internal/crypto"
	"github.com/DvGils/notenv/internal/keymgmt"
	"github.com/DvGils/notenv/internal/secrets"
)

// identityApp builds an app over a recipient-locked vault and points
// NOTENV_IDENTITY at the matching key, so the cold unlock path (master ->
// ensureMaster -> resolveUnlock) runs without a terminal. The namespace "proj"
// is seeded with kv. Caches are the in-memory test doubles, so warming is
// deterministic and touches no real keyring or tmpfs.
func identityApp(t *testing.T, kv map[string]string) (*app, *memstore.Store, *crypto.MasterKey) {
	t.Helper()
	isolateConfig(t)
	ctx := context.Background()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(identityEnv, id.String())
	store := memstore.New()
	header, mk, err := crypto.NewRecipientHeader(id.Recipient(), "owner")
	if err != nil {
		t.Fatal(err)
	}
	header.Revision = 0
	verify := func(hh *crypto.Header) (*crypto.MasterKey, error) { m, _, e := hh.UnlockIdentity(id); return m, e }
	if err := keymgmt.SafePut(ctx, store, header, nil, mk, verify); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	for k, v := range kv {
		writes := []secrets.Write{{Key: k, Value: v, TS: now}}
		if _, _, err := secrets.For(store, "proj", mk).Commit(ctx,
			func(cur *secrets.State) (*secrets.State, error) { return cur.Apply(writes), nil }, nil); err != nil {
			t.Fatalf("seed %s: %v", k, err)
		}
	}
	a := &app{
		namespace:  "proj",
		store:      store,
		cache:      newMapCache(),
		blobs:      newMapBlobCache(),
		cacheScope: "scope",
		cacheTTL:   time.Hour,
	}
	return a, store, mk
}

func TestReportCorruptWarnsPerBlob(t *testing.T) {
	a := &app{namespace: "proj"}
	state := &secrets.State{Corrupt: []secrets.CorruptBlob{
		{Blob: "proj/data-1.age", Reason: "bad MAC"},
		{Blob: "proj/data-2.age", Reason: "missing"},
	}}
	out := captureStderr(t, func() { a.reportCorrupt(state) })
	for _, want := range []string{"proj/data-1.age", "bad MAC", "proj/data-2.age", "missing"} {
		if !strings.Contains(out, want) {
			t.Errorf("reportCorrupt output missing %q: %s", want, out)
		}
	}
}

func TestMasterCacheHitAndSessionGuard(t *testing.T) {
	ctx := context.Background()
	a, _, mk := guardApp(t) // master pre-cached under a.cacheScope
	got, err := a.master(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.PublicKey() != mk.PublicKey() {
		t.Fatal("master() did not return the cached master")
	}
	// Inside a foreign handoff session, master() refuses outright.
	t.Setenv(sessionEnv, "another-scope")
	if _, err := a.master(ctx); err == nil {
		t.Fatal("master() must refuse a vault outside the active session")
	}
}

func TestUnlockViewColdViaIdentity(t *testing.T) {
	ctx := context.Background()
	a, _, mk := identityApp(t, map[string]string{"K": "vvvvvv"})
	view, err := a.unlockView(ctx)
	if err != nil {
		t.Fatalf("unlockView: %v", err)
	}
	if view == nil || view.header == nil {
		t.Fatal("unlockView returned no view")
	}
	if view.mk.PublicKey() != mk.PublicKey() {
		t.Fatal("unlockView resolved a different master")
	}
}

func TestReadStateColdReadsNamespace(t *testing.T) {
	ctx := context.Background()
	a, _, _ := identityApp(t, map[string]string{"K": "vvvvvv", "K2": "wwwwww"})
	state, view, err := a.readState(ctx)
	if err != nil {
		t.Fatalf("readState: %v", err)
	}
	if view == nil {
		t.Fatal("readState returned no view")
	}
	if state.Secrets["K"] != "vvvvvv" || state.Secrets["K2"] != "wwwwww" {
		t.Fatalf("readState resolved wrong secrets: %v", state.Secrets)
	}
}

// TestWithMasterRecoversFromStaleCache: when fn fails under a cached master (the
// shape of another machine having re-keyed), withMaster drops the cache, unlocks
// fresh, and retries fn once.
func TestWithMasterRecoversFromStaleCache(t *testing.T) {
	ctx := context.Background()
	a, _, mk := identityApp(t, map[string]string{"K": "vvvvvv"})
	a.cache.Store(a.cacheScope, mk.String(), time.Hour) // wasCached on entry
	calls := 0
	got, err := a.withMaster(ctx, func(*crypto.MasterKey) error {
		calls++
		if calls == 1 {
			return errors.New("stale master")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("withMaster did not recover: %v", err)
	}
	if calls != 2 {
		t.Fatalf("expected one retry after dropping the stale cache, got %d calls", calls)
	}
	if got.PublicKey() != mk.PublicKey() {
		t.Fatal("recovered a different master")
	}
}

// TestFetchSecretsWarmServesWithoutStorage: a second read is served entirely
// from the warm caches, proven by cutting storage off before it.
func TestFetchSecretsWarmServesWithoutStorage(t *testing.T) {
	ctx := context.Background()
	a, _, _ := identityApp(t, map[string]string{"K": "vvvvvv"})
	if res, err := a.fetchSecrets(ctx, false, false); err != nil || res.secrets["K"] != "vvvvvv" {
		t.Fatalf("cold fetch: res=%v err=%v", res, err)
	}
	a.store = nil // a warm fetch must not reach for storage
	res, err := a.fetchSecrets(ctx, false, false)
	if err != nil {
		t.Fatalf("warm fetch touched storage or failed: %v", err)
	}
	if res.secrets["K"] != "vvvvvv" {
		t.Fatalf("warm fetch resolved wrong secrets: %v", res.secrets)
	}
}
