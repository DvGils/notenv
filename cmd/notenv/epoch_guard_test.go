package main

import (
	"context"
	"testing"
	"time"

	"github.com/DvGils/notenv/internal/backend/memstore"
	"github.com/DvGils/notenv/internal/blobcache"
	"github.com/DvGils/notenv/internal/crypto"
	"github.com/DvGils/notenv/internal/secrets"
)

// mapCache is an in-memory keyring.Cache so the guard tests never touch the
// real kernel keyring.
type mapCache struct{ m map[string]string }

func newMapCache() *mapCache { return &mapCache{m: map[string]string{}} }

func (c *mapCache) Get(scope string) (string, bool) { v, ok := c.m[scope]; return v, ok }
func (c *mapCache) Store(scope, secret string, _ time.Duration) error {
	c.m[scope] = secret
	return nil
}
func (c *mapCache) Drop(scope string) { delete(c.m, scope) }

// guardApp builds an app over a memstore vault, returning it with the master.
func guardApp(t *testing.T) (*app, *memstore.Store, *crypto.MasterKey) {
	t.Helper()
	isolateConfig(t) // the view's pin checks write local trust state
	store := memstore.New()
	header, mk, err := crypto.NewHeader("pass", "owner")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := header.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	store.SetHeader(raw)
	a := &app{
		namespace:  "proj",
		store:      store,
		cache:      newMapCache(),
		blobs:      blobcache.New(0),
		cacheScope: "test-scope",
	}
	a.cache.Store(a.cacheScope, mk.String(), time.Hour)
	return a, store, mk
}

// rotateHeader simulates another machine's flip: the stored header now wraps a
// fresh master. Returns the new master.
func rotateHeader(t *testing.T, store *memstore.Store) *crypto.MasterKey {
	t.Helper()
	header, err := crypto.ParseHeader(store.Header())
	if err != nil {
		t.Fatal(err)
	}
	newMK, err := crypto.GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := header.SetMaster(newMK); err != nil {
		t.Fatal(err)
	}
	header.Revision++
	if err := header.Seal(newMK); err != nil {
		t.Fatal(err)
	}
	raw, err := header.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	store.SetHeader(raw)
	return newMK
}

func TestWriteNamespaceWritesAndRecords(t *testing.T) {
	ctx := context.Background()
	a, store, mk := guardApp(t)

	view, err := a.view(ctx, mk)
	if err != nil {
		t.Fatalf("view: %v", err)
	}
	updated, err := a.writeNamespace(ctx, view, []secrets.Write{{Key: "K", Value: "v"}})
	if err != nil {
		t.Fatalf("writeNamespace: %v", err)
	}
	if updated.Secrets["K"] != "v" {
		t.Fatalf("K = %q, want v", updated.Secrets["K"])
	}
	keys, _ := store.List(ctx, "proj/")
	if len(keys) != 1 {
		t.Fatalf("want 1 stored blob, got %d", len(keys))
	}
	// The write is recorded: the stored header's manifest points at the blob.
	stored, err := crypto.ParseHeader(store.Header())
	if err != nil {
		t.Fatal(err)
	}
	e, ok := stored.NamespaceEntry("proj")
	if !ok || e.Blob != keys[0] {
		t.Fatalf("namespace not recorded at the stored blob: entry=%+v keys=%v", e, keys)
	}
	if stored.Revision <= view.header.Revision {
		t.Fatal("the write must advance the header revision")
	}
}

// TestWriteNamespaceRollsBackOnEpochChange is the writer's half of the
// write-epoch protocol, folded into the header swap: the vault is re-keyed
// between this writer's unlock and its write, so the blob — sealed under the
// superseded master — must be removed again and the stale cache dropped, leaving
// the namespace clean.
func TestWriteNamespaceRollsBackOnEpochChange(t *testing.T) {
	ctx := context.Background()
	a, store, mk := guardApp(t)

	view, err := a.view(ctx, mk)
	if err != nil {
		t.Fatalf("view: %v", err)
	}
	newMK := rotateHeader(t, store) // the flip lands before our write records itself

	if _, err := a.writeNamespace(ctx, view, []secrets.Write{{Key: "K", Value: "v"}}); err == nil {
		t.Fatal("writeNamespace must fail when the master changed mid-write")
	}
	if keys, _ := store.List(ctx, "proj/"); len(keys) != 0 {
		t.Fatalf("rolled-back write must leave no object, got %v", keys)
	}
	if _, ok := a.cache.Get(a.cacheScope); ok {
		t.Fatal("the stale cached master must be dropped")
	}
	// The namespace still reads cleanly for a holder of the new master.
	if _, err := secrets.For(store, "proj", newMK).Read(ctx, crypto.ManifestEntry{}); err != nil {
		t.Fatalf("namespace must stay clean for the new master: %v", err)
	}
}

// TestImportCarriesDescriptionsForward: a batch import overwrites values, not
// what the keys mean — each write re-carries the key's existing description.
func TestImportCarriesDescriptionsForward(t *testing.T) {
	ctx := context.Background()
	a, _, mk := guardApp(t)

	view, err := a.view(ctx, mk)
	if err != nil {
		t.Fatalf("view: %v", err)
	}
	if _, err = a.writeNamespace(ctx, view, []secrets.Write{{Key: "DB_URL", Value: "old", Description: "primary DSN", TS: 100}}); err != nil {
		t.Fatalf("seed write: %v", err)
	}

	view, err = a.view(ctx, mk) // re-read: the batch records against the header holding the seed
	if err != nil {
		t.Fatalf("view: %v", err)
	}
	prev, err := a.namespaceFor(view).Read(ctx, mustEntry(view, "proj"))
	if err != nil {
		t.Fatal(err)
	}
	writes := []secrets.Write{
		{Key: "DB_URL", Value: "new", Description: prev.Meta["DB_URL"].Description},
		{Key: "FRESH", Value: "x"},
	}
	updated, err := a.writeNamespace(ctx, view, writes)
	if err != nil {
		t.Fatalf("writeNamespace batch: %v", err)
	}
	if got := updated.Meta["DB_URL"].Description; got != "primary DSN" {
		t.Fatalf("DB_URL description = %q, want carried forward", got)
	}
	if got := updated.Meta["FRESH"].Description; got != "" {
		t.Fatalf("FRESH description = %q, want empty", got)
	}
}

func mustEntry(view *vaultView, ns string) crypto.ManifestEntry {
	e, _ := view.header.NamespaceEntry(ns)
	return e
}
