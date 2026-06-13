package main

import (
	"context"
	"errors"
	"testing"

	"github.com/DvGils/notenv/internal/backend"
	"github.com/DvGils/notenv/internal/backend/memstore"
	"github.com/DvGils/notenv/internal/crypto"
	"github.com/DvGils/notenv/internal/keymgmt"
	"github.com/DvGils/notenv/internal/secrets"
)

// brickedVault seeds a vault with two recorded segments and corrupts one, so a
// strict fold fails closed. Returns the store, master, and the corrupt object's
// key.
func brickedVault(t *testing.T) (*memstore.Store, *crypto.MasterKey, string) {
	t.Helper()
	ctx := context.Background()
	store := memstore.New()
	header, mk, err := crypto.NewHeader("owner pass", "owner")
	if err != nil {
		t.Fatal(err)
	}
	header.Revision = 0

	manifest := map[string]crypto.ManifestEntry{}
	ns := secrets.For(store, "proj", mk, "m1", manifest)
	view := &secrets.State{Secrets: map[string]string{}}
	var corrupt string
	for i, w := range []secrets.Write{{Key: "A", Value: "alpha"}, {Key: "B", Value: "beta"}} {
		updated, objKey, entry, err := ns.Append(ctx, view, i+1, w)
		if err != nil {
			t.Fatal(err)
		}
		manifest[objKey] = entry
		view = updated
		if w.Key == "B" {
			corrupt = objKey
		}
	}
	header.Manifest = manifest
	verify := func(h *crypto.Header) (*crypto.MasterKey, error) { m, _, _, e := h.Unlock("owner pass"); return m, e }
	if err := keymgmt.SafePut(ctx, store, header, nil, mk, verify); err != nil {
		t.Fatal(err)
	}
	// Any byte flip becomes a decrypt failure under authenticated encryption.
	if err := store.Put(ctx, corrupt, []byte("junk")); err != nil {
		t.Fatal(err)
	}
	if _, err := secrets.For(store, "proj", mk, "m1", manifest).Fold(ctx); err == nil {
		t.Fatal("setup: the vault must be bricked before eviction")
	}
	return store, mk, corrupt
}

// TestEvictObjectUnbricksFold: evicting the corrupt object drops it from both
// the manifest and storage, and a strict fold then succeeds, resolving every
// surviving key while the evicted one is simply gone.
func TestEvictObjectUnbricksFold(t *testing.T) {
	isolateConfig(t)
	ctx := context.Background()
	store, mk, corrupt := brickedVault(t)

	target := &headerTarget{vaultStorage: doctorStore{store}, scope: "scope"}
	if err := evictObject(ctx, target, mk, corrupt); err != nil {
		t.Fatalf("evict: %v", err)
	}

	if _, err := store.Get(ctx, corrupt); !errors.Is(err, backend.ErrNotFound) {
		t.Fatalf("the evicted object must be deleted from storage, got %v", err)
	}
	raw, err := store.GetHeader(ctx)
	if err != nil {
		t.Fatal(err)
	}
	h, err := crypto.ParseHeader(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := h.Manifest[corrupt]; ok {
		t.Fatal("the evicted object must be dropped from the manifest")
	}
	state, err := secrets.For(store, "proj", mk, "m1", h.Manifest).Fold(ctx)
	if err != nil {
		t.Fatalf("a strict fold must succeed after eviction: %v", err)
	}
	if state.Secrets["A"] != "alpha" {
		t.Fatalf("the surviving key must resolve: A=%q", state.Secrets["A"])
	}
	if _, ok := state.Secrets["B"]; ok {
		t.Fatal("the evicted key must be gone")
	}
}

// TestEvictObjectReportsDeleteFailure: when the manifest prune succeeds but the
// object delete fails, eviction surfaces evictDeleteError, and the entry is gone
// regardless so reads no longer require the object.
func TestEvictObjectReportsDeleteFailure(t *testing.T) {
	isolateConfig(t)
	ctx := context.Background()
	store, mk, corrupt := brickedVault(t)

	store.FailDeleteAfter(0, errors.New("storage offline"))
	target := &headerTarget{vaultStorage: doctorStore{store}, scope: "scope"}

	err := evictObject(ctx, target, mk, corrupt)
	var de *evictDeleteError
	if !errors.As(err, &de) {
		t.Fatalf("a failed delete after a successful prune must surface as evictDeleteError, got %v", err)
	}
	raw, err := store.GetHeader(ctx)
	if err != nil {
		t.Fatal(err)
	}
	h, err := crypto.ParseHeader(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := h.Manifest[corrupt]; ok {
		t.Fatal("the entry must be pruned even when the object delete fails")
	}
}
