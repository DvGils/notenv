package main

import (
	"context"
	"testing"

	"github.com/DvGils/notenv/internal/backend/memstore"
	"github.com/DvGils/notenv/internal/crypto"
	"github.com/DvGils/notenv/internal/keymgmt"
	"github.com/DvGils/notenv/internal/secrets"
)

// brickedVault seeds the "proj" namespace with a current blob and a
// one-generation backup, then corrupts the current blob so a strict read fails
// closed. Returns the store, master, and the namespace's manifest entry.
func brickedVault(t *testing.T, alsoCorruptBackup bool) (*memstore.Store, *crypto.MasterKey, crypto.ManifestEntry) {
	t.Helper()
	ctx := context.Background()
	store := memstore.New()
	header, mk, err := crypto.NewHeader("owner pass", "owner")
	if err != nil {
		t.Fatal(err)
	}
	header.Revision = 0

	nsw := secrets.For(store, "proj", mk)
	empty, err := nsw.Read(ctx, crypto.ManifestEntry{})
	if err != nil {
		t.Fatal(err)
	}
	_, prevEntry, err := nsw.WriteBlob(ctx, empty.Apply([]secrets.Write{{Key: "A", Value: "alpha"}}), crypto.ManifestEntry{})
	if err != nil {
		t.Fatal(err)
	}
	curState := empty.Apply([]secrets.Write{{Key: "A", Value: "alpha2"}, {Key: "B", Value: "beta"}})
	_, curEntry, err := nsw.WriteBlob(ctx, curState, prevEntry)
	if err != nil {
		t.Fatal(err)
	}
	header.SetNamespace("proj", curEntry)
	verify := func(h *crypto.Header) (*crypto.MasterKey, error) { m, _, _, e := h.Unlock("owner pass"); return m, e }
	if err := keymgmt.SafePut(ctx, store, header, nil, mk, verify); err != nil {
		t.Fatal(err)
	}
	// A byte flip becomes a decrypt failure under authenticated encryption.
	if err := store.Put(ctx, curEntry.Blob, []byte("junk")); err != nil {
		t.Fatal(err)
	}
	if alsoCorruptBackup {
		if err := store.Put(ctx, curEntry.Prev, []byte("junk")); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := secrets.For(store, "proj", mk).Read(ctx, curEntry); err == nil {
		t.Fatal("setup: the current blob must be unreadable before recovery")
	}
	return store, mk, curEntry
}

// TestRecoverFromBackup: with the current blob corrupt but the backup intact,
// recover rewrites the namespace from the backup, so a strict read then succeeds
// at the last good state (losing only the most recent write).
func TestRecoverFromBackup(t *testing.T) {
	isolateConfig(t)
	ctx := context.Background()
	store, mk, entry := brickedVault(t, false)
	target := &headerTarget{vaultStorage: doctorStore{store}, scope: "scope", cache: newMapCache()}

	state, err := secrets.For(store, "proj", mk).ReadSalvage(ctx, entry)
	if err != nil {
		t.Fatalf("salvage: %v", err)
	}
	if len(state.Corrupt) == 0 {
		t.Fatal("setup: salvage should report the corrupt current blob")
	}
	if err := recoverNamespace(ctx, target, mk, "proj", state, entry); err != nil {
		t.Fatalf("recover: %v", err)
	}

	h, err := crypto.ParseHeader(store.Header())
	if err != nil {
		t.Fatal(err)
	}
	e, ok := h.NamespaceEntry("proj")
	if !ok {
		t.Fatal("the recovered namespace must still have an entry")
	}
	if e.Prev != "" {
		t.Fatal("a recovered namespace starts fresh, with no backup yet")
	}
	recovered, err := secrets.For(store, "proj", mk).Read(ctx, e)
	if err != nil {
		t.Fatalf("a strict read must succeed after recovery: %v", err)
	}
	if recovered.Secrets["A"] != "alpha" {
		t.Fatalf("recovered A = %q, want alpha (the backup)", recovered.Secrets["A"])
	}
	if _, ok := recovered.Secrets["B"]; ok {
		t.Fatal("B was only in the corrupt current blob; it must be gone")
	}
}

// TestRecoverRefusesWhenNothingSurvives: with both generations corrupt, recover
// refuses rather than empty the namespace, and leaves its manifest entry intact
// (clearing it is `namespace delete`, a separate explicit decision).
func TestRecoverRefusesWhenNothingSurvives(t *testing.T) {
	isolateConfig(t)
	ctx := context.Background()
	store, mk, entry := brickedVault(t, true)
	target := &headerTarget{vaultStorage: doctorStore{store}, scope: "scope", cache: newMapCache()}

	state, err := secrets.For(store, "proj", mk).ReadSalvage(ctx, entry)
	if err != nil {
		t.Fatalf("salvage: %v", err)
	}
	if len(state.Secrets) != 0 {
		t.Fatalf("nothing should survive, got %v", state.Secrets)
	}
	if err := recoverNamespace(ctx, target, mk, "proj", state, entry); err == nil {
		t.Fatal("recover must refuse when nothing survives, not rewrite to empty")
	}
	h, err := crypto.ParseHeader(store.Header())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := h.NamespaceEntry("proj"); !ok {
		t.Fatal("a refused recover must leave the namespace entry intact (use `namespace delete` to remove it)")
	}
}
