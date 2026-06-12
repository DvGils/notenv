package keymgmt_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/DvGils/notenv/internal/backend/memstore"
	"github.com/DvGils/notenv/internal/crypto"
	"github.com/DvGils/notenv/internal/keymgmt"
)

// seedVault writes a header (owner passphrase + alice recipient) whose
// manifest records the given objects (each a small plaintext encrypted under
// the master), the way real writes would have.
func seedVault(t *testing.T, store *memstore.Store, blobs map[string]string) (*crypto.MasterKey, *age.X25519Identity) {
	t.Helper()
	ctx := context.Background()
	header, mk, err := crypto.NewHeader("owner-pass", "owner")
	if err != nil {
		t.Fatal(err)
	}
	alice, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	if err := header.AddRecipientSlot(alice.Recipient(), "alice", mk); err != nil {
		t.Fatal(err)
	}
	header.Manifest = map[string]crypto.ManifestEntry{}
	for key, val := range blobs {
		sealed, err := mk.Encrypt([]byte(val))
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Put(ctx, key, sealed); err != nil {
			t.Fatal(err)
		}
		mac, err := mk.ObjectMAC([]byte(val))
		if err != nil {
			t.Fatal(err)
		}
		header.Manifest[key] = crypto.ManifestEntry{MAC: mac}
	}
	if err := header.Seal(mk); err != nil { // re-seal after the slot add and manifest
		t.Fatal(err)
	}
	raw, err := header.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutHeader(ctx, raw); err != nil {
		t.Fatal(err)
	}
	return mk, alice
}

// assertVault checks every blob decrypts to want under the header's current
// master and matches its re-keyed manifest entry, that the old master no
// longer decrypts, and that every slot unlocks.
func assertVault(t *testing.T, store *memstore.Store, oldMK *crypto.MasterKey, alice *age.X25519Identity, want map[string]string) {
	t.Helper()
	ctx := context.Background()
	header, err := crypto.ParseHeader(store.Header())
	if err != nil {
		t.Fatalf("parse header: %v", err)
	}
	cur, _, _, err := header.Unlock("owner-pass")
	if err != nil {
		t.Fatalf("passphrase slot lost: %v", err)
	}
	viaAlice, _, err := header.UnlockIdentity(alice)
	if err != nil || viaAlice.String() != cur.String() {
		t.Fatalf("recipient slot lost: %v", err)
	}
	if cur.String() == oldMK.String() {
		t.Fatal("master was not rotated")
	}
	if len(header.Manifest) != len(want) {
		t.Fatalf("manifest records %d objects, want %d: %v", len(header.Manifest), len(want), header.Manifest)
	}
	for key, val := range want {
		blob, err := store.Get(ctx, key)
		if err != nil {
			t.Fatalf("get %q: %v", key, err)
		}
		plain, err := cur.Decrypt(blob)
		if err != nil || string(plain) != val {
			t.Fatalf("blob %q under new master: %v %q", key, err, plain)
		}
		if _, err := oldMK.Decrypt(blob); err == nil {
			t.Fatalf("blob %q still decrypts under the OLD master", key)
		}
		if err := cur.CheckObjectMAC(plain, header.Manifest[key].MAC); err != nil {
			t.Fatalf("blob %q manifest entry not re-keyed: %v", key, err)
		}
	}
}

func TestRotateMasterHappyPath(t *testing.T) {
	ctx := context.Background()
	store := memstore.New()
	blobs := map[string]string{"proj/snap-aa.age": "a", "other/seg-m-bb.age": "b"}
	oldMK, alice := seedVault(t, store, blobs)

	base := store.Header()
	header, err := crypto.ParseHeader(base)
	if err != nil {
		t.Fatal(err)
	}
	verify := func(h *crypto.Header) (*crypto.MasterKey, error) { m, _, _, e := h.Unlock("owner-pass"); return m, e }

	newMK, err := keymgmt.RotateMaster(ctx, store, header, base, oldMK, verify, nil)
	if err != nil {
		t.Fatalf("RotateMaster: %v", err)
	}
	if newMK.String() == oldMK.String() {
		t.Fatal("new master must differ")
	}
	assertVault(t, store, oldMK, alice, blobs)
}

func TestRotateMasterReRunAfterCrash(t *testing.T) {
	ctx := context.Background()
	store := memstore.New()
	blobs := map[string]string{"proj/snap-aa.age": "a", "other/seg-m-bb.age": "b"}
	oldMK, alice := seedVault(t, store, blobs)
	verify := func(h *crypto.Header) (*crypto.MasterKey, error) { m, _, _, e := h.Unlock("owner-pass"); return m, e }

	// Crash mid-widen: allow one blob, fail the next.
	store.FailPutAfter(1, errors.New("simulated network blip"))
	base := store.Header()
	header, _ := crypto.ParseHeader(base)
	if _, err := keymgmt.RotateMaster(ctx, store, header, base, oldMK, verify, nil); err == nil {
		t.Fatal("expected RotateMaster to fail on the injected error")
	}
	// Header unchanged (flip never happened), so a reader with the old master
	// still works throughout.
	if cur, _, _, err := mustParse(t, store).Unlock("owner-pass"); err != nil || cur.String() != oldMK.String() {
		t.Fatalf("header should still yield the old master after a widen crash: %v", err)
	}

	// Re-run from the current state; it re-keys from whatever the header yields.
	base2 := store.Header()
	header2, _ := crypto.ParseHeader(base2)
	if _, err := keymgmt.RotateMaster(ctx, store, header2, base2, oldMK, verify, nil); err != nil {
		t.Fatalf("re-run RotateMaster: %v", err)
	}
	assertVault(t, store, oldMK, alice, blobs)
}

// TestRotateMasterOnFlipBeforeNarrow checks onFlip fires once the flip commits,
// even if the later narrow pass fails — so the caller can pin the new master and
// a re-run isn't mistaken for a rollback.
func TestRotateMasterOnFlipBeforeNarrow(t *testing.T) {
	ctx := context.Background()
	store := memstore.New()
	blobs := map[string]string{"proj/snap-aa.age": "a", "other/seg-m-bb.age": "b"}
	oldMK, _ := seedVault(t, store, blobs)
	verify := func(h *crypto.Header) (*crypto.MasterKey, error) { m, _, _, e := h.Unlock("owner-pass"); return m, e }

	// 2 widen Puts and the transition record succeed, the flip (a PutHeader)
	// succeeds, the first narrow Put fails.
	store.FailPutAfter(3, errors.New("simulated blip in narrow"))
	base := store.Header()
	header, _ := crypto.ParseHeader(base)

	var flipped *crypto.MasterKey
	if _, err := keymgmt.RotateMaster(ctx, store, header, base, oldMK, verify, func(mk *crypto.MasterKey) { flipped = mk }); err == nil {
		t.Fatal("expected the narrow pass to fail")
	}
	if flipped == nil {
		t.Fatal("onFlip must be called once the flip commits")
	}
	// The header now yields the flipped master, matching what onFlip reported.
	cur, _, _, err := mustParse(t, store).Unlock("owner-pass")
	if err != nil || cur.String() != flipped.String() {
		t.Fatalf("header should yield the flipped master: %v", err)
	}
}

func mustParse(t *testing.T, store *memstore.Store) *crypto.Header {
	t.Helper()
	h, err := crypto.ParseHeader(store.Header())
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// TestRotateMasterLeavesUnrecordedWriteAlone covers the in-flight straggler: a
// segment that landed mid-rotation without a manifest entry (its writer will
// record it, roll it back, or has crashed). Rotation must neither re-key nor
// adopt it — touching it would race the writer's own rollback — and the next
// fold classifies whatever remains.
func TestRotateMasterLeavesUnrecordedWriteAlone(t *testing.T) {
	ctx := context.Background()
	store := memstore.New()
	blobs := map[string]string{"proj/snap-aa.age": "a"}
	oldMK, alice := seedVault(t, store, blobs)
	verify := func(h *crypto.Header) (*crypto.MasterKey, error) { m, _, _, e := h.Unlock("owner-pass"); return m, e }

	sealed, err := oldMK.Encrypt([]byte("late"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(ctx, "proj/seg-m2-late.age", sealed); err != nil {
		t.Fatal(err)
	}

	base := store.Header()
	header, _ := crypto.ParseHeader(base)
	if _, err := keymgmt.RotateMaster(ctx, store, header, base, oldMK, verify, nil); err != nil {
		t.Fatalf("RotateMaster: %v", err)
	}
	assertVault(t, store, oldMK, alice, blobs) // the manifest records only the snapshot

	// The straggler is untouched: still exactly the bytes its writer stored.
	got, err := store.Get(ctx, "proj/seg-m2-late.age")
	if err != nil {
		t.Fatal(err)
	}
	plain, err := oldMK.Decrypt(got)
	if err != nil || string(plain) != "late" {
		t.Fatalf("unrecorded write was modified by the rotation: %v %q", err, plain)
	}
}

// TestRotateMasterRefusesVanishedRecordedObject: a live manifest entry whose
// object is gone must fail the rotation, never be skipped — dropping the entry
// at the flip would erase the evidence of a deletion. (The honest cause, a
// concurrent compaction, bumps the header revision, so the flip would abort
// and the re-run sees the folded entry instead.)
func TestRotateMasterRefusesVanishedRecordedObject(t *testing.T) {
	ctx := context.Background()
	store := memstore.New()
	blobs := map[string]string{"proj/seg-m1-aa.age": "a", "proj/seg-m1-bb.age": "b"}
	oldMK, _ := seedVault(t, store, blobs)
	verify := func(h *crypto.Header) (*crypto.MasterKey, error) { m, _, _, e := h.Unlock("owner-pass"); return m, e }

	base := store.Header()
	header, _ := crypto.ParseHeader(base)
	if err := store.Delete(ctx, "proj/seg-m1-bb.age"); err != nil {
		t.Fatal(err)
	}

	_, err := keymgmt.RotateMaster(ctx, store, header, base, oldMK, verify, nil)
	if err == nil || !strings.Contains(err.Error(), "missing from storage") {
		t.Fatalf("rotation must refuse a vanished recorded object, got %v", err)
	}
	// The flip never happened: the old master still opens everything that exists.
	if cur, _, _, uerr := mustParse(t, store).Unlock("owner-pass"); uerr != nil || cur.String() != oldMK.String() {
		t.Fatalf("header should still yield the old master: %v", uerr)
	}
}

// TestRotateMasterRefusesTamperedObject: a recorded object whose plaintext no
// longer matches its manifest MAC (reverted or substituted) must abort the
// rotation rather than be laundered into the new epoch under a fresh MAC.
func TestRotateMasterRefusesTamperedObject(t *testing.T) {
	ctx := context.Background()
	store := memstore.New()
	blobs := map[string]string{"proj/seg-m1-aa.age": "a"}
	oldMK, _ := seedVault(t, store, blobs)
	verify := func(h *crypto.Header) (*crypto.MasterKey, error) { m, _, _, e := h.Unlock("owner-pass"); return m, e }

	// Replace the object with a different plaintext sealed under the same
	// master — the storage-level revert the manifest exists to catch.
	swapped, err := oldMK.Encrypt([]byte("older value"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(ctx, "proj/seg-m1-aa.age", swapped); err != nil {
		t.Fatal(err)
	}

	base := store.Header()
	header, _ := crypto.ParseHeader(base)
	_, err = keymgmt.RotateMaster(ctx, store, header, base, oldMK, verify, nil)
	if err == nil || !strings.Contains(err.Error(), "manifest") {
		t.Fatalf("rotation must refuse a tampered object, got %v", err)
	}
}

// TestRotateMasterRemovesFoldedLeftovers: entries marked folded (a compaction
// recorded their replacement but its deletions never finished) are cleaned up
// by the rotation — objects deleted, entries dropped at the flip.
func TestRotateMasterRemovesFoldedLeftovers(t *testing.T) {
	ctx := context.Background()
	store := memstore.New()
	blobs := map[string]string{"proj/snap-aa.age": "a", "proj/seg-m1-old.age": "old"}
	oldMK, alice := seedVault(t, store, blobs)
	verify := func(h *crypto.Header) (*crypto.MasterKey, error) { m, _, _, e := h.Unlock("owner-pass"); return m, e }

	// Mark the segment folded, as an interrupted compaction would have.
	header := mustParse(t, store)
	header.ApplyManifest(crypto.ManifestDelta{Fold: []string{"proj/seg-m1-old.age"}})
	if err := header.Seal(oldMK); err != nil {
		t.Fatal(err)
	}
	raw, err := header.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutHeader(ctx, raw); err != nil {
		t.Fatal(err)
	}

	base := store.Header()
	header2, _ := crypto.ParseHeader(base)
	if _, err := keymgmt.RotateMaster(ctx, store, header2, base, oldMK, verify, nil); err != nil {
		t.Fatalf("RotateMaster: %v", err)
	}
	assertVault(t, store, oldMK, alice, map[string]string{"proj/snap-aa.age": "a"})
	if _, err := store.Get(ctx, "proj/seg-m1-old.age"); err == nil {
		t.Fatal("folded leftover object should be deleted by the rotation")
	}
}
