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

// nsBlobs is one namespace's stored blobs for a test: the current value and an
// optional one-generation backup value ("" = no backup).
type nsBlobs struct {
	cur  string
	prev string
}

// seedVault writes a header (owner passphrase + alice recipient) whose manifest
// records the given namespaces, each as a current blob (and optional backup)
// encrypted under the master, the way real writes would have.
func seedVault(t *testing.T, store *memstore.Store, namespaces map[string]nsBlobs) (*crypto.MasterKey, *age.X25519Identity) {
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
	for ns, b := range namespaces {
		entry := putBlob(t, store, mk, ns+"/data-cur.age", b.cur)
		if b.prev != "" {
			pe := putBlob(t, store, mk, ns+"/data-prev.age", b.prev)
			entry.Prev, entry.PrevMAC = pe.Blob, pe.MAC
		}
		header.Manifest[ns] = entry
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

func putBlob(t *testing.T, store *memstore.Store, mk *crypto.MasterKey, key, val string) crypto.ManifestEntry {
	t.Helper()
	sealed, err := mk.Encrypt([]byte(val))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(context.Background(), key, sealed); err != nil {
		t.Fatal(err)
	}
	mac, err := mk.BlobMAC([]byte(val))
	if err != nil {
		t.Fatal(err)
	}
	return crypto.ManifestEntry{Blob: key, MAC: mac}
}

// assertVault checks every namespace's current blob (and backup, if any)
// decrypts to want under the header's current master and matches its re-keyed
// manifest MAC, that the old master no longer decrypts, and that every slot
// unlocks.
func assertVault(t *testing.T, store *memstore.Store, oldMK *crypto.MasterKey, alice *age.X25519Identity, want map[string]nsBlobs) {
	t.Helper()
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
		t.Fatalf("manifest records %d namespaces, want %d: %v", len(header.Manifest), len(want), header.Manifest)
	}
	for ns, b := range want {
		e := header.Manifest[ns]
		assertBlobReKeyed(t, store, oldMK, cur, e.Blob, e.MAC, b.cur)
		if b.prev != "" {
			assertBlobReKeyed(t, store, oldMK, cur, e.Prev, e.PrevMAC, b.prev)
		}
	}
}

func assertBlobReKeyed(t *testing.T, store *memstore.Store, oldMK, cur *crypto.MasterKey, key, mac, want string) {
	t.Helper()
	blob, err := store.Get(context.Background(), key)
	if err != nil {
		t.Fatalf("get %q: %v", key, err)
	}
	plain, err := cur.Decrypt(blob)
	if err != nil || string(plain) != want {
		t.Fatalf("blob %q under new master: %v %q", key, err, plain)
	}
	if _, err := oldMK.Decrypt(blob); err == nil {
		t.Fatalf("blob %q still decrypts under the OLD master", key)
	}
	if err := cur.CheckBlobMAC(plain, mac); err != nil {
		t.Fatalf("blob %q manifest entry not re-keyed: %v", key, err)
	}
}

func ownerVerify(h *crypto.Header) (*crypto.MasterKey, error) {
	m, _, _, e := h.Unlock("owner-pass")
	return m, e
}

func TestRotateMasterHappyPath(t *testing.T) {
	ctx := context.Background()
	store := memstore.New()
	want := map[string]nsBlobs{"proj": {cur: "a"}, "other": {cur: "b"}}
	oldMK, alice := seedVault(t, store, want)

	base := store.Header()
	header, err := crypto.ParseHeader(base)
	if err != nil {
		t.Fatal(err)
	}
	newMK, err := keymgmt.RotateMaster(ctx, store, header, base, oldMK, ownerVerify, nil)
	if err != nil {
		t.Fatalf("RotateMaster: %v", err)
	}
	if newMK.String() == oldMK.String() {
		t.Fatal("new master must differ")
	}
	assertVault(t, store, oldMK, alice, want)
}

// TestRotateMasterReKeysBackup: a namespace's one-generation backup is re-keyed
// alongside its current blob, so the backstop survives the rotation.
func TestRotateMasterReKeysBackup(t *testing.T) {
	ctx := context.Background()
	store := memstore.New()
	want := map[string]nsBlobs{"proj": {cur: "v2", prev: "v1"}}
	oldMK, alice := seedVault(t, store, want)

	base := store.Header()
	header, _ := crypto.ParseHeader(base)
	if _, err := keymgmt.RotateMaster(ctx, store, header, base, oldMK, ownerVerify, nil); err != nil {
		t.Fatalf("RotateMaster: %v", err)
	}
	assertVault(t, store, oldMK, alice, want)
}

func TestRotateMasterReRunAfterCrash(t *testing.T) {
	ctx := context.Background()
	store := memstore.New()
	want := map[string]nsBlobs{"proj": {cur: "a"}, "other": {cur: "b"}}
	oldMK, alice := seedVault(t, store, want)

	// Crash mid-widen: allow one blob, fail the next.
	store.FailPutAfter(1, errors.New("simulated network blip"))
	base := store.Header()
	header, _ := crypto.ParseHeader(base)
	crashErr := func() error {
		_, err := keymgmt.RotateMaster(ctx, store, header, base, oldMK, ownerVerify, nil)
		return err
	}()
	if crashErr == nil {
		t.Fatal("expected RotateMaster to fail on the injected error")
	}
	// A widen (pre-flip) failure is NOT incomplete revocation: the header never
	// changed, so the credential is exactly as valid as before. It must not carry
	// the narrow-incomplete sentinel.
	if errors.Is(crashErr, keymgmt.ErrNarrowIncomplete) {
		t.Fatalf("a pre-flip widen failure must not look like incomplete revocation: %v", crashErr)
	}
	// Header unchanged (flip never happened), so a reader with the old master
	// still works throughout.
	if cur, _, _, err := mustParse(t, store).Unlock("owner-pass"); err != nil || cur.String() != oldMK.String() {
		t.Fatalf("header should still yield the old master after a widen crash: %v", err)
	}

	// Re-run from the current state; it re-keys from whatever the header yields.
	base2 := store.Header()
	header2, _ := crypto.ParseHeader(base2)
	if _, err := keymgmt.RotateMaster(ctx, store, header2, base2, oldMK, ownerVerify, nil); err != nil {
		t.Fatalf("re-run RotateMaster: %v", err)
	}
	assertVault(t, store, oldMK, alice, want)
}

// TestRotateMasterOnFlipBeforeNarrow checks onFlip fires once the flip commits,
// even if the later narrow pass fails — so the caller can pin the new master and
// a re-run isn't mistaken for a rollback.
func TestRotateMasterOnFlipBeforeNarrow(t *testing.T) {
	ctx := context.Background()
	store := memstore.New()
	want := map[string]nsBlobs{"proj": {cur: "a"}, "other": {cur: "b"}}
	oldMK, _ := seedVault(t, store, want)

	// Two widen blob Puts succeed, the flip (a PutHeader, not counted) commits,
	// then the first narrow blob Put fails.
	store.FailPutAfter(2, errors.New("simulated blip in narrow"))
	base := store.Header()
	header, _ := crypto.ParseHeader(base)

	var flipped *crypto.MasterKey
	_, err := keymgmt.RotateMaster(ctx, store, header, base, oldMK, ownerVerify, func(mk *crypto.MasterKey) { flipped = mk })
	if err == nil {
		t.Fatal("expected the narrow pass to fail")
	}
	// A post-flip narrow failure is incomplete revocation: the header is re-keyed
	// but the old master still reads the un-narrowed blobs. The sentinel lets the
	// offboarding caller warn that the removed credential is not yet revoked.
	if !errors.Is(err, keymgmt.ErrNarrowIncomplete) {
		t.Fatalf("a post-flip narrow failure must wrap ErrNarrowIncomplete, got %v", err)
	}
	if flipped == nil {
		t.Fatal("onFlip must be called once the flip commits")
	}
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

// TestRotateMasterLeavesOrphanAlone: a blob with no manifest entry (a write that
// crashed before recording it) is not in any namespace entry, so the rotation
// never touches it.
func TestRotateMasterLeavesOrphanAlone(t *testing.T) {
	ctx := context.Background()
	store := memstore.New()
	want := map[string]nsBlobs{"proj": {cur: "a"}}
	oldMK, alice := seedVault(t, store, want)

	sealed, err := oldMK.Encrypt([]byte("late"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(ctx, "proj/data-orphan.age", sealed); err != nil {
		t.Fatal(err)
	}

	base := store.Header()
	header, _ := crypto.ParseHeader(base)
	if _, err := keymgmt.RotateMaster(ctx, store, header, base, oldMK, ownerVerify, nil); err != nil {
		t.Fatalf("RotateMaster: %v", err)
	}
	assertVault(t, store, oldMK, alice, want)

	got, err := store.Get(ctx, "proj/data-orphan.age")
	if err != nil {
		t.Fatal(err)
	}
	plain, err := oldMK.Decrypt(got)
	if err != nil || string(plain) != "late" {
		t.Fatalf("orphan blob was modified by the rotation: %v %q", err, plain)
	}
}

// TestRotateMasterRefusesVanishedRecordedBlob: a namespace's current blob gone
// from storage must fail the rotation, never be skipped — dropping the entry at
// the flip would erase the evidence of a deletion.
func TestRotateMasterRefusesVanishedRecordedBlob(t *testing.T) {
	ctx := context.Background()
	store := memstore.New()
	want := map[string]nsBlobs{"proj": {cur: "a"}}
	oldMK, _ := seedVault(t, store, want)

	base := store.Header()
	header, _ := crypto.ParseHeader(base)
	if err := store.Delete(ctx, "proj/data-cur.age"); err != nil {
		t.Fatal(err)
	}

	_, err := keymgmt.RotateMaster(ctx, store, header, base, oldMK, ownerVerify, nil)
	if err == nil || !strings.Contains(err.Error(), "missing from storage") {
		t.Fatalf("rotation must refuse a vanished recorded blob, got %v", err)
	}
	if cur, _, _, uerr := mustParse(t, store).Unlock("owner-pass"); uerr != nil || cur.String() != oldMK.String() {
		t.Fatalf("header should still yield the old master: %v", uerr)
	}
}

// TestRotateMasterRefusesTamperedBlob: a recorded blob whose plaintext no longer
// matches its manifest MAC (reverted or substituted) must abort the rotation
// rather than be laundered into the new epoch under a fresh MAC.
func TestRotateMasterRefusesTamperedBlob(t *testing.T) {
	ctx := context.Background()
	store := memstore.New()
	want := map[string]nsBlobs{"proj": {cur: "a"}}
	oldMK, _ := seedVault(t, store, want)

	swapped, err := oldMK.Encrypt([]byte("older value"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(ctx, "proj/data-cur.age", swapped); err != nil {
		t.Fatal(err)
	}

	base := store.Header()
	header, _ := crypto.ParseHeader(base)
	_, err = keymgmt.RotateMaster(ctx, store, header, base, oldMK, ownerVerify, nil)
	if err == nil || !strings.Contains(err.Error(), "manifest") {
		t.Fatalf("rotation must refuse a tampered blob, got %v", err)
	}
}
