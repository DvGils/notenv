package keymgmt_test

import (
	"context"
	"strings"
	"testing"

	"github.com/DvGils/notenv/internal/backend/memstore"
	"github.com/DvGils/notenv/internal/crypto"
	"github.com/DvGils/notenv/internal/keymgmt"
)

// verifyWith returns a SafePut verify closure that unlocks with a passphrase.
func verifyWith(passphrase string) func(*crypto.Header) (*crypto.MasterKey, error) {
	return func(h *crypto.Header) (*crypto.MasterKey, error) {
		mk, _, _, err := h.Unlock(passphrase)
		return mk, err
	}
}

// seed writes an initial (sealed) header and returns its raw bytes and master.
func seed(t *testing.T, store *memstore.Store, passphrase string) ([]byte, *crypto.MasterKey) {
	t.Helper()
	header, mk, err := crypto.NewHeader(passphrase, "owner@laptop")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := header.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutHeader(context.Background(), raw); err != nil {
		t.Fatal(err)
	}
	return raw, mk
}

// withSlot parses base and adds a second passphrase slot, returning the mutated
// header for SafePut (which will bump the revision and reseal it).
func withSlot(t *testing.T, base []byte, mk *crypto.MasterKey, passphrase string) *crypto.Header {
	t.Helper()
	h, err := crypto.ParseHeader(base)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.AddPassphraseSlot(passphrase, "second", mk); err != nil {
		t.Fatal(err)
	}
	return h
}

func TestSafePutHappyPath(t *testing.T) {
	ctx := context.Background()
	store := memstore.New()
	base, mk := seed(t, store, "owner-pass")
	h := withSlot(t, base, mk, "second-pass")

	if err := keymgmt.SafePut(ctx, store, h, base, mk, verifyWith("owner-pass")); err != nil {
		t.Fatalf("SafePut: %v", err)
	}
	if store.Prev() == nil {
		t.Fatal("SafePut must write a .prev backup before overwriting the header")
	}
	stored, err := crypto.ParseHeader(store.Header())
	if err != nil {
		t.Fatalf("stored header invalid: %v", err)
	}
	if stored.Revision != 2 {
		t.Fatalf("revision = %d, want 2 (bumped from 1)", stored.Revision)
	}
	if err := stored.Verify(mk); err != nil {
		t.Fatalf("stored header should authenticate: %v", err)
	}
}

func TestSafePutDetectsCorruptWrite(t *testing.T) {
	ctx := context.Background()
	store := memstore.New()
	base, mk := seed(t, store, "owner-pass")
	h := withSlot(t, base, mk, "second-pass")

	store.CorruptNextPut(func(b []byte) []byte { return b[:len(b)/2] }) // truncate

	err := keymgmt.SafePut(ctx, store, h, base, mk, verifyWith("owner-pass"))
	if err == nil {
		t.Fatal("SafePut should fail when the write is corrupted")
	}
	if !strings.Contains(err.Error(), "restore-backup") {
		t.Fatalf("error should point at recovery, got: %v", err)
	}
	if store.Prev() == nil {
		t.Fatal("backup must be preserved after a failed write")
	}
}

func TestSafePutDetectsWrongMasterKey(t *testing.T) {
	ctx := context.Background()
	store := memstore.New()
	base, mk := seed(t, store, "owner-pass")

	// A header wrapping a DIFFERENT master: it unlocks fine under its own
	// passphrase, but the expected-master check must reject it.
	other, _, err := crypto.NewHeader("new-pass", "owner@laptop")
	if err != nil {
		t.Fatal(err)
	}
	if err := keymgmt.SafePut(ctx, store, other, base, mk, verifyWith("new-pass")); err == nil {
		t.Fatal("SafePut should reject a header that unlocks to the wrong master key")
	}
}

func TestSafePutFreshnessAbort(t *testing.T) {
	ctx := context.Background()
	store := memstore.New()
	base, mk := seed(t, store, "owner-pass")
	h := withSlot(t, base, mk, "second-pass")

	staleBase := []byte("a different header than what is stored")
	err := keymgmt.SafePut(ctx, store, h, staleBase, mk, verifyWith("owner-pass"))
	if err == nil {
		t.Fatal("SafePut should abort when the header changed underneath it")
	}
	if !strings.Contains(err.Error(), "changed since") {
		t.Fatalf("want a freshness error, got: %v", err)
	}
	if store.PutHeaderCount() != 1 { // only the seed write; no overwrite happened
		t.Fatalf("aborted SafePut must not write, PutHeader count = %d", store.PutHeaderCount())
	}
}

func TestRestoreBackupRecoversBrokenHeader(t *testing.T) {
	ctx := context.Background()
	store := memstore.New()
	base, mk := seed(t, store, "owner-pass")
	h := withSlot(t, base, mk, "second-pass")

	if err := keymgmt.SafePut(ctx, store, h, base, mk, verifyWith("owner-pass")); err != nil {
		t.Fatalf("SafePut: %v", err)
	}
	store.SetHeader([]byte("garbage"))

	if err := keymgmt.RestoreBackup(ctx, store); err != nil {
		t.Fatalf("RestoreBackup: %v", err)
	}
	if _, err := crypto.ParseHeader(store.Header()); err != nil {
		t.Fatalf("restored header should parse: %v", err)
	}
}

func TestRestoreBackupNoBackup(t *testing.T) {
	ctx := context.Background()
	store := memstore.New()
	if err := keymgmt.RestoreBackup(ctx, store); err == nil {
		t.Fatal("RestoreBackup should fail when there is no backup")
	}
}
