package keymgmt_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/DvGils/notenv/internal/backend/memstore"
	"github.com/DvGils/notenv/internal/crypto"
	"github.com/DvGils/notenv/internal/keymgmt"
)

func TestVerifyEpochUnchangedMasterPasses(t *testing.T) {
	store := memstore.New()
	mk, _ := seedVault(t, store, nil)
	if err := keymgmt.VerifyEpoch(context.Background(), store, mk); err != nil {
		t.Fatalf("unchanged master must verify: %v", err)
	}
}

func TestVerifyEpochDetectsRotatedMaster(t *testing.T) {
	store := memstore.New()
	oldMK, _ := seedVault(t, store, nil)

	// Simulate another machine's flip: the header now wraps a fresh master.
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

	err = keymgmt.VerifyEpoch(context.Background(), store, oldMK)
	if !errors.Is(err, keymgmt.ErrEpochChanged) {
		t.Fatalf("want ErrEpochChanged for a superseded master, got %v", err)
	}
	if err := keymgmt.VerifyEpoch(context.Background(), store, newMK); err != nil {
		t.Fatalf("the new master must verify: %v", err)
	}
}

func TestVerifyEpochRefusesMissingHeader(t *testing.T) {
	store := memstore.New()
	mk, _ := seedVault(t, store, nil)
	store.SetHeader(nil)
	if err := keymgmt.VerifyEpoch(context.Background(), store, mk); err == nil {
		t.Fatal("a vanished header must not verify")
	}
}

func TestVerifyEpochRefusesTamperedHeader(t *testing.T) {
	store := memstore.New()
	mk, _ := seedVault(t, store, nil)

	// Flip bytes inside the stored header without resealing: the recipient
	// still matches, so the tag must catch it.
	raw := store.Header()
	tampered := bytes.Replace(raw, []byte(`"revision": 1`), []byte(`"revision": 9`), 1)
	if bytes.Equal(raw, tampered) {
		t.Fatal("test setup: revision field not found to tamper")
	}
	store.SetHeader(tampered)

	if err := keymgmt.VerifyEpoch(context.Background(), store, mk); err == nil {
		t.Fatal("a tampered header must not verify")
	}
}
