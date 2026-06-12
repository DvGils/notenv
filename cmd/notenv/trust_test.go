package main

import (
	"context"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/DvGils/notenv/internal/backend/memstore"
	"github.com/DvGils/notenv/internal/config"
	"github.com/DvGils/notenv/internal/crypto"
	"github.com/DvGils/notenv/internal/keymgmt"
)

// trustVault builds a pinned vault on a memstore: one passphrase slot plus a
// recipient identity (so rotations can re-unlock without scrypt), with this
// "machine" pinned at the initial master.
func trustVault(t *testing.T) (*memstore.Store, *crypto.MasterKey, *age.X25519Identity, string) {
	t.Helper()
	isolateConfig(t)
	ctx := context.Background()
	store := memstore.New()
	scope := "trust-scope"

	header, mk, err := crypto.NewHeader("pass", "owner")
	if err != nil {
		t.Fatal(err)
	}
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	if err := header.AddRecipientSlot(id.Recipient(), "machine", mk); err != nil {
		t.Fatal(err)
	}
	if err := header.Seal(mk); err != nil {
		t.Fatal(err)
	}
	raw, err := header.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	store.SetHeader(raw)

	if err := trustHeader(ctx, store, scope, header, mk); err != nil {
		t.Fatalf("first contact must pin: %v", err)
	}
	return store, mk, id, scope
}

// rotateElsewhere re-keys the vault the way another machine would: through
// RotateMaster, without touching this machine's local pin.
func rotateElsewhere(t *testing.T, store *memstore.Store, id *age.X25519Identity) *crypto.MasterKey {
	t.Helper()
	base := store.Header()
	header, err := crypto.ParseHeader(base)
	if err != nil {
		t.Fatal(err)
	}
	current, _, err := header.UnlockIdentity(id)
	if err != nil {
		t.Fatal(err)
	}
	verify := func(h *crypto.Header) (*crypto.MasterKey, error) { m, _, e := h.UnlockIdentity(id); return m, e }
	newMK, err := keymgmt.RotateMaster(context.Background(), store, header, base, current, verify, nil)
	if err != nil {
		t.Fatal(err)
	}
	return newMK
}

// TestTrustHeaderFollowsSignedRotation: a rotation performed on another
// machine must be accepted silently — the signed transition chain proves it —
// and the local pin must move to the new master.
func TestTrustHeaderFollowsSignedRotation(t *testing.T) {
	ctx := context.Background()
	store, _, id, scope := trustVault(t)

	newMK := rotateElsewhere(t, store, id)
	header, err := crypto.ParseHeader(store.Header())
	if err != nil {
		t.Fatal(err)
	}
	if err := trustHeader(ctx, store, scope, header, newMK); err != nil {
		t.Fatalf("a signed rotation must not alarm: %v", err)
	}
	pin, have, err := config.ReadPin(header.VaultID)
	if err != nil || !have {
		t.Fatalf("pin missing after walk: have=%v err=%v", have, err)
	}
	if pin.MasterPub != newMK.PublicKey() {
		t.Fatal("pin must advance to the rotated master")
	}

	// Two more rotations, checked in one step: the chain is walked, not just
	// the latest hop.
	rotateElsewhere(t, store, id)
	finalMK := rotateElsewhere(t, store, id)
	header, err = crypto.ParseHeader(store.Header())
	if err != nil {
		t.Fatal(err)
	}
	if err := trustHeader(ctx, store, scope, header, finalMK); err != nil {
		t.Fatalf("a multi-hop signed chain must not alarm: %v", err)
	}
}

// TestTrustHeaderStillAlarmsOnSubstitution: a header wrapping a master with no
// signed path from the pin must alarm exactly as before transitions existed.
func TestTrustHeaderStillAlarmsOnSubstitution(t *testing.T) {
	ctx := context.Background()
	store, _, _, scope := trustVault(t)

	header, err := crypto.ParseHeader(store.Header())
	if err != nil {
		t.Fatal(err)
	}
	intruder, err := crypto.GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := header.SetMaster(intruder); err != nil {
		t.Fatal(err)
	}
	header.Revision++
	if err := header.Seal(intruder); err != nil {
		t.Fatal(err)
	}
	raw, err := header.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	store.SetHeader(raw)

	err = trustHeader(ctx, store, scope, header, intruder)
	if err == nil {
		t.Fatal("an unsigned master change must alarm")
	}
}

// TestTrustHeaderAlarmsOnVaultReplacement: a different vault appearing at a
// bound storage location is wholesale replacement, alarmed regardless of how
// internally consistent the new vault is.
func TestTrustHeaderAlarmsOnVaultReplacement(t *testing.T) {
	ctx := context.Background()
	store, _, _, scope := trustVault(t)

	replacement, mk, err := crypto.NewHeader("other-pass", "intruder")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := replacement.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	store.SetHeader(raw)

	err = trustHeader(ctx, store, scope, replacement, mk)
	if err == nil || !strings.Contains(err.Error(), "replaced") {
		t.Fatalf("a swapped vault identity must alarm as replacement, got %v", err)
	}
}
