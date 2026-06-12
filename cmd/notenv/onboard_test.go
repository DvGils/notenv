package main

import (
	"context"
	"strings"
	"testing"

	"github.com/DvGils/notenv/internal/backend/memstore"
	"github.com/DvGils/notenv/internal/crypto"
)

// provisionalFixture builds a header with an owner slot and a provisional
// teammate slot, unlocked via the temporary passphrase.
func provisionalFixture(t *testing.T) (*crypto.Header, []byte, *unlockResult) {
	t.Helper()
	header, mk, err := crypto.NewHeader("owner pass", "owner")
	if err != nil {
		t.Fatal(err)
	}
	if err := header.AddPassphraseSlot("temp-onboarding-pass", "alice", mk); err != nil {
		t.Fatal(err)
	}
	header.Slots[1].Provisional = true
	if err := header.Seal(mk); err != nil {
		t.Fatal(err)
	}
	raw, err := header.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, slot, slotKey, err := header.Unlock("temp-onboarding-pass")
	if err != nil || slot != 1 {
		t.Fatalf("unlock provisional slot: slot=%d err=%v", slot, err)
	}
	return header, raw, &unlockResult{mk: got, slot: slot, slotKey: slotKey}
}

// A unlock through a slot that is not provisional passes the gate untouched.
func TestEnforceProvisionalNoOp(t *testing.T) {
	header, raw, _ := provisionalFixture(t)
	got, slot, slotKey, err := header.Unlock("owner pass")
	if err != nil || slot != 0 {
		t.Fatalf("unlock owner slot: slot=%d err=%v", slot, err)
	}
	res := &unlockResult{mk: got, slot: slot, slotKey: slotKey}
	rotated, err := enforceProvisional(context.Background(), memstore.New(), "scope", "", header, raw, res)
	if err != nil || rotated {
		t.Fatalf("owner slot must pass the gate: rotated=%v err=%v", rotated, err)
	}
}

// An identity unlock that matches no slot (slot -1) passes the gate.
func TestEnforceProvisionalSkipsUnmatchedSlot(t *testing.T) {
	header, raw, res := provisionalFixture(t)
	unmatched := &unlockResult{mk: res.mk, slot: -1}
	rotated, err := enforceProvisional(context.Background(), memstore.New(), "scope", "", header, raw, unmatched)
	if err != nil || rotated {
		t.Fatalf("an unmatched slot must pass the gate: rotated=%v err=%v", rotated, err)
	}
}

// A provisional unlock against read-only storage must explain the conflict:
// replacing the temporary passphrase is a header write.
func TestEnforceProvisionalRefusesReadOnly(t *testing.T) {
	header, raw, res := provisionalFixture(t)
	store := memstore.New()
	rotated, err := enforceProvisional(context.Background(), store, "scope", `storage "ro" is read-only`, header, raw, res)
	if rotated || err == nil {
		t.Fatalf("rotated=%v err=%v, want a refusal", rotated, err)
	}
	if !strings.Contains(err.Error(), "temporary onboarding passphrase") || !strings.Contains(err.Error(), "write-capable") {
		t.Fatalf("the refusal must name the provisional slot and the way out, got: %v", err)
	}
	if header.Slots[1].Provisional == false {
		t.Fatal("the slot must stay provisional after a refusal")
	}
}
