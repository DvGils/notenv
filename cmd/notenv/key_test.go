package main

import (
	"testing"

	"filippo.io/age"

	"github.com/DvGils/notenv/internal/config"
	"github.com/DvGils/notenv/internal/crypto"
)

// TestRefuseRecipientPrimary: primary may move to a human passphrase slot, but
// not to a machine identity, which would strand governance if that machine is
// lost.
func TestRefuseRecipientPrimary(t *testing.T) {
	h, mk, err := crypto.NewHeader("owner passphrase", "owner@laptop")
	if err != nil {
		t.Fatalf("NewHeader: %v", err)
	}
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	if err := h.AddRecipientSlot(id.Recipient(), "ci", mk); err != nil {
		t.Fatalf("AddRecipientSlot: %v", err)
	}
	// slot 0 is the owner's passphrase slot, slot 1 the machine identity.
	if err := refuseRecipientPrimary(h, 0); err != nil {
		t.Fatalf("a passphrase slot must be allowed as primary: %v", err)
	}
	if err := refuseRecipientPrimary(h, 1); err == nil {
		t.Fatal("a recipient (machine) slot must be refused as primary")
	}
}

// TestRepinRestored: a restored header that verifies under the master moves the
// pin to its (lower) revision so the operator's next command does not raise a
// rollback alarm; one that does not verify is left alone.
func TestRepinRestored(t *testing.T) {
	isolateConfig(t)
	header, mk, err := crypto.NewHeader("owner pass", "owner")
	if err != nil {
		t.Fatal(err)
	}
	header.Revision = 5
	if err := header.Seal(mk); err != nil { // re-seal so the tag covers revision 5
		t.Fatal(err)
	}

	if !repinRestored("scope", header, mk) {
		t.Fatal("a header that verifies under the master must re-pin")
	}
	pin, have, err := config.ReadPin(header.VaultID)
	if err != nil {
		t.Fatal(err)
	}
	if !have || pin.Revision != 5 {
		t.Fatalf("pin = %+v have=%v, want revision 5", pin, have)
	}

	_, other, err := crypto.NewHeader("other pass", "x")
	if err != nil {
		t.Fatal(err)
	}
	if repinRestored("scope", header, other) {
		t.Fatal("a header that does not verify under the given master must not re-pin")
	}
	if repinRestored("scope", header, nil) {
		t.Fatal("a nil master must not re-pin")
	}
}
