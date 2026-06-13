package main

import (
	"testing"

	"filippo.io/age"

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
