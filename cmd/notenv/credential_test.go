package main

import (
	"path/filepath"
	"testing"

	"filippo.io/age"

	"github.com/DvGils/notenv/internal/config"
	"github.com/DvGils/notenv/internal/crypto"
)

// TestLoadHeaderStoreHonorsNotenvStorage guards the v0.19.1 fix: the header path
// behind `credential`, `vault export`, and `vault copy` must resolve storage the
// same way the rest of the CLI does (--storage, then NOTENV_STORAGE, then binding/default),
// so an agent or CI pointed at a vault only via NOTENV_STORAGE is not silently sent
// to the machine default.
func TestLoadHeaderStoreHonorsNotenvStorage(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir()) // isolate from the real machine config
	dir := t.TempDir()
	t.Setenv(storageEnv, "local:"+dir)

	target, err := loadHeaderStore()
	if err != nil {
		t.Fatalf("loadHeaderStore: %v", err)
	}
	if want := (config.Effective{Path: filepath.Clean(dir)}).Scope(); target.scope != want {
		t.Fatalf("loadHeaderStore scope = %q, want %q (NOTENV_STORAGE ignored?)", target.scope, want)
	}
}

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
