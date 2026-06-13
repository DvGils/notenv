package crypto

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"filippo.io/age"
)

func TestHeaderLifecycle(t *testing.T) {
	header, mk, err := NewHeader("escrowed passphrase", "demian@legion")
	if err != nil {
		t.Fatalf("NewHeader: %v", err)
	}
	if !header.Slots[0].Primary || header.Slots[0].Name != "demian@legion" {
		t.Errorf("slot 0 should be primary and named: %+v", header.Slots[0])
	}
	if header.Slots[0].Type != SlotPassphrase || header.Slots[0].PublicKey == "" {
		t.Errorf("slot 0 should be a passphrase slot with a public key: %+v", header.Slots[0])
	}

	blob, err := mk.Encrypt([]byte(`{"K":"v"}`))
	if err != nil {
		t.Fatalf("master Encrypt: %v", err)
	}

	// Marshal, parse, unlock, as a fresh machine would.
	raw, err := header.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	parsed, err := ParseHeader(raw)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	unlocked, idx, _, err := parsed.Unlock("escrowed passphrase")
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if idx != 0 {
		t.Fatalf("matched slot = %d, want 0", idx)
	}
	plaintext, err := unlocked.Decrypt(blob)
	if err != nil {
		t.Fatalf("Decrypt with unlocked key: %v", err)
	}
	if !bytes.Equal(plaintext, []byte(`{"K":"v"}`)) {
		t.Fatalf("round trip mismatch: %q", plaintext)
	}

	if _, _, _, err := parsed.Unlock("wrong"); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("want ErrWrongPassphrase, got %v", err)
	}
}

func TestHeaderSecondSlot(t *testing.T) {
	header, mk, err := NewHeader("first", "owner@laptop")
	if err != nil {
		t.Fatal(err)
	}
	if err := header.AddPassphraseSlot("second", "backup@laptop", mk); err != nil {
		t.Fatalf("AddPassphraseSlot: %v", err)
	}
	if header.Slots[1].Primary {
		t.Error("added slot must not be primary")
	}

	for want, pass := range map[int]string{0: "first", 1: "second"} {
		unlocked, idx, _, err := header.Unlock(pass)
		if err != nil {
			t.Fatalf("Unlock(%q): %v", pass, err)
		}
		if idx != want {
			t.Fatalf("Unlock(%q) matched slot %d, want %d", pass, idx, want)
		}
		if unlocked.String() != mk.String() {
			t.Fatalf("slot %q unwrapped a different master key", pass)
		}
	}
}

func TestRecipientSlot(t *testing.T) {
	header, mk, err := NewHeader("escrowed", "owner@laptop")
	if err != nil {
		t.Fatal(err)
	}
	teammate, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	if err := header.AddRecipientSlot(teammate.Recipient(), "alice", mk); err != nil {
		t.Fatalf("AddRecipientSlot: %v", err)
	}
	slot := header.Slots[1]
	if slot.Type != SlotRecipient || slot.PublicKey != teammate.Recipient().String() || len(slot.Wrapped) != 0 {
		t.Fatalf("recipient slot malformed: %+v", slot)
	}

	got, idx, err := header.UnlockIdentity(teammate)
	if err != nil {
		t.Fatalf("UnlockIdentity: %v", err)
	}
	if idx != 1 || got.String() != mk.String() {
		t.Fatalf("recipient unlock: idx=%d key match=%v", idx, got.String() == mk.String())
	}

	// The original passphrase slot still works.
	if viaPass, _, _, err := header.Unlock("escrowed"); err != nil || viaPass.String() != mk.String() {
		t.Fatalf("passphrase slot broken alongside recipient slot: %v", err)
	}

	// A stranger's identity does not unlock.
	stranger, _ := age.GenerateX25519Identity()
	if _, _, err := header.UnlockIdentity(stranger); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("stranger should not unlock, got %v", err)
	}
}

// TestSetMasterLossless is the core model-B property: rotating the master
// re-wraps it to every slot's public key, so every slot keeps working.
func TestSetMasterLossless(t *testing.T) {
	header, oldMK, err := NewHeader("pass", "owner@laptop")
	if err != nil {
		t.Fatal(err)
	}
	teammate, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	if err := header.AddRecipientSlot(teammate.Recipient(), "alice", oldMK); err != nil {
		t.Fatal(err)
	}

	newMK, err := GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	if newMK.String() == oldMK.String() {
		t.Fatal("a fresh master must differ")
	}
	if err := header.SetMaster(newMK); err != nil {
		t.Fatalf("SetMaster: %v", err)
	}

	// Both the passphrase slot and the recipient slot now yield the new master.
	if got, _, _, err := header.Unlock("pass"); err != nil || got.String() != newMK.String() {
		t.Fatalf("passphrase slot lost in rotation: %v", err)
	}
	if got, _, err := header.UnlockIdentity(teammate); err != nil || got.String() != newMK.String() {
		t.Fatalf("recipient slot lost in rotation: %v", err)
	}
}

func TestRotateSlotPreservesMasterKey(t *testing.T) {
	header, mk, err := NewHeader("old-pass", "owner@laptop")
	if err != nil {
		t.Fatal(err)
	}
	blob, err := mk.Encrypt([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}

	_, idx, slotKey, err := header.Unlock("old-pass")
	if err != nil {
		t.Fatal(err)
	}
	if err := header.RotateSlot(idx, "new-pass", slotKey); err != nil {
		t.Fatalf("RotateSlot: %v", err)
	}

	if _, _, _, err := header.Unlock("old-pass"); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("old passphrase should no longer open the slot, got %v", err)
	}
	rotated, _, _, err := header.Unlock("new-pass")
	if err != nil {
		t.Fatalf("Unlock(new-pass): %v", err)
	}
	plain, err := rotated.Decrypt(blob)
	if err != nil || string(plain) != "secret" {
		t.Fatalf("master key changed under rotation: %v %q", err, plain)
	}
	if !header.Slots[0].Primary {
		t.Fatal("rotation should preserve the primary flag")
	}
}

func TestRemoveSlot(t *testing.T) {
	header, mk, err := NewHeader("first", "owner@laptop")
	if err != nil {
		t.Fatal(err)
	}
	if err := header.AddPassphraseSlot("second", "backup@laptop", mk); err != nil {
		t.Fatal(err)
	}

	if err := header.RemoveSlot(1, mk); err != nil {
		t.Fatalf("RemoveSlot: %v", err)
	}
	if len(header.Slots) != 1 {
		t.Fatalf("expected 1 slot after removal, got %d", len(header.Slots))
	}
	if _, _, _, err := header.Unlock("second"); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("removed slot should not unlock, got %v", err)
	}
	if got, _, _, err := header.Unlock("first"); err != nil || got.String() != mk.String() {
		t.Fatalf("surviving slot should still unlock: %v", err)
	}

	if err := header.RemoveSlot(0, mk); err == nil {
		t.Fatal("removing the last slot must be refused")
	}
	if err := header.RemoveSlot(5, mk); err == nil {
		t.Fatal("out-of-range index must be refused")
	}
}

func TestSetPrimary(t *testing.T) {
	header, mk, err := NewHeader("first", "owner@laptop")
	if err != nil {
		t.Fatal(err)
	}
	if err := header.AddPassphraseSlot("second", "backup@laptop", mk); err != nil {
		t.Fatal(err)
	}
	if header.PrimarySlot() != 0 {
		t.Fatalf("initial primary = %d, want 0", header.PrimarySlot())
	}
	if err := header.SetPrimary(1); err != nil {
		t.Fatalf("SetPrimary: %v", err)
	}
	if header.Slots[0].Primary || !header.Slots[1].Primary || header.PrimarySlot() != 1 {
		t.Fatalf("primary not transferred: %+v", header.Slots)
	}
	if err := header.SetPrimary(5); err == nil {
		t.Error("out-of-range SetPrimary should error")
	}
}

func TestMasterKeyMismatch(t *testing.T) {
	_, mk1, err := NewHeader("p", "")
	if err != nil {
		t.Fatal(err)
	}
	_, mk2, err := NewHeader("p", "")
	if err != nil {
		t.Fatal(err)
	}
	blob, err := mk1.Encrypt([]byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mk2.Decrypt(blob); err == nil {
		t.Fatal("want error decrypting with the wrong master key")
	}
}

func TestParseHeaderRejectsBad(t *testing.T) {
	good, _, err := NewHeader("p", "owner")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := good.Marshal()
	if !strings.Contains(string(raw), `"version": 5`) {
		t.Fatalf("expected version 5 header, got:\n%s", raw)
	}

	const idAndKey = `"vault_id":"v1","sign_pub":"ab",`
	if _, err := ParseHeader([]byte(`{"version":99,` + idAndKey + `"master":"AA==","slots":[{"public_key":"x"}],"auth":"AA=="}`)); err == nil {
		t.Error("want error for a newer version")
	}
	for _, old := range []string{"1", "2", "3", "4"} {
		if _, err := ParseHeader([]byte(`{"version":` + old + `,` + idAndKey + `"master":"AA==","slots":[{"public_key":"x"}],"auth":"AA=="}`)); err == nil || !strings.Contains(err.Error(), "older storage format") {
			t.Errorf("version %s must report an unreadable older format, got %v", old, err)
		}
	}
	if _, err := ParseHeader([]byte(`{"version":5,"sign_pub":"ab","master":"AA==","slots":[{"public_key":"x"}],"auth":"AA=="}`)); err == nil {
		t.Error("want error for missing vault id")
	}
	if _, err := ParseHeader([]byte(`{"version":5,"vault_id":"v1","master":"AA==","slots":[{"public_key":"x"}],"auth":"AA=="}`)); err == nil {
		t.Error("want error for missing signing public key")
	}
	if _, err := ParseHeader([]byte(`{"version":5,` + idAndKey + `"master":"AA==","slots":[],"auth":"AA=="}`)); err == nil {
		t.Error("want error for empty slots")
	}
	if _, err := ParseHeader([]byte(`{"version":5,` + idAndKey + `"slots":[{"public_key":"x"}],"auth":"AA=="}`)); err == nil {
		t.Error("want error for missing master")
	}
	if _, err := ParseHeader([]byte(`{"version":5,` + idAndKey + `"master":"AA==","slots":[{"public_key":"x"}]}`)); err == nil {
		t.Error("want error for missing authentication tag")
	}
	if _, err := ParseHeader([]byte(`not json`)); err == nil {
		t.Error("want error for non-JSON")
	}
}

// A provisional slot survives the marshal round-trip and is absent from the
// canonical bytes when unset.
func TestProvisionalSlotRoundTrip(t *testing.T) {
	header, mk, err := NewHeader("owner pass", "owner")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := header.Marshal()
	if strings.Contains(string(raw), "provisional") || strings.Contains(string(raw), `"ts"`) {
		t.Fatalf("unset provisional/ts must be omitted:\n%s", raw)
	}

	if err := header.AddPassphraseSlot("temp onboarding pass", "alice", mk); err != nil {
		t.Fatal(err)
	}
	header.Slots[1].Provisional = true
	header.Slots[1].TS = 1765500000
	raw, _ = header.Marshal()
	parsed, err := ParseHeader(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.Slots[1].Provisional || parsed.Slots[1].TS != 1765500000 {
		t.Fatalf("provisional/ts lost in round-trip: %+v", parsed.Slots[1])
	}
}

// Rotating a provisional slot to an own passphrase clears the flag, keeps the
// creation time, kills the temporary passphrase, and preserves the master.
func TestProvisionalRotationClears(t *testing.T) {
	header, mk, err := NewHeader("owner pass", "owner")
	if err != nil {
		t.Fatal(err)
	}
	if err := header.AddPassphraseSlot("temp onboarding pass", "alice", mk); err != nil {
		t.Fatal(err)
	}
	header.Slots[1].Provisional = true
	header.Slots[1].TS = 1765500000

	unlocked, idx, slotKey, err := header.Unlock("temp onboarding pass")
	if err != nil || idx != 1 {
		t.Fatalf("Unlock with temp passphrase: idx=%d err=%v", idx, err)
	}
	if err := header.RotateSlot(idx, "alice's own pass", slotKey); err != nil {
		t.Fatal(err)
	}
	if header.Slots[1].Provisional {
		t.Fatal("RotateSlot must clear Provisional")
	}
	if header.Slots[1].TS != 1765500000 {
		t.Fatal("RotateSlot must not touch TS")
	}
	if _, _, _, err := header.Unlock("temp onboarding pass"); err == nil {
		t.Fatal("the temporary passphrase must stop opening the slot after rotation")
	}
	again, _, _, err := header.Unlock("alice's own pass")
	if err != nil {
		t.Fatal(err)
	}
	if again.String() != unlocked.String() {
		t.Fatal("rotation must preserve the master key")
	}
}

// TestUnlockSkipsSlotThatDoesNotOpenMaster: a passphrase slot whose wrapped key
// decrypts under the passphrase but is not a recipient of the master (a stale or
// planted slot) must not shadow a valid later slot that shares the passphrase.
func TestUnlockSkipsSlotThatDoesNotOpenMaster(t *testing.T) {
	const pass = "shared passphrase"
	header, mk, err := NewHeader(pass, "owner@laptop")
	if err != nil {
		t.Fatalf("NewHeader: %v", err)
	}
	if err := header.AddPassphraseSlot(pass, "backup@laptop", mk); err != nil {
		t.Fatalf("AddPassphraseSlot: %v", err)
	}
	// Poison slot 0: its blob still decrypts under the passphrase, but to an
	// identity that is not a recipient of the master, so it cannot open it.
	foreign, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	poisoned, err := NewPassphraseCipher(pass).Encrypt([]byte(foreign.String()))
	if err != nil {
		t.Fatal(err)
	}
	header.Slots[0].Wrapped = poisoned

	got, idx, _, err := header.Unlock(pass)
	if err != nil {
		t.Fatalf("Unlock must skip the poisoned slot and use the valid one: %v", err)
	}
	if idx != 1 {
		t.Fatalf("opened slot %d, want the valid slot 1", idx)
	}
	if got.PublicKey() != mk.PublicKey() {
		t.Fatal("Unlock returned a master other than the vault's")
	}
}

// TestUnlockMatchedButNoneOpens: when the passphrase matches a slot whose key
// cannot open the master and no other slot opens, Unlock reports
// ErrWrongPassphrase (so callers re-prompt) rather than a raw age error.
func TestUnlockMatchedButNoneOpens(t *testing.T) {
	const pass = "the passphrase"
	header, _, err := NewHeader(pass, "owner@laptop")
	if err != nil {
		t.Fatalf("NewHeader: %v", err)
	}
	foreign, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	poisoned, err := NewPassphraseCipher(pass).Encrypt([]byte(foreign.String()))
	if err != nil {
		t.Fatal(err)
	}
	header.Slots[0].Wrapped = poisoned

	if _, _, _, err := header.Unlock(pass); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("Unlock = %v, want ErrWrongPassphrase", err)
	}
}
