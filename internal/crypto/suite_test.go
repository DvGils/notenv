package crypto

import (
	"strings"
	"testing"

	"filippo.io/age"
)

// TestNewVaultRecordsSuiteAndKDF: a freshly minted vault records the suite it
// was built under, and a passphrase slot records its KDF. A recipient slot has
// no KDF (it is not passphrase-wrapped).
func TestNewVaultRecordsSuiteAndKDF(t *testing.T) {
	h, _, err := NewHeader("pass", "owner")
	if err != nil {
		t.Fatal(err)
	}
	if h.Suite != SuiteX25519 {
		t.Fatalf("new header suite = %q, want %q", h.Suite, SuiteX25519)
	}
	if h.Slots[0].KDF != KDFAgeScrypt {
		t.Fatalf("passphrase slot KDF = %q, want %q", h.Slots[0].KDF, KDFAgeScrypt)
	}

	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	rh, _, err := NewRecipientHeader(id.Recipient(), "ci")
	if err != nil {
		t.Fatal(err)
	}
	if rh.Suite != SuiteX25519 {
		t.Fatalf("recipient header suite = %q, want %q", rh.Suite, SuiteX25519)
	}
	if rh.Slots[0].KDF != "" {
		t.Fatalf("recipient slot must carry no KDF, got %q", rh.Slots[0].KDF)
	}
}

// TestParseHeaderRoundTripsSuiteAndKDF: the suite and per-slot KDF survive a
// marshal/parse cycle, so a vault read on another machine resolves the same
// algorithm bundle it was written under.
func TestParseHeaderRoundTripsSuiteAndKDF(t *testing.T) {
	h, _, err := NewHeader("pass", "owner")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := h.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseHeader(raw)
	if err != nil {
		t.Fatalf("a header on a known suite must parse: %v", err)
	}
	if parsed.Suite != SuiteX25519 || parsed.Slots[0].KDF != KDFAgeScrypt {
		t.Fatalf("suite/KDF did not round-trip: suite=%q kdf=%q", parsed.Suite, parsed.Slots[0].KDF)
	}
}

// TestParseHeaderRejectsUnknownSuite: a vault naming a suite this build does not
// implement is refused, fail-closed, not best-effort parsed. This is what makes
// an older binary refuse a vault written under a newer suite (the compatibility
// contract), rather than silently mishandling it.
func TestParseHeaderRejectsUnknownSuite(t *testing.T) {
	h, _, err := NewHeader("pass", "owner")
	if err != nil {
		t.Fatal(err)
	}
	h.Suite = "pq-some-future-suite"
	raw, err := h.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	_, err = ParseHeader(raw)
	if err == nil || !strings.Contains(err.Error(), "upgrade notenv") {
		t.Fatalf("an unknown suite must be refused with an upgrade pointer, got %v", err)
	}
}

// TestParseHeaderRejectsUnknownSlotKDF: a passphrase slot wrapped under a KDF
// this build does not implement is refused the same way.
func TestParseHeaderRejectsUnknownSlotKDF(t *testing.T) {
	h, _, err := NewHeader("pass", "owner")
	if err != nil {
		t.Fatal(err)
	}
	h.Slots[0].KDF = "argon2id-future"
	raw, err := h.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	_, err = ParseHeader(raw)
	if err == nil || !strings.Contains(err.Error(), "upgrade notenv") {
		t.Fatalf("an unknown slot KDF must be refused with an upgrade pointer, got %v", err)
	}
}

// TestParseHeaderRejectsMissingSuite: a structurally complete header with no
// suite at all is corrupt, not defaulted.
func TestParseHeaderRejectsMissingSuite(t *testing.T) {
	h, _, err := NewHeader("pass", "owner")
	if err != nil {
		t.Fatal(err)
	}
	h.Suite = ""
	raw, err := h.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseHeader(raw); err == nil || !strings.Contains(err.Error(), "no cipher suite") {
		t.Fatalf("a header with no suite must be refused as corrupt, got %v", err)
	}
}

// TestRotateSlotModernizesKDF: re-wrapping a slot stamps it with the current
// KDF, so a passphrase KDF upgrade reaches a slot the next time its owner
// rotates, with no vault-wide flag day.
func TestRotateSlotModernizesKDF(t *testing.T) {
	h, _, err := NewHeader("old pass", "owner")
	if err != nil {
		t.Fatal(err)
	}
	_, _, slotKey, err := h.Unlock("old pass")
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a slot wrapped under some prior KDF; rotation must bring it current.
	h.Slots[0].KDF = "legacy-kdf"
	if err := h.RotateSlot(0, "new pass", slotKey); err != nil {
		t.Fatal(err)
	}
	if h.Slots[0].KDF != currentKDF {
		t.Fatalf("rotated slot KDF = %q, want current %q", h.Slots[0].KDF, currentKDF)
	}
}

// TestRegistryMembership: the public predicates report exactly the shipped
// algorithms.
func TestRegistryMembership(t *testing.T) {
	if !SuiteKnown(SuiteX25519) || SuiteKnown("nope") {
		t.Fatal("SuiteKnown must accept the shipped suite and reject others")
	}
	if !KDFKnown(KDFAgeScrypt) || KDFKnown("nope") {
		t.Fatal("KDFKnown must accept the shipped KDF and reject others")
	}
}
