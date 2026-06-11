package crypto

import (
	"testing"
)

func TestSealVerify(t *testing.T) {
	header, mk, err := NewHeader("pass", "owner")
	if err != nil {
		t.Fatal(err)
	}
	// NewHeader seals, so a fresh header verifies.
	if err := header.Verify(mk); err != nil {
		t.Fatalf("fresh header should verify: %v", err)
	}

	// Survives a marshal/parse round-trip (canonicalization is stable).
	raw, err := header.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseHeader(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := parsed.Verify(mk); err != nil {
		t.Fatalf("parsed header should verify: %v", err)
	}

	// A different master's key does not verify.
	other, _ := GenerateMasterKey()
	if err := parsed.Verify(other); err == nil {
		t.Fatal("verify under the wrong master should fail")
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	header, mk, err := NewHeader("pass", "owner")
	if err != nil {
		t.Fatal(err)
	}
	// Tamper with the slot set without re-sealing (an attacker without the key).
	header.Slots = append(header.Slots, Slot{Name: "intruder", Type: SlotRecipient, PublicKey: "age1xxx"})
	if err := header.Verify(mk); err == nil {
		t.Fatal("verify must detect an added slot")
	}

	// Tamper with the revision.
	header2, mk2, _ := NewHeader("pass", "owner")
	header2.Revision = 999
	if err := header2.Verify(mk2); err == nil {
		t.Fatal("verify must detect a changed revision")
	}
}
