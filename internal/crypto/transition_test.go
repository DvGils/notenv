package crypto

import (
	"strings"
	"testing"
)

func twoMasters(t *testing.T) (*MasterKey, *MasterKey) {
	t.Helper()
	old, err := GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	new, err := GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	return old, new
}

func TestSignPubIsStablePerMaster(t *testing.T) {
	old, new := twoMasters(t)
	a1, err := old.SignPub()
	if err != nil {
		t.Fatal(err)
	}
	a2, err := old.SignPub()
	if err != nil {
		t.Fatal(err)
	}
	b, err := new.SignPub()
	if err != nil {
		t.Fatal(err)
	}
	if a1 != a2 {
		t.Fatal("a master's signing key must be deterministic")
	}
	if a1 == b {
		t.Fatal("distinct masters must derive distinct signing keys")
	}
	// Round-trips through the string form the session cache uses.
	reparsed, err := ParseMasterKey(old.String())
	if err != nil {
		t.Fatal(err)
	}
	r, err := reparsed.SignPub()
	if err != nil {
		t.Fatal(err)
	}
	if r != a1 {
		t.Fatal("signing key must survive the cache round-trip")
	}
}

func TestTransitionRoundTrip(t *testing.T) {
	old, new := twoMasters(t)
	tr, err := NewTransition(old, new, "vault-1", 7)
	if err != nil {
		t.Fatal(err)
	}
	if err := tr.Verify(); err != nil {
		t.Fatalf("freshly signed transition must verify: %v", err)
	}
	if tr.ToMasterPub != new.PublicKey() || tr.ToRevision != 7 || tr.VaultID != "vault-1" {
		t.Fatalf("transition fields wrong: %+v", tr)
	}
}

func TestTransitionRejectsTampering(t *testing.T) {
	old, new := twoMasters(t)
	for name, mutate := range map[string]func(*Transition){
		"vault id":    func(tr *Transition) { tr.VaultID = "other-vault" },
		"to sign pub": func(tr *Transition) { tr.ToSignPub = strings.Repeat("ab", 32) },
		"to master":   func(tr *Transition) { tr.ToMasterPub = "age1other" },
		"revision":    func(tr *Transition) { tr.ToRevision++ },
		"signature":   func(tr *Transition) { tr.Sig[0] ^= 1 },
	} {
		tr, err := NewTransition(old, new, "vault-1", 7)
		if err != nil {
			t.Fatal(err)
		}
		mutate(tr)
		if err := tr.Verify(); err == nil {
			t.Fatalf("tampered %s must not verify", name)
		}
	}
}

func TestTransitionRejectsForeignSigner(t *testing.T) {
	old, new := twoMasters(t)
	intruder, err := GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	// An intruder signs a transition claiming to be from the pinned master:
	// the record's FromSignPub (the pinned key) must not verify their sig.
	tr, err := NewTransition(intruder, new, "vault-1", 7)
	if err != nil {
		t.Fatal(err)
	}
	pinned, err := old.SignPub()
	if err != nil {
		t.Fatal(err)
	}
	tr.FromSignPub = pinned
	if err := tr.Verify(); err == nil {
		t.Fatal("a transition not signed by its claimed from-key must not verify")
	}
}
