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

func TestSplitOnboardingString(t *testing.T) {
	pass, fp := splitOnboardingString("edge-bats-prize-dab-pagan-probe/3f6k2c7m4x2p")
	if pass != "edge-bats-prize-dab-pagan-probe" || fp != "3f6k2c7m4x2p" {
		t.Fatalf("split = %q, %q", pass, fp)
	}
	for _, plain := range []string{
		"my own passphrase",
		"with/slash",
		"edge-bats-prize-dab-pagan-probe",              // no code
		"edge-bats-prize-dab-pagan-probe/3f6k2c",       // code too short
		"edge-bats-prize-dab/3f6k2c7m4x2p",             // too few words
		"Edge-bats-prize-dab-pagan-probe/3f6k2c7m4x2p", // uppercase
		"edge-bats-prize-dab-pagan-probe/3f6k2c7m4x21", // 1 is not base32
	} {
		if pass, fp := splitOnboardingString(plain); pass != plain || fp != "" {
			t.Fatalf("%q must not split, got %q, %q", plain, pass, fp)
		}
	}
}

// TestVerifyOnboardingFingerprint: a matching code passes, a mismatched code
// is refused naming the substitution risk (no transitions exist to walk).
func TestVerifyOnboardingFingerprint(t *testing.T) {
	ctx := context.Background()
	header, mk, err := crypto.NewHeader("owner pass", "owner")
	if err != nil {
		t.Fatal(err)
	}
	store := memstore.New()

	good := crypto.Fingerprint(header.VaultID, header.SignPub)
	if err := verifyOnboardingFingerprint(ctx, store, header, mk, good); err != nil {
		t.Fatalf("matching code: %v", err)
	}
	err = verifyOnboardingFingerprint(ctx, store, header, mk, "aaaaaaaaaaaa")
	if err == nil || !strings.Contains(err.Error(), "substituted") {
		t.Fatalf("mismatched code: err = %v, want a substitution refusal", err)
	}
}

// TestRequireHumanPassphraseNonInteractive: plaintext egress needs a human;
// with no terminal it refuses outright, before touching storage.
func TestRequireHumanPassphraseNonInteractive(t *testing.T) {
	forceNonInteractive(t)
	a := &app{}
	err := a.requireHumanPassphrase(context.Background(), "--no-mask sends raw secret values to a captured stream")
	if err == nil || !strings.Contains(err.Error(), "no terminal") {
		t.Fatalf("err = %v, want a no-terminal refusal", err)
	}
}
