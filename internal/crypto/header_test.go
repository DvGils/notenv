package crypto

import (
	"bytes"
	"errors"
	"testing"
)

func TestHeaderLifecycle(t *testing.T) {
	header, mk, err := NewHeader("escrowed passphrase", "demian@legion")
	if err != nil {
		t.Fatalf("NewHeader: %v", err)
	}
	if !header.Slots[0].Primary || header.Slots[0].Name != "demian@legion" {
		t.Errorf("slot 0 should be primary and named: %+v", header.Slots[0])
	}

	// Blob round-trip under the master key.
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
	unlocked, err := parsed.Unlock("escrowed passphrase")
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	plaintext, err := unlocked.Decrypt(blob)
	if err != nil {
		t.Fatalf("Decrypt with unlocked key: %v", err)
	}
	if !bytes.Equal(plaintext, []byte(`{"K":"v"}`)) {
		t.Fatalf("round trip mismatch: %q", plaintext)
	}

	if _, err := parsed.Unlock("wrong"); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("want ErrWrongPassphrase, got %v", err)
	}
}

func TestHeaderSecondSlot(t *testing.T) {
	header, mk, err := NewHeader("first", "owner@laptop")
	if err != nil {
		t.Fatal(err)
	}
	if err := header.AddSlot("second", "teammate@desktop", mk); err != nil {
		t.Fatalf("AddSlot: %v", err)
	}
	if header.Slots[1].Primary {
		t.Error("added slot must not be primary")
	}

	for _, pass := range []string{"first", "second"} {
		unlocked, err := header.Unlock(pass)
		if err != nil {
			t.Fatalf("Unlock(%q): %v", pass, err)
		}
		if unlocked.String() != mk.String() {
			t.Fatalf("slot %q unwrapped a different master key", pass)
		}
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
	if _, err := ParseHeader([]byte(`{"version":2,"slots":[{"wrapped":"AA=="}]}`)); err == nil {
		t.Error("want error for unknown version")
	}
	if _, err := ParseHeader([]byte(`{"version":1,"slots":[]}`)); err == nil {
		t.Error("want error for empty slots")
	}
	if _, err := ParseHeader([]byte(`not json`)); err == nil {
		t.Error("want error for non-JSON")
	}
}
