package crypto

import (
	"bytes"
	"errors"
	"testing"

	"filippo.io/age"
)

// TestDecryptRejectsHighWorkFactor: a slot wrapped above the work-factor cap is
// refused (age checks the embedded factor before running scrypt, so a planted
// high-cost slot costs nothing), while a slot at the cap still opens. The cap is
// lowered here so both fixtures are cheap to build.
func TestDecryptRejectsHighWorkFactor(t *testing.T) {
	const pass = "correct horse battery staple"
	prev := maxScryptWorkFactor
	maxScryptWorkFactor = 8
	t.Cleanup(func() { maxScryptWorkFactor = prev })

	wrapAt := func(logN int) []byte {
		t.Helper()
		r, err := age.NewScryptRecipient(pass)
		if err != nil {
			t.Fatal(err)
		}
		r.SetWorkFactor(logN)
		ct, err := encryptTo([]byte("slot-key"), r)
		if err != nil {
			t.Fatal(err)
		}
		return ct
	}

	if got, err := NewPassphraseCipher(pass).Decrypt(wrapAt(8)); err != nil || string(got) != "slot-key" {
		t.Fatalf("a slot at the work-factor cap must open: got %q, err %v", got, err)
	}
	if _, err := NewPassphraseCipher(pass).Decrypt(wrapAt(10)); err == nil {
		t.Fatal("a slot wrapped above the work-factor cap must be refused")
	}
}

func TestPassphraseRoundTrip(t *testing.T) {
	plaintext := []byte(`{"DATABASE_URL":"postgres://x"}`)
	c := NewPassphraseCipher("correct horse battery staple")

	sealed, err := c.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if bytes.Contains(sealed, []byte("postgres")) {
		t.Fatal("ciphertext leaks plaintext")
	}

	got, err := c.Decrypt(sealed)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round trip mismatch: got %q", got)
	}
}

func TestWrongPassphrase(t *testing.T) {
	sealed, err := NewPassphraseCipher("right").Encrypt([]byte("secret"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	_, err = NewPassphraseCipher("wrong").Decrypt(sealed)
	if !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("want ErrWrongPassphrase, got %v", err)
	}
}
