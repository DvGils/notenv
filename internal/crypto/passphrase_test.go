package crypto

import (
	"bytes"
	"errors"
	"testing"
)

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
