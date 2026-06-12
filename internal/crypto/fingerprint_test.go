package crypto

import (
	"regexp"
	"testing"
)

func TestFingerprintShape(t *testing.T) {
	code := Fingerprint("vault-1", "abcdef")
	if !regexp.MustCompile(`^[a-z2-7]{12}$`).MatchString(code) {
		t.Fatalf("fingerprint %q must be 12 lowercase base32 characters", code)
	}
	if Fingerprint("vault-1", "abcdef") != code {
		t.Fatal("fingerprint must be deterministic")
	}
	if Fingerprint("vault-2", "abcdef") == code || Fingerprint("vault-1", "abcdeg") == code {
		t.Fatal("fingerprint must depend on both the vault id and the signing key")
	}
	// The separator makes ("ab","c") and ("a","bc") distinct preimages.
	if Fingerprint("ab", "c") == Fingerprint("a", "bc") {
		t.Fatal("field boundaries must be domain-separated")
	}
}
