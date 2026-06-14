package crypto

import (
	"crypto/sha256"
	"encoding/base32"
	"strings"
)

// fingerprintContext domain-separates the onboarding fingerprint from any
// other hash of header fields.
const fingerprintContext = "notenv-onboarding-fingerprint-v1"

// fingerprintLen is the printed length in base32 characters: 16 characters
// carry 80 bits. This is the only cryptographic barrier against an active
// substitution attacker on a compromised onboarding channel (the temp passphrase
// already defeats substitution otherwise), and the attack is an offline grind of
// attacker-chosen vault identities until the digest matches, so the bar must be a
// resourced-adversary bar, not a casual one. 80 bits is past a GPU-cluster grind
// while still short enough to ride along a chat message.
const fingerprintLen = 16

// fingerprintEncoding is lowercase base32 without padding: case-insensitive
// to retype, no characters that need escaping or break on word boundaries.
var fingerprintEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// Fingerprint digests a vault's identity and signing key into a short code
// the vault owner sends out-of-band during onboarding. A first contact that
// verifies the served header against it (directly, or through the signed
// rotation chain to an ancestor signing key) cannot be pointed at a
// substituted vault, which closes trust-on-first-use for onboarded humans.
func Fingerprint(vaultID, signPub string) string {
	h := sha256.New()
	h.Write([]byte(fingerprintContext))
	h.Write([]byte{0})
	h.Write([]byte(vaultID))
	h.Write([]byte{0})
	h.Write([]byte(signPub))
	code := strings.ToLower(fingerprintEncoding.EncodeToString(h.Sum(nil)))
	return code[:fingerprintLen]
}
