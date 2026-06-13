package crypto

import "fmt"

// Cryptographic agility lives here. A vault records which algorithm bundle it
// uses, so a future change (a stronger KDF, a hybrid post-quantum recipient) is
// an additive registry entry rather than a format break. notenv owns the choice
// entirely: users never name or select a suite. See design/crypto-agility.md.
//
// The discipline that keeps agility safe: a single identifier selects a whole
// vetted bundle (no per-primitive negotiation, so no attacker-chosen weak
// combination), the identifier rides inside the header where the master-keyed
// auth tag covers it (so a downgrade needs the master), and an unrecognized
// identifier is refused, never best-effort parsed.

// Suite identifiers. A suite bundles the master-key type, object/wrap
// encryption, the header and manifest MACs, and the rotation signature.
const (
	// SuiteX25519 is notenv's only suite: an age X25519 master, age
	// (X25519 -> ChaCha20-Poly1305) encryption, HMAC-SHA256 header and manifest
	// MACs keyed via HKDF-SHA256, and Ed25519 rotation signatures.
	SuiteX25519 = "x25519-hmacsha256-ed25519"

	// currentSuite is the suite new vaults are minted under and rotations land
	// on. notenv reads any known suite but writes only this one.
	currentSuite = SuiteX25519
)

// knownSuites is the curated registry. A header whose suite is absent here is
// refused: a newer notenv wrote it, or it is corrupt. A second suite is added by
// implementing its primitives and listing it here.
var knownSuites = map[string]bool{
	SuiteX25519: true,
}

// SuiteKnown reports whether this build can read a vault on the given suite.
func SuiteKnown(suite string) bool { return knownSuites[suite] }

// KDF identifiers. The passphrase KDF is recorded per slot, not per suite,
// because slots are independently re-wrapped (RotateSlot), so a KDF can be
// upgraded one slot at a time as each owner re-enters their passphrase.
const (
	// KDFAgeScrypt is age's scrypt passphrase recipient: the only KDF today. age
	// embeds its own work factor in the wrapped blob, so a parameter bump needs
	// no new identifier; this tag exists for the family jump (scrypt -> Argon2id)
	// that age cannot express.
	KDFAgeScrypt = "age-scrypt"

	// currentKDF is the KDF a new or rotated passphrase slot is wrapped under.
	currentKDF = KDFAgeScrypt
)

var knownKDFs = map[string]bool{
	KDFAgeScrypt: true,
}

// KDFKnown reports whether this build can unwrap a slot wrapped under the given
// KDF.
func KDFKnown(kdf string) bool { return knownKDFs[kdf] }

// slotCipher wraps and unwraps a passphrase slot's private key. The KDF
// identifier on a slot selects the implementation, so a future Argon2id cipher
// slots in alongside the age-scrypt one.
type slotCipher interface {
	Encrypt([]byte) ([]byte, error)
	Decrypt([]byte) ([]byte, error)
}

// slotCipherFor returns the slot cipher for a KDF identifier and passphrase.
// Today the sole entry is age-scrypt; an unknown KDF is an error (callers reach
// this only past ParseHeader, which already fail-closes on unknown KDFs).
func slotCipherFor(kdf, passphrase string) (slotCipher, error) {
	switch kdf {
	case KDFAgeScrypt:
		return NewPassphraseCipher(passphrase), nil
	default:
		return nil, fmt.Errorf("unknown passphrase KDF %q", kdf)
	}
}

// generateMaster mints a fresh master key for a suite. Today the sole entry is
// the X25519 master; a hybrid suite would mint its own master type here, which
// is the "leave room for a hybrid recipient" seam.
func generateMaster(suite string) (*MasterKey, error) {
	switch suite {
	case SuiteX25519:
		return newX25519Master()
	default:
		return nil, fmt.Errorf("unknown suite %q", suite)
	}
}
