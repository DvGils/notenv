package crypto

import (
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// The master can sign as well as decrypt. Its Ed25519 key is derived from the
// master secret with HKDF under its own label — the same construction as the
// header-MAC key, a different domain. Deriving (rather than storing a second
// key in the header's Master blob) means the signing key exists wherever the
// master does, rotates with it, and adds nothing to the on-storage format
// beyond the public key. The master secret is uniformly random and HKDF breaks
// any algebraic relation, so the X25519 and Ed25519 keys share no structure.
//
// Signatures exist for rotation transitions: a machine that has only *pinned*
// a master (it holds the public half, not the secret) must be able to verify
// that the master's holder authorized a successor. A MAC cannot serve a
// verifier without the secret; a signature can.

const signInfo = "notenv/transition-sign/v1"

// signingKey derives the master's Ed25519 private key.
func (m *MasterKey) signingKey() (ed25519.PrivateKey, error) {
	seed, err := hkdf.Key(sha256.New, []byte(m.identity.String()), nil, signInfo, ed25519.SeedSize)
	if err != nil {
		return nil, fmt.Errorf("derive signing key: %w", err)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// SignPub returns the master's Ed25519 public key, hex-encoded — the form the
// header carries and pins store.
func (m *MasterKey) SignPub() (string, error) {
	key, err := m.signingKey()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(key.Public().(ed25519.PublicKey)), nil
}

// sign signs msg with the master's derived key.
func (m *MasterKey) sign(msg []byte) ([]byte, error) {
	key, err := m.signingKey()
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(key, msg), nil
}

// verifySignature checks sig over msg under a hex-encoded Ed25519 public key.
func verifySignature(signPub string, msg, sig []byte) error {
	pub, err := hex.DecodeString(signPub)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid signing public key %q", signPub)
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), msg, sig) {
		return fmt.Errorf("signature does not verify under %s…", signPub[:16])
	}
	return nil
}
