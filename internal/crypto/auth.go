package crypto

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
)

// Header authentication: every header carries an HMAC tag over its canonical
// bytes, keyed by a secret derived from the master. A party with storage write
// but not the master cannot forge or alter a header without detection. The tag
// is symmetric (every legitimate verifier holds the master, so there is no
// verify-only party that would need a public key); it makes tampering evident,
// while a monotonic Revision plus a local pin (see config) make rollback
// evident.

const authInfo = "notenv/header-auth/v1"

// macKey derives the header-authentication key from the master identity.
func (m *MasterKey) macKey() ([]byte, error) {
	key, err := hkdf.Key(sha256.New, []byte(m.identity.String()), nil, authInfo, 32)
	if err != nil {
		return nil, fmt.Errorf("derive header auth key: %w", err)
	}
	return key, nil
}

// PublicKey returns the master's public key (its rollback-pin fingerprint).
func (m *MasterKey) PublicKey() string { return m.identity.Recipient().String() }

// Seal sets the header's authentication tag over its current contents.
func (h *Header) Seal(mk *MasterKey) error {
	tag, err := h.computeAuth(mk)
	if err != nil {
		return err
	}
	h.Auth = tag
	return nil
}

// Verify recomputes the tag and constant-time compares it to the stored one.
func (h *Header) Verify(mk *MasterKey) error {
	if len(h.Auth) == 0 {
		return errors.New("header is not authenticated (no tag)")
	}
	want, err := h.computeAuth(mk)
	if err != nil {
		return err
	}
	if !hmac.Equal(want, h.Auth) {
		return errors.New("vault header failed verification: it was tampered with, or unlocked with the wrong key")
	}
	return nil
}

// computeAuth is the HMAC over the canonical header with the tag field cleared.
// It marshals a copy with Auth=nil so seal and verify always hash the same
// bytes regardless of the stored representation.
func (h *Header) computeAuth(mk *MasterKey) ([]byte, error) {
	key, err := mk.macKey()
	if err != nil {
		return nil, err
	}
	clone := *h
	clone.Auth = nil
	canonical, err := json.Marshal(&clone)
	if err != nil {
		return nil, fmt.Errorf("canonicalize header: %w", err)
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(canonical)
	return mac.Sum(nil), nil
}
