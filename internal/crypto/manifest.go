package crypto

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

// The manifest binds the vault's namespace blobs to the authenticated header:
// one entry per namespace, keyed by namespace name, carrying a MAC of the
// namespace's current blob plaintext (and of its one-generation backup). A
// party with storage write access but not the master can no longer revert,
// substitute, or relocate a namespace's blob without detection: a read checks
// the blob against the manifest, and the manifest is covered by the header's
// tag, revision, and local pin.
//
// The MAC is over the plaintext, keyed from the master, for two reasons. The
// header is stored in the clear, so an unkeyed digest of a secret's payload
// would be an offline guessing oracle (hash candidate values, compare). And
// rotation re-encrypts blobs in place, so a ciphertext digest would go stale
// mid-rotation, while plaintext is stable across re-encryption. The MAC key
// changes exactly at the header flip, which rewrites the manifest anyway. The
// blob plaintext records the namespace it belongs to, so the MAC transitively
// binds the name as well as the content.

const manifestInfo = "notenv/manifest/v1"

// ManifestEntry is one namespace's blob the header vouches for. Blob is the
// object key of the current blob and MAC is its plaintext MAC. Prev/PrevMAC name
// the one-generation backup (the blob the previous write superseded), kept so a
// corrupt current blob can fall back to the last good one; both are empty on a
// namespace's first write, before any generation has been superseded.
type ManifestEntry struct {
	Blob    string `json:"blob"`
	MAC     string `json:"mac"`
	Prev    string `json:"prev,omitempty"`
	PrevMAC string `json:"prev_mac,omitempty"`
}

// NamespaceEntry returns the manifest entry for a namespace and whether one
// exists. A namespace that was never created has none; one that exists keeps its
// entry even when it holds no secrets (namespaces are persistent), so presence
// here means "the namespace exists", not "it holds secrets".
func (h *Header) NamespaceEntry(ns string) (ManifestEntry, bool) {
	e, ok := h.Manifest[ns]
	return e, ok
}

// SetNamespace records (or replaces) a namespace's blob entry.
func (h *Header) SetNamespace(ns string, e ManifestEntry) {
	if h.Manifest == nil {
		h.Manifest = map[string]ManifestEntry{}
	}
	h.Manifest[ns] = e
}

// RemoveNamespace drops a namespace's entry (its secrets were deleted, or an
// unrecoverable blob was evicted).
func (h *Header) RemoveNamespace(ns string) {
	delete(h.Manifest, ns)
}

// manifestKey derives the object-MAC key from the master identity.
func (m *MasterKey) manifestKey() ([]byte, error) {
	key, err := hkdf.Key(sha256.New, []byte(m.identity.String()), nil, manifestInfo, 32)
	if err != nil {
		return nil, fmt.Errorf("derive manifest key: %w", err)
	}
	return key, nil
}

// BlobMAC computes the manifest MAC for a blob's plaintext.
func (m *MasterKey) BlobMAC(plaintext []byte) (string, error) {
	key, err := m.manifestKey()
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(plaintext)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// CheckBlobMAC verifies a blob's plaintext against a recorded MAC in constant
// time.
func (m *MasterKey) CheckBlobMAC(plaintext []byte, want string) error {
	got, err := m.BlobMAC(plaintext)
	if err != nil {
		return err
	}
	if !hmac.Equal([]byte(got), []byte(want)) {
		return errors.New("stored secret does not match the vault manifest: it may have been reverted or substituted")
	}
	return nil
}
