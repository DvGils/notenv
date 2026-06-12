package crypto

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
)

// The manifest binds the vault's object set to the authenticated header: one
// entry per segment/snapshot object, keyed by the full object key, carrying a
// MAC of the object's plaintext. A party with storage write access but not the
// master can no longer revert, delete, resurrect, or relocate an object
// without detection: readers check every object against the manifest, and the
// manifest is covered by the header's tag, revision, and local pin.
//
// The MAC is over the plaintext, keyed from the master, for two reasons. The
// header is stored in the clear, so an unkeyed digest of a secret's payload
// would be an offline guessing oracle (hash candidate values, compare). And
// rotation re-encrypts objects in place, so a ciphertext digest would go stale
// mid-rotation, while plaintext is stable across re-encryption. The MAC key
// changes exactly at the header flip, which rewrites the manifest anyway. The
// payload itself records the object key it was written under, so the MAC
// transitively binds the name as well as the content.

const manifestInfo = "notenv/manifest/v1"

// ManifestEntry is one object the header vouches for. Folded marks an object a
// compaction has subsumed but possibly not yet deleted: readers skip it, and a
// later manifest write prunes the entry once the object is confirmed gone.
type ManifestEntry struct {
	MAC    string `json:"mac"`
	Folded bool   `json:"folded,omitempty"`
}

// ManifestDelta is one writer's change to the manifest, applied atomically
// under the header compare-and-swap. Add lands new or adopted entries, Fold
// marks existing entries as subsumed by a snapshot, Prune drops entries whose
// objects are confirmed gone. Applied in that order.
type ManifestDelta struct {
	Add   map[string]ManifestEntry
	Fold  []string
	Prune []string
}

// Empty reports whether applying the delta would change nothing.
func (d ManifestDelta) Empty() bool {
	return len(d.Add) == 0 && len(d.Fold) == 0 && len(d.Prune) == 0
}

// ApplyManifest applies a delta to the header's manifest.
func (h *Header) ApplyManifest(d ManifestDelta) {
	if h.Manifest == nil && len(d.Add) > 0 {
		h.Manifest = map[string]ManifestEntry{}
	}
	maps.Copy(h.Manifest, d.Add)
	for _, key := range d.Fold {
		if e, ok := h.Manifest[key]; ok {
			e.Folded = true
			h.Manifest[key] = e
		}
	}
	for _, key := range d.Prune {
		delete(h.Manifest, key)
	}
}

// manifestKey derives the object-MAC key from the master identity.
func (m *MasterKey) manifestKey() ([]byte, error) {
	key, err := hkdf.Key(sha256.New, []byte(m.identity.String()), nil, manifestInfo, 32)
	if err != nil {
		return nil, fmt.Errorf("derive manifest key: %w", err)
	}
	return key, nil
}

// ObjectMAC computes the manifest MAC for an object's plaintext.
func (m *MasterKey) ObjectMAC(plaintext []byte) (string, error) {
	key, err := m.manifestKey()
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(plaintext)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// CheckObjectMAC verifies an object's plaintext against a manifest entry's MAC
// in constant time.
func (m *MasterKey) CheckObjectMAC(plaintext []byte, want string) error {
	got, err := m.ObjectMAC(plaintext)
	if err != nil {
		return err
	}
	if !hmac.Equal([]byte(got), []byte(want)) {
		return errors.New("object does not match the vault manifest (reverted or substituted?)")
	}
	return nil
}
