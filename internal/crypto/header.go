package crypto

import (
	"encoding/json"
	"errors"
	"fmt"

	"filippo.io/age"
)

// The header is LUKS2-style key management on dumb storage: a random
// X25519 master key encrypts every blob, and the header object stores that
// master key wrapped under N passphrase slots (age scrypt). Unlocking any
// slot yields the master key; rotating a passphrase rewrites the header
// and touches no blobs; a future recipient slot (master key encrypted to a
// teammate's age public key) is how team mode lands in the same format.
//
// Trade-off, same as LUKS/restic: the header lives next to the blobs, so
// an attacker with storage access can brute-force a weak passphrase
// offline (scrypt-hardened). The escrowed passphrase is the root of trust.

// Header is the parsed header object.
type Header struct {
	Version   int    `json:"version"`
	Recipient string `json:"recipient"` // master public key
	Slots     []Slot `json:"slots"`
}

// Slot is one wrapped copy of the master key. Name identifies whose slot
// it is (user@host), the future hook for per-user factors (TOTP, etc).
// Primary marks the slot whose owner may rotate/remove other slots;
// advisory until header signing exists (no server = no cryptographic
// enforcement), but tooling refuses to remove or demote it.
type Slot struct {
	Name    string `json:"name,omitempty"`
	Primary bool   `json:"primary,omitempty"`
	Wrapped []byte `json:"wrapped"` // age scrypt ciphertext of the master identity
}

// MasterKey is the unwrapped master identity. It satisfies Cipher: Encrypt
// seals to the master recipient, Decrypt opens with the identity.
type MasterKey struct {
	identity *age.X25519Identity
}

// NewHeader generates a master key and a header with one passphrase slot:
// the primary slot, owned by whoever initialized the storage.
func NewHeader(passphrase, slotName string) (*Header, *MasterKey, error) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, nil, fmt.Errorf("generate master key: %w", err)
	}
	mk := &MasterKey{identity: identity}
	header := &Header{Version: 1, Recipient: identity.Recipient().String()}
	if err := header.AddSlot(passphrase, slotName, mk); err != nil {
		return nil, nil, err
	}
	header.Slots[0].Primary = true
	return header, mk, nil
}

// AddSlot wraps the master key under an additional passphrase.
func (h *Header) AddSlot(passphrase, name string, mk *MasterKey) error {
	wrapped, err := NewPassphraseCipher(passphrase).Encrypt([]byte(mk.identity.String()))
	if err != nil {
		return fmt.Errorf("wrap master key: %w", err)
	}
	h.Slots = append(h.Slots, Slot{Name: name, Wrapped: wrapped})
	return nil
}

// Unlock tries the passphrase against every slot. Returns
// ErrWrongPassphrase when none opens.
func (h *Header) Unlock(passphrase string) (*MasterKey, error) {
	cipher := NewPassphraseCipher(passphrase)
	for _, slot := range h.Slots {
		identityStr, err := cipher.Decrypt(slot.Wrapped)
		if errors.Is(err, ErrWrongPassphrase) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("slot %q: %w", slot.Name, err)
		}
		return ParseMasterKey(string(identityStr))
	}
	return nil, ErrWrongPassphrase
}

func ParseHeader(data []byte) (*Header, error) {
	var h Header
	if err := json.Unmarshal(data, &h); err != nil {
		return nil, fmt.Errorf("corrupt header: %w", err)
	}
	if h.Version != 1 {
		return nil, fmt.Errorf("unsupported header version %d (upgrade notenv?)", h.Version)
	}
	if len(h.Slots) == 0 {
		return nil, errors.New("corrupt header: no key slots")
	}
	return &h, nil
}

func (h *Header) Marshal() ([]byte, error) {
	return json.MarshalIndent(h, "", "  ")
}

// ParseMasterKey parses the identity string form (used by the session
// cache, which stores the unwrapped master key, not the passphrase).
func ParseMasterKey(s string) (*MasterKey, error) {
	identity, err := age.ParseX25519Identity(s)
	if err != nil {
		return nil, fmt.Errorf("invalid master key: %w", err)
	}
	return &MasterKey{identity: identity}, nil
}

func (m *MasterKey) String() string { return m.identity.String() }

func (m *MasterKey) Encrypt(plaintext []byte) ([]byte, error) {
	return encryptTo(plaintext, m.identity.Recipient())
}

func (m *MasterKey) Decrypt(ciphertext []byte) ([]byte, error) {
	plaintext, err := decryptWith(ciphertext, m.identity)
	if err != nil {
		var noMatch *age.NoIdentityMatchError
		if errors.As(err, &noMatch) {
			return nil, errors.New("blob was not encrypted under the current master key. Was this storage re-initialized? Re-create it with `notenv set`")
		}
		return nil, err
	}
	return plaintext, nil
}
