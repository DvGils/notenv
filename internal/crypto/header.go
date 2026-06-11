package crypto

import (
	"encoding/json"
	"errors"
	"fmt"

	"filippo.io/age"
)

// The header is LUKS2-style key management on dumb storage, with one layer of
// indirection so master rotation is lossless. A random X25519 master key
// encrypts every blob. The master identity is stored once in the header,
// age-encrypted to the public key of every slot (a multi-recipient blob). Each
// slot owns a long-lived keypair:
//
//   - passphrase slot: its private key is scrypt-encrypted under a passphrase
//     and stored in the slot; its public key is a recipient of Master.
//   - recipient slot: a teammate's public key is the slot key; they hold the
//     private key, so nothing is stored in the slot beyond the public key.
//
// Unlocking obtains a slot private key (a passphrase unwraps its stored one, a
// teammate already holds theirs) and decrypts Master. Re-encrypting Master to
// every slot's public key needs no secrets, so adding/removing a slot and
// rotating the master preserve every surviving slot.
//
// Trade-off, same as LUKS/restic: the header lives next to the blobs, so an
// attacker with storage access can brute-force a weak passphrase offline
// (scrypt-hardened). The escrowed passphrase is the root of trust.

// headerVersion is the header's on-storage format version. There is one format:
// the indirect slot model with header authentication + a monotonic revision (see
// auth.go). ParseHeader accepts only exactly this version with a valid auth tag,
// with no lenient or unversioned path, since accepting an unauthenticated or
// unknown-version header would be a security hole. The segment/snapshot payloads
// (internal/secrets) are versioned by the same exact-match rule. Bump only on a
// future incompatible change.
const headerVersion = 1

// Header is the parsed header object.
type Header struct {
	Version   int    `json:"version"`
	Recipient string `json:"recipient"` // master public key (decorative)
	Revision  int    `json:"revision"`  // monotonic; bumped on every write (anti-rollback)
	Master    []byte `json:"master"`    // master identity, age-encrypted to every slot's public key
	Slots     []Slot `json:"slots"`
	Auth      []byte `json:"auth,omitempty"` // HMAC over the header keyed from the master (see auth.go)
}

// Slot is one credential that can unlock the master. Name identifies its owner
// (user@host). Primary marks the slot whose owner may rotate/remove other slots;
// advisory until header signing exists, but tooling refuses to remove or demote
// it. PublicKey is the slot's age public key (a recipient of Master); for a
// recipient slot it is the teammate's public key.
type Slot struct {
	Name      string `json:"name,omitempty"`
	Primary   bool   `json:"primary,omitempty"`
	Type      string `json:"type"`              // "passphrase" | "recipient"
	PublicKey string `json:"public_key"`        // recipient of Master
	Wrapped   []byte `json:"wrapped,omitempty"` // passphrase slots: slot private key, scrypt-encrypted
}

// Slot type tags.
const (
	SlotPassphrase = "passphrase"
	SlotRecipient  = "recipient"
)

// MasterKey is the unwrapped master identity. It satisfies Cipher: Encrypt
// seals to the master recipient, Decrypt opens with the identity.
type MasterKey struct {
	identity *age.X25519Identity
}

// NewHeader generates a master key and a header with one passphrase slot:
// the primary slot, owned by whoever initialized the storage.
func NewHeader(passphrase, slotName string) (*Header, *MasterKey, error) {
	mk, err := GenerateMasterKey()
	if err != nil {
		return nil, nil, err
	}
	header := &Header{Version: headerVersion, Revision: 1}
	if err := header.AddPassphraseSlot(passphrase, slotName, mk); err != nil {
		return nil, nil, err
	}
	header.Slots[0].Primary = true
	if err := header.Seal(mk); err != nil {
		return nil, nil, err
	}
	return header, mk, nil
}

// GenerateMasterKey mints a fresh master key with no header (used by rotation).
func GenerateMasterKey() (*MasterKey, error) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, fmt.Errorf("generate master key: %w", err)
	}
	return &MasterKey{identity: identity}, nil
}

// AddPassphraseSlot creates a slot keypair, wraps its private key under the
// passphrase, and re-encrypts the master to include the new slot.
func (h *Header) AddPassphraseSlot(passphrase, name string, mk *MasterKey) error {
	slotKey, err := age.GenerateX25519Identity()
	if err != nil {
		return fmt.Errorf("generate slot key: %w", err)
	}
	wrapped, err := NewPassphraseCipher(passphrase).Encrypt([]byte(slotKey.String()))
	if err != nil {
		return fmt.Errorf("wrap slot key: %w", err)
	}
	h.Slots = append(h.Slots, Slot{
		Name:      name,
		Type:      SlotPassphrase,
		PublicKey: slotKey.Recipient().String(),
		Wrapped:   wrapped,
	})
	return h.rewrapMaster(mk)
}

// AddRecipientSlot adds a teammate by their age public key, which is the slot
// key; they hold the private key and unlock with their own age identity.
func (h *Header) AddRecipientSlot(recipient *age.X25519Recipient, name string, mk *MasterKey) error {
	h.Slots = append(h.Slots, Slot{
		Name:      name,
		Type:      SlotRecipient,
		PublicKey: recipient.String(),
	})
	return h.rewrapMaster(mk)
}

// RotateSlot re-wraps a passphrase slot's private key under a new passphrase.
// The master, the slot keypair, and Master are untouched, so other slots and
// every blob are unaffected. slotKey is the slot's private key, obtained from
// Unlock.
func (h *Header) RotateSlot(i int, newPassphrase string, slotKey *age.X25519Identity) error {
	if i < 0 || i >= len(h.Slots) {
		return fmt.Errorf("slot index %d out of range", i)
	}
	if h.Slots[i].Type != SlotPassphrase {
		return errors.New("only a passphrase slot has a passphrase to rotate")
	}
	wrapped, err := NewPassphraseCipher(newPassphrase).Encrypt([]byte(slotKey.String()))
	if err != nil {
		return fmt.Errorf("wrap slot key: %w", err)
	}
	h.Slots[i].Wrapped = wrapped
	return nil
}

// RemoveSlot deletes slot i and re-encrypts the master to the survivors, so the
// removed slot can no longer decrypt the master. It refuses to remove the last
// slot (which would brick the header). NOTE: this does not re-key blobs, so a
// holder who retained the master is not revoked; true revocation re-keys via
// SetMaster (rotate-master). mk is the current master.
func (h *Header) RemoveSlot(i int, mk *MasterKey) error {
	if i < 0 || i >= len(h.Slots) {
		return fmt.Errorf("slot index %d out of range", i)
	}
	if len(h.Slots) == 1 {
		return errors.New("cannot remove the last key slot")
	}
	h.Slots = append(h.Slots[:i], h.Slots[i+1:]...)
	return h.rewrapMaster(mk)
}

// SetMaster installs a new master key, re-encrypting it to every slot's public
// key. Used by rotate-master after the blobs have been re-keyed.
func (h *Header) SetMaster(mk *MasterKey) error {
	return h.rewrapMaster(mk)
}

// SetPrimary makes slot i the sole primary slot.
func (h *Header) SetPrimary(i int) error {
	if i < 0 || i >= len(h.Slots) {
		return fmt.Errorf("slot index %d out of range", i)
	}
	for j := range h.Slots {
		h.Slots[j].Primary = j == i
	}
	return nil
}

// PrimarySlot returns the index of the primary slot, or -1 if none is marked.
func (h *Header) PrimarySlot() int {
	for i, slot := range h.Slots {
		if slot.Primary {
			return i
		}
	}
	return -1
}

// rewrapMaster re-encrypts the master identity to every slot's public key.
func (h *Header) rewrapMaster(mk *MasterKey) error {
	recipients := make([]age.Recipient, 0, len(h.Slots))
	for _, slot := range h.Slots {
		r, err := age.ParseX25519Recipient(slot.PublicKey)
		if err != nil {
			return fmt.Errorf("slot %q: invalid public key: %w", slot.Name, err)
		}
		recipients = append(recipients, r)
	}
	wrapped, err := encryptTo([]byte(mk.identity.String()), recipients...)
	if err != nil {
		return fmt.Errorf("wrap master key: %w", err)
	}
	h.Master = wrapped
	h.Recipient = mk.identity.Recipient().String()
	return nil
}

// Unlock opens the master via a passphrase. It finds the passphrase slot whose
// wrapped private key the passphrase decrypts, then decrypts the master with
// that slot key. Returns the master, the matched slot index, and the slot
// private key (needed to rotate that passphrase). ErrWrongPassphrase if none
// opens.
func (h *Header) Unlock(passphrase string) (*MasterKey, int, *age.X25519Identity, error) {
	cipher := NewPassphraseCipher(passphrase)
	for i, slot := range h.Slots {
		if slot.Type == SlotRecipient || len(slot.Wrapped) == 0 {
			continue
		}
		plain, err := cipher.Decrypt(slot.Wrapped)
		if errors.Is(err, ErrWrongPassphrase) {
			continue
		}
		if err != nil {
			return nil, -1, nil, fmt.Errorf("slot %q: %w", slot.Name, err)
		}
		slotKey, err := age.ParseX25519Identity(string(plain))
		if err != nil {
			return nil, -1, nil, fmt.Errorf("slot %q: invalid slot key: %w", slot.Name, err)
		}
		mk, err := h.unlockMaster(slotKey)
		return mk, i, slotKey, err
	}
	return nil, -1, nil, ErrWrongPassphrase
}

// UnlockIdentity opens the master via a teammate's age identity (their recipient
// slot). Returns the master and the matched slot index (or -1 if the identity
// decrypts the master but matches no slot's public key). ErrWrongPassphrase if
// the identity is not a recipient of the master.
func (h *Header) UnlockIdentity(id *age.X25519Identity) (*MasterKey, int, error) {
	mk, err := h.unlockMaster(id)
	if err != nil {
		var noMatch *age.NoIdentityMatchError
		if errors.As(err, &noMatch) {
			return nil, -1, ErrWrongPassphrase
		}
		return nil, -1, err
	}
	pub := id.Recipient().String()
	for i, slot := range h.Slots {
		if slot.PublicKey == pub {
			return mk, i, nil
		}
	}
	return mk, -1, nil
}

// unlockMaster decrypts the master identity with a slot private key.
func (h *Header) unlockMaster(slotKey *age.X25519Identity) (*MasterKey, error) {
	plain, err := decryptWith(h.Master, slotKey)
	if err != nil {
		return nil, err
	}
	return ParseMasterKey(string(plain))
}

func ParseHeader(data []byte) (*Header, error) {
	var h Header
	if err := json.Unmarshal(data, &h); err != nil {
		return nil, fmt.Errorf("corrupt header: %w", err)
	}
	if h.Version != headerVersion {
		return nil, fmt.Errorf("unsupported header version %d (this notenv supports version %d)", h.Version, headerVersion)
	}
	if len(h.Slots) == 0 {
		return nil, errors.New("corrupt header: no key slots")
	}
	if len(h.Master) == 0 {
		return nil, errors.New("corrupt header: no wrapped master key")
	}
	if len(h.Auth) == 0 {
		return nil, errors.New("corrupt header: missing authentication tag")
	}
	return &h, nil
}

func (h *Header) Marshal() ([]byte, error) {
	return json.MarshalIndent(h, "", "  ")
}

// ParseMasterKey parses the identity string form (used by the session cache,
// which stores the unwrapped master key, not the passphrase).
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

// EncryptToMasters seals plaintext to every master's recipient, so any of their
// identities can decrypt it. Rotation uses this to keep a blob readable under
// both the old and new master at once during the transition.
func EncryptToMasters(plaintext []byte, masters ...*MasterKey) ([]byte, error) {
	recipients := make([]age.Recipient, 0, len(masters))
	for _, m := range masters {
		recipients = append(recipients, m.identity.Recipient())
	}
	return encryptTo(plaintext, recipients...)
}

// ErrNotRecipient reports that a ciphertext is valid age but was not encrypted
// to the key that tried to open it — the key is wrong, not the data. Callers
// (rotation's fallback read, the stale-cache retry) branch on it with errors.Is.
var ErrNotRecipient = errors.New("blob was not encrypted under the current master key")

func (m *MasterKey) Decrypt(ciphertext []byte) ([]byte, error) {
	plaintext, err := decryptWith(ciphertext, m.identity)
	if err != nil {
		var noMatch *age.NoIdentityMatchError
		if errors.As(err, &noMatch) {
			return nil, fmt.Errorf("%w. Was this storage re-initialized or re-keyed? Re-create the value with `notenv set`", ErrNotRecipient)
		}
		return nil, err
	}
	return plaintext, nil
}
