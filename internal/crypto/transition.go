package crypto

import (
	"encoding/json"
	"fmt"
)

// A Transition is the outgoing master's signed statement that a successor is
// legitimate: "I, the master whose signing key is FromSignPub, was replaced by
// the master (ToSignPub, ToMasterPub) at header revision ToRevision, in vault
// VaultID." A machine whose local pin still names the old master verifies the
// signature with the pinned public key and follows the change without raising
// the master-changed alarm, so the alarm fires only for changes nobody with
// the old master authorized.
//
// The slot set is deliberately not covered: the new header's own MAC
// authenticates it under the new master, and the old key's signature over it
// would stop no one it doesn't already stop. The vault ID prevents replaying
// a transition from one vault against another; the revision orders chains.
type Transition struct {
	VaultID     string `json:"vault_id"`
	FromSignPub string `json:"from_sign_pub"`
	ToSignPub   string `json:"to_sign_pub"`
	ToMasterPub string `json:"to_master_pub"`
	ToRevision  int    `json:"to_revision"`
	Sig         []byte `json:"sig"`
}

// transitionContext domain-separates transition signatures from any other use
// of the master's signing key.
const transitionContext = "notenv/transition/v1\x00"

// NewTransition builds and signs the record for a master change: old is the
// master being replaced (it signs), newKey the successor, toRevision the header
// revision the successor is installed at.
func NewTransition(old, newKey *MasterKey, vaultID string, toRevision int) (*Transition, error) {
	fromPub, err := old.SignPub()
	if err != nil {
		return nil, err
	}
	toPub, err := newKey.SignPub()
	if err != nil {
		return nil, err
	}
	t := &Transition{
		VaultID:     vaultID,
		FromSignPub: fromPub,
		ToSignPub:   toPub,
		ToMasterPub: newKey.PublicKey(),
		ToRevision:  toRevision,
	}
	msg, err := t.signedBytes()
	if err != nil {
		return nil, err
	}
	if t.Sig, err = old.sign(msg); err != nil {
		return nil, fmt.Errorf("sign transition: %w", err)
	}
	return t, nil
}

// Verify checks the signature under the transition's own FromSignPub. The
// caller decides whether that key is one it trusts (its pin, or the end of a
// previously verified chain); Verify only proves the record is internally
// authentic.
func (t *Transition) Verify() error {
	msg, err := t.signedBytes()
	if err != nil {
		return err
	}
	if err := verifySignature(t.FromSignPub, msg, t.Sig); err != nil {
		return fmt.Errorf("transition %s… → %s…: %w", short(t.FromSignPub), short(t.ToSignPub), err)
	}
	return nil
}

// signedBytes is the canonical signing input: the record with Sig cleared,
// JSON-marshaled, under a domain-separation prefix.
func (t *Transition) signedBytes() ([]byte, error) {
	clone := *t
	clone.Sig = nil
	canonical, err := json.Marshal(&clone)
	if err != nil {
		return nil, fmt.Errorf("canonicalize transition: %w", err)
	}
	return append([]byte(transitionContext), canonical...), nil
}

func short(pub string) string {
	if len(pub) > 8 {
		return pub[:8]
	}
	return pub
}
