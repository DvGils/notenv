package keymgmt

import (
	"errors"

	"github.com/DvGils/notenv/internal/crypto"
)

// FollowRotations proves, from the header's signed transitions alone, that the
// master a header now wraps descends legitimately from the master this machine
// pinned. It searches for a chain of valid transitions from the pinned signing
// key to the header's, each signed by its predecessor, all within this vault,
// with strictly increasing revisions that stay within the pinned revision's
// future and end no later than the observed header's. mk is the unlocked master
// the header yielded; the final hop must name exactly it, binding the chain to
// the key actually in hand rather than to header metadata.
//
// A nil error means the pin may advance to the observed header silently. Any
// failure returns ErrNoPath: the caller falls back to the alarm it would have
// raised anyway: walking can clear an alarm, never create one.
func FollowRotations(h *crypto.Header, pinned string, pinnedRevision int, mk *crypto.MasterKey) error {
	mkSignPub, err := mk.SignPub()
	if err != nil {
		return err
	}
	if mkSignPub != h.SignPub {
		// The header names a signing key its own master does not derive:
		// inconsistent metadata, nothing a chain could legitimize.
		return ErrNoPath
	}
	if walk(h.Transitions, h.VaultID, pinned, pinnedRevision, mkSignPub, mk.PublicKey(), h.Revision, map[string]bool{}) {
		return nil
	}
	return ErrNoPath
}

// ErrNoPath reports that no chain of valid signed transitions connects the
// pinned master to the observed one.
var ErrNoPath = errors.New("no signed rotation path from the pinned master to the current one")

// Descends proves that the master a header now wraps descends, through valid
// signed transitions, from some past signing key the caller recognizes (via
// accept). It serves the onboarding fingerprint: the code in hand digests a
// signing key that may have been rotated away between `credential add` and first
// contact, so the verifier must accept any recognized ancestor, not only the
// current key. The caller checks the current key itself before calling; this
// only searches history. Revisions are unbounded below: the fingerprint carries
// no revision, and the chain's signatures are what bind it.
func Descends(h *crypto.Header, mk *crypto.MasterKey, accept func(signPub string) bool) error {
	mkSignPub, err := mk.SignPub()
	if err != nil {
		return err
	}
	if mkSignPub != h.SignPub {
		return ErrNoPath
	}
	tried := map[string]bool{}
	for i := range h.Transitions {
		from := h.Transitions[i].FromSignPub
		if h.Transitions[i].VaultID != h.VaultID || tried[from] || !accept(from) {
			continue
		}
		tried[from] = true
		if walk(h.Transitions, h.VaultID, from, 0, mkSignPub, mk.PublicKey(), h.Revision, map[string]bool{}) {
			return nil
		}
	}
	return ErrNoPath
}

// walk searches depth-first for a valid chain from `from` (at fromRevision) to
// the target signing key. Multiple entries can share a from-key (a rotation
// retried after a failed flip leaves orphan siblings), so every candidate is
// explored; visited keys are skipped to terminate on any entry graph.
func walk(ts []crypto.Transition, vaultID, from string, fromRevision int, targetSignPub, targetMasterPub string, targetRevision int, visited map[string]bool) bool {
	if visited[from] {
		return false
	}
	visited[from] = true
	for i := range ts {
		t := &ts[i]
		if t.VaultID != vaultID || t.FromSignPub != from {
			continue
		}
		if t.ToRevision <= fromRevision || t.ToRevision > targetRevision {
			continue
		}
		if t.Verify() != nil {
			continue
		}
		if t.ToSignPub == targetSignPub {
			// The chain must end at the master actually unlocked, not merely at a
			// matching signing key.
			if t.ToMasterPub == targetMasterPub {
				return true
			}
			continue
		}
		if walk(ts, vaultID, t.ToSignPub, t.ToRevision, targetSignPub, targetMasterPub, targetRevision, visited) {
			return true
		}
	}
	return false
}
