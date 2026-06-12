package keymgmt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/DvGils/notenv/internal/backend"
	"github.com/DvGils/notenv/internal/crypto"
)

// transitionsObject is where a vault's rotation history lives: one JSON array
// of crypto.Transition records at the vault root, appended on every master
// change. Entries are individually signed, so the object itself needs no
// integrity protection — a reader that cannot assemble a valid chain from it
// alarms and falls back to `notenv key trust`, never silently accepts. Entries
// are a few hundred bytes and rotations are rare, so the history is kept
// whole: truncating it would only strand long-offline machines.
const transitionsObject = ".transitions.json"

func loadTransitions(ctx context.Context, store backend.Backend) ([]crypto.Transition, error) {
	raw, err := store.Get(ctx, transitionsObject)
	if errors.Is(err, backend.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", transitionsObject, err)
	}
	var ts []crypto.Transition
	if err := json.Unmarshal(raw, &ts); err != nil {
		return nil, fmt.Errorf("%s is corrupt: %w; machines pinned at older masters will alarm until it is repaired or removed", transitionsObject, err)
	}
	return ts, nil
}

// appendTransition records one master change. It re-reads the current history
// rather than trusting a cached copy, so concurrent rotations lose at most
// their own entry (and a rotation whose flip fails leaves a harmless orphan —
// an entry no chain ever walks through).
func appendTransition(ctx context.Context, store backend.Backend, t *crypto.Transition) error {
	ts, err := loadTransitions(ctx, store)
	if err != nil {
		return err
	}
	ts = append(ts, *t)
	raw, err := json.MarshalIndent(ts, "", "  ")
	if err != nil {
		return err
	}
	if err := store.Put(ctx, transitionsObject, raw); err != nil {
		return fmt.Errorf("write %s: %w", transitionsObject, err)
	}
	return nil
}

// FollowRotations proves, from signed transitions alone, that the master a
// header now wraps descends legitimately from the master this machine pinned.
// It searches for a chain of valid transitions from the pinned signing key to
// the header's, each signed by its predecessor, all within this vault, with
// strictly increasing revisions that stay within the pinned revision's future
// and end no later than the observed header's. mk is the unlocked master the
// header yielded; the final hop must name exactly it, binding the chain to the
// key actually in hand rather than to header metadata.
//
// A nil error means the pin may advance to the observed header silently. Any
// failure returns ErrNoPath: the caller falls back to the alarm it would have
// raised anyway — walking can clear an alarm, never create one.
func FollowRotations(ctx context.Context, store backend.Backend, h *crypto.Header, pinned string, pinnedRevision int, mk *crypto.MasterKey) error {
	ts, err := loadTransitions(ctx, store)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrNoPath, err)
	}
	mkSignPub, err := mk.SignPub()
	if err != nil {
		return err
	}
	if mkSignPub != h.SignPub {
		// The header names a signing key its own master does not derive:
		// inconsistent metadata, nothing a chain could legitimize.
		return ErrNoPath
	}
	if walk(ts, h.VaultID, pinned, pinnedRevision, mkSignPub, mk.PublicKey(), h.Revision, map[string]bool{}) {
		return nil
	}
	return ErrNoPath
}

// ErrNoPath reports that no chain of valid signed transitions connects the
// pinned master to the observed one.
var ErrNoPath = errors.New("no signed rotation path from the pinned master to the current one")

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
			// The chain must end at the master actually unlocked, not merely
			// at a matching signing key.
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
