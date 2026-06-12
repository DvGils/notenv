package keymgmt

import (
	"context"
	"errors"
	"fmt"

	"github.com/DvGils/notenv/internal/backend"
	"github.com/DvGils/notenv/internal/crypto"
)

// ErrEpochChanged reports that the vault's header no longer wraps the master
// key the caller is holding: a rotation (or a substitution) landed since the
// caller unlocked. The caller's in-flight work was sealed under a superseded
// key and must not be left on storage.
var ErrEpochChanged = errors.New("the vault's master key changed since this operation started")

// updateAttempts bounds the swap-race retries. Each retry re-reads the header,
// so losing this many times in a row means something is hammering the vault.
const updateAttempts = 4

// UpdateManifest records one writer's manifest delta in the vault header,
// under the header compare-and-swap. It is the write-epoch check and the
// manifest update in one authenticated step: every attempt re-reads the
// header, requires it to wrap mk, and verifies its tag, so a rotation that
// landed since the caller unlocked surfaces as ErrEpochChanged before anything
// is written — the caller removes the object it just stored and re-runs. When
// another writer merely lands first (backend.ErrHeaderChanged), the delta is
// re-applied to the fresh header and the swap retried, so concurrent writers'
// entries are never clobbered. Returns the header as written, for the caller's
// local rollback pin.
//
// The header's recipient field is attacker-writable in principle (it is only
// authenticated by a tag keyed from the master it names), so a mismatch is
// treated as "redo the unlock ceremony" — which runs the real pin and
// authentication checks — never as a reason to trust anything new here. When
// the recipient does match mk, the tag must verify under it, so a tampered
// header cannot pass as "unchanged".
func UpdateManifest(ctx context.Context, store backend.HeaderStore, mk *crypto.MasterKey, delta crypto.ManifestDelta) (*crypto.Header, error) {
	var lastErr error
	for range updateAttempts {
		raw, err := store.GetHeader(ctx)
		if errors.Is(err, backend.ErrNotFound) {
			return nil, errors.New("the vault's key header is gone from storage; refusing to trust this write")
		}
		if err != nil {
			return nil, fmt.Errorf("re-read header to record the write: %w", err)
		}
		h, err := crypto.ParseHeader(raw)
		if err != nil {
			return nil, err
		}
		if h.Recipient != mk.PublicKey() {
			return nil, ErrEpochChanged
		}
		if err := h.Verify(mk); err != nil {
			return nil, err
		}
		h.ApplyManifest(delta)
		// The verify hook normally re-unlocks with the operator's credential;
		// a manifest write happens mid-operation with the master already in
		// hand and no slot material changing, so that re-proof adds nothing.
		err = SafePut(ctx, store, h, raw, mk, func(*crypto.Header) (*crypto.MasterKey, error) { return mk, nil })
		if errors.Is(err, backend.ErrHeaderChanged) {
			lastErr = err
			continue
		}
		if err != nil {
			return nil, err
		}
		return h, nil
	}
	return nil, fmt.Errorf("could not record the write in the vault manifest after %d attempts: %w", updateAttempts, lastErr)
}
