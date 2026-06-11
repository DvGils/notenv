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

// VerifyEpoch confirms mk is still the master the vault's header yields. It is
// the post-write half of the write-epoch protocol: a writer seals an object,
// then calls this; on ErrEpochChanged it removes its own object and retries
// under the new master. Together with rotation re-listing the namespace after
// its header flip (see RotateMaster), this closes the race where a write lands
// mid-rotation sealed under the old master and ends up unreadable by everyone
// once the old key is gone.
//
// The header's recipient field is attacker-writable in principle (it is only
// authenticated by a tag keyed from the master it names), so a mismatch is
// treated as "redo the unlock ceremony" — which runs the real pin and
// authentication checks — never as a reason to trust anything new here. When
// the recipient does match mk, the tag must verify under it, so a tampered
// header cannot pass as "unchanged".
func VerifyEpoch(ctx context.Context, store backend.HeaderStore, mk *crypto.MasterKey) error {
	raw, err := store.GetHeader(ctx)
	if err != nil {
		if errors.Is(err, backend.ErrNotFound) {
			return errors.New("the vault's key header is gone from storage; refusing to trust this write")
		}
		return fmt.Errorf("re-read header to confirm the master key: %w", err)
	}
	h, err := crypto.ParseHeader(raw)
	if err != nil {
		return err
	}
	if h.Recipient != mk.PublicKey() {
		return ErrEpochChanged
	}
	return h.Verify(mk)
}
