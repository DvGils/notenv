// Package keymgmt holds the safe header-write protocol shared by every
// operation that mutates the key-slot header. A clobbered or half-written
// header locks the user out of every blob under it, so writes go through
// SafePut: back up the current header, confirm it hasn't changed underneath
// us, write, then read back and verify the result still unlocks before
// trusting it. RestoreBackup is the recovery counterpart.
//
// This is the one place that needs both the storage layer (backend) and the
// crypto layer (crypto): the backend handles backup and the raw read/write,
// crypto parses and unlocks the result. Keeping the orchestration here lets
// each of those layers stay unaware of the other.
package keymgmt

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/DvGils/notenv/internal/backend"
	"github.com/DvGils/notenv/internal/crypto"
)

// SafePut writes header h with the full safety protocol around it. It bumps h's
// revision, seals it (authentication tag) with mk, and writes the marshaled
// result.
//
//   - base is the exact header bytes read at the start of the operation (nil if
//     the storage had no header yet). The write goes through the store's
//     SwapHeader, which refuses (backend.ErrHeaderChanged) if the stored header
//     no longer matches base, so a concurrent header mutation can't be silently
//     overwritten. How atomic that is depends on the store; callers that can
//     re-apply their change retry on ErrHeaderChanged.
//   - mk is the master the header should wrap; SafePut seals with it and, after
//     writing, confirms the read-back header's authentication tag verifies under
//     it (catches a corrupted/substituted write).
//   - verify re-unlocks the read-back header with the caller's own credential (a
//     passphrase or an age identity) and must yield mk, an end-to-end check that
//     the header is still usable by the caller before they walk away.
//
// On any verification failure SafePut returns an error and leaves the backup in
// place; recover with RestoreBackup.
func SafePut(ctx context.Context, store backend.HeaderStore, h *crypto.Header, base []byte, mk *crypto.MasterKey, verify func(*crypto.Header) (*crypto.MasterKey, error)) error {
	// Bump the monotonic revision and (re)seal before serializing.
	h.Revision++
	if err := h.Seal(mk); err != nil {
		return fmt.Errorf("seal header: %w", err)
	}
	newRaw, err := h.Marshal()
	if err != nil {
		return err
	}

	// Back up before touching the live header, but only when one exists (base is
	// the header read at the start, nil on virgin storage). Skipping the backup on
	// virgin avoids asking the backend "is there a header?" through a copy that
	// fails ambiguously; when a header does exist, a backup failure aborts the
	// write, since overwriting without a recoverable copy is the one outcome this
	// protocol must prevent.
	if base != nil {
		if err := store.BackupHeader(ctx); err != nil {
			return fmt.Errorf("back up header before write: %w", err)
		}
	}

	if err := store.SwapHeader(ctx, base, newRaw); err != nil {
		if errors.Is(err, backend.ErrHeaderChanged) {
			return fmt.Errorf("%w (another notenv run?); re-run the command", err)
		}
		return err // includes backend.ErrCommitUncertain: the write may have landed
	}

	// Past the swap the write has committed; a failure to read it back and verify
	// is "committed but unverified", never "rolled back". Tagging it
	// ErrCommitUncertain stops the caller from deleting the data object it wrote
	// for this now-live header (that would strand the committed header).
	if err := confirmHeaderWrite(ctx, store, newRaw, mk, verify); err != nil {
		return fmt.Errorf("%w: %v; recover with `notenv key restore-backup` if a later read fails", backend.ErrCommitUncertain, err)
	}
	return nil
}

// confirmHeaderWrite reads the just-written header back and checks it parses,
// authenticates under mk, and unlocks with the caller's credential. It runs only
// after the swap has committed, so SafePut treats any error here as "committed
// but unverified" (backend.ErrCommitUncertain), never as a reason to roll back.
func confirmHeaderWrite(ctx context.Context, store backend.HeaderStore, want []byte, mk *crypto.MasterKey, verify func(*crypto.Header) (*crypto.MasterKey, error)) error {
	readBack, err := store.GetHeader(ctx)
	if err != nil {
		return fmt.Errorf("read header back after write: %w", err)
	}
	if !bytes.Equal(readBack, want) {
		return errors.New("the header read back differently than written")
	}
	parsed, err := crypto.ParseHeader(readBack)
	if err != nil {
		return fmt.Errorf("the written header does not parse: %w", err)
	}
	if err := parsed.Verify(mk); err != nil {
		return fmt.Errorf("the written header failed authentication: %w", err)
	}
	got, err := verify(parsed)
	if err != nil {
		return fmt.Errorf("the written header does not unlock with the expected credential: %w", err)
	}
	if got.String() != mk.String() {
		return errors.New("the written header unlocked to the wrong master key")
	}
	return nil
}

// RestoreBackup copies the header backup back over the header and confirms the
// result parses, so recovery from a bad write is one command instead of a raw
// rclone incantation. It reports a clear error when there is no backup to
// restore (none has been written yet: a vault gets its first backup on its
// second header write).
func RestoreBackup(ctx context.Context, store backend.HeaderStore) error {
	if err := store.RestoreHeaderBackup(ctx); err != nil {
		if errors.Is(err, backend.ErrNotFound) {
			return errors.New("no header backup found to restore (a vault's first backup is written on its second header write); if your remote keeps object versions, recover a prior version with rclone")
		}
		return fmt.Errorf("restore header backup: %w", err)
	}
	raw, err := store.GetHeader(ctx)
	if err != nil {
		return fmt.Errorf("read restored header: %w", err)
	}
	if _, err := crypto.ParseHeader(raw); err != nil {
		return fmt.Errorf("restored header is still corrupt: %w", err)
	}
	return nil
}
