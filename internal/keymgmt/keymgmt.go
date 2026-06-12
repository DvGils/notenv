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

	// Back up before touching the live header. Refuse to overwrite a header we
	// could not preserve. (A no-op on versioned remotes and on virgin storage.)
	if err := store.BackupHeader(ctx); err != nil {
		return fmt.Errorf("back up header before write: %w", err)
	}

	if err := store.SwapHeader(ctx, base, newRaw); err != nil {
		if errors.Is(err, backend.ErrHeaderChanged) {
			return fmt.Errorf("%w (another notenv run?); re-run the command", err)
		}
		return err
	}

	// Read back the bytes we just wrote and verify the result.
	readBack, err := store.GetHeader(ctx)
	if err != nil {
		return fmt.Errorf("read header back after write (%w); recover with `notenv key restore-backup`", err)
	}
	if !bytes.Equal(readBack, newRaw) {
		return errors.New("the header read back differently than written; recover with `notenv key restore-backup`")
	}
	parsed, err := crypto.ParseHeader(readBack)
	if err != nil {
		return fmt.Errorf("the written header does not parse (%w); recover with `notenv key restore-backup`", err)
	}
	if err := parsed.Verify(mk); err != nil {
		return fmt.Errorf("the written header failed authentication (%w); recover with `notenv key restore-backup`", err)
	}
	got, err := verify(parsed)
	if err != nil {
		return fmt.Errorf("the written header does not unlock with the expected credential (%w); recover with `notenv key restore-backup`", err)
	}
	if got.String() != mk.String() {
		return errors.New("the written header unlocked to the wrong master key; recover with `notenv key restore-backup`")
	}
	return nil
}

// RestoreBackup copies the header backup back over the header and confirms the
// result parses, so recovery from a bad write is one command instead of a raw
// rclone incantation. It reports a clear error when there is no backup to
// restore, which includes versioned remotes (recover a prior object version
// through the remote's version history there).
func RestoreBackup(ctx context.Context, store backend.HeaderStore) error {
	if err := store.RestoreHeaderBackup(ctx); err != nil {
		if errors.Is(err, backend.ErrNotFound) {
			return errors.New("no header backup found to restore (on a versioned remote, recover a prior version with rclone)")
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
