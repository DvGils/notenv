package keymgmt

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/DvGils/notenv/internal/backend"
	"github.com/DvGils/notenv/internal/crypto"
)

// Vault is a backend that holds both the ciphertext objects and the key header,
// which rotation needs together.
type Vault interface {
	backend.Backend
	backend.HeaderStore
}

// ErrNarrowIncomplete reports that the post-flip narrow pass did not finish: the
// header is already re-keyed (committed at the flip), but some recorded blobs are
// still encrypted to the old master as well, so a holder of the old credential
// can still read them until a re-run completes. For a precautionary rotate this
// is merely "re-run to finish"; for an offboarding (a slot was removed) it means
// the removed credential is NOT yet revoked, which the caller must say plainly.
var ErrNarrowIncomplete = errors.New("re-keying did not finish: some blobs still carry the old master")

// RotateMaster re-keys a vault: it mints a fresh master, re-encrypts every
// manifest-recorded blob under it, and rewrites the header to wrap the new
// master under hdr's slots, with the manifest re-keyed in the same write, since
// the blob MACs are derived from the master. hdr carries the desired slot set
// (unchanged for a precautionary rotate, minus a slot for offboarding) and the
// manifest the caller verified; base is the current header bytes (freshness);
// oldMK the current master; verify re-unlocks the new header with the operator's
// credential. Returns the new master.
//
// It never leaves a reader unable to decrypt, via a three-phase transition that
// keeps the invariant "the master the header yields is a recipient of every
// recorded blob" at all times:
//
//  1. widen: re-encrypt every recorded blob to {old, new}, header still yields
//     old. Each blob's plaintext is checked against its manifest MAC first: a
//     reverted or substituted blob must never be laundered into the new epoch.
//  2. flip: write the new header (yields new, manifest re-MAC'd under new); every
//     recorded blob already has new.
//  3. narrow: re-encrypt every recorded blob to {new} only.
//
// Each namespace's current blob and its one-generation backup (Prev) are both
// re-keyed, so the backstop survives the rotation. A current blob missing from
// storage fails the rotation, the same alarm a read raises: dropping its entry
// would erase the evidence of a deletion. A missing backup is not fatal: it is
// never served, so its loss only narrows recovery, and the rotated entry simply
// carries no backup until the namespace's next write re-establishes one.
//
// Writes racing the rotation resolve through the header compare-and-swap. A
// concurrent writer's header update either lands before the flip, bumping the
// revision, so the flip's freshness check aborts the rotation (re-run), or
// reaches the swap after the flip, sees the new master, and rolls its own write
// back.
//
// A crash loses the in-memory new master, but the operation is re-runnable from
// any state: a re-run re-keys from whatever the header currently yields.
//
// onFlip, if non-nil, is called with the new master immediately after the header
// flip succeeds (before the narrow pass). The caller uses it to advance its
// local rollback pin to the new master at the moment it becomes authoritative,
// so an interrupted narrow doesn't leave the pin behind the header (which would
// make a re-run look like a rollback).
func RotateMaster(ctx context.Context, store Vault, hdr *crypto.Header, base []byte, oldMK *crypto.MasterKey, verify func(*crypto.Header) (*crypto.MasterKey, error), onFlip func(*crypto.MasterKey)) (*crypto.MasterKey, error) {
	newMK, err := crypto.GenerateMasterKey()
	if err != nil {
		return nil, err
	}

	// Phase 1: widen, every recorded blob readable under the old AND new master,
	// its re-keyed MAC collected for the flip.
	rekeyed := map[string]crypto.ManifestEntry{}
	for _, ns := range sortedNamespaces(hdr.Manifest) {
		next, err := widenNamespace(ctx, store, ns, hdr.Manifest[ns], oldMK, newMK)
		if err != nil {
			return nil, err
		}
		rekeyed[ns] = next
	}

	// Stage the signed transition in the header so the rotation's record and its
	// flip land in one compare-and-swap. A machine pinned at the old master then
	// can never observe the new header without the proof that the old master's
	// holder authorized it, and a concurrent rotation that loses the swap leaves
	// no stray record behind (its transition was only ever in this in-memory
	// header). The revision the flip assigns is the current one plus SafePut's
	// bump, which this transition's ToRevision already names.
	transition, err := crypto.NewTransition(oldMK, newMK, hdr.VaultID, hdr.Revision+1)
	if err != nil {
		return nil, err
	}
	hdr.Transitions = append(hdr.Transitions, *transition)

	// Phase 2: flip, install the new master and the re-keyed manifest in the
	// header (the one write that goes through the safe-write protocol, which bumps
	// the revision and seals).
	hdr.Manifest = rekeyed
	if err := hdr.SetMaster(newMK); err != nil {
		return nil, err
	}
	if err := SafePut(ctx, store, hdr, base, newMK, verify); err != nil {
		return nil, err
	}
	// The flip is committed; the new master is now authoritative. Let the caller
	// pin it before the narrow pass, so an interrupted narrow is re-runnable.
	if onFlip != nil {
		onFlip(newMK)
	}

	// Phase 3: narrow, every recorded blob readable under the new master only;
	// old can no longer decrypt. A blob that vanishes here is skipped, not an
	// error: post-flip its entry survives, so a deletion still alarms on the next
	// read, while an honest concurrent write that superseded it stays quiet.
	for _, ns := range sortedNamespaces(rekeyed) {
		if err := narrowNamespace(ctx, store, ns, rekeyed[ns], newMK); err != nil {
			// Tag every narrow-phase failure so the caller can tell it apart from a
			// pre-flip abort: here the flip already committed, so a removed slot is
			// gone but the old master can still read the un-narrowed blobs.
			return nil, fmt.Errorf("%w: %w", ErrNarrowIncomplete, err)
		}
	}
	return newMK, nil
}

// widenNamespace re-encrypts a namespace's current blob (and its backup, if any)
// to {old, new}, returning the re-keyed manifest entry. A missing current blob
// fails the rotation (the alarm a read raises); a missing backup is dropped (it
// is never served).
func widenNamespace(ctx context.Context, store Vault, ns string, e crypto.ManifestEntry, oldMK, newMK *crypto.MasterKey) (crypto.ManifestEntry, error) {
	mac, err := reencryptRecorded(ctx, store, e.Blob, e.MAC, oldMK, newMK, oldMK, newMK)
	if errors.Is(err, backend.ErrNotFound) {
		return crypto.ManifestEntry{}, fmt.Errorf("namespace %q blob %s is recorded in the vault manifest but missing from storage: a write was deleted or withheld (if another machine is writing right now, re-run)", ns, e.Blob)
	}
	if err != nil {
		return crypto.ManifestEntry{}, fmt.Errorf("re-encrypt namespace %q (widen): %w", ns, err)
	}
	next := crypto.ManifestEntry{Blob: e.Blob, MAC: mac}
	if e.Prev != "" {
		pmac, perr := reencryptRecorded(ctx, store, e.Prev, e.PrevMAC, oldMK, newMK, oldMK, newMK)
		switch {
		case errors.Is(perr, backend.ErrNotFound):
			// Backup gone: never served, so drop it rather than fail.
		case perr != nil:
			return crypto.ManifestEntry{}, fmt.Errorf("re-encrypt namespace %q backup (widen): %w", ns, perr)
		default:
			next.Prev, next.PrevMAC = e.Prev, pmac
		}
	}
	return next, nil
}

// narrowNamespace re-encrypts a namespace's current blob (and its backup) to
// {new} only. A vanished blob is skipped, not an error (its entry survives, so a
// deletion still alarms on the next read).
func narrowNamespace(ctx context.Context, store Vault, ns string, e crypto.ManifestEntry, newMK *crypto.MasterKey) error {
	if _, err := reencryptRecorded(ctx, store, e.Blob, e.MAC, newMK, newMK, newMK); err != nil && !errors.Is(err, backend.ErrNotFound) {
		return fmt.Errorf("re-encrypt namespace %q (narrow): %w; the vault is re-keyed but some blobs still carry the old key, re-run `notenv credential rotate-master`", ns, err)
	}
	if e.Prev != "" {
		if _, err := reencryptRecorded(ctx, store, e.Prev, e.PrevMAC, newMK, newMK, newMK); err != nil && !errors.Is(err, backend.ErrNotFound) {
			return fmt.Errorf("re-encrypt namespace %q backup (narrow): %w; re-run `notenv credential rotate-master`", ns, err)
		}
	}
	return nil
}

// sortedNamespaces returns the manifest's namespace keys sorted, for
// deterministic processing.
func sortedNamespaces(manifest map[string]crypto.ManifestEntry) []string {
	out := make([]string, 0, len(manifest))
	for ns := range manifest {
		out = append(out, ns)
	}
	sort.Strings(out)
	return out
}

// reencryptRecorded reads the recorded blob at key, opens it with readMK, checks
// it against its recorded MAC, and re-encrypts it to writeMKs in place,
// returning the plaintext's MAC under macMK. A missing blob surfaces as
// backend.ErrNotFound for the caller to judge: fatal for a current blob before
// the flip, skippable after and for a backup.
func reencryptRecorded(ctx context.Context, store Vault, key string, wantMAC string, readMK *crypto.MasterKey, macMK *crypto.MasterKey, writeMKs ...*crypto.MasterKey) (string, error) {
	blob, err := store.Get(ctx, key)
	if err != nil {
		return "", err
	}
	plain, err := readMK.Decrypt(blob)
	if err != nil {
		return "", err
	}
	if err := readMK.CheckBlobMAC(plain, wantMAC); err != nil {
		return "", err
	}
	mac, err := macMK.BlobMAC(plain)
	if err != nil {
		return "", err
	}
	sealed, err := crypto.EncryptToMasters(plain, writeMKs...)
	if err != nil {
		return "", err
	}
	if err := store.Put(ctx, key, sealed); err != nil {
		return "", err
	}
	return mac, nil
}
