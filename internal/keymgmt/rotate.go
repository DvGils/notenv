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

// RotateMaster re-keys a vault: it mints a fresh master, re-encrypts every
// manifest-recorded blob under it, and rewrites the header to wrap the new
// master under hdr's slots — with the manifest re-keyed in the same write,
// since the object MACs are derived from the master. hdr carries the desired
// slot set (unchanged for a precautionary rotate, minus a slot for
// offboarding) and the manifest the caller verified; base is the current
// header bytes (freshness); oldMK the current master; verify re-unlocks the
// new header with the operator's credential. Returns the new master.
//
// It never leaves a reader unable to decrypt, via a three-phase transition that
// keeps the invariant "the master the header yields is a recipient of every
// recorded blob" at all times:
//
//  1. widen  — re-encrypt every recorded blob to {old, new}, header still
//     yields old. Each blob's plaintext is checked against its manifest MAC
//     first: a reverted or substituted object must never be laundered into the
//     new epoch.
//  2. flip   — write the new header (yields new, manifest re-MAC'd under new);
//     every recorded blob already has new.
//  3. narrow — re-encrypt every recorded blob to {new} only.
//
// Writes racing the rotation resolve through the header compare-and-swap. A
// concurrent writer's manifest update either lands before the flip — bumping
// the revision, so the flip's freshness check aborts the rotation (re-run) —
// or reaches the swap after the flip, sees the new master, and rolls its own
// write back. An object whose manifest update never ran (its writer crashed,
// or is about to roll back) is deliberately left alone: re-keying or adopting
// it here would race the writer's own rollback deletion, and the next fold
// classifies whatever remains. Objects deleted while rotating (a concurrent
// compaction folding them away) are skipped; the compaction's own manifest
// update arbitrates through the same swap.
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

	// Phase 1: widen — every recorded object readable under the old AND new
	// master, its re-keyed MAC collected for the flip. Folded entries (objects a
	// compaction subsumed, awaiting deletion) are not re-keyed: their content
	// lives in a live snapshot, so they are deleted here instead — rotation is a
	// natural cleanup point — and their entries dropped at the flip.
	rekeyed := map[string]crypto.ManifestEntry{}
	live, folded := splitManifest(hdr.Manifest)
	for _, key := range live {
		mac, err := reencryptRecorded(ctx, store, key, hdr.Manifest[key], oldMK, newMK, oldMK, newMK)
		if errors.Is(err, backend.ErrNotFound) {
			// A vanished recorded object must fail the rotation, not be skipped:
			// dropping its entry at the flip would erase the evidence of a
			// deletion. The honest cause — a concurrent compaction that folded
			// it — moved the header revision, so the flip would abort and a
			// re-run sees the folded entry; anything else deserves the alarm.
			return nil, fmt.Errorf("object %s is recorded in the vault manifest but missing from storage: a write was deleted or withheld (if another machine is compacting right now, re-run)", key)
		}
		if err != nil {
			return nil, fmt.Errorf("re-encrypt %q (widen): %w", key, err)
		}
		rekeyed[key] = crypto.ManifestEntry{MAC: mac}
	}
	for _, key := range folded {
		if err := store.Delete(ctx, key); err != nil {
			return nil, fmt.Errorf("remove folded object %q: %w", key, err)
		}
	}

	// Record the signed transition before the flip, so a machine pinned at the
	// old master never observes the new header without the proof that the old
	// master's holder authorized it. The revision the flip will assign is the
	// current one plus SafePut's bump; if another write lands first, SafePut's
	// freshness check aborts the rotation and this entry remains an orphan no
	// chain walks through (the retry appends a fresh one).
	transition, err := crypto.NewTransition(oldMK, newMK, hdr.VaultID, hdr.Revision+1)
	if err != nil {
		return nil, err
	}
	if err := appendTransition(ctx, store, transition); err != nil {
		return nil, fmt.Errorf("record rotation: %w", err)
	}

	// Phase 2: flip — install the new master and the re-keyed manifest in the
	// header (the one write that goes through the safe-write protocol, which
	// bumps the revision and seals).
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

	// Phase 3: narrow — every recorded object readable under the new master
	// only; old can no longer decrypt. Every entry that survived to the flip was
	// widened, so the new master reads each directly. An object that vanishes
	// here is skipped, not an error: post-flip its live entry survives, so a
	// deletion still alarms on the next fold, while the honest cause (a
	// new-master compaction folding it away) stays quiet.
	for key := range rekeyed {
		if _, err := reencryptRecorded(ctx, store, key, rekeyed[key], newMK, newMK, newMK); err != nil && !errors.Is(err, backend.ErrNotFound) {
			return nil, fmt.Errorf("re-encrypt %q (narrow): %w; the vault is re-keyed but some secrets still carry the old key, re-run `notenv key rotate-master`", key, err)
		}
	}
	return newMK, nil
}

// splitManifest partitions manifest keys into live and folded, sorted for
// deterministic processing.
func splitManifest(manifest map[string]crypto.ManifestEntry) (live, folded []string) {
	for key, e := range manifest {
		if e.Folded {
			folded = append(folded, key)
		} else {
			live = append(live, key)
		}
	}
	sort.Strings(live)
	sort.Strings(folded)
	return live, folded
}

// reencryptRecorded reads the recorded object at key, opens it with readMK,
// checks it against its manifest entry, and re-encrypts it to writeMKs in
// place, returning the plaintext's MAC under the last writeMK. A missing
// object surfaces as backend.ErrNotFound for the caller to judge: fatal before
// the flip, skippable after.
func reencryptRecorded(ctx context.Context, store Vault, key string, e crypto.ManifestEntry, readMK *crypto.MasterKey, macMK *crypto.MasterKey, writeMKs ...*crypto.MasterKey) (string, error) {
	blob, err := store.Get(ctx, key)
	if err != nil {
		return "", err
	}
	plain, err := readMK.Decrypt(blob)
	if err != nil {
		return "", err
	}
	if err := readMK.CheckObjectMAC(plain, e.MAC); err != nil {
		return "", err
	}
	mac, err := macMK.ObjectMAC(plain)
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
