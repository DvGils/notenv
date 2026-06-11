package keymgmt

import (
	"context"
	"fmt"
	"strings"

	"github.com/DvGils/notenv/internal/backend"
	"github.com/DvGils/notenv/internal/crypto"
)

// Vault is a backend that holds both the ciphertext objects and the key header,
// which rotation needs together.
type Vault interface {
	backend.Backend
	backend.HeaderStore
}

// RotateMaster re-keys a vault: it mints a fresh master, re-encrypts every blob
// under it, and rewrites the header to wrap the new master under hdr's slots.
// hdr carries the desired slot set (unchanged for a precautionary rotate, minus
// a slot for offboarding). base is the current header bytes (freshness); oldMK
// the current master; verify re-unlocks the new header with the operator's
// credential. Returns the new master.
//
// It never leaves a reader unable to decrypt, via a three-phase transition that
// keeps the invariant "the master the header yields is a recipient of every
// blob" at all times:
//
//  1. widen  — re-encrypt every blob to {old, new}, header still yields old.
//  2. flip   — write the new header (yields new); every blob already has new.
//  3. narrow — re-encrypt every blob to {new} only; old can no longer decrypt.
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
	objects, err := blobObjects(ctx, store)
	if err != nil {
		return nil, fmt.Errorf("list secrets: %w", err)
	}

	// Phase 1: widen — every object readable under the old AND new master.
	for _, key := range objects {
		if err := reencrypt(ctx, store, key, oldMK, oldMK, newMK); err != nil {
			return nil, fmt.Errorf("re-encrypt %q (widen): %w", key, err)
		}
	}

	// Phase 2: flip — install the new master in the header (the one write that
	// goes through the safe-write protocol, which bumps the revision and seals).
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

	// Phase 3: narrow — every object readable under the new master only.
	for _, key := range objects {
		if err := reencrypt(ctx, store, key, newMK, newMK); err != nil {
			return nil, fmt.Errorf("re-encrypt %q (narrow): %w; the vault is re-keyed but some secrets still carry the old key, re-run `notenv key rotate-master`", key, err)
		}
	}
	return newMK, nil
}

// blobObjects lists every ciphertext object a rotation must re-key: the
// snapshots and segments under every namespace. The key header is managed
// separately, so it (and its ".prev") is excluded by the ".age" suffix.
func blobObjects(ctx context.Context, store Vault) ([]string, error) {
	keys, err := store.List(ctx, "")
	if err != nil {
		return nil, err
	}
	var objects []string
	for _, key := range keys {
		// Ciphertext lives under a namespace prefix (<ns>/...); requiring the
		// slash also skips any stray root-level blob from an earlier layout.
		if strings.Contains(key, "/") && strings.HasSuffix(key, ".age") {
			objects = append(objects, key)
		}
	}
	return objects, nil
}

// reencrypt reads the object at key, decrypts it with readMK, and re-encrypts
// it to writeMKs in place.
func reencrypt(ctx context.Context, store Vault, key string, readMK *crypto.MasterKey, writeMKs ...*crypto.MasterKey) error {
	blob, err := store.Get(ctx, key)
	if err != nil {
		return err
	}
	plain, err := readMK.Decrypt(blob)
	if err != nil {
		return err
	}
	sealed, err := crypto.EncryptToMasters(plain, writeMKs...)
	if err != nil {
		return err
	}
	return store.Put(ctx, key, sealed)
}
