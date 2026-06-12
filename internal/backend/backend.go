// Package backend defines where ciphertext lives. The Backend interface is a
// flat object store keyed by base-relative path: it only moves opaque bytes.
// The append-only segment/snapshot layout a namespace is assembled from lives a
// layer up, in internal/secrets. RcloneStorage is the only implementation.
package backend

import (
	"context"
	"errors"
)

// ErrNotFound is returned by Get and Delete when no object exists at the key.
var ErrNotFound = errors.New("object not found")

// ErrHeaderChanged is returned by SwapHeader when the stored header does not
// match the bytes the caller's operation started from: another writer landed
// first. The caller re-reads, re-applies its change, and retries.
var ErrHeaderChanged = errors.New("the header changed since this operation started")

// Backend is a flat object store. Keys are base-relative paths (for example
// "myapp/snapshot.age"); the store prepends its own base and moves bytes,
// nothing more.
type Backend interface {
	// Get returns the object stored at key (or ErrNotFound).
	Get(ctx context.Context, key string) ([]byte, error)
	// Put stores data at key, overwriting any existing object.
	Put(ctx context.Context, key string, data []byte) error
	// List returns the keys of every object under prefix, base-relative and
	// recursive. An absent prefix yields no keys, not an error.
	List(ctx context.Context, prefix string) ([]string, error)
	// Delete removes the object at key. Removing an absent key is not an error.
	Delete(ctx context.Context, key string) error
}

// HeaderStore is implemented by client-side-crypto backends, which keep the
// key-slot header next to the ciphertext objects (see internal/crypto:
// LUKS2-style wrapped master key). Backends where the provider holds
// plaintext have no key material and won't implement it.
type HeaderStore interface {
	// GetHeader returns the raw header object (or ErrNotFound).
	GetHeader(ctx context.Context) ([]byte, error)
	// PutHeader stores the raw header object unconditionally. Mutations of an
	// existing header should go through SwapHeader; PutHeader remains for
	// recovery paths that must overwrite no matter what.
	PutHeader(ctx context.Context, raw []byte) error
	// SwapHeader stores updated iff the current header bytes equal base (nil
	// base: no header may exist yet), and returns ErrHeaderChanged otherwise —
	// the compare-and-swap every concurrent header mutation serializes on.
	// Implementations make this as atomic as their storage allows; see each
	// implementation for the guarantee it actually provides.
	SwapHeader(ctx context.Context, base, updated []byte) error
	// BackupHeader preserves the current header before an overwrite, so a
	// clobbered header doesn't lock the user out of every blob. It is a no-op
	// when the remote keeps native object versions (the versions ARE the
	// backup) or when no header exists yet; otherwise it copies the header to
	// a sibling backup object. The safe-write protocol calls it before
	// PutHeader and refuses to proceed if it errors.
	BackupHeader(ctx context.Context) error
	// RestoreHeaderBackup copies the sibling backup object back over the
	// header, the recovery counterpart to BackupHeader. It returns
	// ErrNotFound when no backup exists. On versioned remotes there is no
	// ".prev" backup (restore a prior object version with rclone instead), so
	// implementations there return ErrNotFound.
	RestoreHeaderBackup(ctx context.Context) error
}
