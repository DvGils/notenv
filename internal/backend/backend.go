// Package backend defines where ciphertext lives. The Backend interface is
// the seam between client-side-crypto and provider-holds-plaintext storage
// models: RcloneStorage is the only MVP implementation. A future
// KeyVaultBackend can implement the same interface and simply ignore the
// crypto layer.
package backend

import (
	"context"
	"errors"
)

// ErrNotFound is returned by Get when no blob exists for the namespace.
var ErrNotFound = errors.New("namespace not found")

type Backend interface {
	// Get returns the stored ciphertext for a namespace (or ErrNotFound).
	Get(ctx context.Context, namespace string) ([]byte, error)
	// Put stores ciphertext. Implementations SHOULD retain prior versions.
	Put(ctx context.Context, namespace string, ciphertext []byte) error
	// List returns known namespaces.
	List(ctx context.Context) ([]string, error)
}

// HeaderStore is implemented by client-side-crypto backends, which keep the
// key-slot header next to the namespace blobs (see internal/crypto:
// LUKS2-style wrapped master key). Backends where the provider holds
// plaintext have no key material and won't implement it.
type HeaderStore interface {
	// GetHeader returns the raw header object (or ErrNotFound).
	GetHeader(ctx context.Context) ([]byte, error)
	// PutHeader stores the raw header object.
	PutHeader(ctx context.Context, raw []byte) error
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
