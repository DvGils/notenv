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
}
