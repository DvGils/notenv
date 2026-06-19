// Package backend defines where ciphertext lives. The Backend interface is a
// flat object store keyed by base-relative path: it only moves opaque bytes.
// The per-namespace blob layout a namespace's secrets live in is a layer up, in
// internal/secrets. RcloneStorage and local.Storage are the implementations.
package backend

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"strings"
)

// ErrNotFound is returned by Get and Delete when no object exists at the key.
var ErrNotFound = errors.New("object not found")

// ErrObjectTooLarge reports that a stored object is bigger than notenv will read
// into memory. Storage is treated as dumb and possibly hostile, so a read is
// bounded before the bytes are trusted: the header in particular is fetched and
// JSON-parsed before its master-keyed tag can be checked, on paths that never
// unlock (inspect --all, the namespace first-use check), so an unbounded read
// would let a remote OOM the machine pre-auth. Reads fail closed with this error
// instead.
var ErrObjectTooLarge = errors.New("stored object exceeds the maximum size notenv will read")

// Read caps. Far above any real vault, far below exhausting RAM. A header holds
// the key slots, the rotation log, and one manifest entry per namespace; a single
// object is one namespace's blob; MaxListBytes caps the total object-key bytes one
// List pulls in (a vault stores a couple of objects per namespace, so 64 MiB is
// ~a million keys). Capping the bytes also bounds the element count JSON parsing
// can allocate (a header cannot smuggle 10^7 slots in a few MiB).
const (
	MaxHeaderBytes int64 = 8 << 20  // 8 MiB
	MaxObjectBytes int64 = 64 << 20 // 64 MiB
	MaxListBytes   int64 = 64 << 20 // 64 MiB
)

// ReadCapped reads from r until EOF or max bytes, whichever comes first, and
// returns ErrObjectTooLarge if r holds more than max (it reads one byte past max
// to detect the overflow). Memory is bounded to max+1 regardless of how much r
// would yield, so a huge or endless object cannot exhaust memory. It never
// returns a truncated object: on overflow it errors rather than hand back a
// partial read the crypto layer would then reject anyway.
func ReadCapped(r io.Reader, max int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("%w (limit %d bytes)", ErrObjectTooLarge, max)
	}
	return data, nil
}

// ErrHeaderChanged is returned by SwapHeader when the stored header does not
// match the bytes the caller's operation started from: another writer landed
// first. The caller re-reads, re-applies its change, and retries.
var ErrHeaderChanged = errors.New("the header changed since this operation started")

// ErrCommitUncertain reports that a header write may have taken effect but could
// not be confirmed (the store wrote the bytes but a read-back to verify them
// failed, e.g. a transient error or read-after-write lag on an eventually
// consistent remote). It is distinct from ErrHeaderChanged, which means the
// write definitely did NOT land. A caller that wrote a data object for this
// header must NOT roll that object back on ErrCommitUncertain: the header may
// already reference it, so deleting it would strand the committed header. The
// write is durable; the right response is to surface "written but unverified,
// recover with `notenv credential restore-backup` if a later read fails".
var ErrCommitUncertain = errors.New("the header write may have taken effect but could not be verified")

// Reserved object names are storage plumbing, not user blobs: the key-slot
// header, its backup, the write lock, the connectivity probe, and any temp file
// a write is staging. They share the flat key space with namespace blobs, so
// every List MUST exclude them (via IsReserved) and no caller may ever delete
// one as if it were data. The single source of truth lives here because the two
// backends once diverged on it: the local store filtered the header out of List
// and the rclone store did not, which let orphan cleanup mistake the header for
// a stray and delete it.
const (
	HeaderName       = ".header.json"
	HeaderBackupName = HeaderName + ".prev"
	HeaderLockName   = ".header.lock"
	ProbeName        = ".notenv-probe"
	TempPrefix       = ".tmp-"
)

// IsReserved reports whether key names storage plumbing rather than a user
// object. List implementations exclude these so no caller can mistake one for a
// data blob; the copy and delete paths exclude them too.
func IsReserved(key string) bool {
	switch key {
	case HeaderName, HeaderBackupName, HeaderLockName, ProbeName:
		return true
	}
	return strings.HasPrefix(path.Base(key), TempPrefix)
}

// namespaceBlobKey matches the only non-reserved object notenv writes: a namespace
// blob keyed "<namespace>/data-<16 hex>.age". The namespace charset mirrors
// contract.NamespaceName and the "data-<hex>.age" shape is internal/secrets'
// generated blob name; TestNamespaceBlobKeyTracksContract guards the first against
// drift. Anything else in a vault directory is a file notenv did not put there.
var namespaceBlobKey = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]*/data-[0-9a-f]{16}\.age$`)

// IsNamespaceBlob reports whether key names a namespace data blob. This is the
// delete whitelist for the copy reconcile and vault teardown: a key that is not a
// namespace blob is never a stray to clean up, it is either plumbing (handled
// separately) or a foreign file notenv must not touch.
func IsNamespaceBlob(key string) bool {
	return namespaceBlobKey.MatchString(key)
}

// IsNotenvObject reports whether key is something notenv itself put in a vault:
// reserved plumbing or a namespace blob. Everything else is a foreign file that
// does not belong to the vault. Recognizing our own files, rather than trusting
// that a path notenv was handed is safe to own, is what stops copy from deleting a
// mispointed destination's contents and delete from removing an unrelated tree.
func IsNotenvObject(key string) bool {
	return IsReserved(key) || IsNamespaceBlob(key)
}

// WithinPrefix reports whether key falls under the directory named by prefix:
// everything when prefix is empty, the object exactly at prefix, or anything
// beneath "prefix/". It matches on the slash boundary, not a raw byte prefix, so
// a prefix of "ns" never also matches a sibling "ns2/...". This is the single
// source of truth for what a List prefix means, so the directory backends select
// the same set rclone's directory-scoped listing does (the same divergence risk
// IsReserved guards). Surrounding slashes are insignificant.
func WithinPrefix(key, prefix string) bool {
	clean := strings.Trim(prefix, "/")
	return clean == "" || key == clean || strings.HasPrefix(key, clean+"/")
}

// Backend is a flat object store. Keys are base-relative paths (for example
// "myapp/data-9f3a.age"); the store prepends its own base and moves bytes,
// nothing more.
type Backend interface {
	// Get returns the object stored at key (or ErrNotFound). It must return the
	// exact bytes Put stored: the write path reads a blob back after writing and
	// treats a byte difference as corruption.
	Get(ctx context.Context, key string) ([]byte, error)
	// Put stores data at key. The live write path writes uniquely-named blobs and
	// never overwrites one; overwrite semantics are still required for whole-vault
	// mirroring (vault copy/fork) and idempotent retries.
	Put(ctx context.Context, key string, data []byte) error
	// List returns the keys of every object under prefix, base-relative and
	// recursive. An absent prefix yields no keys, not an error. The read/write
	// path keys off the authenticated header manifest, not List; List is for
	// whole-vault operations (copy, delete) and orphan detection (doctor, gc).
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
	// base: no header may exist yet), and returns ErrHeaderChanged otherwise:
	// the compare-and-swap every concurrent header mutation serializes on.
	// Implementations make this as atomic as their storage allows; see each
	// implementation for the guarantee it actually provides.
	SwapHeader(ctx context.Context, base, updated []byte) error
	// BackupHeader copies the current header to a sibling backup object so a
	// clobbered header doesn't lock the user out of every blob (on every backend;
	// notenv keeps its own backup rather than relying on a remote's version
	// history). The safe-write protocol calls it ONLY when a header exists (it
	// skips the backup on virgin storage) and refuses to proceed if it errors, so
	// an absent header here is a race or a real failure, never the virgin case: it
	// returns an error and the write fails closed rather than overwrite without a
	// recoverable copy. (Treating a missing header as a no-op is exactly how an
	// ambiguous "not found" could let a write proceed unprotected.)
	BackupHeader(ctx context.Context) error
	// RestoreHeaderBackup copies the sibling backup object back over the
	// header, the recovery counterpart to BackupHeader. It returns ErrNotFound
	// when no backup exists yet (a vault's first backup is written on its second
	// header write).
	RestoreHeaderBackup(ctx context.Context) error
}
