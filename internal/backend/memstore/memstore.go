// Package memstore is an in-memory backend.HeaderStore (and backend.Backend)
// for tests. It keeps the header, its ".prev" backup, and stored objects in
// maps instead of talking to rclone, so the safe-write protocol and any code
// that mutates the header can be tested without storage or network.
//
// It is held to the same contract as the real backend by the shared
// conformance suite in internal/backend/backendtest, so a test that passes
// against this fake means the same thing it would against rclone.
package memstore

import (
	"bytes"
	"context"
	"strings"

	"github.com/DvGils/notenv/internal/backend"
)

// Store is an in-memory HeaderStore and Backend. The zero value is not usable;
// construct one with New. A Store is not safe for concurrent use; tests drive
// it from a single goroutine.
type Store struct {
	header   []byte // nil means no header object exists
	prev     []byte // nil means no ".prev" backup exists
	blobs    map[string][]byte
	corrupt  func([]byte) []byte // applied to PutHeader bytes when set, then cleared
	putCount int

	// blob-Put fault injection: allow putOK successful Puts, then fail one with
	// putErr (one-shot). Used to simulate a crash mid-rotation.
	putOK  int
	putErr error
}

// Option configures a Store.
type Option func(*Store)

// New returns an empty Store (no header, no blobs).
func New(opts ...Option) *Store {
	s := &Store{blobs: map[string][]byte{}}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Compile-time proof the fake satisfies the interfaces it stands in for.
var (
	_ backend.Backend     = (*Store)(nil)
	_ backend.HeaderStore = (*Store)(nil)
)

func (s *Store) GetHeader(_ context.Context) ([]byte, error) {
	if s.header == nil {
		return nil, backend.ErrNotFound
	}
	return clone(s.header), nil
}

// PutHeader stores the header. If a corruption hook is armed (CorruptNextPut),
// it is applied to the bytes actually stored and then disarmed, simulating a
// write that lands different bytes than intended so read-back verification has
// something to catch.
func (s *Store) PutHeader(_ context.Context, raw []byte) error {
	s.putCount++
	stored := clone(raw)
	if s.corrupt != nil {
		stored = s.corrupt(stored)
		s.corrupt = nil
	}
	s.header = stored
	return nil
}

// SwapHeader is a true compare-and-swap: the compare and the store happen in
// one step with nothing interleaving (the Store is single-goroutine by
// contract), so code tested against this fake sees the strongest semantics the
// interface allows. The store goes through PutHeader so corruption hooks and
// the put counter keep working.
func (s *Store) SwapHeader(ctx context.Context, base, updated []byte) error {
	if !bytes.Equal(s.header, base) {
		return backend.ErrHeaderChanged
	}
	return s.PutHeader(ctx, updated)
}

// BackupHeader copies the header to ".prev", a no-op only when no header exists
// yet, matching RcloneStorage.
func (s *Store) BackupHeader(_ context.Context) error {
	if s.header == nil {
		return nil
	}
	s.prev = clone(s.header)
	return nil
}

// RestoreHeaderBackup copies ".prev" back over the header, or returns
// ErrNotFound when there is no backup.
func (s *Store) RestoreHeaderBackup(_ context.Context) error {
	if s.prev == nil {
		return backend.ErrNotFound
	}
	s.header = clone(s.prev)
	return nil
}

func (s *Store) Get(_ context.Context, key string) ([]byte, error) {
	blob, ok := s.blobs[key]
	if !ok {
		return nil, backend.ErrNotFound
	}
	return clone(blob), nil
}

func (s *Store) Put(_ context.Context, key string, data []byte) error {
	if s.putErr != nil {
		if s.putOK > 0 {
			s.putOK--
		} else {
			err := s.putErr
			s.putErr = nil // one-shot
			return err
		}
	}
	s.blobs[key] = clone(data)
	return nil
}

func (s *Store) Delete(_ context.Context, key string) error {
	delete(s.blobs, key)
	return nil
}

// FailPutAfter makes the (n+1)th object Put return err once (simulating a crash
// mid-rotation); earlier and later Puts succeed.
func (s *Store) FailPutAfter(n int, err error) { s.putOK, s.putErr = n, err }

func (s *Store) List(_ context.Context, prefix string) ([]string, error) {
	// Model the real backends: the header and its backup share the flat key space
	// with blobs (on rclone they list as ordinary files), and a correct List
	// filters them out via backend.IsReserved. The fake surfaces them to that
	// filter so the conformance suite actually exercises it; keeping them in
	// separate fields used to make this List silently model the local backend's
	// pre-filtered listing and hide the rclone-only gap.
	keys := make([]string, 0, len(s.blobs)+2)
	candidates := make([]string, 0, len(s.blobs)+2)
	for key := range s.blobs {
		candidates = append(candidates, key)
	}
	if s.header != nil {
		candidates = append(candidates, backend.HeaderName)
	}
	if s.prev != nil {
		candidates = append(candidates, backend.HeaderBackupName)
	}
	for _, key := range candidates {
		if backend.IsReserved(key) {
			continue
		}
		if strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
	}
	return keys, nil
}

// CorruptNextPut arms a one-shot transform applied to the bytes the next
// PutHeader stores, so a test can simulate a bad write (truncation, a flipped
// byte) and assert the safe-write protocol detects it on read-back.
func (s *Store) CorruptNextPut(fn func([]byte) []byte) { s.corrupt = fn }

// SetHeader seeds the header directly, bypassing PutHeader, for test setup.
func (s *Store) SetHeader(raw []byte) { s.header = clone(raw) }

// Header returns the currently stored header bytes (nil if none).
func (s *Store) Header() []byte { return clone(s.header) }

// Prev returns the currently stored ".prev" backup bytes (nil if none).
func (s *Store) Prev() []byte { return clone(s.prev) }

// PutHeaderCount reports how many times PutHeader has been called.
func (s *Store) PutHeaderCount() int { return s.putCount }

func clone(b []byte) []byte {
	if b == nil {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}
