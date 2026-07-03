// Package backendtest holds the shared conformance suites for backend
// implementations. Both the in-memory fake (memstore) and the real
// RcloneStorage run them, so a behavior the fake is trusted to model is the
// behavior the real backend is required to have. The suites assert only what
// the interfaces expose, so they work against any implementation.
package backendtest

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/DvGils/notenv/internal/backend"
)

// BackendContract runs the object-store conformance suite. newStore must return
// a fresh, empty store on each call (registering any cleanup via t itself).
func BackendContract(t *testing.T, newStore func(t *testing.T) backend.Backend) {
	t.Helper()
	t.Run("GetMissingIsNotFound", func(t *testing.T) { testGetMissing(t, newStore) })
	t.Run("PutGetRoundTrip", func(t *testing.T) { testObjectRoundTrip(t, newStore) })
	t.Run("PutOverwrites", func(t *testing.T) { testPutOverwrites(t, newStore) })
	t.Run("ListByPrefixIsRecursive", func(t *testing.T) { testListByPrefix(t, newStore) })
	t.Run("DeleteRemovesAndMissingIsNoError", func(t *testing.T) { testDelete(t, newStore) })
}

func testGetMissing(t *testing.T, newStore func(t *testing.T) backend.Backend) {
	if _, err := newStore(t).Get(context.Background(), "ns/missing.age"); !errors.Is(err, backend.ErrNotFound) {
		t.Fatalf("Get of absent key: want ErrNotFound, got %v", err)
	}
}

func testObjectRoundTrip(t *testing.T, newStore func(t *testing.T) backend.Backend) {
	ctx := context.Background()
	s := newStore(t)
	want := []byte("ciphertext")
	if err := s.Put(ctx, "ns/seg-a-1.age", want); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := s.Get(ctx, "ns/seg-a-1.age")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("round trip mismatch: got %q want %q", got, want)
	}
}

func testPutOverwrites(t *testing.T, newStore func(t *testing.T) backend.Backend) {
	ctx := context.Background()
	s := newStore(t)
	if err := s.Put(ctx, "ns/snap-1.age", []byte("v1")); err != nil {
		t.Fatalf("Put v1: %v", err)
	}
	if err := s.Put(ctx, "ns/snap-1.age", []byte("v2")); err != nil {
		t.Fatalf("Put v2: %v", err)
	}
	got, err := s.Get(ctx, "ns/snap-1.age")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != "v2" {
		t.Fatalf("overwrite: got %q want v2", got)
	}
}

func testListByPrefix(t *testing.T, newStore func(t *testing.T) backend.Backend) {
	ctx := context.Background()
	s := newStore(t)
	// "ns2/..." shares the byte-prefix "ns" with the "ns/" namespace: a List that
	// matched a raw byte prefix instead of a directory boundary would leak it in.
	for _, key := range []string{"ns/snap-1.age", "ns/seg-a-1.age", "ns2/snap-1.age", "other/snap-1.age"} {
		if err := s.Put(ctx, key, []byte("x")); err != nil {
			t.Fatalf("Put %s: %v", key, err)
		}
	}
	want := []string{"ns/seg-a-1.age", "ns/snap-1.age"}
	// "ns/" and the bare "ns" must scope identically (a directory boundary), and
	// neither may pull in the sibling "ns2/...". Every backend must agree.
	for _, prefix := range []string{"ns/", "ns"} {
		scoped, err := s.List(ctx, prefix)
		if err != nil {
			t.Fatalf("List %q: %v", prefix, err)
		}
		slices.Sort(scoped)
		if !slices.Equal(scoped, want) {
			t.Fatalf("List %q: got %v want %v", prefix, scoped, want)
		}
	}
	all, err := s.List(ctx, "")
	if err != nil {
		t.Fatalf("List all: %v", err)
	}
	if len(all) != 4 {
		t.Fatalf("List all: got %d keys, want 4 (%v)", len(all), all)
	}
}

func testDelete(t *testing.T, newStore func(t *testing.T) backend.Backend) {
	ctx := context.Background()
	s := newStore(t)
	if err := s.Delete(ctx, "ns/absent.age"); err != nil {
		t.Fatalf("Delete of absent key: want nil, got %v", err)
	}
	if err := s.Put(ctx, "ns/seg-a-1.age", []byte("x")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := s.Delete(ctx, "ns/seg-a-1.age"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Get(ctx, "ns/seg-a-1.age"); !errors.Is(err, backend.ErrNotFound) {
		t.Fatalf("Get after Delete: want ErrNotFound, got %v", err)
	}
}

// HeaderStoreContract runs the header conformance suite. newStore must return a
// fresh, empty store on each call (registering any cleanup via t itself). Every
// store keeps a ".prev" backup (notenv no longer relies on a remote's own
// version history as a substitute).
func HeaderStoreContract(t *testing.T, newStore func(t *testing.T) backend.HeaderStore) {
	t.Helper()
	t.Run("GetHeaderNotFoundWhenEmpty", func(t *testing.T) { testHeaderMissing(t, newStore) })
	t.Run("PutGetRoundTrip", func(t *testing.T) { testHeaderRoundTrip(t, newStore) })
	t.Run("SwapHeaderCreatesWhenAbsent", func(t *testing.T) { testSwapCreate(t, newStore) })
	t.Run("SwapHeaderReplacesOnMatch", func(t *testing.T) { testSwapReplace(t, newStore) })
	t.Run("SwapHeaderRefusesOnMismatch", func(t *testing.T) { testSwapMismatch(t, newStore) })
	t.Run("BackupNoHeaderFailsClosed", func(t *testing.T) { testBackupNoHeader(t, newStore) })
	t.Run("RestoreWithoutBackupIsNotFound", func(t *testing.T) { testRestoreWithoutBackup(t, newStore) })
	t.Run("BackupThenRestoreRecoversPriorHeader", func(t *testing.T) { testBackupThenRestore(t, newStore) })
}

func testHeaderMissing(t *testing.T, newStore func(t *testing.T) backend.HeaderStore) {
	if _, err := newStore(t).GetHeader(context.Background()); !errors.Is(err, backend.ErrNotFound) {
		t.Fatalf("GetHeader on empty store: want ErrNotFound, got %v", err)
	}
}

func testHeaderRoundTrip(t *testing.T, newStore func(t *testing.T) backend.HeaderStore) {
	ctx := context.Background()
	s := newStore(t)
	want := []byte(`{"version":1}`)
	if err := s.PutHeader(ctx, want); err != nil {
		t.Fatalf("PutHeader: %v", err)
	}
	got, err := s.GetHeader(ctx)
	if err != nil {
		t.Fatalf("GetHeader: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("round trip mismatch: got %q want %q", got, want)
	}
}

func testSwapCreate(t *testing.T, newStore func(t *testing.T) backend.HeaderStore) {
	ctx := context.Background()
	s := newStore(t)
	if err := s.SwapHeader(ctx, nil, []byte("v1")); err != nil {
		t.Fatalf("SwapHeader(nil base) on empty store: %v", err)
	}
	assertHeader(t, s, []byte("v1"), "create-swap did not store")
}

func testSwapReplace(t *testing.T, newStore func(t *testing.T) backend.HeaderStore) {
	ctx := context.Background()
	s := newStore(t)
	if err := s.PutHeader(ctx, []byte("v1")); err != nil {
		t.Fatalf("PutHeader: %v", err)
	}
	if err := s.SwapHeader(ctx, []byte("v1"), []byte("v2")); err != nil {
		t.Fatalf("SwapHeader with matching base: %v", err)
	}
	assertHeader(t, s, []byte("v2"), "swap did not replace")
}

func testSwapMismatch(t *testing.T, newStore func(t *testing.T) backend.HeaderStore) {
	ctx := context.Background()
	s := newStore(t)

	// A non-nil base against an empty store must refuse: the operation started
	// from a header that no longer exists.
	if err := s.SwapHeader(ctx, []byte("v0"), []byte("v1")); !errors.Is(err, backend.ErrHeaderChanged) {
		t.Fatalf("SwapHeader with base against empty store: want ErrHeaderChanged, got %v", err)
	}
	if err := s.PutHeader(ctx, []byte("other")); err != nil {
		t.Fatalf("PutHeader: %v", err)
	}
	if err := s.SwapHeader(ctx, []byte("v0"), []byte("v1")); !errors.Is(err, backend.ErrHeaderChanged) {
		t.Fatalf("SwapHeader with stale base: want ErrHeaderChanged, got %v", err)
	}
	// A nil base against an existing header must refuse: "create" lost to a
	// writer that initialized first.
	if err := s.SwapHeader(ctx, nil, []byte("v1")); !errors.Is(err, backend.ErrHeaderChanged) {
		t.Fatalf("SwapHeader(nil base) against existing header: want ErrHeaderChanged, got %v", err)
	}
	assertHeader(t, s, []byte("other"), "failed swaps must not modify the header")
}

func testBackupNoHeader(t *testing.T, newStore func(t *testing.T) backend.HeaderStore) {
	ctx := context.Background()
	s := newStore(t)
	// The safe-write protocol calls BackupHeader only when a header exists (it
	// skips the backup on virgin storage), so backing up with no header must fail
	// rather than be a silent no-op: that no-op was how an ambiguous "not found"
	// could let a write overwrite the header without a recoverable copy.
	if err := s.BackupHeader(ctx); err == nil {
		t.Fatal("BackupHeader with no header: want an error, got nil")
	}
	if err := s.RestoreHeaderBackup(ctx); !errors.Is(err, backend.ErrNotFound) {
		t.Fatalf("RestoreHeaderBackup with no backup: want ErrNotFound, got %v", err)
	}
}

func testRestoreWithoutBackup(t *testing.T, newStore func(t *testing.T) backend.HeaderStore) {
	ctx := context.Background()
	s := newStore(t)
	if err := s.PutHeader(ctx, []byte("v1")); err != nil {
		t.Fatalf("PutHeader: %v", err)
	}
	if err := s.RestoreHeaderBackup(ctx); !errors.Is(err, backend.ErrNotFound) {
		t.Fatalf("RestoreHeaderBackup before any backup: want ErrNotFound, got %v", err)
	}
}

func testBackupThenRestore(t *testing.T, newStore func(t *testing.T) backend.HeaderStore) {
	ctx := context.Background()
	s := newStore(t)
	v1, v2 := []byte("header-v1"), []byte("header-v2")
	if err := s.PutHeader(ctx, v1); err != nil {
		t.Fatalf("PutHeader v1: %v", err)
	}
	if err := s.BackupHeader(ctx); err != nil {
		t.Fatalf("BackupHeader: %v", err)
	}
	if err := s.PutHeader(ctx, v2); err != nil {
		t.Fatalf("PutHeader v2: %v", err)
	}

	if err := s.RestoreHeaderBackup(ctx); err != nil {
		t.Fatalf("RestoreHeaderBackup: %v", err)
	}
	assertHeader(t, s, v1, "restore did not recover prior header")
}

// Vault is a backend that holds both objects and the key-slot header in one flat
// key space, the shape every client-side-crypto backend has.
type Vault interface {
	backend.Backend
	backend.HeaderStore
}

// VaultContract asserts the property the Backend and HeaderStore suites miss by
// running on separate stores: when a header and blobs coexist, List must return
// only the blobs, never the header artifacts. A backend that leaks the header
// into List lets whole-vault and orphan-cleanup callers mistake it for a stray
// object and delete it, bricking the vault. newStore must return a fresh, empty
// store on each call.
func VaultContract(t *testing.T, newStore func(t *testing.T) Vault) {
	t.Helper()
	t.Run("ListExcludesHeaderArtifacts", func(t *testing.T) { testListExcludesHeader(t, newStore) })
}

func testListExcludesHeader(t *testing.T, newStore func(t *testing.T) Vault) {
	ctx := context.Background()
	s := newStore(t)

	// Make both the header and its ".prev" backup exist alongside real blobs.
	if err := s.PutHeader(ctx, []byte(`{"version":1}`)); err != nil {
		t.Fatalf("PutHeader v1: %v", err)
	}
	if err := s.BackupHeader(ctx); err != nil {
		t.Fatalf("BackupHeader: %v", err)
	}
	if err := s.PutHeader(ctx, []byte(`{"version":2}`)); err != nil {
		t.Fatalf("PutHeader v2: %v", err)
	}
	blobs := []string{"app/data-a.age", "app/data-b.age"}
	for _, key := range blobs {
		if err := s.Put(ctx, key, []byte("ciphertext")); err != nil {
			t.Fatalf("Put %s: %v", key, err)
		}
	}

	got, err := s.List(ctx, "")
	if err != nil {
		t.Fatalf("List all: %v", err)
	}
	slices.Sort(got)
	if !slices.Equal(got, blobs) {
		t.Fatalf("List with a header present: got %v, want only the blobs %v (header artifacts must be excluded)", got, blobs)
	}
}

func assertHeader(t *testing.T, s backend.HeaderStore, want []byte, msg string) {
	t.Helper()
	got, err := s.GetHeader(context.Background())
	if err != nil {
		t.Fatalf("GetHeader: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s: got %q want %q", msg, got, want)
	}
}
