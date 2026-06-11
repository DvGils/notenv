// Package backendtest holds the shared conformance suites for backend
// implementations. Both the in-memory fake (memstore) and the real
// RcloneStorage run them, so a behaviour the fake is trusted to model is the
// behaviour the real backend is required to have. The suites assert only what
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
	for _, key := range []string{"ns/snap-1.age", "ns/seg-a-1.age", "other/snap-1.age"} {
		if err := s.Put(ctx, key, []byte("x")); err != nil {
			t.Fatalf("Put %s: %v", key, err)
		}
	}
	scoped, err := s.List(ctx, "ns/")
	if err != nil {
		t.Fatalf("List ns/: %v", err)
	}
	slices.Sort(scoped)
	if want := []string{"ns/seg-a-1.age", "ns/snap-1.age"}; !slices.Equal(scoped, want) {
		t.Fatalf("List ns/: got %v want %v", scoped, want)
	}
	all, err := s.List(ctx, "")
	if err != nil {
		t.Fatalf("List all: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("List all: got %d keys, want 3 (%v)", len(all), all)
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
// fresh, empty store on each call (registering any cleanup via t itself).
// versioned states whether the store keeps native object versions, which
// changes the expected backup and restore behaviour.
func HeaderStoreContract(t *testing.T, newStore func(t *testing.T) backend.HeaderStore, versioned bool) {
	t.Helper()
	t.Run("GetHeaderNotFoundWhenEmpty", func(t *testing.T) { testHeaderMissing(t, newStore) })
	t.Run("PutGetRoundTrip", func(t *testing.T) { testHeaderRoundTrip(t, newStore) })
	t.Run("BackupNoHeaderIsNoop", func(t *testing.T) { testBackupNoHeader(t, newStore) })
	t.Run("RestoreWithoutBackupIsNotFound", func(t *testing.T) { testRestoreWithoutBackup(t, newStore) })
	t.Run("BackupThenRestoreRecoversPriorHeader", func(t *testing.T) { testBackupThenRestore(t, newStore, versioned) })
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

func testBackupNoHeader(t *testing.T, newStore func(t *testing.T) backend.HeaderStore) {
	ctx := context.Background()
	s := newStore(t)
	if err := s.BackupHeader(ctx); err != nil {
		t.Fatalf("BackupHeader with no header: want nil, got %v", err)
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

func testBackupThenRestore(t *testing.T, newStore func(t *testing.T) backend.HeaderStore, versioned bool) {
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

	err := s.RestoreHeaderBackup(ctx)
	if versioned {
		// Versioned remotes keep no ".prev"; recovery goes through the remote's
		// own version history, not RestoreHeaderBackup.
		if !errors.Is(err, backend.ErrNotFound) {
			t.Fatalf("RestoreHeaderBackup on versioned store: want ErrNotFound, got %v", err)
		}
		assertHeader(t, s, v2, "versioned store header changed unexpectedly")
		return
	}
	if err != nil {
		t.Fatalf("RestoreHeaderBackup: %v", err)
	}
	assertHeader(t, s, v1, "restore did not recover prior header")
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
