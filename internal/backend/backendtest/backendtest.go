// Package backendtest holds the shared conformance suite for
// backend.HeaderStore implementations. Both the in-memory fake (memstore) and
// the real RcloneStorage run it, so a behaviour the fake is trusted to model
// is the behaviour the real backend is required to have. The suite asserts
// only what the interface exposes, so it works against any implementation.
package backendtest

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/DvGils/notenv/internal/backend"
)

// HeaderStoreContract runs the full conformance suite. newStore must return a
// fresh, empty store on each call (registering any cleanup via t itself).
// versioned states whether the store keeps native object versions, which
// changes the expected backup and restore behaviour.
func HeaderStoreContract(t *testing.T, newStore func(t *testing.T) backend.HeaderStore, versioned bool) {
	t.Helper()
	ctx := context.Background()

	t.Run("GetHeaderNotFoundWhenEmpty", func(t *testing.T) {
		s := newStore(t)
		if _, err := s.GetHeader(ctx); !errors.Is(err, backend.ErrNotFound) {
			t.Fatalf("GetHeader on empty store: want ErrNotFound, got %v", err)
		}
	})

	t.Run("PutGetRoundTrip", func(t *testing.T) {
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
	})

	t.Run("BackupNoHeaderIsNoop", func(t *testing.T) {
		s := newStore(t)
		if err := s.BackupHeader(ctx); err != nil {
			t.Fatalf("BackupHeader with no header: want nil, got %v", err)
		}
		if err := s.RestoreHeaderBackup(ctx); !errors.Is(err, backend.ErrNotFound) {
			t.Fatalf("RestoreHeaderBackup with no backup: want ErrNotFound, got %v", err)
		}
	})

	t.Run("RestoreWithoutBackupIsNotFound", func(t *testing.T) {
		s := newStore(t)
		if err := s.PutHeader(ctx, []byte("v1")); err != nil {
			t.Fatalf("PutHeader: %v", err)
		}
		if err := s.RestoreHeaderBackup(ctx); !errors.Is(err, backend.ErrNotFound) {
			t.Fatalf("RestoreHeaderBackup before any backup: want ErrNotFound, got %v", err)
		}
	})

	t.Run("BackupThenRestoreRecoversPriorHeader", func(t *testing.T) {
		s := newStore(t)
		v1 := []byte("header-v1")
		v2 := []byte("header-v2")
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
			// Versioned remotes keep no ".prev"; recovery goes through the
			// remote's own version history, not RestoreHeaderBackup.
			if !errors.Is(err, backend.ErrNotFound) {
				t.Fatalf("RestoreHeaderBackup on versioned store: want ErrNotFound, got %v", err)
			}
			got, err := s.GetHeader(ctx)
			if err != nil {
				t.Fatalf("GetHeader: %v", err)
			}
			if !bytes.Equal(got, v2) {
				t.Fatalf("versioned store header changed unexpectedly: got %q want %q", got, v2)
			}
			return
		}
		if err != nil {
			t.Fatalf("RestoreHeaderBackup: %v", err)
		}
		got, err := s.GetHeader(ctx)
		if err != nil {
			t.Fatalf("GetHeader after restore: %v", err)
		}
		if !bytes.Equal(got, v1) {
			t.Fatalf("restore did not recover prior header: got %q want %q", got, v1)
		}
	})
}
