package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/DvGils/notenv/internal/backend/local"
	"github.com/DvGils/notenv/internal/config"
)

const testBlobKey = "api/data-0123456789abcdef.age"

func TestDangerousVaultPath(t *testing.T) {
	if _, bad := dangerousVaultPath(string(filepath.Separator)); !bad {
		t.Errorf("dangerousVaultPath(root) = not flagged, want flagged")
	}
	if home, err := os.UserHomeDir(); err == nil {
		if _, bad := dangerousVaultPath(home); !bad {
			t.Errorf("dangerousVaultPath(home) = not flagged, want flagged")
		}
		if _, bad := dangerousVaultPath(filepath.Join(home, "notenv-vault")); bad {
			t.Errorf("dangerousVaultPath(home/notenv-vault) = flagged, want allowed")
		}
	}
	if _, bad := dangerousVaultPath(""); bad {
		t.Errorf("dangerousVaultPath(\"\") = flagged, want allowed (a remote destination)")
	}
	if _, bad := dangerousVaultPath(t.TempDir()); bad {
		t.Errorf("dangerousVaultPath(tempdir) = flagged, want allowed")
	}
}

func TestRefuseForeignDestination(t *testing.T) {
	ctx := context.Background()

	empty := &local.Storage{Path: t.TempDir()}
	if err := refuseForeignDestination(ctx, empty); err != nil {
		t.Errorf("empty destination refused: %v", err)
	}

	blobOnly := &local.Storage{Path: t.TempDir()}
	if err := blobOnly.Put(ctx, testBlobKey, []byte("ciphertext")); err != nil {
		t.Fatal(err)
	}
	if err := refuseForeignDestination(ctx, blobOnly); err != nil {
		t.Errorf("blob-only (interrupted-copy) destination refused: %v", err)
	}

	foreign := &local.Storage{Path: t.TempDir()}
	if err := os.WriteFile(filepath.Join(foreign.Path, "notes.txt"), []byte("mine"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := refuseForeignDestination(ctx, foreign); err == nil {
		t.Error("destination holding a foreign file was not refused")
	}
}

// TestCopyObjectsNeverDeletesForeignFiles is the core regression for the
// vault-copy footgun: the reconcile pass must remove a stale namespace blob but
// must never delete a file notenv did not write, even when the source has no
// objects at all (the worst case, where every destination key looks "stale").
func TestCopyObjectsNeverDeletesForeignFiles(t *testing.T) {
	ctx := context.Background()
	src := &local.Storage{Path: t.TempDir()}
	dst := &local.Storage{Path: t.TempDir()}

	foreign := filepath.Join(dst.Path, "notes.txt")
	if err := os.WriteFile(foreign, []byte("do not delete me"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := dst.Put(ctx, testBlobKey, []byte("stale ciphertext")); err != nil {
		t.Fatal(err)
	}

	if err := copyObjects(ctx, src, dst); err != nil {
		t.Fatalf("copyObjects: %v", err)
	}

	if _, err := os.Stat(foreign); err != nil {
		t.Errorf("foreign file was deleted by the reconcile pass: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dst.Path, filepath.FromSlash(testBlobKey))); !os.IsNotExist(err) {
		t.Errorf("stale namespace blob survived the reconcile (err=%v); it should be gone", err)
	}
}

func TestDestroyVaultLocalRefusesForeignFiles(t *testing.T) {
	ctx := context.Background()

	dir := t.TempDir()
	store := &local.Storage{Path: dir}
	if err := store.Put(ctx, testBlobKey, []byte("ciphertext")); err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(dir, "important.txt")
	if err := os.WriteFile(foreign, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}

	eff := config.Effective{Path: dir}
	if err := destroyVault(ctx, eff, store); err == nil {
		t.Error("destroyVault removed a directory holding a foreign file; it must refuse")
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Errorf("foreign file was deleted by a refused destroyVault: %v", err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Errorf("vault directory was removed despite the refusal: %v", err)
	}
}
