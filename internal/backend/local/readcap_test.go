package local

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/DvGils/notenv/internal/backend"
)

func TestReadFileCapped(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "obj")
	if err := os.WriteFile(path, []byte("0123456789"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := readFileCapped(path, 10); err != nil {
		t.Fatalf("a 10-byte file under a 10-byte cap must read: %v", err)
	}
	if _, err := readFileCapped(path, 9); !errors.Is(err, backend.ErrObjectTooLarge) {
		t.Fatalf("a 10-byte file over a 9-byte cap must be ErrObjectTooLarge, got %v", err)
	}
	if _, err := readFileCapped(filepath.Join(dir, "absent"), 10); !errors.Is(err, backend.ErrNotFound) {
		t.Fatalf("a missing file must be ErrNotFound, got %v", err)
	}
}

func TestListCapped(t *testing.T) {
	ctx := context.Background()
	s := &Storage{Path: t.TempDir()}
	for _, k := range []string{"ns/a.age", "ns/b.age", "ns/c.age"} {
		if err := s.Put(ctx, k, []byte("x")); err != nil {
			t.Fatal(err)
		}
	}

	// Under the (default, generous) cap: every object is listed.
	got, err := s.List(ctx, "")
	if err != nil || len(got) != 3 {
		t.Fatalf("uncapped list: got %v, err %v; want 3 keys", got, err)
	}

	// A cap below the total key-name bytes aborts the walk and fails closed.
	prev := maxListBytes
	maxListBytes = 5 // one "ns/a.age" key alone (8 bytes) exceeds it
	t.Cleanup(func() { maxListBytes = prev })
	if _, err := s.List(ctx, ""); !errors.Is(err, backend.ErrObjectTooLarge) {
		t.Fatalf("an over-cap listing must be ErrObjectTooLarge, got %v", err)
	}
}
