package keymgmt_test

import (
	"context"
	"errors"
	"testing"

	"github.com/DvGils/notenv/internal/backend/memstore"
	"github.com/DvGils/notenv/internal/crypto"
	"github.com/DvGils/notenv/internal/keymgmt"
)

func newRecordedVault(t *testing.T) (*memstore.Store, *crypto.MasterKey) {
	t.Helper()
	store := memstore.New()
	header, mk, err := crypto.NewHeader("pass", "owner")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := header.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutHeader(context.Background(), raw); err != nil {
		t.Fatal(err)
	}
	return store, mk
}

func TestUpdateHeaderRecordsMutation(t *testing.T) {
	ctx := context.Background()
	store, mk := newRecordedVault(t)

	h, err := keymgmt.UpdateHeader(ctx, store, mk, func(h *crypto.Header) error {
		h.SetNamespace("proj", crypto.ManifestEntry{Blob: "proj/data-aa.age", MAC: "ab"})
		return nil
	})
	if err != nil {
		t.Fatalf("UpdateHeader: %v", err)
	}
	if h.Manifest["proj"].MAC != "ab" {
		t.Fatalf("returned header missing the entry: %v", h.Manifest)
	}
	stored := mustParse(t, store)
	if stored.Manifest["proj"].MAC != "ab" {
		t.Fatalf("stored header missing the entry: %v", stored.Manifest)
	}
	if stored.Revision != h.Revision || stored.Revision < 2 {
		t.Fatalf("revision must advance with the write, got %d", stored.Revision)
	}
	if err := stored.Verify(mk); err != nil {
		t.Fatalf("stored header must verify: %v", err)
	}
}

// TestUpdateHeaderEpochChange: when the header no longer wraps the caller's
// master (a rotation landed since unlock), nothing is written and the caller
// gets the sentinel that triggers its rollback.
func TestUpdateHeaderEpochChange(t *testing.T) {
	ctx := context.Background()
	store, _ := newRecordedVault(t)
	other, err := crypto.GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}

	before := store.Header()
	_, err = keymgmt.UpdateHeader(ctx, store, other, func(h *crypto.Header) error {
		h.SetNamespace("proj", crypto.ManifestEntry{Blob: "proj/data-aa.age", MAC: "ab"})
		return nil
	})
	if !errors.Is(err, keymgmt.ErrEpochChanged) {
		t.Fatalf("want ErrEpochChanged, got %v", err)
	}
	if string(store.Header()) != string(before) {
		t.Fatal("a refused update must not modify the header")
	}
}

// racingStore lands a competing header write in the window between another
// writer's header read and its swap, once — the swap loses and must retry.
type racingStore struct {
	*memstore.Store
	t     *testing.T
	mk    *crypto.MasterKey
	raced bool
}

func (s *racingStore) SwapHeader(ctx context.Context, base, updated []byte) error {
	if !s.raced {
		s.raced = true
		if _, err := keymgmt.UpdateHeader(ctx, s.Store, s.mk, func(h *crypto.Header) error {
			h.SetNamespace("other", crypto.ManifestEntry{Blob: "other/data-bb.age", MAC: "cd"})
			return nil
		}); err != nil {
			s.t.Fatalf("competing write: %v", err)
		}
	}
	return s.Store.SwapHeader(ctx, base, updated)
}

// TestUpdateHeaderRetriesLostSwap: a writer that loses the swap race re-reads
// the fresh header and re-runs its mutation, so neither writer's entry is
// clobbered.
func TestUpdateHeaderRetriesLostSwap(t *testing.T) {
	ctx := context.Background()
	store, mk := newRecordedVault(t)
	racing := &racingStore{Store: store, t: t, mk: mk}

	h, err := keymgmt.UpdateHeader(ctx, racing, mk, func(h *crypto.Header) error {
		h.SetNamespace("proj", crypto.ManifestEntry{Blob: "proj/data-aa.age", MAC: "ab"})
		return nil
	})
	if err != nil {
		t.Fatalf("UpdateHeader losing one swap: %v", err)
	}
	if !racing.raced {
		t.Fatal("the competing write never ran")
	}
	if h.Manifest["proj"].MAC != "ab" || h.Manifest["other"].MAC != "cd" {
		t.Fatalf("both writers' entries must survive, got %v", h.Manifest)
	}
}
