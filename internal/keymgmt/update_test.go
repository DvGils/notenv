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

func TestUpdateManifestRecordsDelta(t *testing.T) {
	ctx := context.Background()
	store, mk := newRecordedVault(t)

	h, err := keymgmt.UpdateManifest(ctx, store, mk, crypto.ManifestDelta{
		Add: map[string]crypto.ManifestEntry{"proj/seg-m1-aa.age": {MAC: "ab"}},
	})
	if err != nil {
		t.Fatalf("UpdateManifest: %v", err)
	}
	if h.Manifest["proj/seg-m1-aa.age"].MAC != "ab" {
		t.Fatalf("returned header missing the entry: %v", h.Manifest)
	}
	stored := mustParse(t, store)
	if stored.Manifest["proj/seg-m1-aa.age"].MAC != "ab" {
		t.Fatalf("stored header missing the entry: %v", stored.Manifest)
	}
	if stored.Revision != h.Revision || stored.Revision < 2 {
		t.Fatalf("revision must advance with the write, got %d", stored.Revision)
	}
	if err := stored.Verify(mk); err != nil {
		t.Fatalf("stored header must verify: %v", err)
	}
}

// TestUpdateManifestEpochChange: when the header no longer wraps the caller's
// master (a rotation landed since unlock), nothing is written and the caller
// gets the sentinel that triggers its rollback.
func TestUpdateManifestEpochChange(t *testing.T) {
	ctx := context.Background()
	store, _ := newRecordedVault(t)
	other, err := crypto.GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}

	before := store.Header()
	_, err = keymgmt.UpdateManifest(ctx, store, other, crypto.ManifestDelta{
		Add: map[string]crypto.ManifestEntry{"proj/seg-m1-aa.age": {MAC: "ab"}},
	})
	if !errors.Is(err, keymgmt.ErrEpochChanged) {
		t.Fatalf("want ErrEpochChanged, got %v", err)
	}
	if string(store.Header()) != string(before) {
		t.Fatal("a refused update must not modify the header")
	}
}

// racingStore lands a competing manifest write in the window between another
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
		if _, err := keymgmt.UpdateManifest(ctx, s.Store, s.mk, crypto.ManifestDelta{
			Add: map[string]crypto.ManifestEntry{"proj/seg-m2-bb.age": {MAC: "cd"}},
		}); err != nil {
			s.t.Fatalf("competing write: %v", err)
		}
	}
	return s.Store.SwapHeader(ctx, base, updated)
}

// TestUpdateManifestRetriesLostSwap: a writer that loses the swap race re-reads
// the fresh header and re-applies its delta, so neither writer's entry is
// clobbered.
func TestUpdateManifestRetriesLostSwap(t *testing.T) {
	ctx := context.Background()
	store, mk := newRecordedVault(t)
	racing := &racingStore{Store: store, t: t, mk: mk}

	h, err := keymgmt.UpdateManifest(ctx, racing, mk, crypto.ManifestDelta{
		Add: map[string]crypto.ManifestEntry{"proj/seg-m1-aa.age": {MAC: "ab"}},
	})
	if err != nil {
		t.Fatalf("UpdateManifest losing one swap: %v", err)
	}
	if !racing.raced {
		t.Fatal("the competing write never ran")
	}
	if h.Manifest["proj/seg-m1-aa.age"].MAC != "ab" || h.Manifest["proj/seg-m2-bb.age"].MAC != "cd" {
		t.Fatalf("both writers' entries must survive, got %v", h.Manifest)
	}
}
