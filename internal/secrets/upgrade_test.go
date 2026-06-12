package secrets

import (
	"context"
	"testing"

	"github.com/DvGils/notenv/internal/backend/memstore"
	"github.com/DvGils/notenv/internal/crypto"
)

// seedOldVault stores version-1 payloads (no self-name) the way a pre-0.8
// notenv would have written them.
func seedOldVault(t *testing.T, store *memstore.Store, mk *crypto.MasterKey) {
	t.Helper()
	ctx := context.Background()
	objects := map[string]string{
		"proj/seg-m1-aaaaaaaaaaaa.age":  `{"v":1,"machine":"m1","seq":1,"lamport":1,"key":"A","value":"1"}`,
		"proj/seg-m1-bbbbbbbbbbbb.age":  `{"v":1,"machine":"m1","seq":2,"lamport":2,"key":"B","value":"2"}`,
		"other/snap-cccccccccccc.age":   `{"v":1,"lamport":3,"entries":{"C":{"value":"3","lamport":3,"machine":"m2","seq":1}}}`,
		"proj/.notenv-probe-not-an-age": `ignored`,
	}
	for key, plain := range objects {
		sealed, err := mk.Encrypt([]byte(plain))
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Put(ctx, key, sealed); err != nil {
			t.Fatal(err)
		}
	}
}

func TestUpgradeObjects(t *testing.T) {
	ctx := context.Background()
	mk := newMaster(t)
	store := memstore.New()
	seedOldVault(t, store, mk)

	entries, err := UpgradeObjects(ctx, store, mk)
	if err != nil {
		t.Fatalf("UpgradeObjects: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("want 3 recorded payload objects, got %v", entries)
	}

	// Every namespace folds cleanly under the returned manifest, with the
	// values intact and nothing left adoptable or stray.
	proj, err := For(store, "proj", mk, "m1", entries).Fold(ctx)
	if err != nil {
		t.Fatalf("fold proj after upgrade: %v", err)
	}
	if proj.Secrets["A"] != "1" || proj.Secrets["B"] != "2" {
		t.Fatalf("proj values lost in upgrade: %v", proj.Secrets)
	}
	if len(proj.Adoptable) != 0 || len(proj.Strays) != 0 {
		t.Fatalf("upgrade must record everything: adoptable=%v strays=%v", proj.Adoptable, proj.Strays)
	}
	other, err := For(store, "other", mk, "m1", entries).Fold(ctx)
	if err != nil {
		t.Fatalf("fold other after upgrade: %v", err)
	}
	if other.Secrets["C"] != "3" {
		t.Fatalf("other values lost in upgrade: %v", other.Secrets)
	}

	// Idempotent: a re-run after a partial failure changes nothing.
	again, err := UpgradeObjects(ctx, store, mk)
	if err != nil {
		t.Fatalf("re-run UpgradeObjects: %v", err)
	}
	for key, e := range entries {
		if again[key] != e {
			t.Fatalf("re-run changed entry for %s: %+v != %+v", key, again[key], e)
		}
	}
}

func TestUpgradeObjectsRefusesNewerFormat(t *testing.T) {
	ctx := context.Background()
	mk := newMaster(t)
	store := memstore.New()
	sealed, err := mk.Encrypt([]byte(`{"v":99,"machine":"m1","seq":1,"lamport":1,"key":"A","value":"1"}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(ctx, "proj/seg-m1-aaaaaaaaaaaa.age", sealed); err != nil {
		t.Fatal(err)
	}
	if _, err := UpgradeObjects(ctx, store, mk); err == nil {
		t.Fatal("upgrade must refuse an object from a newer notenv")
	}
}
