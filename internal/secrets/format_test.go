package secrets

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/DvGils/notenv/internal/backend/memstore"
	"github.com/DvGils/notenv/internal/crypto"
)

func sealedAt(t *testing.T, mk *crypto.MasterKey, raw []byte) []byte {
	t.Helper()
	sealed, err := mk.Encrypt(raw)
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

func newMaster(t *testing.T) *crypto.MasterKey {
	t.Helper()
	mk, err := crypto.GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	return mk
}

// TestFoldRejectsNewerFormat: an object stamped with a higher format version was
// written by a newer notenv and must be refused, not misread.
func TestFoldRejectsNewerFormat(t *testing.T) {
	ctx := context.Background()
	mk := newMaster(t)
	store := memstore.New()
	raw, err := json.Marshal(segment{Version: formatVersion + 1, Machine: "m1", Seq: 1, Lamport: 1, Key: "K", Value: "v"})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(ctx, "proj/seg-m1-future.age", sealedAt(t, mk, raw)); err != nil {
		t.Fatal(err)
	}
	if _, err := For(store, "proj", mk, "m1").Fold(ctx); err == nil {
		t.Fatal("fold must reject an object written by a newer notenv")
	}
}

// TestFoldRejectsVersionlessObject: a segment with no version field (a pre-0.4
// layout) is refused with a pointer at the upgrade path, not guessed at. The
// lenient read it used to get was migration logic with no remaining users.
func TestFoldRejectsVersionlessObject(t *testing.T) {
	ctx := context.Background()
	mk := newMaster(t)
	store := memstore.New()
	raw := []byte(`{"machine":"m1","seq":1,"lamport":1,"key":"K","value":"v"}`)
	if err := store.Put(ctx, "proj/seg-m1-legacy.age", sealedAt(t, mk, raw)); err != nil {
		t.Fatal(err)
	}
	if _, err := For(store, "proj", mk, "m1").Fold(ctx); err == nil {
		t.Fatal("fold must reject a versionless (pre-0.4) object")
	}
}
