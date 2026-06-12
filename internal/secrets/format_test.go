package secrets

import (
	"bytes"
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
	if _, err := For(store, "proj", mk, "m1", nil).Fold(ctx); err == nil {
		t.Fatal("fold must reject an object written by a newer notenv")
	}
}

// TestFoldRejectsOlderFormat: a segment in the previous payload format is
// refused with a pointer at the upgrade path, not read leniently.
func TestFoldRejectsOlderFormat(t *testing.T) {
	ctx := context.Background()
	mk := newMaster(t)
	store := memstore.New()
	raw := []byte(`{"v":1,"machine":"m1","seq":1,"lamport":1,"key":"K","value":"v"}`)
	if err := store.Put(ctx, "proj/seg-m1-legacy.age", sealedAt(t, mk, raw)); err != nil {
		t.Fatal(err)
	}
	if _, err := For(store, "proj", mk, "m1", nil).Fold(ctx); err == nil {
		t.Fatal("fold must reject an object in the previous payload format")
	}
}

// TestFoldRejectsRelocatedObject: a payload that names a different object key
// than it was fetched from was copied or renamed — including across
// namespaces — and must never pass as the name it sits under.
func TestFoldRejectsRelocatedObject(t *testing.T) {
	ctx := context.Background()
	mk := newMaster(t)
	store := memstore.New()
	raw, err := json.Marshal(segment{Version: formatVersion, Object: "other/seg-m1-aaaaaaaaaaaa.age", Machine: "m1", Seq: 1, Lamport: 1, Key: "K", Value: "v"})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(ctx, "proj/seg-m1-aaaaaaaaaaaa.age", sealedAt(t, mk, raw)); err != nil {
		t.Fatal(err)
	}
	if _, err := For(store, "proj", mk, "m1", nil).Fold(ctx); err == nil {
		t.Fatal("fold must reject an object that declares a different name")
	}
}

// TestMetadataOmittedWhenEmpty: a write with no description or timestamp
// marshals without the metadata keys at all. This is what makes the fields a
// no-bump change: a metadata-less 0.11 segment is byte-compatible with what
// 0.10 wrote, and older readers see nothing new to mishandle.
func TestMetadataOmittedWhenEmpty(t *testing.T) {
	raw, err := json.Marshal(segment{Version: formatVersion, Object: "proj/seg-m1-aaaaaaaaaaaa.age", Machine: "m1", Seq: 1, Lamport: 1, Key: "K", Value: "v"})
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"desc", "ts"} {
		if bytes.Contains(raw, []byte(`"`+field+`"`)) {
			t.Fatalf("empty %s must be omitted from the segment payload: %s", field, raw)
		}
	}
	entryRaw, err := json.Marshal(entry{Value: "v", Lamport: 1, Machine: "m1", Seq: 1})
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"desc", "ts"} {
		if bytes.Contains(entryRaw, []byte(`"`+field+`"`)) {
			t.Fatalf("empty %s must be omitted from snapshot entries: %s", field, entryRaw)
		}
	}
}
