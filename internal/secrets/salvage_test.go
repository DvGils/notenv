package secrets

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/DvGils/notenv/internal/backend/memstore"
	"github.com/DvGils/notenv/internal/crypto"
)

// recorder appends writes and records them in a manifest, the way the command
// layer does, returning each segment's object key.
func recorder(t *testing.T, ctx context.Context, ns func() *Namespace, manifest *simManifest, view **State) func(Write, int) string {
	t.Helper()
	return func(w Write, seq int) string {
		updated, objKey, entry, err := ns().Append(ctx, *view, seq, w)
		if err != nil {
			t.Fatalf("append %q: %v", w.Key, err)
		}
		if err := manifest.apply(crypto.ManifestDelta{Add: map[string]crypto.ManifestEntry{objKey: entry}}); err != nil {
			t.Fatal(err)
		}
		*view = updated
		return objKey
	}
}

// TestFoldSalvageSkipsCorruptSegment: a strict fold fails closed on one corrupt
// segment, but FoldSalvage drops it, resolves every healthy key, and reports the
// dropped object. The corrupt segment was a key's only copy, so that key is
// simply absent under salvage.
func TestFoldSalvageSkipsCorruptSegment(t *testing.T) {
	ctx := context.Background()
	mk := newMaster(t)
	store := memstore.New()
	manifest := &simManifest{entries: map[string]crypto.ManifestEntry{}}
	ns := func() *Namespace { return For(store, "proj", mk, "m1", manifest.entries) }

	view := &State{Secrets: map[string]string{}}
	record := recorder(t, ctx, ns, manifest, &view)
	record(Write{Key: "A", Value: "alpha"}, 1)
	bad := record(Write{Key: "B", Value: "beta"}, 2)

	// Authenticated encryption turns any byte flip into a decryption failure, so
	// overwriting the object with junk is a faithful stand-in for bit-rot.
	if err := store.Put(ctx, bad, []byte("not a valid age message")); err != nil {
		t.Fatal(err)
	}

	if _, err := ns().Fold(ctx); err == nil {
		t.Fatal("a strict fold must fail closed on the corrupt segment")
	}
	state, err := ns().FoldSalvage(ctx)
	if err != nil {
		t.Fatalf("salvage must not fail: %v", err)
	}
	if state.Secrets["A"] != "alpha" {
		t.Fatalf("salvage must still resolve the healthy key: A=%q", state.Secrets["A"])
	}
	if _, ok := state.Secrets["B"]; ok {
		t.Fatal("the corrupt segment's key must be absent: its only copy was dropped")
	}
	if len(state.Corrupt) != 1 || state.Corrupt[0].Key != bad {
		t.Fatalf("salvage must report exactly the dropped object, got %+v", state.Corrupt)
	}
}

// TestFoldSalvageRevertsMissingToSnapshot: when the lost object is a fresh write
// layered over a compacted snapshot, salvage does not erase the key, it reverts
// it to the older snapshot value. This is the semantics the warning promises
// (absent or stale), and exactly why salvage is opt-in.
func TestFoldSalvageRevertsMissingToSnapshot(t *testing.T) {
	ctx := context.Background()
	mk := newMaster(t)
	store := memstore.New()
	manifest := &simManifest{entries: map[string]crypto.ManifestEntry{}}
	ns := func() *Namespace { return For(store, "proj", mk, "m1", manifest.entries) }

	view := &State{Secrets: map[string]string{}}
	record := recorder(t, ctx, ns, manifest, &view)
	record(Write{Key: "A", Value: "alpha"}, 1)
	record(Write{Key: "B", Value: "beta"}, 2)
	if err := ns().Compact(ctx, manifest.apply); err != nil {
		t.Fatalf("compact: %v", err)
	}

	folded, err := ns().Fold(ctx)
	if err != nil {
		t.Fatalf("fold after compaction: %v", err)
	}
	view = folded
	newB := record(Write{Key: "B", Value: "beta2"}, folded.HighWater("m1")+1)

	// The fresh write is lost (a non-versioned remote drops it, a flaky NAS eats
	// the upload). A strict read fails closed naming it.
	if err := store.Delete(ctx, newB); err != nil {
		t.Fatal(err)
	}
	if _, err := ns().Fold(ctx); err == nil {
		t.Fatal("a strict fold must fail closed on the recorded-but-missing object")
	}

	state, err := ns().FoldSalvage(ctx)
	if err != nil {
		t.Fatalf("salvage must not fail: %v", err)
	}
	if state.Secrets["A"] != "alpha" {
		t.Fatalf("the untouched key must survive: A=%q", state.Secrets["A"])
	}
	if state.Secrets["B"] != "beta" {
		t.Fatalf("the lost write must revert B to its snapshot value, got %q", state.Secrets["B"])
	}
	if len(state.Corrupt) != 1 || state.Corrupt[0].Key != newB {
		t.Fatalf("salvage must report the missing object, got %+v", state.Corrupt)
	}
	if !strings.Contains(state.Corrupt[0].Reason, "missing") {
		t.Fatalf("the reason should name the missing object, got %q", state.Corrupt[0].Reason)
	}
}

// TestFoldSalvageStillFailsOnFormatSkew: salvage tolerates an untrustable object,
// not a newer storage format. A recorded object whose MAC is valid but whose
// format version is from a newer notenv means "upgrade notenv", and skipping it
// would silently drop data the running build cannot read. It must still fail.
func TestFoldSalvageStillFailsOnFormatSkew(t *testing.T) {
	ctx := context.Background()
	mk := newMaster(t)
	store := memstore.New()
	objKey := "proj/seg-m1-future.age"
	raw, err := json.Marshal(segment{Version: formatVersion + 1, Object: objKey, Machine: "m1", Seq: 1, Lamport: 1, Key: "K", Value: "v"})
	if err != nil {
		t.Fatal(err)
	}
	mac, err := mk.ObjectMAC(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(ctx, objKey, sealedAt(t, mk, raw)); err != nil {
		t.Fatal(err)
	}
	ns := For(store, "proj", mk, "m1", map[string]crypto.ManifestEntry{objKey: {MAC: mac}})

	if _, err := ns.Fold(ctx); err == nil {
		t.Fatal("a strict fold must reject a newer storage format")
	}
	if _, err := ns.FoldSalvage(ctx); err == nil {
		t.Fatal("salvage must NOT mask a format-version skew: the remedy is to upgrade notenv, not to drop the object")
	}
}
