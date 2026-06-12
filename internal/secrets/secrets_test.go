package secrets_test

import (
	"context"
	"maps"
	"strings"
	"testing"

	"github.com/DvGils/notenv/internal/backend/memstore"
	"github.com/DvGils/notenv/internal/crypto"
	"github.com/DvGils/notenv/internal/secrets"
)

// testVault is the shared vault state fixtures write through: the store, the
// master, and the manifest every machine's writes are recorded in — applied
// the way the command layer would (append → record one delta, compact → the
// commit callback).
type testVault struct {
	store    *memstore.Store
	mk       *crypto.MasterKey
	manifest map[string]crypto.ManifestEntry
}

func newVault(t *testing.T) *testVault {
	t.Helper()
	mk, err := crypto.GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	return &testVault{store: memstore.New(), mk: mk, manifest: map[string]crypto.ManifestEntry{}}
}

// record applies a manifest delta, standing in for the header swap. Like the
// real swap — which parses a fresh header per attempt — it never mutates the
// map a previously built namespace is holding.
func (v *testVault) record(d crypto.ManifestDelta) error {
	h := &crypto.Header{Manifest: maps.Clone(v.manifest)}
	h.ApplyManifest(d)
	v.manifest = h.Manifest
	return nil
}

// fixture drives one machine's writes against a shared vault.
type fixture struct {
	t       *testing.T
	v       *testVault
	machine string
	seq     int
}

func newFixture(t *testing.T, v *testVault, machine string) *fixture {
	return &fixture{t: t, v: v, machine: machine}
}

func (f *fixture) ns() *secrets.Namespace {
	return secrets.For(f.v.store, "proj", f.v.mk, f.machine, f.v.manifest)
}

func (f *fixture) fold() *secrets.State {
	f.t.Helper()
	state, err := f.ns().Fold(context.Background())
	if err != nil {
		f.t.Fatalf("fold: %v", err)
	}
	return state
}

// set appends a write based on the given prior state (controlling the Lamport
// clock) and records it, returning the resulting state.
func (f *fixture) set(prev *secrets.State, key, value string) *secrets.State {
	return f.append(prev, key, value, false)
}

func (f *fixture) del(prev *secrets.State, key string) *secrets.State {
	return f.append(prev, key, "", true)
}

func (f *fixture) append(prev *secrets.State, key, value string, deleted bool) *secrets.State {
	f.t.Helper()
	f.seq++
	next, objKey, entry, err := f.ns().Append(context.Background(), prev, f.seq, secrets.Write{Key: key, Value: value, Deleted: deleted})
	if err != nil {
		f.t.Fatalf("append: %v", err)
	}
	delta := crypto.ManifestDelta{Add: map[string]crypto.ManifestEntry{objKey: entry}, Prune: prev.Prunable}
	if err := f.v.record(delta); err != nil {
		f.t.Fatalf("record: %v", err)
	}
	return next
}

func (f *fixture) compact() error {
	return f.ns().Compact(context.Background(), f.v.record)
}

func TestFoldEmptyNamespace(t *testing.T) {
	v := newVault(t)
	state := newFixture(t, v, "m1").fold()
	if state.HasHistory() {
		t.Fatal("empty namespace should report no history")
	}
	if len(state.Secrets) != 0 {
		t.Fatalf("empty namespace should have no secrets, got %v", state.Secrets)
	}
}

func TestSetThenFold(t *testing.T) {
	v := newVault(t)
	f := newFixture(t, v, "m1")
	f.set(f.fold(), "API_KEY", "abc")

	state := f.fold()
	if !state.HasHistory() {
		t.Fatal("namespace with a write should report history")
	}
	if state.Secrets["API_KEY"] != "abc" {
		t.Fatalf("API_KEY = %q, want abc", state.Secrets["API_KEY"])
	}
	if len(state.Conflicts) != 0 {
		t.Fatalf("unexpected conflicts: %v", state.Conflicts)
	}
	if len(state.Adoptable) != 0 {
		t.Fatalf("a recorded write must not be adoptable: %v", state.Adoptable)
	}
}

func TestLastWriteWinsSameMachine(t *testing.T) {
	v := newVault(t)
	f := newFixture(t, v, "m1")
	s := f.set(f.fold(), "K", "v1")
	f.set(s, "K", "v2") // higher Lamport, no conflict

	if got := f.fold().Secrets["K"]; got != "v2" {
		t.Fatalf("K = %q, want v2 (last write wins)", got)
	}
	if c := f.fold().Conflicts; len(c) != 0 {
		t.Fatalf("sequential writes are not a conflict: %v", c)
	}
}

func TestConcurrentDifferentKeysBothSurvive(t *testing.T) {
	v := newVault(t)
	a := newFixture(t, v, "m1")
	b := newFixture(t, v, "m2")

	// Both fold the empty namespace, then write — neither saw the other.
	base := a.fold()
	a.set(base, "API_KEY", "from-a")
	b.set(b.fold(), "DB_URL", "from-b") // b folds before seeing a's write in this construction

	state := a.fold()
	if state.Secrets["API_KEY"] != "from-a" || state.Secrets["DB_URL"] != "from-b" {
		t.Fatalf("both concurrent keys should survive, got %v", state.Secrets)
	}
	if len(state.Conflicts) != 0 {
		t.Fatalf("different keys are not a conflict: %v", state.Conflicts)
	}
}

func TestConcurrentSameKeyConflict(t *testing.T) {
	v := newVault(t)
	a := newFixture(t, v, "m1")
	b := newFixture(t, v, "m2")

	// Both base on the empty fold, so both write at Lamport 1: a true conflict.
	base := a.fold()
	a.set(base, "K", "from-a")
	b.set(base, "K", "from-b")

	state := a.fold()
	if got := state.Secrets["K"]; got != "from-b" {
		t.Fatalf("K = %q, want from-b (higher machine id wins deterministically)", got)
	}
	if len(state.Conflicts) != 1 {
		t.Fatalf("want one conflict, got %v", state.Conflicts)
	}
	c := state.Conflicts[0]
	if c.Key != "K" || c.Winner != "m2" || len(c.Shadowed) != 1 || c.Shadowed[0] != "m1" {
		t.Fatalf("conflict = %+v, want K winner=m2 shadowed=[m1]", c)
	}
}

func TestConflictResolutionIsDeterministic(t *testing.T) {
	v := newVault(t)
	a := newFixture(t, v, "m1")
	b := newFixture(t, v, "m2")
	base := a.fold()
	a.set(base, "K", "from-a")
	b.set(base, "K", "from-b")

	// Folding from either machine yields the same winner.
	if a.fold().Secrets["K"] != b.fold().Secrets["K"] {
		t.Fatal("conflict winner must not depend on which machine folds")
	}
}

func TestDeleteTombstone(t *testing.T) {
	v := newVault(t)
	f := newFixture(t, v, "m1")
	s := f.set(f.fold(), "K", "v")
	f.del(s, "K")

	state := f.fold()
	if _, present := state.Secrets["K"]; present {
		t.Fatalf("deleted key should be absent, got %v", state.Secrets)
	}
	if !state.HasHistory() {
		t.Fatal("a namespace emptied by deletes still has history")
	}
}

func TestCompactCollapsesAndPreserves(t *testing.T) {
	v := newVault(t)
	f := newFixture(t, v, "m1")
	s := f.set(f.fold(), "A", "1")
	s = f.set(s, "B", "2")
	s = f.set(s, "A", "1b") // overwrite
	f.del(s, "B")           // tombstone

	if err := f.compact(); err != nil {
		t.Fatalf("compact: %v", err)
	}

	snaps, segs := classify(t, v.store)
	if snaps != 1 || segs != 0 {
		t.Fatalf("after compaction want 1 snapshot and 0 segments, got %d/%d", snaps, segs)
	}
	if len(v.manifest) != 1 {
		t.Fatalf("after compaction the manifest should record exactly the snapshot, got %v", v.manifest)
	}

	state := f.fold()
	if state.Secrets["A"] != "1b" {
		t.Fatalf("A = %q, want 1b after compaction", state.Secrets["A"])
	}
	if _, present := state.Secrets["B"]; present {
		t.Fatal("tombstoned B should stay gone after compaction")
	}
}

func TestWriteAfterCompactFoldsOnSnapshot(t *testing.T) {
	v := newVault(t)
	f := newFixture(t, v, "m1")
	f.set(f.fold(), "A", "1")
	if err := f.compact(); err != nil {
		t.Fatalf("compact: %v", err)
	}
	f.set(f.fold(), "C", "3") // append on top of the snapshot

	state := f.fold()
	if state.Secrets["A"] != "1" || state.Secrets["C"] != "3" {
		t.Fatalf("snapshot + later segment should both fold in, got %v", state.Secrets)
	}
}

func TestSegmentCountTracksUncompacted(t *testing.T) {
	v := newVault(t)
	f := newFixture(t, v, "m1")
	s := f.fold()
	for range 3 {
		s = f.set(s, "K", "v")
	}
	if got := f.fold().SegmentCount(); got != 3 {
		t.Fatalf("SegmentCount = %d, want 3 (drives auto-compaction)", got)
	}
	if err := f.compact(); err != nil {
		t.Fatalf("compact: %v", err)
	}
	if got := f.fold().SegmentCount(); got != 0 {
		t.Fatalf("SegmentCount after compaction = %d, want 0", got)
	}
}

// classify counts the snapshot and segment objects stored for the namespace.
func classify(t *testing.T, store *memstore.Store) (snaps, segs int) {
	t.Helper()
	keys, err := store.List(context.Background(), "proj/")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	for _, key := range keys {
		base := strings.TrimPrefix(key, "proj/")
		switch {
		case strings.HasPrefix(base, "snap-"):
			snaps++
		case strings.HasPrefix(base, "seg-"):
			segs++
		}
	}
	return snaps, segs
}
