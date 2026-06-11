package secrets_test

import (
	"context"
	"strings"
	"testing"

	"github.com/DvGils/notenv/internal/backend/memstore"
	"github.com/DvGils/notenv/internal/crypto"
	"github.com/DvGils/notenv/internal/secrets"
)

// fixture wires a namespace over a shared store and master for one machine.
type fixture struct {
	t       *testing.T
	store   *memstore.Store
	mk      *crypto.MasterKey
	machine string
	seq     int
}

func newFixture(t *testing.T, store *memstore.Store, mk *crypto.MasterKey, machine string) *fixture {
	return &fixture{t: t, store: store, mk: mk, machine: machine}
}

func (f *fixture) ns() *secrets.Namespace {
	return secrets.For(f.store, "proj", f.mk, f.machine)
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
// clock), returning the resulting state.
func (f *fixture) set(prev *secrets.State, key, value string) *secrets.State {
	f.t.Helper()
	f.seq++
	next, _, err := f.ns().Append(context.Background(), prev, f.seq, key, value, false)
	if err != nil {
		f.t.Fatalf("append: %v", err)
	}
	return next
}

func (f *fixture) del(prev *secrets.State, key string) *secrets.State {
	f.t.Helper()
	f.seq++
	next, _, err := f.ns().Append(context.Background(), prev, f.seq, key, "", true)
	if err != nil {
		f.t.Fatalf("append delete: %v", err)
	}
	return next
}

func newStoreMaster(t *testing.T) (*memstore.Store, *crypto.MasterKey) {
	mk, err := crypto.GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	return memstore.New(), mk
}

func TestFoldEmptyNamespace(t *testing.T) {
	store, mk := newStoreMaster(t)
	state := newFixture(t, store, mk, "m1").fold()
	if state.HasHistory() {
		t.Fatal("empty namespace should report no history")
	}
	if len(state.Secrets) != 0 {
		t.Fatalf("empty namespace should have no secrets, got %v", state.Secrets)
	}
}

func TestSetThenFold(t *testing.T) {
	store, mk := newStoreMaster(t)
	f := newFixture(t, store, mk, "m1")
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
}

func TestLastWriteWinsSameMachine(t *testing.T) {
	store, mk := newStoreMaster(t)
	f := newFixture(t, store, mk, "m1")
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
	store, mk := newStoreMaster(t)
	a := newFixture(t, store, mk, "m1")
	b := newFixture(t, store, mk, "m2")

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
	store, mk := newStoreMaster(t)
	a := newFixture(t, store, mk, "m1")
	b := newFixture(t, store, mk, "m2")

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
	store, mk := newStoreMaster(t)
	a := newFixture(t, store, mk, "m1")
	b := newFixture(t, store, mk, "m2")
	base := a.fold()
	a.set(base, "K", "from-a")
	b.set(base, "K", "from-b")

	// Folding from either machine yields the same winner.
	if a.fold().Secrets["K"] != b.fold().Secrets["K"] {
		t.Fatal("conflict winner must not depend on which machine folds")
	}
}

func TestDeleteTombstone(t *testing.T) {
	store, mk := newStoreMaster(t)
	f := newFixture(t, store, mk, "m1")
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
	ctx := context.Background()
	store, mk := newStoreMaster(t)
	f := newFixture(t, store, mk, "m1")
	s := f.set(f.fold(), "A", "1")
	s = f.set(s, "B", "2")
	s = f.set(s, "A", "1b") // overwrite
	f.del(s, "B")           // tombstone

	if err := f.ns().Compact(ctx, nil); err != nil {
		t.Fatalf("compact: %v", err)
	}

	snaps, segs := classify(t, store)
	if snaps != 1 || segs != 0 {
		t.Fatalf("after compaction want 1 snapshot and 0 segments, got %d/%d", snaps, segs)
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
	ctx := context.Background()
	store, mk := newStoreMaster(t)
	f := newFixture(t, store, mk, "m1")
	f.set(f.fold(), "A", "1")
	if err := f.ns().Compact(ctx, nil); err != nil {
		t.Fatalf("compact: %v", err)
	}
	f.set(f.fold(), "C", "3") // append on top of the snapshot

	state := f.fold()
	if state.Secrets["A"] != "1" || state.Secrets["C"] != "3" {
		t.Fatalf("snapshot + later segment should both fold in, got %v", state.Secrets)
	}
}

func TestSegmentCountTracksUncompacted(t *testing.T) {
	store, mk := newStoreMaster(t)
	f := newFixture(t, store, mk, "m1")
	s := f.fold()
	for range 3 {
		s = f.set(s, "K", "v")
	}
	if got := f.fold().SegmentCount(); got != 3 {
		t.Fatalf("SegmentCount = %d, want 3 (drives auto-compaction)", got)
	}
	if err := f.ns().Compact(context.Background(), nil); err != nil {
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
