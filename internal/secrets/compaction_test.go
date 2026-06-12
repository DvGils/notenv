package secrets_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/DvGils/notenv/internal/crypto"
)

// TestCompactInterruptedKeepsData simulates a crash after the snapshot is
// recorded but before the folded segments are removed. No write is lost, the
// leftovers are skipped (folded entries), and a re-run finishes the deletion.
func TestCompactInterruptedKeepsData(t *testing.T) {
	v := newVault(t)
	a := newFixture(t, v, "m1")
	s := a.set(a.fold(), "A", "1")
	a.set(s, "B", "2")

	v.store.FailDeleteAfter(0, errors.New("blip")) // first delete after the snapshot is recorded fails
	if err := a.compact(); err == nil {
		t.Fatal("expected compaction to surface the delete failure")
	}
	if state := a.fold(); state.Secrets["A"] != "1" || state.Secrets["B"] != "2" {
		t.Fatalf("data lost after interrupted compaction: %v", state.Secrets)
	}
	if err := a.compact(); err != nil {
		t.Fatalf("re-run compaction: %v", err)
	}
	if snaps, segs := classify(t, v.store); snaps != 1 || segs != 0 {
		t.Fatalf("re-run should leave 1 snapshot and 0 segments, got %d/%d", snaps, segs)
	}
	if len(v.manifest) != 1 {
		t.Fatalf("re-run should prune every folded entry, got %v", v.manifest)
	}
}

// TestCompactRejectsCorruptSnapshot simulates a snapshot write that lands
// different bytes than intended. Compaction catches it on read-back, drops the
// bad snapshot, and leaves every segment in place.
func TestCompactRejectsCorruptSnapshot(t *testing.T) {
	v := newVault(t)
	a := newFixture(t, v, "m1")
	s := a.set(a.fold(), "A", "1")
	a.set(s, "B", "2")

	v.store.CorruptNextBlobPut(func([]byte) []byte { return []byte("mangled") })
	if err := a.compact(); err == nil {
		t.Fatal("expected compaction to reject a corrupted snapshot")
	}
	if snaps, segs := classify(t, v.store); snaps != 0 || segs != 2 {
		t.Fatalf("bad snapshot should be dropped and segments kept, got %d/%d", snaps, segs)
	}
	if state := a.fold(); state.Secrets["A"] != "1" || state.Secrets["B"] != "2" {
		t.Fatalf("data lost after a rejected compaction: %v", state.Secrets)
	}
	if err := a.compact(); err != nil {
		t.Fatalf("clean re-run compaction: %v", err)
	}
}

// TestCompactKeepsConcurrentWrite injects a recorded write from another machine
// right after the compaction has listed its objects. The new segment was never
// listed, so it is not deleted; its manifest entry was never folded, so it
// stays live and survives the fold.
func TestCompactKeepsConcurrentWrite(t *testing.T) {
	v := newVault(t)
	a := newFixture(t, v, "m1")
	s := a.set(a.fold(), "A", "1")
	a.set(s, "B", "2")

	b := newFixture(t, v, "m2")
	bBase := b.fold()
	v.store.AfterNextList(func() {
		b.set(bBase, "C", "3") // lands after the compaction's listing
	})

	if err := a.compact(); err != nil {
		t.Fatalf("compact: %v", err)
	}
	state := a.fold()
	if state.Secrets["A"] != "1" || state.Secrets["B"] != "2" || state.Secrets["C"] != "3" {
		t.Fatalf("concurrent write lost during compaction: %v", state.Secrets)
	}
}

// TestCompactWithStaleManifestFailsCleanly has another machine fully compact
// after this compaction read the manifest, so the recorded objects it tries to
// read are gone. The compaction fails with the manifest alarm, but a fresh
// fold shows no data was lost.
func TestCompactWithStaleManifestFailsCleanly(t *testing.T) {
	ctx := context.Background()
	v := newVault(t)
	a := newFixture(t, v, "m1")
	s := a.set(a.fold(), "A", "1")
	a.set(s, "B", "2")

	stale := a.ns() // captures the manifest before B's compaction rewrites the world
	b := newFixture(t, v, "m2")
	if err := b.compact(); err != nil {
		t.Fatalf("B's compaction: %v", err)
	}

	err := stale.Compact(ctx, v.record)
	if err == nil {
		t.Fatal("expected the stale compaction to fail on its missing recorded objects")
	}
	if !strings.Contains(err.Error(), "missing from storage") {
		t.Fatalf("stale compaction should fail with the manifest alarm, got: %v", err)
	}
	if state := a.fold(); state.Secrets["A"] != "1" || state.Secrets["B"] != "2" {
		t.Fatalf("data lost after a raced compaction: %v", state.Secrets)
	}
}

// TestEmptiedNamespaceKeepsClockAfterCompaction guards the snapshot-Lamport
// fix: a namespace emptied by a delete and then compacted must still report
// history (its clock survives even though no live entry carries it).
func TestEmptiedNamespaceKeepsClockAfterCompaction(t *testing.T) {
	v := newVault(t)
	f := newFixture(t, v, "m1")
	s := f.set(f.fold(), "K", "v")
	f.del(s, "K")
	if err := f.compact(); err != nil {
		t.Fatalf("compact: %v", err)
	}
	if !f.fold().HasHistory() {
		t.Fatal("emptied-then-compacted namespace must keep its clock (history)")
	}
}

// TestCompactionPreservesClockAcrossDelete is the cross-machine consequence of
// the same fix: after a delete bumps the clock and a compaction drops the
// tombstone, a later write must not regress its Lamport and silently lose to a
// stale concurrent write — it must surface as a reported conflict instead.
func TestCompactionPreservesClockAcrossDelete(t *testing.T) {
	v := newVault(t)
	a := newFixture(t, v, "m1")
	b := newFixture(t, v, "m2")

	s := a.set(a.fold(), "A", "1")
	s = a.set(s, "X", "9")
	a.del(s, "X")     // advances the clock past every surviving entry
	bBase := b.fold() // B captures the full clock before compaction

	if err := a.compact(); err != nil {
		t.Fatalf("compact: %v", err)
	}
	a.set(a.fold(), "A", "from-a") // from the compacted state
	b.set(bBase, "A", "from-b")    // concurrent, from B's pre-compaction view

	if conflicts := a.fold().Conflicts; len(conflicts) == 0 {
		t.Fatal("concurrent post-compaction writes must conflict, not silently resolve")
	}
}

// TestCompactAbortsWhenCommitFails covers the commit hook (the manifest swap,
// which is also the master-epoch check): when it errors, the compaction
// removes its own snapshot and leaves the namespace exactly as it found it.
func TestCompactAbortsWhenCommitFails(t *testing.T) {
	ctx := context.Background()
	v := newVault(t)
	a := newFixture(t, v, "m1")
	s := a.set(a.fold(), "A", "1")
	a.set(s, "B", "2")

	commit := func(crypto.ManifestDelta) error { return errors.New("master changed under us") }
	if err := a.ns().Compact(ctx, commit); err == nil {
		t.Fatal("expected compaction to surface the failed commit")
	}
	if snaps, segs := classify(t, v.store); snaps != 0 || segs != 2 {
		t.Fatalf("aborted compaction must undo its snapshot and keep segments, got %d/%d", snaps, segs)
	}
	if state := a.fold(); state.Secrets["A"] != "1" || state.Secrets["B"] != "2" {
		t.Fatalf("data changed by an aborted compaction: %v", state.Secrets)
	}
}

// TestCompactAdoptsInFlightWrite covers adoption end-to-end: a segment whose
// manifest update never landed (its writer crashed mid-protocol) folds in with
// a warning, and a compaction makes it durable.
func TestCompactAdoptsInFlightWrite(t *testing.T) {
	ctx := context.Background()
	v := newVault(t)
	a := newFixture(t, v, "m1")
	s := a.set(a.fold(), "A", "1")

	// A crashed writer: the segment landed, the manifest update never ran.
	if _, _, _, err := a.ns().Append(ctx, s, a.seq+1, "B", "2", false); err != nil {
		t.Fatal(err)
	}

	state := a.fold()
	if state.Secrets["B"] != "2" {
		t.Fatalf("in-flight write must fold in, got %v", state.Secrets)
	}
	if len(state.Adoptable) != 1 {
		t.Fatalf("in-flight write must be reported adoptable, got %v", state.Adoptable)
	}

	if err := a.compact(); err != nil {
		t.Fatalf("compact: %v", err)
	}
	after := a.fold()
	if after.Secrets["A"] != "1" || after.Secrets["B"] != "2" {
		t.Fatalf("adopted write lost by compaction: %v", after.Secrets)
	}
	if len(after.Adoptable) != 0 {
		t.Fatalf("nothing should remain adoptable after compaction, got %v", after.Adoptable)
	}
}

// TestCompactRemovesStraySnapshot covers the crashed-compactor artifact: a
// snapshot no compaction ever recorded is ignored by folds (with a report) and
// removed by the next compaction.
func TestCompactRemovesStraySnapshot(t *testing.T) {
	ctx := context.Background()
	v := newVault(t)
	a := newFixture(t, v, "m1")
	s := a.set(a.fold(), "A", "1")
	a.set(s, "B", "2")

	// A compactor that crashes between writing its snapshot and recording it:
	// the snapshot lands, the commit never runs.
	if err := a.ns().Compact(ctx, func(crypto.ManifestDelta) error { return errors.New("crashed") }); err == nil {
		t.Fatal("expected the aborted compaction to error")
	}
	// Compact's own undo removes the snapshot; re-create the crash artifact by
	// failing the undo delete too.
	v.store.FailDeleteAfter(0, errors.New("crashed harder"))
	_ = a.ns().Compact(ctx, func(crypto.ManifestDelta) error { return errors.New("crashed") })

	state := a.fold()
	if len(state.Strays) != 1 {
		t.Fatalf("want one stray snapshot reported, got %v", state.Strays)
	}
	if state.Secrets["A"] != "1" || state.Secrets["B"] != "2" {
		t.Fatalf("stray snapshot must not affect values: %v", state.Secrets)
	}

	if err := a.compact(); err != nil {
		t.Fatalf("compact: %v", err)
	}
	if snaps, segs := classify(t, v.store); snaps != 1 || segs != 0 {
		t.Fatalf("compaction should remove the stray, got %d snapshots / %d segments", snaps, segs)
	}
	if len(a.fold().Strays) != 0 {
		t.Fatal("no stray should remain after compaction")
	}
}

// TestAppendRejectsCorruptWrite covers the read-back in Append: a botched
// segment write is removed and surfaced, never left as a poison pill.
func TestAppendRejectsCorruptWrite(t *testing.T) {
	ctx := context.Background()
	v := newVault(t)
	f := newFixture(t, v, "m1")

	v.store.CorruptNextBlobPut(func([]byte) []byte { return []byte("mangled") })
	if _, _, _, err := f.ns().Append(ctx, f.fold(), 1, "K", "v", false); err == nil {
		t.Fatal("append must reject a write that reads back corrupted")
	}
	if f.fold().HasHistory() {
		t.Fatal("a rejected write must leave no segment behind")
	}
}

// TestFoldRejectsCorruptSegment makes sure a segment that is not valid
// ciphertext surfaces an error rather than being silently skipped.
func TestFoldRejectsCorruptSegment(t *testing.T) {
	ctx := context.Background()
	v := newVault(t)
	a := newFixture(t, v, "m1")
	a.set(a.fold(), "A", "1")

	if err := v.store.Put(ctx, "proj/seg-bad-deadbeef.age", []byte("not age ciphertext")); err != nil {
		t.Fatal(err)
	}
	if _, err := a.ns().Fold(ctx); err == nil {
		t.Fatal("fold must error on a corrupt segment, not skip it")
	}
}
