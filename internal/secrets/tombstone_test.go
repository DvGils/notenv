package secrets_test

import (
	"testing"
)

// TestTombstoneSurvivesCompaction: the Monday-train interleaving. A write
// based on a stale fold lands after the key was deleted and the namespace
// compacted; the deletion is strictly newer by Lamport order and must keep
// winning, exactly as it would have had compaction never run.
func TestTombstoneSurvivesCompaction(t *testing.T) {
	v := newVault(t)
	a := newFixture(t, v, "m1")
	b := newFixture(t, v, "m2")

	s1 := a.set(a.fold(), "DB_URL", "monday-old") // lamport 1
	stale := a.fold()                             // what b saw before suspending
	s2 := a.set(s1, "OTHER", "x")                 // lamport 2
	a.del(s2, "DB_URL")                           // tombstone, lamport 3
	if err := a.compact(); err != nil {
		t.Fatalf("compact: %v", err)
	}

	// b's laptop wakes: its write is based on the stale fold, lamport 2 < 3.
	b.set(stale, "DB_URL", "train-cafe")

	state := a.fold()
	if got, present := state.Secrets["DB_URL"]; present {
		t.Fatalf("deleted key resurrected with %q; the tombstone (lamport 3) outranks the late write (lamport 2)", got)
	}
	if state.Secrets["OTHER"] != "x" {
		t.Fatalf("unrelated key lost: %v", state.Secrets)
	}
}

// TestTombstoneOutcomeIndependentOfCompaction: the same write history must
// resolve identically whether or not a compaction ran in the window; the tie
// case (equal Lamport, machine tie-break) is the sharpest probe.
func TestTombstoneOutcomeIndependentOfCompaction(t *testing.T) {
	run := func(compact bool) (map[string]string, int) {
		v := newVault(t)
		// Machine "z" deletes, machine "a" writes late: z > a, the deletion
		// wins the Lamport tie under the same rule segments use.
		z := newFixture(t, v, "z")
		a := newFixture(t, v, "a")

		s1 := z.set(z.fold(), "KEY", "v0") // lamport 1
		stale := z.fold()
		z.del(s1, "KEY") // tombstone, lamport 2, machine z
		if compact {
			if err := z.compact(); err != nil {
				t.Fatalf("compact: %v", err)
			}
		}
		a.set(stale, "KEY", "late") // lamport 2, machine a: loses the tie
		state := z.fold()
		return state.Secrets, len(state.Conflicts)
	}

	plain, plainConflicts := run(false)
	compacted, compactedConflicts := run(true)
	if _, p := plain["KEY"]; p {
		t.Fatalf("without compaction the deletion wins the tie, got %v", plain)
	}
	if _, p := compacted["KEY"]; p {
		t.Fatalf("with compaction the outcome flipped: %v", compacted)
	}
	if plainConflicts == 0 || compactedConflicts == 0 {
		t.Fatalf("the losing write must be reported as a conflict in both worlds (plain=%d compacted=%d)", plainConflicts, compactedConflicts)
	}
}

// TestTombstoneSupersededByLaterWrite: a genuinely newer write revives the
// key; tombstones shadow the past, not the future. Re-compaction then drops
// the superseded tombstone naturally (the live write is the winner).
func TestTombstoneSupersededByLaterWrite(t *testing.T) {
	v := newVault(t)
	a := newFixture(t, v, "m1")

	s1 := a.set(a.fold(), "KEY", "v1")
	s2 := a.del(s1, "KEY")
	if err := a.compact(); err != nil {
		t.Fatalf("compact: %v", err)
	}
	a.set(s2, "KEY", "v2") // lamport above the tombstone's
	if state := a.fold(); state.Secrets["KEY"] != "v2" {
		t.Fatalf("a newer write must revive the key: %v", state.Secrets)
	}
	if err := a.compact(); err != nil {
		t.Fatalf("re-compact: %v", err)
	}
	if state := a.fold(); state.Secrets["KEY"] != "v2" {
		t.Fatalf("re-compaction lost the revived key: %v", state.Secrets)
	}
}

// TestTombstoneSurvivesRecompaction: compacting twice keeps the receipt.
func TestTombstoneSurvivesRecompaction(t *testing.T) {
	v := newVault(t)
	a := newFixture(t, v, "m1")

	s1 := a.set(a.fold(), "KEY", "v1")
	stale := a.fold()
	s2 := a.set(s1, "PAD", "x")
	a.del(s2, "KEY") // lamport 3
	if err := a.compact(); err != nil {
		t.Fatalf("compact: %v", err)
	}
	if err := a.compact(); err != nil {
		t.Fatalf("second compact: %v", err)
	}

	b := newFixture(t, v, "m2")
	b.set(stale, "KEY", "late") // lamport 2 < 3
	if state := a.fold(); state.Secrets["KEY"] == "late" {
		t.Fatal("the tombstone must survive any number of compactions")
	}
}
