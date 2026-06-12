package secrets_test

import (
	"context"
	"testing"

	"github.com/DvGils/notenv/internal/crypto"
	"github.com/DvGils/notenv/internal/secrets"
)

// write appends an arbitrary Write (description, timestamp, deletion) based on
// prev and records it, the metadata-aware sibling of the fixture's set/del.
func (f *fixture) write(prev *secrets.State, w secrets.Write) *secrets.State {
	f.t.Helper()
	f.seq++
	next, objKey, entry, err := f.ns().Append(context.Background(), prev, f.seq, w)
	if err != nil {
		f.t.Fatalf("append: %v", err)
	}
	delta := crypto.ManifestDelta{Add: map[string]crypto.ManifestEntry{objKey: entry}, Prune: prev.Prunable}
	if err := f.v.record(delta); err != nil {
		f.t.Fatalf("record: %v", err)
	}
	return next
}

// TestMetadataSurvivesFoldAndCompaction: a write's description and timestamp
// come back from a cold fold, and — the part that bites — still come back
// after compaction folds the segment into a snapshot. Snapshot entries must
// carry the fields, or the first compaction destroys them.
func TestMetadataSurvivesFoldAndCompaction(t *testing.T) {
	v := newVault(t)
	f := newFixture(t, v, "m1")
	f.write(f.fold(), secrets.Write{Key: "DB_URL", Value: "v1", Description: "primary Postgres DSN", TS: 1750000000})
	f.set(f.fold(), "OTHER", "x") // a metadata-less write alongside

	check := func(stage string) {
		t.Helper()
		state := f.fold()
		m := state.Meta["DB_URL"]
		if m.Description != "primary Postgres DSN" || m.TS != 1750000000 {
			t.Fatalf("%s: DB_URL meta = %+v, want description and ts intact", stage, m)
		}
		if other := state.Meta["OTHER"]; other != (secrets.Meta{}) {
			t.Fatalf("%s: OTHER meta = %+v, want zero", stage, other)
		}
	}
	check("cold fold")
	if err := f.compact(); err != nil {
		t.Fatalf("compact: %v", err)
	}
	check("after compaction")
	// A second compaction folds snapshot entries, not segments: the carry must
	// hold through that path too.
	f.set(f.fold(), "OTHER", "y")
	if err := f.compact(); err != nil {
		t.Fatalf("re-compact: %v", err)
	}
	check("after re-compaction")
}

// TestMetadataRidesWinningWrite: under a same-Lamport conflict the kept value
// is deterministic (higher machine id), and the metadata must come from that
// same write — never a merge of both.
func TestMetadataRidesWinningWrite(t *testing.T) {
	v := newVault(t)
	m1 := newFixture(t, v, "m1")
	m2 := newFixture(t, v, "m2")

	base := m1.fold()
	m1.write(base, secrets.Write{Key: "K", Value: "from-m1", Description: "m1's note", TS: 100})
	m2.write(base, secrets.Write{Key: "K", Value: "from-m2", Description: "m2's note", TS: 200})

	state := m1.fold()
	if state.Secrets["K"] != "from-m2" {
		t.Fatalf("winner = %q, want m2's value", state.Secrets["K"])
	}
	if m := state.Meta["K"]; m.Description != "m2's note" || m.TS != 200 {
		t.Fatalf("meta = %+v, want the winning write's metadata", m)
	}
}

// TestDeleteDropsMetadata: a tombstone removes the key's metadata with the
// key; re-setting it starts clean rather than resurrecting the old description.
func TestDeleteDropsMetadata(t *testing.T) {
	v := newVault(t)
	f := newFixture(t, v, "m1")
	f.write(f.fold(), secrets.Write{Key: "K", Value: "v", Description: "old purpose", TS: 100})
	f.del(f.fold(), "K")
	f.set(f.fold(), "K", "v2")

	if m := f.fold().Meta["K"]; m != (secrets.Meta{}) {
		t.Fatalf("meta after delete and re-set = %+v, want zero", m)
	}
	if err := f.compact(); err != nil {
		t.Fatalf("compact: %v", err)
	}
	if m := f.fold().Meta["K"]; m != (secrets.Meta{}) {
		t.Fatalf("meta after compaction = %+v, want zero", m)
	}
}
