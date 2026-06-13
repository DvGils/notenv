package secrets

import (
	"context"
	"fmt"
	"testing"

	"github.com/DvGils/notenv/internal/backend/memstore"
	"github.com/DvGils/notenv/internal/crypto"
)

// TestReseedDefeatsCounterReset is the #2 scenario. After a machine's writes are
// compacted (so the snapshot carries its seq high-water), a later write whose
// local counter was lost and reissues a low number is flagged as a replay; a
// write floored at the fold's HighWater clears the replay line and folds
// cleanly. The command layer produces that floored seq via config.NextSeq.
func TestReseedDefeatsCounterReset(t *testing.T) {
	ctx := context.Background()
	mk, err := crypto.GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	store := memstore.New()
	manifest := &simManifest{entries: map[string]crypto.ManifestEntry{}}
	ns := func() *Namespace { return For(store, "proj", mk, "m1", manifest.entries) }

	// m1 writes five recorded segments, then compacts so the snapshot carries its
	// seq high-water and the segments themselves are folded away.
	view := &State{Secrets: map[string]string{}}
	for seq := 1; seq <= 5; seq++ {
		updated, objKey, entry, err := ns().Append(ctx, view, seq, Write{Key: "K", Value: fmt.Sprintf("v%d", seq)})
		if err != nil {
			t.Fatalf("append seq %d: %v", seq, err)
		}
		if err := manifest.apply(crypto.ManifestDelta{Add: map[string]crypto.ManifestEntry{objKey: entry}}); err != nil {
			t.Fatal(err)
		}
		view = updated
	}
	if err := ns().Compact(ctx, manifest.apply); err != nil {
		t.Fatalf("compact: %v", err)
	}

	state, err := ns().Fold(ctx)
	if err != nil {
		t.Fatalf("fold after compaction: %v", err)
	}
	hw := state.HighWater("m1")
	if hw < 5 {
		t.Fatalf("HighWater(m1) = %d, want >= 5 (the compacted high-water)", hw)
	}

	// A write floored at the high-water folds cleanly, even though the local
	// counter was reset: this is the fix.
	if _, _, _, err := ns().Append(ctx, state, hw+1, Write{Key: "K", Value: "reseeded"}); err != nil {
		t.Fatal(err)
	}
	if _, err := ns().Fold(ctx); err != nil {
		t.Fatalf("a write floored above the high-water must fold cleanly: %v", err)
	}

	// Without the floor, a reset counter reissues a low seq that a fold flags as a
	// replay: the bug the floor fixes.
	if _, _, _, err := ns().Append(ctx, state, 1, Write{Key: "K", Value: "reset"}); err != nil {
		t.Fatal(err)
	}
	if _, err := ns().Fold(ctx); err == nil {
		t.Fatal("a reissued low seq must trip the replay check")
	}
}

// TestHighWaterIncludesLiveSegments: a machine whose writes are recorded but not
// yet compacted still reports a high-water from those live segments, so its next
// write is floored above them (no collision with an in-flight one).
func TestHighWaterIncludesLiveSegments(t *testing.T) {
	ctx := context.Background()
	mk, err := crypto.GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	store := memstore.New()
	manifest := &simManifest{entries: map[string]crypto.ManifestEntry{}}
	ns := func() *Namespace { return For(store, "proj", mk, "m1", manifest.entries) }

	view := &State{Secrets: map[string]string{}}
	for seq := 1; seq <= 3; seq++ {
		updated, objKey, entry, err := ns().Append(ctx, view, seq, Write{Key: "K", Value: fmt.Sprintf("v%d", seq)})
		if err != nil {
			t.Fatal(err)
		}
		if err := manifest.apply(crypto.ManifestDelta{Add: map[string]crypto.ManifestEntry{objKey: entry}}); err != nil {
			t.Fatal(err)
		}
		view = updated
	}
	state, err := ns().Fold(ctx) // no compaction: the segments are live, not folded
	if err != nil {
		t.Fatal(err)
	}
	if hw := state.HighWater("m1"); hw != 3 {
		t.Fatalf("HighWater(m1) = %d, want 3 from live segments", hw)
	}
}
