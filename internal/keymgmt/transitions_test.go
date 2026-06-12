package keymgmt_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/DvGils/notenv/internal/backend/memstore"
	"github.com/DvGils/notenv/internal/crypto"
	"github.com/DvGils/notenv/internal/keymgmt"
)

// appendForTest splices an extra transition into the stored history.
func appendForTest(ctx context.Context, store *memstore.Store, tr *crypto.Transition) error {
	var ts []crypto.Transition
	if raw, err := store.Get(ctx, ".transitions.json"); err == nil {
		if err := json.Unmarshal(raw, &ts); err != nil {
			return err
		}
	}
	ts = append(ts, *tr)
	raw, err := json.Marshal(ts)
	if err != nil {
		return err
	}
	return store.Put(ctx, ".transitions.json", raw)
}

// rotatedVault seeds a vault and rotates it n times, returning the store, the
// original master (what a stale machine would have pinned), the original
// header (for its pin fields), and the final master.
func rotatedVault(t *testing.T, n int) (*memstore.Store, *crypto.MasterKey, *crypto.Header, *crypto.MasterKey) {
	t.Helper()
	ctx := context.Background()
	store := memstore.New()
	blobs := map[string]string{"proj/seg-m1-aa.age": "a"}
	firstMK, _ := seedVault(t, store, blobs)
	firstHeader := mustParse(t, store)
	verify := func(h *crypto.Header) (*crypto.MasterKey, error) { m, _, _, e := h.Unlock("owner-pass"); return m, e }

	current := firstMK
	for range n {
		base := store.Header()
		header, _ := crypto.ParseHeader(base)
		next, err := keymgmt.RotateMaster(ctx, store, header, base, current, verify, nil)
		if err != nil {
			t.Fatalf("rotate: %v", err)
		}
		current = next
	}
	return store, firstMK, firstHeader, current
}

// follow runs FollowRotations from the original master's pin to the store's
// current header, returning its verdict.
func follow(t *testing.T, store *memstore.Store, pinnedMK *crypto.MasterKey, pinnedRevision int, currentMK *crypto.MasterKey) error {
	t.Helper()
	header := mustParse(t, store)
	pinnedSignPub, err := pinnedMK.SignPub()
	if err != nil {
		t.Fatal(err)
	}
	return keymgmt.FollowRotations(context.Background(), store, header, pinnedSignPub, pinnedRevision, currentMK)
}

func TestFollowRotationsSingleHop(t *testing.T) {
	store, firstMK, firstHeader, currentMK := rotatedVault(t, 1)
	if err := follow(t, store, firstMK, firstHeader.Revision, currentMK); err != nil {
		t.Fatalf("one legitimate rotation must walk: %v", err)
	}
}

func TestFollowRotationsMultiHop(t *testing.T) {
	store, firstMK, firstHeader, currentMK := rotatedVault(t, 3)
	if err := follow(t, store, firstMK, firstHeader.Revision, currentMK); err != nil {
		t.Fatalf("a machine three rotations behind must walk the chain: %v", err)
	}
}

func TestFollowRotationsRejectsUnrelatedMaster(t *testing.T) {
	store, firstMK, firstHeader, _ := rotatedVault(t, 1)

	// A substituted header: same vault ID, but a master no transition leads to.
	intruder, err := crypto.GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	header := mustParse(t, store)
	if err := header.SetMaster(intruder); err != nil {
		t.Fatal(err)
	}
	header.Revision++
	if err := header.Seal(intruder); err != nil {
		t.Fatal(err)
	}
	raw, err := header.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	store.SetHeader(raw)

	if err := follow(t, store, firstMK, firstHeader.Revision, intruder); err == nil {
		t.Fatal("a master with no signed path from the pin must not walk")
	}
}

func TestFollowRotationsRejectsMissingChain(t *testing.T) {
	ctx := context.Background()
	store, firstMK, firstHeader, currentMK := rotatedVault(t, 1)
	// The transition history vanished (deleted or never synced): fail safe.
	if err := store.Delete(ctx, ".transitions.json"); err != nil {
		t.Fatal(err)
	}
	if err := follow(t, store, firstMK, firstHeader.Revision, currentMK); err == nil {
		t.Fatal("a missing chain must not walk")
	}
}

func TestFollowRotationsToleratesOrphanSiblings(t *testing.T) {
	ctx := context.Background()
	store, firstMK, firstHeader, currentMK := rotatedVault(t, 1)

	// A rotation that died before its flip leaves a transition from the same
	// old master to a master that never took over. The walk must route around
	// it to the hop that actually happened.
	orphanMK, err := crypto.GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	orphan, err := crypto.NewTransition(firstMK, orphanMK, firstHeader.VaultID, firstHeader.Revision+1)
	if err != nil {
		t.Fatal(err)
	}
	if err := appendForTest(ctx, store, orphan); err != nil {
		t.Fatal(err)
	}

	if err := follow(t, store, firstMK, firstHeader.Revision, currentMK); err != nil {
		t.Fatalf("an orphan sibling must not block the real hop: %v", err)
	}
}

func TestFollowRotationsHonorsRevisionCeiling(t *testing.T) {
	store, firstMK, firstHeader, currentMK := rotatedVault(t, 1)
	// A header older than the hop's revision cannot have been produced by it:
	// walking with a target revision below the transition's must fail (this is
	// the rollback check carried into the walk).
	header := mustParse(t, store)
	pinnedSignPub, err := firstMK.SignPub()
	if err != nil {
		t.Fatal(err)
	}
	header.Revision = firstHeader.Revision // pretend the observed header predates the hop
	if err := keymgmt.FollowRotations(context.Background(), store, header, pinnedSignPub, firstHeader.Revision, currentMK); err == nil {
		t.Fatal("a hop beyond the observed revision must not walk")
	}
}
