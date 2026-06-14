package keymgmt_test

import (
	"context"
	"testing"

	"github.com/DvGils/notenv/internal/backend/memstore"
	"github.com/DvGils/notenv/internal/crypto"
	"github.com/DvGils/notenv/internal/keymgmt"
)

// spliceTransition adds an extra transition to the stored header's chain. It
// does not re-seal: the walk verifies each transition's own signature, not the
// header tag.
func spliceTransition(t *testing.T, store *memstore.Store, tr *crypto.Transition) {
	t.Helper()
	header := mustParse(t, store)
	header.Transitions = append(header.Transitions, *tr)
	raw, err := header.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	store.SetHeader(raw)
}

// clearTransitions drops the stored header's rotation history.
func clearTransitions(t *testing.T, store *memstore.Store) {
	t.Helper()
	header := mustParse(t, store)
	header.Transitions = nil
	raw, err := header.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	store.SetHeader(raw)
}

// rotatedVault seeds a vault and rotates it n times, returning the store, the
// original master (what a stale machine would have pinned), the original header
// (for its pin fields), and the final master.
func rotatedVault(t *testing.T, n int) (*memstore.Store, *crypto.MasterKey, *crypto.Header, *crypto.MasterKey) {
	t.Helper()
	ctx := context.Background()
	store := memstore.New()
	firstMK, _ := seedVault(t, store, map[string]nsBlobs{"proj": {cur: "a"}})
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
	return keymgmt.FollowRotations(header, pinnedSignPub, pinnedRevision, currentMK)
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
	store, firstMK, firstHeader, currentMK := rotatedVault(t, 1)
	// The rotation history vanished (a v4-era reader resealed without it, or it
	// was tampered out): fail safe.
	clearTransitions(t, store)
	if err := follow(t, store, firstMK, firstHeader.Revision, currentMK); err == nil {
		t.Fatal("a missing chain must not walk")
	}
}

func TestFollowRotationsToleratesOrphanSiblings(t *testing.T) {
	store, firstMK, firstHeader, currentMK := rotatedVault(t, 1)

	// A rotation that died before its flip leaves a transition from the same old
	// master to a master that never took over. The walk must route around it to
	// the hop that actually happened.
	orphanMK, err := crypto.GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	orphan, err := crypto.NewTransition(firstMK, orphanMK, firstHeader.VaultID, firstHeader.Revision+1)
	if err != nil {
		t.Fatal(err)
	}
	spliceTransition(t, store, orphan)

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
	if err := keymgmt.FollowRotations(header, pinnedSignPub, firstHeader.Revision, currentMK); err == nil {
		t.Fatal("a hop beyond the observed revision must not walk")
	}
}

// TestConcurrentRotationKeepsWinnersTransition: two rotations build on the same
// base; the header compare-and-swap lets exactly one win, and because the
// transition now rides in the header, the loser cannot clobber the winner's
// record (the old bug was a separate transition object the loser's write could
// overwrite). A machine pinned at the original master still walks to the winner.
func TestConcurrentRotationKeepsWinnersTransition(t *testing.T) {
	ctx := context.Background()
	store := memstore.New()
	firstMK, _ := seedVault(t, store, map[string]nsBlobs{})
	firstHeader := mustParse(t, store)
	verify := func(h *crypto.Header) (*crypto.MasterKey, error) { m, _, _, e := h.Unlock("owner-pass"); return m, e }

	base := store.Header()
	headerA, _ := crypto.ParseHeader(base)
	headerB, _ := crypto.ParseHeader(base)

	winnerMK, err := keymgmt.RotateMaster(ctx, store, headerA, base, firstMK, verify, nil)
	if err != nil {
		t.Fatalf("first rotation must win: %v", err)
	}
	if _, err := keymgmt.RotateMaster(ctx, store, headerB, base, firstMK, verify, nil); err == nil {
		t.Fatal("a rotation built on a stale base must lose the header swap")
	}
	if err := follow(t, store, firstMK, firstHeader.Revision, winnerMK); err != nil {
		t.Fatalf("the winner's transition must survive the losing rotation: %v", err)
	}
}

// TestDescends: the onboarding-fingerprint walker accepts any recognized
// ancestor signing key connected to the unlocked master by valid transitions,
// and nothing else.
func TestDescends(t *testing.T) {
	store, firstMK, _, currentMK := rotatedVault(t, 2)
	header := mustParse(t, store)
	firstSignPub, err := firstMK.SignPub()
	if err != nil {
		t.Fatal(err)
	}

	if err := keymgmt.Descends(header, currentMK, func(signPub string) bool {
		return signPub == firstSignPub
	}); err != nil {
		t.Fatalf("the original signing key is an ancestor of the current master: %v", err)
	}
	if err := keymgmt.Descends(header, currentMK, func(string) bool { return false }); err == nil {
		t.Fatal("recognizing no key must not walk")
	}
	if err := keymgmt.Descends(header, currentMK, func(signPub string) bool {
		return signPub == "unrelated"
	}); err == nil {
		t.Fatal("an unrelated key must not walk")
	}
}
