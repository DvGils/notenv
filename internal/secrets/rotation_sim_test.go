package secrets

import (
	"context"
	"fmt"
	"math/rand"
	"testing"

	"filippo.io/age"

	"github.com/DvGils/notenv/internal/backend"
	"github.com/DvGils/notenv/internal/backend/chaos"
	"github.com/DvGils/notenv/internal/backend/memstore"
	"github.com/DvGils/notenv/internal/crypto"
	"github.com/DvGils/notenv/internal/keymgmt"
)

// chaosVault joins the fault-injecting object store with the fake's header
// side: object writes can be interrupted, header operations are reliable. That
// split keeps every failure the script can induce inside the object layer the
// oracle understands, while still letting rotations run their full protocol.
type chaosVault struct {
	*chaos.Backend
	hs backend.HeaderStore
}

func (v *chaosVault) GetHeader(ctx context.Context) ([]byte, error) { return v.hs.GetHeader(ctx) }
func (v *chaosVault) PutHeader(ctx context.Context, raw []byte) error {
	return v.hs.PutHeader(ctx, raw)
}
func (v *chaosVault) BackupHeader(ctx context.Context) error { return v.hs.BackupHeader(ctx) }
func (v *chaosVault) RestoreHeaderBackup(ctx context.Context) error {
	return v.hs.RestoreHeaderBackup(ctx)
}

var _ keymgmt.Vault = (*chaosVault)(nil)

// simVault is a live vault for the rotation simulation: an identity-unlockable
// header over a chaos-wrapped store. Identity unlock is one X25519 operation,
// cheap enough to run on every simulated stale-key recovery inside a fuzz loop
// (a passphrase slot's scrypt would be thousands of times slower).
type simVault struct {
	store *memstore.Store
	cv    *chaosVault
	id    *age.X25519Identity
}

func newSimVault(t *testing.T, seed int64) *simVault {
	t.Helper()
	store := memstore.New()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	mk, err := crypto.GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	vaultID, err := crypto.NewVaultID()
	if err != nil {
		t.Fatal(err)
	}
	header := &crypto.Header{Version: 2, VaultID: vaultID, Revision: 1}
	if err := header.AddRecipientSlot(id.Recipient(), "sim", mk); err != nil {
		t.Fatal(err)
	}
	if err := header.Seal(mk); err != nil {
		t.Fatal(err)
	}
	raw, err := header.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	store.SetHeader(raw)
	cv := &chaosVault{chaos.New(store, seed, chaos.Options{PutFailRate: simPutFailRate}), store}
	return &simVault{store: store, cv: cv, id: id}
}

// currentMaster unlocks whatever master the header yields right now.
func (v *simVault) currentMaster(t *testing.T) *crypto.MasterKey {
	t.Helper()
	header, err := crypto.ParseHeader(v.store.Header())
	if err != nil {
		t.Fatalf("parse header: %v", err)
	}
	mk, _, err := header.UnlockIdentity(v.id)
	if err != nil {
		t.Fatalf("unlock: %v", err)
	}
	return mk
}

// rotMachine is one simulated machine: it holds the master it last unlocked,
// which a rotation elsewhere can silently make stale — exactly the state the
// write-epoch protocol exists to make safe.
type rotMachine struct {
	id   string
	mk   *crypto.MasterKey
	view *State
	seq  int
}

func (m *rotMachine) ns(v *simVault) *Namespace {
	return For(v.cv, "proj", m.mk, m.id)
}

// runRotationScript drives machines through writes, folds, compactions, and
// master rotations, all racing each other through stale keys and interrupted
// uploads. After every step it enforces the invariant the write-epoch protocol
// promises: a fold under the vault's current master always succeeds — no
// committed object is ever stranded under a key the header no longer yields.
func runRotationScript(t *testing.T, data []byte) {
	t.Helper()
	if len(data) == 0 {
		return
	}
	ctx := context.Background()
	v := newSimVault(t, chaosSeed(data))

	machines := make([]*rotMachine, simMachineCount)
	for i := range machines {
		machines[i] = &rotMachine{
			id:   fmt.Sprintf("m%d", i+1),
			mk:   v.currentMaster(t),
			view: &State{Secrets: map[string]string{}},
		}
	}

	// guardedWrite is the cmd layer's write protocol: append, confirm the
	// sealed-under master is still the vault's, undo and refresh otherwise.
	guardedWrite := func(m *rotMachine, key, value string, deleted bool) {
		m.seq++
		updated, objKey, err := m.ns(v).Append(ctx, m.view, m.seq, key, value, deleted)
		if err != nil {
			return // interrupted upload: nothing landed
		}
		if keymgmt.VerifyEpoch(ctx, v.cv, m.mk) != nil {
			_ = v.cv.Delete(ctx, objKey)
			m.mk = v.currentMaster(t)
			m.view = &State{Secrets: map[string]string{}} // stale; refold before reuse
			return
		}
		m.view = updated
	}

	refresh := func(m *rotMachine) {
		st, err := m.ns(v).Fold(ctx)
		if err != nil {
			// The vault was re-keyed since this machine unlocked; recover the
			// way withMaster does and fold again, which must now succeed.
			m.mk = v.currentMaster(t)
			if st, err = m.ns(v).Fold(ctx); err != nil {
				t.Fatalf("fold after key refresh must succeed: %v", err)
			}
		}
		m.view = st
	}

	// fold reads the namespace as a fresh holder of the current master would.
	fold := func(step int) map[string]string {
		obs := &rotMachine{id: "observer", mk: v.currentMaster(t)}
		st, err := obs.ns(v).Fold(ctx)
		if err != nil {
			t.Fatalf("step %d: fold under the current master failed (stranded object): %v", step, err)
		}
		return st.Secrets
	}

	sc := &byteScript{data: data}
	for step := 0; !sc.done(); step++ {
		m := machines[sc.choose(len(machines))]
		switch op := sc.choose(10); {
		case op == 0:
			refresh(m)
		case op == 1: // compaction with the epoch confirm, like the cmd layer
			confirm := func() error { return keymgmt.VerifyEpoch(ctx, v.cv, m.mk) }
			if err := m.ns(v).Compact(ctx, confirm); err != nil {
				m.mk = v.currentMaster(t) // possibly aborted on a stale key
			}
		case op == 2: // rotation must preserve the visible secrets
			before := fold(step)
			base := v.store.Header()
			header, err := crypto.ParseHeader(base)
			if err != nil {
				t.Fatalf("step %d: %v", step, err)
			}
			current, _, err := header.UnlockIdentity(v.id)
			if err != nil {
				t.Fatalf("step %d: %v", step, err)
			}
			verify := func(h *crypto.Header) (*crypto.MasterKey, error) { mk, _, e := h.UnlockIdentity(v.id); return mk, e }
			if _, err := keymgmt.RotateMaster(ctx, v.cv, header, base, current, verify, nil); err != nil {
				break // interrupted rotation: the invariant below still must hold
			}
			if after := fold(step); !sameStringMap(before, after) {
				t.Fatalf("step %d: rotation changed visible secrets: %v -> %v", step, before, after)
			}
		default:
			key := fmt.Sprintf("K%d", sc.choose(simKeyCount))
			if deleted := sc.choose(4) == 0; deleted {
				guardedWrite(m, key, "", true)
			} else {
				guardedWrite(m, key, fmt.Sprintf("%s-%s-%d", m.id, key, step), false)
			}
		}
		fold(step) // the anti-stranding invariant, after every single step
	}

	// Every machine converges: stale keys recover and read the same state.
	want := fold(-1)
	for _, m := range machines {
		refresh(m)
		if !sameStringMap(m.view.Secrets, want) {
			t.Fatalf("machine %s did not converge: %v != %v", m.id, m.view.Secrets, want)
		}
	}
}

func TestRotationLog(t *testing.T) {
	for seed := int64(0); seed < 25; seed++ {
		rng := rand.New(rand.NewSource(seed))
		data := make([]byte, 48)
		_, _ = rng.Read(data)
		runRotationScript(t, data)
	}
}

func FuzzRotationLog(f *testing.F) {
	corpus := make([]byte, 96)
	_, _ = rand.New(rand.NewSource(2)).Read(corpus)
	f.Add(corpus)
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64 {
			data = data[:64] // every step costs at least one fold of the namespace
		}
		runRotationScript(t, data)
	})
}
