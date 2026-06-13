package secrets

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
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
func (v *chaosVault) SwapHeader(ctx context.Context, base, updated []byte) error {
	return v.hs.SwapHeader(ctx, base, updated)
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

func newSimVault(t *testing.T, seed int64, putFailRate float64) *simVault {
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
	header := &crypto.Header{Version: 5, VaultID: vaultID, Revision: 1}
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
	cv := &chaosVault{chaos.New(store, seed, chaos.Options{PutFailRate: putFailRate}), store}
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

// rotMachine is one simulated machine: it holds the master it last unlocked
// and the fold it last saw, both of which a rotation elsewhere can silently
// make stale — exactly the state the write protocol exists to make safe. A
// nil view means the machine must fold before it writes, as every command
// does.
type rotMachine struct {
	id   string
	mk   *crypto.MasterKey
	view *State
	seq  int
}

// rotSim is one rotation-simulation run: machines racing writes, compactions,
// and master rotations over a shared vault, plus the bookkeeping for writers
// that crashed between landing a segment and recording it.
type rotSim struct {
	t        *testing.T
	ctx      context.Context
	v        *simVault
	machines []*rotMachine
	// crashed maps a crashed writer's segment object to the secret key it
	// wrote: pending until adopted by a compaction, or orphaned by a rotation
	// (its alarm names it; the modeled operator removes it).
	crashed map[string]string
}

func newRotSim(t *testing.T, data []byte, putFailRate float64) *rotSim {
	t.Helper()
	s := &rotSim{t: t, ctx: context.Background(), v: newSimVault(t, chaosSeed(data), putFailRate), crashed: map[string]string{}}
	for i := range simMachineCount {
		s.machines = append(s.machines, &rotMachine{id: fmt.Sprintf("m%d", i+1), mk: s.v.currentMaster(t)})
	}
	return s
}

// header parses the vault's current header, the trust root every operation
// starts from.
func (s *rotSim) header() *crypto.Header {
	h, err := crypto.ParseHeader(s.v.store.Header())
	if err != nil {
		s.t.Fatalf("parse header: %v", err)
	}
	return h
}

// ensureCurrent re-unlocks m when the vault's master moved on — the sim's
// stand-in for the unlock ceremony (and its pin checks) that withMaster runs.
func (s *rotSim) ensureCurrent(m *rotMachine, h *crypto.Header) {
	if h.Recipient != m.mk.PublicKey() {
		m.mk = s.v.currentMaster(s.t)
		m.view = nil
	}
}

// foldCurrent folds under the vault's current master, repairing the one alarm
// an honest history can produce: a crashed writer's segment orphaned by a
// later rotation (sealed under the gone master, never recorded). The alarm
// must be exactly that, naming exactly such an object; the modeled operator
// removes it and the fold is retried. Anything else fails the run.
func (s *rotSim) foldCurrent(step int) *State {
	s.t.Helper()
	mk := s.v.currentMaster(s.t)
	for {
		h := s.header()
		for key := range s.crashed {
			if _, recorded := h.Manifest[key]; recorded {
				delete(s.crashed, key) // a compaction adopted it
			}
		}
		st, err := For(s.v.cv, "proj", mk, "observer", h.Manifest).Fold(s.ctx)
		if err == nil {
			return st
		}
		key := s.orphanNamed(err)
		if key == "" {
			s.t.Fatalf("step %d: fold failed on an honest run: %v", step, err)
		}
		_ = s.v.cv.Delete(s.ctx, key)
		delete(s.crashed, key)
	}
}

// orphanNamed returns the pending crashed segment the error names, but only
// when the alarm is the orphaned-by-re-key one; any other alarm is a bug.
func (s *rotSim) orphanNamed(err error) string {
	if !strings.Contains(err.Error(), "does not open under the current master key") {
		return ""
	}
	for key := range s.crashed {
		if strings.Contains(err.Error(), key) {
			return key
		}
	}
	return ""
}

// guardedWrite is the command layer's write protocol under simulation: write
// the segment from the machine's (possibly stale) view and key, then record it
// under the header swap, which is where a stale master surfaces — undo the
// segment and re-unlock, exactly like appendGuarded. With crash, the writer
// dies after the segment lands: nothing is recorded, nothing is undone.
func (s *rotSim) guardedWrite(m *rotMachine, key, value string, deleted, crash bool) {
	if m.view == nil && !s.adoptView(m) {
		return
	}
	m.seq++
	ns := For(s.v.cv, "proj", m.mk, m.id, nil) // Append never reads the manifest
	updated, objKey, entry, err := ns.Append(s.ctx, m.view, m.seq, Write{Key: key, Value: value, Deleted: deleted})
	if err != nil {
		return // interrupted upload: nothing landed
	}
	if crash {
		s.crashed[objKey] = key
		m.view = nil
		return
	}
	delta := crypto.ManifestDelta{Add: map[string]crypto.ManifestEntry{objKey: entry}, Prune: m.view.Prunable}
	if _, err := keymgmt.UpdateManifest(s.ctx, s.v.cv, m.mk, delta); err != nil {
		_ = s.v.cv.Delete(s.ctx, objKey) // sealed under a superseded master: roll it back
		m.mk = s.v.currentMaster(s.t)
		m.view = nil
		return
	}
	m.view = updated
}

// adoptView gives a machine with no working base a fresh fold, re-unlocking
// first if its key went stale. Reports whether a usable view was obtained.
func (s *rotSim) adoptView(m *rotMachine) bool {
	h := s.header()
	s.ensureCurrent(m, h)
	st, err := s.nsFor(m, h).Fold(s.ctx)
	if err != nil {
		return false // a pending orphan alarm; the step-end fold repairs it
	}
	m.view = st
	return true
}

func (s *rotSim) nsFor(m *rotMachine, h *crypto.Header) *Namespace {
	return For(s.v.cv, "proj", m.mk, m.id, h.Manifest)
}

// compact runs the command layer's compaction: a fresh view (re-unlocking if
// stale), then Compact with the manifest swap as its commit.
func (s *rotSim) compact(m *rotMachine) error {
	h := s.header()
	s.ensureCurrent(m, h)
	return s.nsFor(m, h).Compact(s.ctx, func(d crypto.ManifestDelta) error {
		_, err := keymgmt.UpdateManifest(s.ctx, s.v.cv, m.mk, d)
		return err
	})
}

// rotate runs a full master rotation as the key command would, returning false
// when it aborted (an interrupted upload mid-rotation): the vault must remain
// consistent either way.
func (s *rotSim) rotate() bool {
	base := s.v.store.Header()
	header, err := crypto.ParseHeader(base)
	if err != nil {
		s.t.Fatal(err)
	}
	current, _, err := header.UnlockIdentity(s.v.id)
	if err != nil {
		s.t.Fatal(err)
	}
	verify := func(h *crypto.Header) (*crypto.MasterKey, error) { mk, _, e := h.UnlockIdentity(s.v.id); return mk, e }
	_, err = keymgmt.RotateMaster(s.ctx, s.v.cv, header, base, current, verify, nil)
	return err == nil
}

// pendingKeys are the secret keys touched by still-unrecorded crashed writes:
// the only values a rotation may legitimately shed (their writers were never
// confirmed; the post-rotation alarm and its remedy remove them).
func (s *rotSim) pendingKeys() map[string]bool {
	keys := map[string]bool{}
	for _, key := range s.crashed {
		keys[key] = true
	}
	return keys
}

// runRotationScript drives machines through writes (some of which crash
// mid-protocol), folds, compactions, and master rotations, all racing each
// other through stale keys and interrupted uploads. After every step it
// enforces the protocol's promise: a fold under the vault's current master and
// header succeeds — no committed object is ever stranded, and no honest
// history raises an alarm beyond the one documented rotation-orphan case,
// which must name its object and heal by removing it.
func runRotationScript(t *testing.T, data []byte) {
	t.Helper()
	if len(data) == 0 {
		return
	}
	s := newRotSim(t, data, simPutFailRate)

	sc := &byteScript{data: data}
	for step := 0; !sc.done(); step++ {
		m := s.machines[sc.choose(len(s.machines))]
		switch op := sc.choose(10); {
		case op == 0: // refresh this machine's working base
			h := s.header()
			s.ensureCurrent(m, h)
			s.adoptView(m)
		case op == 1: // compaction must be value-transparent
			before := s.foldCurrent(step).Secrets
			if err := s.compact(m); err != nil {
				break // aborted compaction: store unchanged, still consistent
			}
			after := s.foldCurrent(step).Secrets
			if !sameStringMap(before, after) {
				t.Fatalf("step %d: compaction changed visible secrets: %v -> %v", step, before, after)
			}
		case op == 2: // rotation must preserve every recorded secret
			before := s.foldCurrent(step).Secrets
			pending := s.pendingKeys()
			if !s.rotate() {
				break // interrupted rotation: the step-end fold still must hold
			}
			after := s.foldCurrent(step).Secrets
			if !sameMapExcept(before, after, pending) {
				t.Fatalf("step %d: rotation changed recorded secrets: %v -> %v (pending %v)", step, before, after, pending)
			}
		default:
			key := fmt.Sprintf("K%d", sc.choose(simKeyCount))
			deleted := sc.choose(4) == 0
			crash := sc.choose(8) == 0
			value := ""
			if !deleted {
				value = fmt.Sprintf("%s-%s-%d", m.id, key, step)
			}
			s.guardedWrite(m, key, value, deleted, crash)
		}
		s.foldCurrent(step) // the anti-stranding invariant, after every single step
	}

	// Every machine converges: stale keys recover and read the same state.
	want := s.foldCurrent(-1).Secrets
	for _, m := range s.machines {
		h := s.header()
		s.ensureCurrent(m, h)
		if !s.adoptView(m) {
			t.Fatalf("machine %s could not fold at convergence", m.id)
		}
		if !sameStringMap(m.view.Secrets, want) {
			t.Fatalf("machine %s did not converge: %v != %v", m.id, m.view.Secrets, want)
		}
	}
}

// sameMapExcept compares a and b ignoring the given keys.
func sameMapExcept(a, b map[string]string, except map[string]bool) bool {
	for k, v := range a {
		if !except[k] && b[k] != v {
			return false
		}
	}
	for k, v := range b {
		if !except[k] && a[k] != v {
			return false
		}
	}
	return true
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
