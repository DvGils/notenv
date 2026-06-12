package secrets

import (
	"context"
	"fmt"
	"hash/fnv"
	"maps"
	"math/rand"
	"testing"

	"github.com/DvGils/notenv/internal/backend/chaos"
	"github.com/DvGils/notenv/internal/backend/memstore"
	"github.com/DvGils/notenv/internal/crypto"
)

const (
	simMachineCount = 3
	simKeyCount     = 4
	simPutFailRate  = 0.10
)

// recordedWrite is one landed write the oracle remembers, to predict the fold.
// The oracle is exact only while no compaction runs (a segment-only store is
// in one-to-one correspondence with the landed writes).
type recordedWrite struct {
	value   string
	deleted bool
	lamport int
	machine string
	seq     int
}

// simManifest is the header-side manifest the simulation's writes go through,
// applied the way the command layer would. Single-threaded steps make every
// apply atomic, which matches the semantics the real header swap provides.
type simManifest struct {
	entries map[string]crypto.ManifestEntry
}

func (sm *simManifest) apply(d crypto.ManifestDelta) error {
	h := &crypto.Header{Manifest: maps.Clone(sm.entries)}
	h.ApplyManifest(d)
	sm.entries = h.Manifest
	return nil
}

// simMachine is a virtual machine: its id, its sequence counter, and the last
// fold it saw — the (possibly stale) base its next write builds on.
type simMachine struct {
	id   string
	seq  int
	view *State
}

// byteScript yields bounded choices from a byte slice, so a fuzzer's mutations
// steer the operation sequence directly.
type byteScript struct {
	data []byte
	pos  int
}

func (s *byteScript) choose(n int) int {
	if n <= 1 || s.pos >= len(s.data) {
		return 0
	}
	v := int(s.data[s.pos]) % n
	s.pos++
	return v
}

func (s *byteScript) done() bool { return s.pos >= len(s.data) }

func chaosSeed(data []byte) int64 {
	h := fnv.New64a()
	_, _ = h.Write(data)
	return int64(h.Sum64())
}

// secretSim is one simulation run's world: machines sharing a chaos-wrapped
// store, a manifest, and the oracle's write log.
type secretSim struct {
	t        *testing.T
	ctx      context.Context
	mk       *crypto.MasterKey
	store    *chaos.Backend
	manifest *simManifest
	machines []*simMachine
	log      map[string][]recordedWrite
}

func newSecretSim(t *testing.T, data []byte) *secretSim {
	t.Helper()
	mk, err := crypto.GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	s := &secretSim{
		t:        t,
		ctx:      context.Background(),
		mk:       mk,
		store:    chaos.New(memstore.New(), chaosSeed(data), chaos.Options{PutFailRate: simPutFailRate}),
		manifest: &simManifest{entries: map[string]crypto.ManifestEntry{}},
		log:      map[string][]recordedWrite{},
	}
	for i := range simMachineCount {
		s.machines = append(s.machines, &simMachine{id: fmt.Sprintf("m%d", i+1), view: &State{Secrets: map[string]string{}}})
	}
	return s
}

func (s *secretSim) ns(machine string) *Namespace {
	return For(s.store, "proj", s.mk, machine, s.manifest.entries)
}

// fold reads the namespace as an observer holding the current manifest. An
// honest run must never alarm, no matter how writes raced, crashed, or were
// interrupted.
func (s *secretSim) fold(step int) *State {
	s.t.Helper()
	st, err := s.ns("observer").Fold(s.ctx)
	if err != nil {
		s.t.Fatalf("step %d: fold failed on an honest run: %v", step, err)
	}
	return st
}

// write appends one key change from m and, unless the writer "crashes" first,
// records it in the manifest exactly as the command layer would. A crashed
// write lands but goes unrecorded: later folds must still include it, and a
// compaction makes it durable.
func (s *secretSim) write(m *simMachine, key, value string, deleted, crash bool) {
	m.seq++
	updated, objKey, entry, err := s.ns(m.id).Append(s.ctx, m.view, m.seq, key, value, deleted)
	if err != nil {
		return // interrupted upload: nothing landed, nothing recorded
	}
	s.log[key] = append(s.log[key], recordedWrite{value: value, deleted: deleted, lamport: updated.lamport, machine: m.id, seq: m.seq})
	if crash {
		// The process died between the segment landing and the manifest update;
		// its view is gone with it.
		m.view = &State{Secrets: map[string]string{}}
		return
	}
	delta := crypto.ManifestDelta{Add: map[string]crypto.ManifestEntry{objKey: entry}, Prune: m.view.Prunable}
	if err := s.manifest.apply(delta); err != nil {
		s.t.Fatalf("manifest apply: %v", err)
	}
	m.view = updated
}

// runScript drives simMachineCount machines through the operations encoded in
// data, against a chaos-wrapped store that interrupts some uploads and a
// writer population that sometimes crashes between its segment write and its
// manifest update.
//
// With allowCompact, compaction joins the mix and the checks are oracle-free:
// every fold must succeed (no poison pill, no false alarm), and every
// compaction must leave the visible secrets unchanged (compaction is
// transparent). Without it, the store is segment-only, so the landed write log
// is an exact oracle for both the resolved secrets and the reported conflicts
// under concurrent, stale, crashed, and interrupted writes.
func runScript(t *testing.T, data []byte, allowCompact bool) {
	t.Helper()
	if len(data) == 0 {
		return
	}
	s := newSecretSim(t, data)

	sc := &byteScript{data: data}
	for step := 0; !sc.done(); step++ {
		m := s.machines[sc.choose(len(s.machines))]
		switch op := sc.choose(10); {
		case op == 0: // refresh: re-fold this machine's working base
			m.view = s.fold(step)
		case op == 1 && allowCompact: // compaction must be value-transparent
			before := s.fold(step).Secrets
			if err := s.ns(m.id).Compact(s.ctx, s.manifest.apply); err != nil {
				break // interrupted compaction: store unchanged, still consistent
			}
			after := s.fold(step).Secrets
			if !sameStringMap(before, after) {
				t.Fatalf("step %d: compaction changed visible secrets: %v -> %v", step, before, after)
			}
		default: // set, unset, or a crashed variant of either
			key := fmt.Sprintf("K%d", sc.choose(simKeyCount))
			deleted := sc.choose(4) == 0
			crash := sc.choose(8) == 0
			value := ""
			if !deleted {
				value = fmt.Sprintf("%s-%s-%d", m.id, key, step)
			}
			s.write(m, key, value, deleted, crash)
		}
		st := s.fold(step) // a fold must always succeed (and match the oracle when applicable)
		if !allowCompact {
			assertOracle(t, step, st, s.log)
		}
	}
}

// assertOracle checks a fold against the write log: the resolved secrets and the
// reported conflict keys must match what last-write-wins over the log predicts.
func assertOracle(t *testing.T, step int, st *State, log map[string][]recordedWrite) {
	t.Helper()
	wantSecrets, wantConflicts := oracle(log)
	if !sameStringMap(st.Secrets, wantSecrets) {
		t.Fatalf("step %d: fold secrets %v != oracle %v", step, st.Secrets, wantSecrets)
	}
	got := map[string]bool{}
	for _, c := range st.Conflicts {
		got[c.Key] = true
	}
	if len(got) != len(wantConflicts) {
		t.Fatalf("step %d: fold conflicts %v != oracle %v", step, got, wantConflicts)
	}
	for key := range wantConflicts {
		if !got[key] {
			t.Fatalf("step %d: fold missing conflict on %s (oracle %v, got %v)", step, key, wantConflicts, got)
		}
	}
}

// oracle resolves the write log the way the fold should: the winner per key is
// the max by (Lamport, machine, sequence); a key is in conflict when two or more
// machines wrote it at that winning Lamport.
func oracle(log map[string][]recordedWrite) (secrets map[string]string, conflicts map[string]bool) {
	secrets = map[string]string{}
	conflicts = map[string]bool{}
	for key, writes := range log {
		best := writes[0]
		maxLamport := writes[0].lamport
		for _, w := range writes {
			if w.lamport > maxLamport {
				maxLamport = w.lamport
			}
			if oracleLess(best, w) {
				best = w
			}
		}
		if !best.deleted {
			secrets[key] = best.value
		}
		atMax := map[string]bool{}
		for _, w := range writes {
			if w.lamport == maxLamport {
				atMax[w.machine] = true
			}
		}
		if len(atMax) > 1 {
			conflicts[key] = true
		}
	}
	return secrets, conflicts
}

// oracleLess reports whether a loses to b in the fold's total order: higher
// Lamport wins, then higher machine id, then higher sequence.
func oracleLess(a, b recordedWrite) bool {
	if a.lamport != b.lamport {
		return a.lamport < b.lamport
	}
	if a.machine != b.machine {
		return a.machine < b.machine
	}
	return a.seq < b.seq
}

func sameStringMap(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func TestSecretLogConcurrent(t *testing.T) { runSeeds(t, false) }

func TestSecretLogWithCompaction(t *testing.T) { runSeeds(t, true) }

func runSeeds(t *testing.T, allowCompact bool) {
	// Kept modest so the suite stays fast (each oracle check re-folds the whole
	// segment set); `go test -fuzz=FuzzSecretLog` explores far deeper.
	for seed := int64(0); seed < 40; seed++ {
		rng := rand.New(rand.NewSource(seed))
		data := make([]byte, 64)
		_, _ = rng.Read(data)
		runScript(t, data, allowCompact)
	}
}

func FuzzSecretLog(f *testing.F) {
	corpus := make([]byte, 128)
	_, _ = rand.New(rand.NewSource(1)).Read(corpus)
	f.Add(corpus)
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 96 {
			data = data[:96] // bound each exec; the oracle re-folds every step
		}
		runScript(t, data, false)
		runScript(t, data, true)
	})
}
