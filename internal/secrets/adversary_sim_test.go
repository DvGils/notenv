package secrets

import (
	"bytes"
	"fmt"
	"math/rand"
	"slices"
	"sort"
	"strings"
	"testing"
)

// adversarySim drives honest machines through arbitrary write/compact/rotate
// histories and then lets a storage-level attacker — write access to the
// objects, no master — make one move. The property under test is the
// manifest's whole reason to exist: no modeled attack changes a folded value
// undetected, and the honest history before it never alarms. Concretely:
// deletions, relocations, and cross-epoch replays must alarm naming the
// object; the storage-level moves that are provably value-neutral (replaying
// a same-epoch re-encryption of the same plaintext, resurrecting a snapshot
// no fold ever reads) must leave every folded value untouched.
type adversarySim struct {
	*rotSim
	// history holds every byte-state each object key has ever been seen in,
	// and gone the last bytes of objects that have been deleted — the
	// attacker's replay material.
	history map[string][][]byte
	gone    map[string][]byte
}

func newAdversarySim(t *testing.T, data []byte) *adversarySim {
	t.Helper()
	// No chaos: the honest baseline must be impeccable, so that an alarm can
	// only ever mean the attack.
	return &adversarySim{
		rotSim:  newRotSim(t, data, 0),
		history: map[string][][]byte{},
		gone:    map[string][]byte{},
	}
}

// observe diffs the namespace's stored objects against everything seen so far,
// extending the attacker's knowledge: an attacker watching storage (or a
// versioned remote) sees every version of every object, including ones later
// deleted.
func (s *adversarySim) observe() {
	listed, err := s.v.cv.List(s.ctx, "proj/")
	if err != nil {
		s.t.Fatal(err)
	}
	present := map[string]bool{}
	for _, key := range listed {
		present[key] = true
		blob, err := s.v.cv.Get(s.ctx, key)
		if err != nil {
			s.t.Fatal(err)
		}
		seen := s.history[key]
		if len(seen) == 0 || !bytes.Equal(seen[len(seen)-1], blob) {
			s.history[key] = append(seen, blob)
		}
		delete(s.gone, key)
	}
	for key, versions := range s.history {
		if !present[key] {
			s.gone[key] = versions[len(versions)-1]
		}
	}
}

// liveRecorded returns the current manifest's live object keys, sorted.
func (s *adversarySim) liveRecorded() []string {
	var keys []string
	for key, e := range s.header().Manifest {
		if !e.Folded {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}

// attack performs one adversary move. It returns the attacked object key and
// whether the move is one of the provably value-neutral ones (caught is then
// "values unchanged" rather than an alarm); "" when there is no material.
func (s *adversarySim) attack(kind, pick int) (key string, neutral bool) {
	switch kind {
	case 0:
		return s.revert(pick)
	case 1: // delete a recorded object: the missing entry must alarm
		keys := s.liveRecorded()
		if len(keys) == 0 {
			return "", false
		}
		key := keys[pick%len(keys)]
		_ = s.v.cv.Delete(s.ctx, key)
		return key, false
	case 2: // resurrect a deleted object
		var keys []string
		for key := range s.gone {
			keys = append(keys, key)
		}
		if len(keys) == 0 {
			return "", false
		}
		sort.Strings(keys)
		key := keys[pick%len(keys)]
		_ = s.v.cv.Put(s.ctx, key, s.gone[key])
		// A resurrected snapshot is ignored by design (no fold ever reads an
		// unrecorded snapshot); a resurrected segment must alarm — it is
		// either below its machine's folded seq mark or sealed under a gone
		// master.
		return key, strings.HasPrefix(strings.TrimPrefix(key, "proj/"), "snap-")
	default: // copy a recorded object to a new name: self-naming must alarm
		keys := s.liveRecorded()
		if len(keys) == 0 {
			return "", false
		}
		src := keys[pick%len(keys)]
		blob, err := s.v.cv.Get(s.ctx, src)
		if err != nil {
			s.t.Fatal(err)
		}
		dst := fmt.Sprintf("proj/seg-evil-%012d.age", pick)
		_ = s.v.cv.Put(s.ctx, dst, blob)
		return dst, false
	}
}

// revert overwrites a recorded object with an older byte-version of itself.
// Objects are write-once, so an older version is either a same-epoch
// re-encryption of the same plaintext (rotation rewrites in place: value
// neutral, must not alarm or change anything) or sealed under a gone master
// (must alarm). Old-epoch material is preferred when both exist.
func (s *adversarySim) revert(pick int) (string, bool) {
	mk := s.v.currentMaster(s.t)
	type option struct {
		key     string
		old     []byte
		neutral bool
	}
	var options []option
	for _, key := range s.liveRecorded() {
		cur, err := s.v.cv.Get(s.ctx, key)
		if err != nil {
			s.t.Fatal(err)
		}
		for _, old := range s.history[key] {
			if bytes.Equal(old, cur) {
				continue
			}
			_, err := mk.Decrypt(old)
			options = append(options, option{key: key, old: old, neutral: err == nil})
		}
	}
	if len(options) == 0 {
		return "", false
	}
	slices.SortStableFunc(options, func(a, b option) int {
		switch {
		case a.neutral == b.neutral:
			return strings.Compare(a.key, b.key)
		case a.neutral:
			return 1
		default:
			return -1
		}
	})
	chosen := options[pick%len(options)]
	_ = s.v.cv.Put(s.ctx, chosen.key, chosen.old)
	return chosen.key, chosen.neutral
}

// assertCaught requires the attack's outcome: an alarm naming the object, or —
// for the value-neutral moves — a clean fold with every value unchanged.
func (s *adversarySim) assertCaught(step int, attacked string, neutral bool, before map[string]string) {
	s.t.Helper()
	mk := s.v.currentMaster(s.t)
	h := s.header()
	st, err := For(s.v.cv, "proj", mk, "observer", h.Manifest).Fold(s.ctx)
	if neutral {
		if err != nil {
			s.t.Fatalf("step %d: value-neutral move on %s must not alarm: %v", step, attacked, err)
		}
		if !sameStringMap(st.Secrets, before) {
			s.t.Fatalf("step %d: value-neutral move on %s changed values: %v -> %v", step, attacked, before, st.Secrets)
		}
		return
	}
	if err == nil {
		s.t.Fatalf("step %d: attack on %s went undetected", step, attacked)
	}
	if !strings.Contains(err.Error(), attacked) {
		s.t.Fatalf("step %d: alarm for the attack on %s does not name it: %v", step, attacked, err)
	}
}

// runAdversaryScript builds an honest history from the script and, when the
// script calls for it, performs one attack and checks the fold catches or
// tolerates it correctly. Scripts that never reach an attack op simply assert
// the honest invariant throughout.
func runAdversaryScript(t *testing.T, data []byte) {
	t.Helper()
	if len(data) == 0 {
		return
	}
	s := newAdversarySim(t, data)

	sc := &byteScript{data: data}
	for step := 0; !sc.done(); step++ {
		m := s.machines[sc.choose(len(s.machines))]
		switch op := sc.choose(14); {
		case op == 0:
			h := s.header()
			s.ensureCurrent(m, h)
			s.adoptView(m)
		case op == 1:
			if err := s.compact(m); err != nil {
				t.Fatalf("step %d: compaction failed in an honest run: %v", step, err)
			}
		case op == 2:
			if !s.rotate() {
				t.Fatalf("step %d: rotation failed in an honest run", step)
			}
		case op >= 10: // one adversary move ends the run
			s.observe()
			before := s.foldCurrent(step).Secrets
			if attacked, neutral := s.attack(op-10, sc.choose(250)); attacked != "" {
				s.assertCaught(step, attacked, neutral, before)
				return
			}
		default:
			key := fmt.Sprintf("K%d", sc.choose(simKeyCount))
			if deleted := sc.choose(4) == 0; deleted {
				s.guardedWrite(m, key, "", true, false)
			} else {
				s.guardedWrite(m, key, fmt.Sprintf("%s-%s-%d", m.id, key, step), false, false)
			}
		}
		s.observe()
		s.foldCurrent(step) // honest history: never an alarm
	}
}

func TestAdversaryLog(t *testing.T) {
	for seed := int64(100); seed < 130; seed++ {
		rng := rand.New(rand.NewSource(seed))
		data := make([]byte, 48)
		_, _ = rng.Read(data)
		runAdversaryScript(t, data)
	}
}

func FuzzAdversaryLog(f *testing.F) {
	corpus := make([]byte, 96)
	_, _ = rand.New(rand.NewSource(3)).Read(corpus)
	f.Add(corpus)
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64 {
			data = data[:64]
		}
		runAdversaryScript(t, data)
	})
}
