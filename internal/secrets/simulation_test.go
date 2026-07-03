package secrets_test

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"math/rand"
	"testing"

	"github.com/DvGils/notenv/internal/backend/memstore"
	"github.com/DvGils/notenv/internal/crypto"
	"github.com/DvGils/notenv/internal/secrets"
)

// FuzzMultiWriterCommit drives the commit path under simulated concurrency and
// interrupted uploads, the two conditions a sequential commit fuzz never reaches.
// The sequential FuzzCommitSequence always wins its header swap on the first try,
// so the compare-and-swap RETRY path and the reclaim-under-contention path it
// guards go unexercised; this target forces them by interleaving competing
// commits at swap boundaries, while a seeded fraction of blob uploads fail before
// storing. The concurrency is modeled deterministically (one goroutine, all
// randomness derived from the fuzz input), so a crash replays exactly and the
// last-write-wins oracle stays precise. It checks the same invariants the
// sequential target does, now after racing and failed writes: the namespace reads
// back exactly the model, and storage holds no blob the manifest does not
// reference; and additionally that the header revision only ever advances (no
// rollback).

// errChaosInterrupted models an interrupted upload: a blob Put that fails before
// storing, so the write atomically never lands and the oracle stays exact (a
// failed write is simply a write that did not happen).
var errChaosInterrupted = errors.New("chaos: interrupted upload")

// chaosStore wraps a memstore with two seed-driven behaviors. A blob Put fails
// before storing at putFail probability, exercising recovery around an interrupted
// write. beforeSwap fires before every header compare-and-swap, the seam the
// harness uses to interleave competing commits and so drive the ErrHeaderChanged
// retry path. Everything else forwards to the embedded store. Single-goroutine, so
// memstore's no-concurrent-use rule holds.
type chaosStore struct {
	*memstore.Store
	rng        *rand.Rand
	putFail    float64
	beforeSwap func()
}

func (c *chaosStore) Put(ctx context.Context, key string, data []byte) error {
	if c.putFail > 0 && c.rng.Float64() < c.putFail {
		return errChaosInterrupted
	}
	return c.Store.Put(ctx, key, data)
}

func (c *chaosStore) SwapHeader(ctx context.Context, base, updated []byte) error {
	if c.beforeSwap != nil {
		c.beforeSwap()
	}
	return c.Store.SwapHeader(ctx, base, updated)
}

// wop is one queued write the simulation commits: a set, or a delete.
type wop struct {
	key, val string
	del      bool
}

// multiWriter replays a fuzzed queue of writes against one shared vault as if
// several machines committed concurrently. The concurrency is modeled without
// goroutines: at a top-level commit's first swap it may inject competing commits
// (consuming further queued ops), which land first and leave the top-level
// commit's base stale, so the real Commit takes its ErrHeaderChanged retry,
// re-reads, and re-applies. model is the last-write-wins oracle, updated in the
// exact order commits succeed.
type multiWriter struct {
	ctx     context.Context
	t       *testing.T
	ns      *secrets.Namespace
	rng     *rand.Rand
	ops     []wop
	cursor  int
	model   map[string]string
	lastRev int
	armed   bool
}

func (m *multiWriter) run() {
	for m.cursor < len(m.ops) {
		op := m.ops[m.cursor]
		m.cursor++
		m.armed = true // one injection opportunity per top-level commit
		m.commitOp(op)
		m.armed = false
	}
}

// maybeInject is chaosStore.beforeSwap. At the first swap of a top-level commit it
// may run a few queued ops as competing commits, then disarms so the top-level
// commit's retry and the nested commits do not recurse into more injection.
func (m *multiWriter) maybeInject() {
	if !m.armed {
		return
	}
	m.armed = false
	for n := m.rng.Intn(3); n > 0 && m.cursor < len(m.ops); n-- {
		op := m.ops[m.cursor]
		m.cursor++
		m.commitOp(op)
	}
}

// commitOp runs one real Commit. An interrupted upload is a write that did not
// land (model unchanged); any other error is a bug. On success it updates the LWW
// oracle and asserts the revision advanced (anti-rollback).
func (m *multiWriter) commitOp(op wop) {
	w := secrets.Write{Key: op.key, Value: op.val, Deleted: op.del}
	_, h, err := m.ns.Commit(m.ctx, func(cur *secrets.State) (*secrets.State, error) {
		return cur.Apply([]secrets.Write{w}), nil
	}, nil)
	if errors.Is(err, errChaosInterrupted) {
		return
	}
	if err != nil {
		m.t.Fatalf("commit %+v: %v", op, err)
	}
	if op.del {
		delete(m.model, op.key)
	} else {
		m.model[op.key] = op.val
	}
	if h.Revision <= m.lastRev {
		m.t.Fatalf("revision did not advance: %d after %d (a rollback)", h.Revision, m.lastRev)
	}
	m.lastRev = h.Revision
}

func FuzzMultiWriterCommit(f *testing.F) {
	f.Add([]byte{0x01, 0x00, 0x11, 0x02, 0x21, 0x01, 0x00, 0x00})
	f.Add([]byte{0x05, 0x00, 0x05, 0x01, 0x05, 0x02, 0x05, 0x03})
	f.Add([]byte{0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00}) // one key, contended
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, script []byte) {
		ctx := context.Background()
		mem, mk := seededFast(t)
		// Derive all randomness from the script so a crashing input replays exactly.
		hsh := fnv.New64a()
		_, _ = hsh.Write(script)
		seed := int64(hsh.Sum64())
		cs := &chaosStore{Store: mem, rng: rand.New(rand.NewSource(seed)), putFail: 0.1}
		m := &multiWriter{
			ctx:   ctx,
			t:     t,
			ns:    secrets.For(cs, "proj", mk),
			rng:   rand.New(rand.NewSource(seed ^ 0x5eed5eed)),
			model: map[string]string{},
			ops:   parseWops(script),
		}
		cs.beforeSwap = m.maybeInject
		m.run()
		verifyVault(t, ctx, mem, mk, m.model)
	})
}

// parseWops reads two bytes per op (operation, key index) the way
// FuzzCommitSequence does, so the same corpus shape feeds both: a delete one time
// in four, the key drawn from a small set so writes contend.
func parseWops(script []byte) []wop {
	const numKeys = 4
	var ops []wop
	for i := 0; i+1 < len(script); i += 2 {
		op, arg := script[i], script[i+1]
		key := fmt.Sprintf("k%d", int(arg)%numKeys)
		if op%4 == 0 {
			ops = append(ops, wop{key: key, del: true})
		} else {
			ops = append(ops, wop{key: key, val: fmt.Sprintf("v%d", op)})
		}
	}
	return ops
}

// verifyVault asserts the invariants after racing and interrupted writes: the
// namespace reads back exactly the LWW model, and storage holds no blob the
// manifest does not reference.
func verifyVault(t *testing.T, ctx context.Context, mem *memstore.Store, mk *crypto.MasterKey, model map[string]string) {
	t.Helper()
	raw, err := mem.GetHeader(ctx)
	if err != nil {
		t.Fatalf("get header: %v", err)
	}
	header, err := crypto.ParseHeader(raw)
	if err != nil {
		t.Fatalf("parse header: %v", err)
	}
	entry, _ := header.NamespaceEntry("proj")
	got, err := secrets.For(mem, "proj", mk).Read(ctx, entry)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if len(got.Secrets) != len(model) {
		t.Fatalf("read %d secrets, model has %d: %v vs %v", len(got.Secrets), len(model), got.Secrets, model)
	}
	for k, v := range model {
		if got.Secrets[k] != v {
			t.Fatalf("key %q: read %q, model %q", k, got.Secrets[k], v)
		}
	}
	blobs, err := mem.List(ctx, "proj/")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	referenced := map[string]bool{}
	if entry.Blob != "" {
		referenced[entry.Blob] = true
	}
	if entry.Prev != "" {
		referenced[entry.Prev] = true
	}
	for _, b := range blobs {
		if !referenced[b] {
			t.Fatalf("orphan blob %q not referenced by the manifest (entry %+v)", b, entry)
		}
	}
}
