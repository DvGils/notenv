// Package secrets assembles a namespace's secrets from the objects a backend
// holds for it: an append-only set of per-write segments over zero or more
// folded snapshots. Each write appends a new, uniquely named segment, so
// concurrent writers never overwrite one another. Reads fold the snapshots and
// segments together by a Lamport clock — last write per key wins, ties between
// machines are reported as conflicts. Compaction collapses what it reads into a
// fresh snapshot and deletes the objects it folded.
//
// Every object is one age message sealed under the master key. The layout
// (segment vs snapshot, ordering, provenance) lives in object names and
// authenticated payloads, never in plaintext on the wire.
package secrets

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/DvGils/notenv/internal/backend"
	"github.com/DvGils/notenv/internal/crypto"
)

// formatVersion is the on-storage schema version of segment and snapshot objects
// (the secret values). Every object written carries it; a read rejects any
// object stamped with a different version — higher means a newer notenv wrote
// it, absent (0) means a pre-0.4 layout this notenv no longer reads (compact
// with 0.4 first, or re-set the values). The key header (internal/crypto) is
// versioned separately by the same exact-match rule. Bump only on an
// incompatible change to these payloads.
const formatVersion = 1

// segment is one append: a single key write or deletion, ordered across
// machines by a Lamport clock and, within a machine, by Seq.
type segment struct {
	Version int    `json:"v"`
	Machine string `json:"machine"`
	Seq     int    `json:"seq"`
	Lamport int    `json:"lamport"`
	Key     string `json:"key"`
	Value   string `json:"value,omitempty"`
	Deleted bool   `json:"deleted,omitempty"`
}

// entry is one key's winning write in a snapshot, carrying the provenance
// needed to merge the snapshot deterministically against later segments.
type entry struct {
	Value   string `json:"value"`
	Lamport int    `json:"lamport"`
	Machine string `json:"machine"`
	Seq     int    `json:"seq"`
}

// snapshot is a folded namespace state: every live key with its provenance, and
// the highest Lamport it folded in.
type snapshot struct {
	Version int              `json:"v"`
	Lamport int              `json:"lamport"`
	Entries map[string]entry `json:"entries"`
}

// Namespace reads and writes one namespace's secrets through a backend, sealing
// every object under master. machine identifies and orders this machine's
// writes so two machines never produce the same segment.
type Namespace struct {
	store   backend.Backend
	name    string
	master  *crypto.MasterKey
	machine string
}

// For binds a namespace to a backend and master key.
func For(store backend.Backend, name string, master *crypto.MasterKey, machine string) *Namespace {
	return &Namespace{store: store, name: name, master: master, machine: machine}
}

// DefaultCompactThreshold is the segment count at or above which a write
// triggers automatic compaction. It bounds the objects a cold read folds, so
// reads stay fast without anyone running `notenv compact` by hand.
const DefaultCompactThreshold = 16

// State is a folded namespace: the resolved secrets and any same-key conflicts
// detected during the fold. lamport is the highest Lamport folded, the basis
// for the next write's clock; segments is how many segment objects it folded.
type State struct {
	Secrets   map[string]string
	Conflicts []Conflict
	lamport   int
	segments  int
}

// Conflict reports a key written concurrently on more than one machine (equal
// Lamport). Winner's value is the one kept; the others are shadowed but remain
// recoverable from their segments until the next compaction.
type Conflict struct {
	Key      string
	Winner   string
	Shadowed []string
}

func (n *Namespace) prefix() string { return n.name + "/" }

// HasHistory reports whether any write has ever been folded into this state;
// false means the namespace is untouched (distinct from one emptied by deletes).
func (s *State) HasHistory() bool { return s.lamport > 0 }

// SegmentCount is how many uncompacted segment objects this fold read, the
// signal a caller uses to decide whether the next write should compact.
func (s *State) SegmentCount() int { return s.segments }

// Exists reports whether a namespace has any stored object yet. It only lists,
// so it needs no master key.
func Exists(ctx context.Context, store backend.Backend, name string) (bool, error) {
	keys, err := store.List(ctx, name+"/")
	if err != nil {
		return false, err
	}
	return len(keys) > 0, nil
}

// Fold reads every object in the namespace and resolves the current secrets.
func (n *Namespace) Fold(ctx context.Context) (*State, error) {
	l, err := n.load(ctx)
	if err != nil {
		return nil, err
	}
	acc, maxLamport := accumulate(l)
	state := &State{Secrets: map[string]string{}, lamport: maxLamport, segments: len(l.segKeys)}
	for key, w := range acc {
		if !w.deleted {
			state.Secrets[key] = w.value
		}
		if len(w.tied) > 1 {
			state.Conflicts = append(state.Conflicts, w.conflict(key))
		}
	}
	sort.Slice(state.Conflicts, func(i, j int) bool {
		return state.Conflicts[i].Key < state.Conflicts[j].Key
	})
	return state, nil
}

// Append writes one key change as a new segment and returns the resulting
// state plus the object key the segment landed under, so the caller can remove
// the write again if a post-write check (the master-epoch confirm) fails. prev
// is the fold this write builds on; its Lamport sets the new clock.
func (n *Namespace) Append(ctx context.Context, prev *State, seq int, key, value string, deleted bool) (*State, string, error) {
	seg := segment{
		Version: formatVersion,
		Machine: n.machine,
		Seq:     seq,
		Lamport: prev.lamport + 1,
		Key:     key,
		Value:   value,
		Deleted: deleted,
	}
	raw, err := json.Marshal(seg)
	if err != nil {
		return nil, "", err
	}
	sealed, err := n.master.Encrypt(raw)
	if err != nil {
		return nil, "", err
	}
	objKey, err := n.objectKey("seg-" + n.machine)
	if err != nil {
		return nil, "", err
	}
	if err := n.putVerified(ctx, objKey, sealed); err != nil {
		return nil, "", err
	}
	return prev.with(seg), objKey, nil
}

// Compact folds the namespace into a single fresh snapshot and removes the
// objects it folded. It writes the new snapshot before deleting anything and
// only deletes objects it read, so a write that lands concurrently — under a
// name it never listed — is never lost. Running two compactions against one
// namespace at the same time is safe but wasteful; coordinate them.
//
// confirm, if non-nil, runs after the snapshot is written and verified but
// before anything is deleted. If it errors, Compact removes its own snapshot
// and returns the error with the namespace untouched. The caller uses it to
// confirm the master it sealed the snapshot with is still the vault's master:
// without the check, a compaction racing a master rotation could collapse the
// whole namespace into a snapshot only the superseded key can open.
func (n *Namespace) Compact(ctx context.Context, confirm func() error) error {
	l, err := n.load(ctx)
	if err != nil {
		return err
	}
	if len(l.segments) == 0 && len(l.snapshots) <= 1 {
		return nil // already a single snapshot, nothing to fold
	}

	sealed, err := n.master.Encrypt(mustMarshal(foldSnapshot(l)))
	if err != nil {
		return err
	}
	key, err := n.objectKey("snap")
	if err != nil {
		return err
	}
	// Write and verify the snapshot before removing what it subsumes, so a
	// botched write leaves the namespace untouched rather than half-collapsed.
	if err := n.putVerified(ctx, key, sealed); err != nil {
		return err
	}
	if confirm != nil {
		if err := confirm(); err != nil {
			_ = n.store.Delete(ctx, key) // undo our own snapshot; originals are intact
			return fmt.Errorf("compaction abandoned before deleting anything: %w", err)
		}
	}
	for _, folded := range append(l.snapKeys, l.segKeys...) {
		if err := n.store.Delete(ctx, folded); err != nil {
			return fmt.Errorf("remove %s after compaction: %w", folded, err)
		}
	}
	return nil
}

// loaded holds a namespace's decrypted objects and the keys they came from.
type loaded struct {
	snapshots []snapshot
	segments  []segment
	snapKeys  []string
	segKeys   []string
}

func (n *Namespace) load(ctx context.Context) (*loaded, error) {
	keys, err := n.store.List(ctx, n.prefix())
	if err != nil {
		return nil, err
	}
	var l loaded
	for _, key := range keys {
		base := strings.TrimPrefix(key, n.prefix())
		switch {
		case strings.HasPrefix(base, "snap-"):
			var s snapshot
			if err := n.openInto(ctx, key, &s); err != nil {
				return nil, err
			}
			if err := checkFormat(s.Version, key); err != nil {
				return nil, err
			}
			l.snapshots = append(l.snapshots, s)
			l.snapKeys = append(l.snapKeys, key)
		case strings.HasPrefix(base, "seg-"):
			var s segment
			if err := n.openInto(ctx, key, &s); err != nil {
				return nil, err
			}
			if err := checkFormat(s.Version, key); err != nil {
				return nil, err
			}
			l.segments = append(l.segments, s)
			l.segKeys = append(l.segKeys, key)
		}
	}
	return &l, nil
}

func (n *Namespace) openInto(ctx context.Context, key string, v any) error {
	blob, err := n.store.Get(ctx, key)
	if err != nil {
		return err
	}
	plain, err := n.master.Decrypt(blob)
	if err != nil {
		// Name the object: when one undecryptable object poisons a fold, the
		// recovery (inspect or remove it with rclone) starts from its key.
		return fmt.Errorf("object %s: %w", key, err)
	}
	if err := json.Unmarshal(plain, v); err != nil {
		return fmt.Errorf("corrupt object %s: %w", key, err)
	}
	return nil
}

// checkFormat rejects an object this build cannot faithfully read: a higher
// version was written by a newer notenv, and an absent version (0) by a
// pre-0.4 one.
func checkFormat(version int, key string) error {
	switch {
	case version > formatVersion:
		return fmt.Errorf("%s was written by a newer notenv (format v%d, this build understands up to v%d); upgrade notenv", key, version, formatVersion)
	case version < 1:
		return fmt.Errorf("%s carries no format version (written by a pre-0.4 notenv); compact the namespace with notenv 0.4 to rewrite it, or re-add its values with `notenv set`", key)
	}
	return nil
}

// objectKey builds a unique key under the namespace from a name prefix and a
// random suffix, so no two writes ever collide on a name.
func (n *Namespace) objectKey(prefix string) (string, error) {
	buf := make([]byte, 6)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s%s-%s.age", n.prefix(), prefix, hex.EncodeToString(buf)), nil
}

// putVerified writes sealed at key and reads it back. Because reads fail closed
// on any unreadable object (a dropped or tampered write must not be silently
// skipped), a botched write would otherwise poison every later fold; this stops
// a genuinely corrupt object from being left behind. It deletes only on a real
// byte mismatch: a read-back that merely errors could be read-after-write lag,
// and deleting a write that may have landed is the wrong reflex, so it surfaces
// the error and leaves the object for the caller to retry over.
func (n *Namespace) putVerified(ctx context.Context, key string, sealed []byte) error {
	if err := n.store.Put(ctx, key, sealed); err != nil {
		return err
	}
	got, err := n.store.Get(ctx, key)
	if err != nil {
		return fmt.Errorf("verify %s after write: %w", key, err)
	}
	if !bytes.Equal(got, sealed) {
		// The backend stored different bytes than we sent: a corrupt write.
		_ = n.store.Delete(ctx, key)
		return fmt.Errorf("object %s read back corrupted; write not recorded", key)
	}
	return nil
}

// winner tracks the leading write for a key during a fold.
type winner struct {
	value   string
	machine string
	seq     int
	lamport int
	deleted bool
	tied    map[string]struct{} // machines that wrote at the leading Lamport
}

// accumulate replays a namespace's snapshots and segments into the winning
// write per key (last write wins by Lamport, then machine, then Seq) and
// returns the highest Lamport seen.
func accumulate(l *loaded) (map[string]*winner, int) {
	acc := map[string]*winner{}
	maxLamport := 0
	apply := func(key, value, machine string, seq, lamport int, deleted bool) {
		if lamport > maxLamport {
			maxLamport = lamport
		}
		w := acc[key]
		if w == nil {
			acc[key] = &winner{value: value, machine: machine, seq: seq, lamport: lamport, deleted: deleted, tied: map[string]struct{}{machine: {}}}
			return
		}
		switch {
		case lamport > w.lamport:
			*w = winner{value: value, machine: machine, seq: seq, lamport: lamport, deleted: deleted, tied: map[string]struct{}{machine: {}}}
		case lamport == w.lamport:
			w.tied[machine] = struct{}{}
			if leads(machine, seq, w.machine, w.seq) {
				w.value, w.machine, w.seq, w.deleted = value, machine, seq, deleted
			}
		}
	}
	for _, s := range l.snapshots {
		// A snapshot's clock can outlive its entries: a delete folded into it
		// leaves a higher Lamport than any surviving entry. Carry it forward so
		// the next write's clock never regresses (and re-compaction preserves it).
		if s.Lamport > maxLamport {
			maxLamport = s.Lamport
		}
		for key, e := range s.Entries {
			apply(key, e.Value, e.Machine, e.Seq, e.Lamport, false)
		}
	}
	for _, s := range l.segments {
		apply(s.Key, s.Value, s.Machine, s.Seq, s.Lamport, s.Deleted)
	}
	return acc, maxLamport
}

// foldSnapshot accumulates a namespace into a snapshot of its live keys,
// dropping tombstones (their job is done once nothing older survives).
func foldSnapshot(l *loaded) snapshot {
	acc, maxLamport := accumulate(l)
	s := snapshot{Version: formatVersion, Lamport: maxLamport, Entries: map[string]entry{}}
	for key, w := range acc {
		if w.deleted {
			continue
		}
		s.Entries[key] = entry{Value: w.value, Lamport: w.lamport, Machine: w.machine, Seq: w.seq}
	}
	return s
}

// leads reports whether write a outranks write b at an equal Lamport: higher
// machine id wins, then higher sequence number, giving every machine the same
// deterministic winner.
func leads(aMachine string, aSeq int, bMachine string, bSeq int) bool {
	if aMachine != bMachine {
		return aMachine > bMachine
	}
	return aSeq > bSeq
}

func (w *winner) conflict(key string) Conflict {
	shadowed := make([]string, 0, len(w.tied)-1)
	for machine := range w.tied {
		if machine != w.machine {
			shadowed = append(shadowed, machine)
		}
	}
	sort.Strings(shadowed)
	return Conflict{Key: key, Winner: w.machine, Shadowed: shadowed}
}

// with returns the state after applying one freshly written segment: the
// segment is now the sole leader for its key, clearing any prior conflict there.
func (s *State) with(seg segment) *State {
	next := &State{Secrets: make(map[string]string, len(s.Secrets)), lamport: seg.Lamport}
	for key, value := range s.Secrets {
		next.Secrets[key] = value
	}
	if seg.Deleted {
		delete(next.Secrets, seg.Key)
	} else {
		next.Secrets[seg.Key] = seg.Value
	}
	for _, c := range s.Conflicts {
		if c.Key != seg.Key {
			next.Conflicts = append(next.Conflicts, c)
		}
	}
	return next
}

// mustMarshal serializes a value that cannot fail to marshal (plain structs of
// strings, ints, and maps thereof).
func mustMarshal(v any) []byte {
	data, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return data
}
