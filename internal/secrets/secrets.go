// Package secrets assembles a namespace's secrets from the objects a backend
// holds for it: an append-only set of per-write segments over zero or more
// folded snapshots. Each write appends a new, uniquely named segment, so
// concurrent writers never overwrite one another. Reads fold the snapshots and
// segments together by a Lamport clock: last write per key wins, ties between
// machines are reported as conflicts. Compaction collapses what it reads into a
// fresh snapshot and deletes the objects it folded.
//
// Every object is one age message sealed under the master key, and every
// object is bound to the vault's authenticated header by a manifest entry (a
// keyed MAC of its plaintext, see internal/crypto). A fold trusts the
// manifest, not the storage listing: a manifest-listed object that is missing,
// altered, or relocated is an alarm, and an object the manifest does not know
// is folded in only when it can be nothing but an honest in-flight write.
package secrets

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"

	"github.com/DvGils/notenv/internal/backend"
	"github.com/DvGils/notenv/internal/crypto"
)

// formatVersion is the on-storage schema version of segment and snapshot
// objects (the secret values). Every object written carries it; a read rejects
// any object stamped with a different version: higher means a newer notenv
// wrote it, lower means an older layout this notenv no longer reads. The key
// header (internal/crypto) is versioned separately by the same exact-match
// rule. Bump only on an incompatible change to these payloads.
//
// Version 2 added Object: the key the payload was written under, checked
// against the key it was fetched from, so a master-sealed object copied to
// another name (or namespace) can never pass as that name.
const formatVersion = 2

// segment is one append: a single key write or deletion, ordered across
// machines by a Lamport clock and, within a machine, by Seq. Description and
// TS are advisory metadata riding the write: TS is wall-clock Unix seconds
// (clocks lie, so it is never used for ordering; Lamport is the truth), and
// both are carried into snapshot entries so compaction preserves them.
type segment struct {
	Version     int    `json:"v"`
	Object      string `json:"object"`
	Machine     string `json:"machine"`
	Seq         int    `json:"seq"`
	Lamport     int    `json:"lamport"`
	Key         string `json:"key"`
	Value       string `json:"value,omitempty"`
	Deleted     bool   `json:"deleted,omitempty"`
	Description string `json:"desc,omitempty"`
	TS          int64  `json:"ts,omitempty"`
}

// entry is one key's winning write in a snapshot, carrying the provenance
// needed to merge the snapshot deterministically against later segments, plus
// the write's advisory metadata; without it here, the first compaction would
// destroy every description and timestamp.
type entry struct {
	Value       string `json:"value"`
	Lamport     int    `json:"lamport"`
	Machine     string `json:"machine"`
	Seq         int    `json:"seq"`
	Description string `json:"desc,omitempty"`
	TS          int64  `json:"ts,omitempty"`
}

// snapshot is a folded namespace state: every live key with its provenance,
// the highest Lamport it folded in, and each machine's highest folded seq.
// Seqs is what makes replay detection exact: a machine's seqs only move
// forward, so a stray segment at or below its machine's mark can only be a
// deleted object someone put back (see classify).
type snapshot struct {
	Version int              `json:"v"`
	Object  string           `json:"object"`
	Lamport int              `json:"lamport"`
	Seqs    map[string]int   `json:"seqs"`
	Entries map[string]entry `json:"entries"`
}

// Namespace reads and writes one namespace's secrets through a backend, sealing
// every object under master. machine identifies and orders this machine's
// writes so two machines never produce the same segment. manifest is the
// verified header's object manifest; folds check every object against it.
type Namespace struct {
	store    backend.Backend
	name     string
	master   *crypto.MasterKey
	machine  string
	manifest map[string]crypto.ManifestEntry
}

// For binds a namespace to a backend, master key, and the verified header's
// manifest.
func For(store backend.Backend, name string, master *crypto.MasterKey, machine string, manifest map[string]crypto.ManifestEntry) *Namespace {
	return &Namespace{store: store, name: name, master: master, machine: machine, manifest: manifest}
}

// DefaultCompactThreshold is the segment count at or above which a write
// triggers automatic compaction. It bounds the objects a cold read folds, so
// reads stay fast without anyone running `notenv compact` by hand.
const DefaultCompactThreshold = 16

// Meta is a live key's advisory metadata: what the secret is for and when its
// winning write happened (wall-clock Unix seconds; 0 means the write predates
// timestamps). Advisory means exactly that: nothing orders or trusts by it.
type Meta struct {
	Description string
	TS          int64
}

// State is a folded namespace: the resolved secrets and any same-key conflicts
// detected during the fold. lamport is the highest Lamport folded, the basis
// for the next write's clock; segments is how many segment objects it folded.
type State struct {
	Secrets   map[string]string
	Meta      map[string]Meta
	Conflicts []Conflict
	// Adoptable lists objects the fold trusted as honest in-flight writes (see
	// classify) but the manifest does not record yet, with the entries a writer
	// should add to adopt them.
	Adoptable map[string]crypto.ManifestEntry
	// Prunable lists manifest entries marked folded whose objects are confirmed
	// gone; any writer may drop them.
	Prunable []string
	// Strays lists unknown snapshots the fold ignored (a compaction that crashed
	// between writing its snapshot and recording it); `notenv compact` removes
	// them.
	Strays []string

	lamport  int
	segments int
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
	state := &State{
		Secrets:   map[string]string{},
		Meta:      map[string]Meta{},
		Adoptable: l.adoptable,
		Prunable:  l.prunable,
		Strays:    l.strays,
		lamport:   maxLamport,
		segments:  len(l.segKeys),
	}
	for key, w := range acc {
		if !w.deleted {
			state.Secrets[key] = w.value
			state.Meta[key] = Meta{Description: w.description, TS: w.ts}
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

// Write is one key change to append: a value (with optional advisory
// metadata) or a deletion. TS is the write's wall-clock Unix seconds, supplied
// by the caller so this package never reads a clock; 0 omits it.
type Write struct {
	Key         string
	Value       string
	Description string
	TS          int64
	Deleted     bool
}

// Append writes one key change as a new segment and returns the resulting
// state, the object key the segment landed under (so the caller can remove the
// write again if recording it in the manifest fails), and the manifest entry
// that records it. prev is the fold this write builds on; its Lamport sets the
// new clock.
func (n *Namespace) Append(ctx context.Context, prev *State, seq int, w Write) (*State, string, crypto.ManifestEntry, error) {
	objKey, err := n.objectKey("seg-" + n.machine)
	if err != nil {
		return nil, "", crypto.ManifestEntry{}, err
	}
	seg := segment{
		Version:     formatVersion,
		Object:      objKey,
		Machine:     n.machine,
		Seq:         seq,
		Lamport:     prev.lamport + 1,
		Key:         w.Key,
		Value:       w.Value,
		Deleted:     w.Deleted,
		Description: w.Description,
		TS:          w.TS,
	}
	raw, err := json.Marshal(seg)
	if err != nil {
		return nil, "", crypto.ManifestEntry{}, err
	}
	mac, err := n.master.ObjectMAC(raw)
	if err != nil {
		return nil, "", crypto.ManifestEntry{}, err
	}
	sealed, err := n.master.Encrypt(raw)
	if err != nil {
		return nil, "", crypto.ManifestEntry{}, err
	}
	if err := putVerified(ctx, n.store, objKey, sealed); err != nil {
		return nil, "", crypto.ManifestEntry{}, err
	}
	return prev.with(seg), objKey, crypto.ManifestEntry{MAC: mac}, nil
}

// Compact folds the namespace into a single fresh snapshot and removes the
// objects it folded, adopting any in-flight writes it found along the way. It
// writes the new snapshot before deleting anything and only deletes objects it
// read, so a write that lands concurrently (under a name it never listed) is
// never lost.
//
// commit makes the snapshot authoritative: it must apply the given manifest
// delta to the vault header (under the compare-and-swap, which also confirms
// the master this compaction sealed with is still the vault's master). If it
// errors, Compact removes its own snapshot and returns with the namespace
// untouched. After the subsumed objects are deleted, commit is called once
// more, best-effort, to prune their now-pointless entries.
func (n *Namespace) Compact(ctx context.Context, commit func(crypto.ManifestDelta) error) error {
	l, err := n.load(ctx)
	if err != nil {
		return err
	}
	needFold := len(l.segments) > 0 || len(l.snapshots) > 1
	if !needFold && len(l.prunable) == 0 && len(l.deadwood) == 0 && len(l.strays) == 0 {
		return nil // already a single recorded snapshot, nothing to do
	}

	delta := crypto.ManifestDelta{Prune: l.prunable}
	var snapKey string
	if needFold {
		if snapKey, err = n.writeSnapshot(ctx, l, &delta); err != nil {
			return err
		}
	}
	if !delta.Empty() {
		if err := commit(delta); err != nil {
			if snapKey != "" {
				_ = n.store.Delete(ctx, snapKey) // undo our own snapshot; originals are intact
			}
			return fmt.Errorf("compaction abandoned before deleting anything: %w", err)
		}
	}
	return n.sweep(ctx, l, needFold, commit)
}

// sweep deletes everything a compaction has made redundant and best-effort
// commits the prune of their entries. By this point everything subsumed is
// marked folded in the manifest, so deletion is safe at any pace: deadwood
// (left by an earlier interrupted run) and strays (snapshots no compaction
// recorded) go too. The objects this run folded are doomed only when a new
// snapshot actually subsumed them; strays never had an entry to prune.
func (n *Namespace) sweep(ctx context.Context, l *loaded, needFold bool, commit func(crypto.ManifestDelta) error) error {
	var doomed []string
	if needFold {
		doomed = append(append(doomed, l.snapKeys...), l.segKeys...)
	}
	doomed = append(append(doomed, l.deadwood...), l.strays...)
	var prune []string
	for _, gone := range doomed {
		if err := n.store.Delete(ctx, gone); err != nil {
			return fmt.Errorf("remove %s after compaction: %w (its manifest entry stays marked folded; a later compaction cleans it up)", gone, err)
		}
		if !slices.Contains(l.strays, gone) {
			prune = append(prune, gone)
		}
	}
	if len(prune) > 0 {
		_ = commit(crypto.ManifestDelta{Prune: prune}) // best-effort tidy-up
	}
	return nil
}

// writeSnapshot folds l into a fresh verified snapshot object and extends the
// delta that makes it authoritative: the snapshot's entry, plus every subsumed
// object marked folded (adopted in-flight writes get their first entry already
// folded: the snapshot subsumes them the moment it is recorded).
func (n *Namespace) writeSnapshot(ctx context.Context, l *loaded, delta *crypto.ManifestDelta) (string, error) {
	snapKey, err := n.objectKey("snap")
	if err != nil {
		return "", err
	}
	snap := foldSnapshot(l)
	snap.Object = snapKey
	plain := mustMarshal(snap)
	mac, err := n.master.ObjectMAC(plain)
	if err != nil {
		return "", err
	}
	sealed, err := n.master.Encrypt(plain)
	if err != nil {
		return "", err
	}
	// Write and verify the snapshot before removing what it subsumes, so a
	// botched write leaves the namespace untouched rather than half-collapsed.
	if err := putVerified(ctx, n.store, snapKey, sealed); err != nil {
		return "", err
	}
	delta.Add = map[string]crypto.ManifestEntry{snapKey: {MAC: mac}}
	for _, folded := range append(append([]string{}, l.snapKeys...), l.segKeys...) {
		if adopted, ok := l.adoptable[folded]; ok {
			delta.Add[folded] = crypto.ManifestEntry{MAC: adopted.MAC, Folded: true}
		} else {
			delta.Fold = append(delta.Fold, folded)
		}
	}
	return snapKey, nil
}

// loaded holds a namespace's decrypted objects, the keys they came from, and
// what the fold's classification found around them.
type loaded struct {
	snapshots []snapshot
	segments  []segment
	snapKeys  []string
	segKeys   []string

	adoptable map[string]crypto.ManifestEntry
	prunable  []string
	deadwood  []string
	strays    []string
}

// foldedSeq is machine's seq high-water mark across the recorded snapshots:
// everything that machine wrote up to it has been folded.
func (l *loaded) foldedSeq(machine string) int {
	mark := 0
	for _, s := range l.snapshots {
		mark = max(mark, s.Seqs[machine])
	}
	return mark
}

// load assembles the namespace from its manifest entries, then classifies
// whatever else the listing shows. The manifest, not the listing, is the
// source of truth: a listed-but-unrecorded object is the exception that has to
// prove itself, never silently equal to a recorded one.
func (n *Namespace) load(ctx context.Context) (*loaded, error) {
	l := &loaded{adoptable: map[string]crypto.ManifestEntry{}}

	live, folded := n.manifestKeys()
	for _, key := range live {
		if err := n.openRecorded(ctx, l, key); err != nil {
			return nil, err
		}
	}

	listed, err := n.store.List(ctx, n.prefix())
	if err != nil {
		return nil, err
	}
	sort.Strings(listed)
	present := map[string]bool{}
	for _, key := range listed {
		present[key] = true
		if _, ok := n.manifest[key]; ok {
			continue // recorded: live ones were opened above, folded ones are dead weight awaiting deletion
		}
		if err := n.classify(ctx, l, key); err != nil {
			return nil, err
		}
	}
	// Folded entries split by whether their object still exists: a gone object
	// frees its entry (prunable), a present one awaits deletion (deadwood).
	for _, key := range folded {
		if present[key] {
			l.deadwood = append(l.deadwood, key)
		} else {
			l.prunable = append(l.prunable, key)
		}
	}
	sort.Strings(l.prunable)
	return l, nil
}

// manifestKeys splits this namespace's manifest entries into live and folded
// object keys, sorted for deterministic processing.
func (n *Namespace) manifestKeys() (live, folded []string) {
	for key, e := range n.manifest {
		if !strings.HasPrefix(key, n.prefix()) {
			continue
		}
		if e.Folded {
			folded = append(folded, key)
		} else {
			live = append(live, key)
		}
	}
	sort.Strings(live)
	sort.Strings(folded)
	return live, folded
}

// openRecorded opens one live manifest entry's object and folds it into l.
// Everything the manifest promises is enforced here: the object must exist,
// open under the master, match its recorded MAC, and carry its own key.
func (n *Namespace) openRecorded(ctx context.Context, l *loaded, key string) error {
	blob, err := n.store.Get(ctx, key)
	if errors.Is(err, backend.ErrNotFound) {
		return fmt.Errorf("object %s is recorded in the vault manifest but missing from storage: a write was deleted or withheld (if another machine is compacting right now, re-run)", key)
	}
	if err != nil {
		return err
	}
	plain, err := n.master.Decrypt(blob)
	if err != nil {
		return fmt.Errorf("object %s: %w", key, err)
	}
	if err := n.master.CheckObjectMAC(plain, n.manifest[key].MAC); err != nil {
		return fmt.Errorf("object %s: %w", key, err)
	}
	return n.fold(l, key, plain)
}

// classify decides what an object the manifest does not know is allowed to be.
// The only honest explanation for a stray segment is a write whose manifest
// update has not landed (still in flight, lost the swap race, or its writer
// crashed): such a segment opens under the current master and carries a seq
// above its machine's folded high-water mark, and is folded in and reported
// adoptable. A stray segment at or below the mark can only be a deleted object
// someone put back: the machine's own seqs already moved past it, and every
// honest write is preceded by a fold that adopts whatever in-flight segments
// exist before the seq can advance over them. Stray snapshots are reported for
// cleanup without any further judgment, undecipherable ones included: no fold
// ever reads an unrecorded snapshot, so it cannot affect a value, and alarming
// would turn an honest crashed compaction overtaken by a re-key into a
// permanent false positive. Everything else is evidence and fails the fold.
func (n *Namespace) classify(ctx context.Context, l *loaded, key string) error {
	base := strings.TrimPrefix(key, n.prefix())
	isSeg := strings.HasPrefix(base, "seg-")
	if !isSeg && !strings.HasPrefix(base, "snap-") {
		return nil // not a payload object; nothing folds it, so it can't carry a value
	}
	if !isSeg {
		l.strays = append(l.strays, key)
		return nil
	}
	blob, err := n.store.Get(ctx, key)
	if errors.Is(err, backend.ErrNotFound) {
		return nil // vanished between list and read: an in-flight writer undid it
	}
	if err != nil {
		return err
	}
	plain, err := n.master.Decrypt(blob)
	if err != nil {
		return fmt.Errorf("object %s is not recorded in the vault manifest and does not open under the current master key (left over from a write interrupted by a re-key, or planted); inspect it and remove it, e.g. `rclone deletefile`: %w", key, err)
	}
	seg, err := n.intoSegment(key, plain)
	if err != nil {
		return err
	}
	if seg.Seq <= l.foldedSeq(seg.Machine) {
		return fmt.Errorf("object %s is not recorded in the vault manifest, and machine %s's writes up to its seq are already folded: it looks like a deleted write that was put back (replayed); remove it to continue, e.g. `rclone deletefile`", key, seg.Machine)
	}
	mac, err := n.master.ObjectMAC(plain)
	if err != nil {
		return err
	}
	l.segments = append(l.segments, seg)
	l.segKeys = append(l.segKeys, key)
	l.adoptable[key] = crypto.ManifestEntry{MAC: mac}
	return nil
}

// fold parses a recorded object's plaintext into l under its kind's rules.
func (n *Namespace) fold(l *loaded, key string, plain []byte) error {
	if strings.HasPrefix(strings.TrimPrefix(key, n.prefix()), "snap-") {
		snap, err := n.intoSnapshot(key, plain)
		if err != nil {
			return err
		}
		l.snapshots = append(l.snapshots, snap)
		l.snapKeys = append(l.snapKeys, key)
		return nil
	}
	seg, err := n.intoSegment(key, plain)
	if err != nil {
		return err
	}
	l.segments = append(l.segments, seg)
	l.segKeys = append(l.segKeys, key)
	return nil
}

func (n *Namespace) intoSegment(key string, plain []byte) (segment, error) {
	var seg segment
	if err := json.Unmarshal(plain, &seg); err != nil {
		return segment{}, fmt.Errorf("corrupt object %s: %w", key, err)
	}
	if err := checkPayload(seg.Version, seg.Object, key); err != nil {
		return segment{}, err
	}
	return seg, nil
}

func (n *Namespace) intoSnapshot(key string, plain []byte) (snapshot, error) {
	var snap snapshot
	if err := json.Unmarshal(plain, &snap); err != nil {
		return snapshot{}, fmt.Errorf("corrupt object %s: %w", key, err)
	}
	if err := checkPayload(snap.Version, snap.Object, key); err != nil {
		return snapshot{}, err
	}
	return snap, nil
}

// checkPayload rejects an object this build cannot faithfully trust: a format
// version other than ours (higher: a newer notenv wrote it; lower: upgrade the
// vault), or a payload that names a different object key than it was fetched
// from (a copy or rename is never the object it claims to be).
func checkPayload(version int, object, key string) error {
	switch {
	case version > formatVersion:
		return fmt.Errorf("%s was written by a newer notenv (format v%d, this build understands up to v%d); upgrade notenv", key, version, formatVersion)
	case version < formatVersion:
		return fmt.Errorf("%s was written in an older storage format (v%d) that this version of notenv no longer reads", key, version)
	case object != key:
		return fmt.Errorf("object %s declares it was written as %s: it was copied or renamed, and is not trusted", key, object)
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
func putVerified(ctx context.Context, store backend.Backend, key string, sealed []byte) error {
	if err := store.Put(ctx, key, sealed); err != nil {
		return err
	}
	got, err := store.Get(ctx, key)
	if err != nil {
		return fmt.Errorf("verify %s after write: %w", key, err)
	}
	if !bytes.Equal(got, sealed) {
		// The backend stored different bytes than we sent: a corrupt write.
		_ = store.Delete(ctx, key)
		return fmt.Errorf("object %s read back corrupted; write not recorded", key)
	}
	return nil
}

// winner tracks the leading write for a key during a fold.
type winner struct {
	value       string
	machine     string
	seq         int
	lamport     int
	deleted     bool
	description string
	ts          int64
	tied        map[string]struct{} // machines that wrote at the leading Lamport
}

// lead replaces the winner's write wholesale; metadata rides the winning write.
func (w *winner) lead(e entry, deleted bool) {
	w.value, w.machine, w.seq, w.lamport, w.deleted = e.Value, e.Machine, e.Seq, e.Lamport, deleted
	w.description, w.ts = e.Description, e.TS
}

// accumulate replays a namespace's snapshots and segments into the winning
// write per key (last write wins by Lamport, then machine, then Seq) and
// returns the highest Lamport seen. Writes travel as entries: a snapshot's
// entries directly, a segment reshaped into one.
func accumulate(l *loaded) (map[string]*winner, int) {
	acc := map[string]*winner{}
	maxLamport := 0
	apply := func(key string, e entry, deleted bool) {
		if e.Lamport > maxLamport {
			maxLamport = e.Lamport
		}
		w := acc[key]
		if w == nil {
			w = &winner{tied: map[string]struct{}{}}
			w.lead(e, deleted)
			w.tied[e.Machine] = struct{}{}
			acc[key] = w
			return
		}
		switch {
		case e.Lamport > w.lamport:
			w.lead(e, deleted)
			w.tied = map[string]struct{}{e.Machine: {}}
		case e.Lamport == w.lamport:
			w.tied[e.Machine] = struct{}{}
			if leads(e.Machine, e.Seq, w.machine, w.seq) {
				w.lead(e, deleted)
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
			apply(key, e, false)
		}
	}
	for _, s := range l.segments {
		apply(s.Key, entry{Value: s.Value, Lamport: s.Lamport, Machine: s.Machine, Seq: s.Seq, Description: s.Description, TS: s.TS}, s.Deleted)
	}
	return acc, maxLamport
}

// foldSnapshot accumulates a namespace into a snapshot of its live keys,
// dropping tombstones (their job is done once nothing older survives). The
// per-machine seq marks fold in everything (prior snapshots' marks and every
// segment, tombstones included), so the marks never regress.
func foldSnapshot(l *loaded) snapshot {
	acc, maxLamport := accumulate(l)
	s := snapshot{Version: formatVersion, Lamport: maxLamport, Seqs: map[string]int{}, Entries: map[string]entry{}}
	for _, prior := range l.snapshots {
		for machine, seq := range prior.Seqs {
			s.Seqs[machine] = max(s.Seqs[machine], seq)
		}
	}
	for _, seg := range l.segments {
		s.Seqs[seg.Machine] = max(s.Seqs[seg.Machine], seg.Seq)
	}
	for key, w := range acc {
		if w.deleted {
			continue
		}
		s.Entries[key] = entry{Value: w.value, Lamport: w.lamport, Machine: w.machine, Seq: w.seq, Description: w.description, TS: w.ts}
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
// The classification slices are dropped on purpose: the caller's manifest
// update consumes them alongside the new segment's own entry.
func (s *State) with(seg segment) *State {
	next := &State{Secrets: make(map[string]string, len(s.Secrets)), Meta: make(map[string]Meta, len(s.Meta)), lamport: seg.Lamport}
	maps.Copy(next.Secrets, s.Secrets)
	maps.Copy(next.Meta, s.Meta)
	if seg.Deleted {
		delete(next.Secrets, seg.Key)
		delete(next.Meta, seg.Key)
	} else {
		next.Secrets[seg.Key] = seg.Value
		next.Meta[seg.Key] = Meta{Description: seg.Description, TS: seg.TS}
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
