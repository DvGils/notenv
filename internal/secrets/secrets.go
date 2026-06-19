// Package secrets stores one namespace's secrets as a single encrypted blob.
// A read decrypts the blob the vault header points at, verifies it against the
// header's manifest MAC, and returns its keys. A write decrypts the current
// blob, applies the change in memory (last write wins per key), writes a new,
// uniquely named blob, and points the header at it under the header
// compare-and-swap (see internal/keymgmt): two concurrent writers serialize on
// that swap, and the loser re-reads the now-current blob and re-applies its
// change, so writes to different keys both survive and only same-key writes
// resolve last-writer-wins.
//
// Writing a fresh blob and only then repointing the header keeps a crash
// harmless: until the swap commits, the header still names the prior blob, which
// is untouched. The write the header just superseded is kept as a
// one-generation backup (the manifest's Prev pointer), so a corrupt or
// bit-rotted current blob can fall back to the last good one, losing at most the
// most recent write. A blob written by a crashed write that never swapped the
// header is an orphan no read ever consults; `notenv doctor` sweeps it.
//
// The blob is one age message sealed under the master key, bound to the vault's
// authenticated header by its manifest MAC (a keyed MAC of its plaintext, see
// internal/crypto) and self-identifying its namespace, so a blob copied to
// another namespace cannot pass as that namespace's.
package secrets

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"unicode"
	"unicode/utf8"

	"github.com/DvGils/notenv/internal/backend"
	"github.com/DvGils/notenv/internal/crypto"
	"github.com/DvGils/notenv/internal/keymgmt"
)

// blobVersion is the on-storage schema version of a namespace blob. Every blob
// carries it; a read rejects any blob stamped with a different version (higher:
// a newer notenv wrote it; lower: an older layout this build no longer reads).
// The key header (internal/crypto) is versioned separately by the same
// exact-match rule. Bump only on an incompatible change to this payload.
//
// Version 2 base64-encodes each entry's value and description (see encodeField):
// v1 stored them as raw JSON strings, where Go's json encoder silently coerces
// invalid UTF-8 to U+FFFD, so a value that was never given back exactly was
// effectively lost. Encoding makes the blob hold opaque bytes, so any stored
// byte is recoverable verbatim; ValidateValue independently gates what may be
// stored, leaving the encoding as the integrity backstop rather than the gate.
//
// Version 3 adds metadata: a namespace-level meta object (description, creation
// and last-modification stamps, and reserved sensitivity/egress defaults) and
// per-secret by/sensitivity/egress fields. The bump is deliberate rather than an
// additive struct extension: an older reader must refuse a v3 blob (fail closed)
// rather than silently drop the new metadata on a rewrite, so the version is
// exact-match. There is no in-place upgrade from v2 (pre-1.0, no stable
// release): `notenv export` from the old binary and `notenv import` into v3.
const blobVersion = 3

// blob is a namespace's whole state: its namespace-level metadata plus every
// live key with its advisory metadata. NS records the namespace it belongs to,
// checked on read so a blob copied from another namespace cannot pass as this one
// (the MAC binds NS, Meta, and the entries alike).
type blob struct {
	Version int               `json:"v"`
	NS      string            `json:"ns"`
	Meta    nsMeta            `json:"meta"`
	Entries map[string]record `json:"entries"`
}

// nsMeta is a namespace's stored metadata (the on-storage form: Description is
// base64 via encodeField, like a record's). All of it is advisory and forgeable
// (single shared master), so nothing orders or trusts by it. Sensitivity and
// Egress are reserved here so the frozen format carries them; they are not
// populated or consumed yet.
type nsMeta struct {
	Description string   `json:"desc,omitempty"`
	Created     int64    `json:"created,omitempty"`
	CreatedBy   string   `json:"created_by,omitempty"`
	Updated     int64    `json:"updated,omitempty"`
	UpdatedBy   string   `json:"updated_by,omitempty"`
	Sensitivity string   `json:"sensitivity,omitempty"`
	Egress      []string `json:"egress,omitempty"`
}

// record is one key's stored value and its advisory metadata. Advisory means
// exactly that: nothing orders or trusts by it. Sensitivity and Egress are
// reserved so the frozen format carries them; they are not populated or consumed
// yet.
type record struct {
	Value       string   `json:"value"`
	Description string   `json:"desc,omitempty"`
	TS          int64    `json:"ts,omitempty"`
	By          string   `json:"by,omitempty"`
	Sensitivity string   `json:"sensitivity,omitempty"`
	Egress      []string `json:"egress,omitempty"`
}

// Namespace reads and writes one namespace's secrets through a backend, sealing
// its blob under master.
type Namespace struct {
	store  backend.Backend
	name   string
	master *crypto.MasterKey
	stamp  Stamp
}

// Stamp is the actor and wall-clock time the command layer attributes a write
// to: who (a label, e.g. user@host) and when (Unix seconds). The secrets package
// never reads a clock or the environment, so the caller supplies both, exactly as
// it already supplies per-Write TS. A zero Stamp (the default when WithStamp is
// not called) leaves the namespace's who/when metadata unset, which a read
// resolves as "unknown"; this is what tests and pure reads get.
type Stamp struct {
	By string
	TS int64
}

// For binds a namespace to a backend and master key.
func For(store backend.Backend, name string, master *crypto.MasterKey) *Namespace {
	return &Namespace{store: store, name: name, master: master}
}

// WithStamp sets the actor and time stamped onto namespace-level metadata
// (created/updated) at the WriteBlob chokepoint, so every write records who last
// changed the namespace and when, with no per-command drift. It returns the
// receiver for chaining: secrets.For(...).WithStamp(s).Commit(...). Per-secret
// `by` rides on each Write, not this.
func (n *Namespace) WithStamp(s Stamp) *Namespace {
	n.stamp = s
	return n
}

// Meta is a live key's advisory metadata: what the secret is for, when its write
// happened (wall-clock Unix seconds; 0 means the write predates timestamps), and
// who last wrote it (By, a label). Sensitivity and Egress are decoded here for
// forward compatibility but are not populated or consumed yet. Advisory means
// exactly that: nothing orders or trusts by it.
type Meta struct {
	Description string
	TS          int64
	By          string
	Sensitivity string
	Egress      []string
}

// NamespaceMeta is a namespace's advisory metadata (the in-memory, decoded form):
// a description, creation and last-modification stamps, and reserved
// sensitivity/egress defaults. Created/Updated are wall-clock Unix seconds (0 =
// unknown). Like Meta, it is advisory and forgeable.
type NamespaceMeta struct {
	Description string
	Created     int64
	CreatedBy   string
	Updated     int64
	UpdatedBy   string
	Sensitivity string
	Egress      []string
}

// State is a namespace's resolved secrets and namespace-level metadata. Corrupt
// is populated only by a salvage read that fell back past an untrustable blob; a
// strict read fails instead of listing.
type State struct {
	Secrets   map[string]string
	Meta      map[string]Meta
	Namespace NamespaceMeta
	Corrupt   []CorruptBlob

	has bool // a blob existed (distinct from a namespace emptied by deletes)
}

// CorruptBlob is a blob a salvage read could not trust and read past: missing
// from storage, undecryptable, or MAC-mismatched. Blob is its object key; Reason
// is the read error that disqualified it.
type CorruptBlob struct {
	Blob   string
	Reason string
}

// Write is one key change to apply: a value (with optional advisory metadata)
// or a deletion. TS is the write's wall-clock Unix seconds, supplied by the
// caller so this package never reads a clock; 0 omits it. KeepDescription
// carries the key's existing description forward instead of setting Description,
// evaluated against the state being applied to (the live blob inside Commit, not
// a stale pre-read), so re-stating a value never reverts a concurrent
// description edit.
type Write struct {
	Key             string
	Value           string
	Description     string
	KeepDescription bool
	TS              int64
	By              string
	Deleted         bool
}

// errCorruptBlob tags a blob a read cannot trust: missing, undecryptable, or
// MAC-mismatched. It is exactly the set a salvage read may fall back past. A
// transient backend error and a format-version skew are deliberately excluded: a
// read blip is not corruption, and a newer format means "upgrade notenv", not
// "this blob rotted".
var errCorruptBlob = errors.New("blob cannot be trusted")

// corruptBlobError carries a human-readable message and matches
// errCorruptBlob under errors.Is, so a salvage read can tell an untrustable
// blob from an error that must still stop the read.
type corruptBlobError struct{ msg string }

func (e *corruptBlobError) Error() string        { return e.msg }
func (e *corruptBlobError) Is(target error) bool { return target == errCorruptBlob }

func corruptBlobf(format string, a ...any) error {
	return &corruptBlobError{msg: fmt.Sprintf(format, a...)}
}

// HasHistory reports whether the namespace has ever stored a blob; false means
// it is untouched (distinct from one emptied by deletes, which still has a blob).
func (s *State) HasHistory() bool { return s.has }

// Exists reports whether a namespace exists in the vault, by consulting the
// authenticated header manifest rather than the raw object listing: a crashed
// write can leave an orphan blob under the namespace prefix that no manifest
// entry references, and that must not read as the namespace existing. Because
// namespaces are persistent, this is true for a namespace that holds no secrets
// too (one created empty, or emptied by deletes), not only one that holds some.
// It needs no master key (parsing the header is enough; the manifest's
// trustworthiness is confirmed at unlock). Virgin storage (no header) reports
// false.
func Exists(ctx context.Context, store backend.HeaderStore, name string) (bool, error) {
	raw, err := store.GetHeader(ctx)
	if errors.Is(err, backend.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	h, err := crypto.ParseHeader(raw)
	if err != nil {
		return false, err
	}
	_, ok := h.NamespaceEntry(name)
	return ok, nil
}

// Read resolves the namespace's secrets from the blob the manifest entry names.
// An untrustable blob (missing, undecryptable, MAC-mismatched) fails closed,
// naming it: a dropped or altered write must never be silently skipped.
// ReadSalvage is the opt-in escape for a vault stuck on honest media loss. A
// zero entry (the namespace has no blob yet) yields empty state.
func (n *Namespace) Read(ctx context.Context, entry crypto.ManifestEntry) (*State, error) {
	if entry.Blob == "" {
		return emptyState(false), nil
	}
	return n.readBlob(ctx, entry.Blob, entry.MAC)
}

// ReadSalvage resolves what it can when a strict Read refuses. If the current
// blob is untrustable it falls back to the verified one-generation backup
// (entry.Prev), reporting the dropped blob on State.Corrupt instead of failing,
// so the user sees exactly what reverted. It is non-destructive and deliberately
// opt-in: silently serving an older blob would hide an attacker who suppressed
// the latest write. A transient error or a format-version skew still stops the
// read (those are not "this blob rotted").
func (n *Namespace) ReadSalvage(ctx context.Context, entry crypto.ManifestEntry) (*State, error) {
	if entry.Blob == "" {
		return emptyState(false), nil
	}
	state, err := n.readBlob(ctx, entry.Blob, entry.MAC)
	if err == nil {
		return state, nil
	}
	if !errors.Is(err, errCorruptBlob) {
		return nil, err
	}
	corrupt := []CorruptBlob{{Blob: entry.Blob, Reason: err.Error()}}
	if entry.Prev != "" {
		if prev, perr := n.readBlob(ctx, entry.Prev, entry.PrevMAC); perr == nil {
			prev.Corrupt = corrupt
			return prev, nil
		} else if errors.Is(perr, errCorruptBlob) {
			corrupt = append(corrupt, CorruptBlob{Blob: entry.Prev, Reason: perr.Error()})
		} else {
			return nil, perr
		}
	}
	// Both generations are gone. Report the loss and resolve to nothing; the
	// namespace did hold secrets, so it is not "untouched" (has stays true).
	s := emptyState(true)
	s.Corrupt = corrupt
	return s, nil
}

// readBlob opens the blob at key and resolves it. Everything the manifest
// promises is enforced: the blob must exist, open under the master, match the
// recorded MAC, parse at this format version, and carry this namespace's name.
func (n *Namespace) readBlob(ctx context.Context, key, mac string) (*State, error) {
	raw, err := n.store.Get(ctx, key)
	if errors.Is(err, backend.ErrNotFound) {
		return nil, corruptBlobf("namespace %q blob %s is recorded in the vault manifest but missing from storage: a write was deleted or withheld (if another machine is writing right now, re-run)", n.name, key)
	}
	if err != nil {
		return nil, err // transient: not corruption
	}
	plain, err := n.master.Decrypt(raw)
	if err != nil {
		return nil, corruptBlobf("namespace %q blob %s: %v", n.name, key, err)
	}
	if err := n.master.CheckBlobMAC(plain, mac); err != nil {
		return nil, corruptBlobf("namespace %q blob %s: %v", n.name, key, err)
	}
	return n.decode(key, plain)
}

// decode parses a verified blob plaintext into state. A version skew is a plain
// error, not corruption: it means upgrade notenv (higher) or this build no
// longer reads it (lower), so even a salvage read stops on it. A namespace
// mismatch is corruption (a blob copied from elsewhere).
func (n *Namespace) decode(key string, plain []byte) (*State, error) {
	var b blob
	if err := json.Unmarshal(plain, &b); err != nil {
		return nil, corruptBlobf("namespace %q blob %s: %v", n.name, key, err)
	}
	switch {
	case b.Version > blobVersion:
		return nil, fmt.Errorf("namespace %q blob %s was written by a newer notenv (format v%d, this version of notenv understands v%d); upgrade notenv", n.name, key, b.Version, blobVersion)
	case b.Version < blobVersion:
		return nil, fmt.Errorf("namespace %q blob %s was written in an older storage format (v%d) that this version of notenv no longer reads", n.name, key, b.Version)
	case b.NS != n.name:
		return nil, corruptBlobf("namespace %q blob %s declares namespace %q: it was copied from another namespace and is not trusted", n.name, key, b.NS)
	}
	state := emptyState(true)
	nsDesc, err := decodeField(b.Meta.Description)
	if err != nil {
		return nil, corruptBlobf("namespace %q blob %s: namespace description: %v", n.name, key, err)
	}
	state.Namespace = NamespaceMeta{
		Description: nsDesc,
		Created:     b.Meta.Created,
		CreatedBy:   b.Meta.CreatedBy,
		Updated:     b.Meta.Updated,
		UpdatedBy:   b.Meta.UpdatedBy,
		Sensitivity: b.Meta.Sensitivity,
		Egress:      b.Meta.Egress,
	}
	for k, r := range b.Entries {
		value, err := decodeField(r.Value)
		if err != nil {
			return nil, corruptBlobf("namespace %q blob %s: secret %q: %v", n.name, key, k, err)
		}
		desc, err := decodeField(r.Description)
		if err != nil {
			return nil, corruptBlobf("namespace %q blob %s: secret %q description: %v", n.name, key, k, err)
		}
		state.Secrets[k] = value
		state.Meta[k] = Meta{Description: desc, TS: r.TS, By: r.By, Sensitivity: r.Sensitivity, Egress: r.Egress}
	}
	return state, nil
}

// Apply returns the state after applying writes under last-write-wins: a value
// overwrites, a deletion removes. The receiver is not mutated, so a caller can
// re-apply the same writes against a freshly re-read state on a swap-race retry.
func (s *State) Apply(writes []Write) *State {
	next := &State{Secrets: maps.Clone(s.Secrets), Meta: maps.Clone(s.Meta), Namespace: s.Namespace, has: true}
	if next.Secrets == nil {
		next.Secrets = map[string]string{}
	}
	if next.Meta == nil {
		next.Meta = map[string]Meta{}
	}
	for _, w := range writes {
		if w.Deleted {
			delete(next.Secrets, w.Key)
			delete(next.Meta, w.Key)
			continue
		}
		prev := next.Meta[w.Key] // zero for a new key
		desc := w.Description
		if w.KeepDescription {
			desc = prev.Description // carry the current description forward
		}
		next.Secrets[w.Key] = w.Value
		// Sensitivity/Egress are carried from the existing record (they are not set
		// by any write today; this keeps a value update from clearing them once they
		// are). By/TS record this write's actor and time.
		next.Meta[w.Key] = Meta{Description: desc, TS: w.TS, By: w.By, Sensitivity: prev.Sensitivity, Egress: prev.Egress}
	}
	return next
}

// ValidateValue reports why a secret value cannot be stored. A value becomes an
// environment variable (passed to a child by execve) and may be written back out
// as a .env file, so it has to be text that survives both: valid UTF-8 with no
// control characters other than the newline family (\n, \t, \r). A NUL cannot
// ride in an environment variable at all, an ESC and friends cannot be
// represented in a .env, and invalid UTF-8 is silently coerced to U+FFFD by the
// blob's JSON encoder, so all of them are refused here, early, rather than stored
// as data notenv could not later hand back intact. Binary belongs base64-encoded,
// which is itself valid text and passes. The newline family is allowed because
// real secrets carry it (PEM keys, JSON blobs, CRLF certs) and a .env can
// represent it. This is the single definition of what may enter the vault;
// callers (set, import, edit) reuse it for friendly errors, WriteBlob enforces it.
func ValidateValue(value string) error {
	if !utf8.ValidString(value) {
		return errors.New("value is not valid UTF-8 text; an environment variable holds text. If this is binary (a key, a cert bundle), base64-encode it first, e.g. `base64 -w0 file | notenv set KEY --stdin`")
	}
	for _, r := range value {
		if r == '\n' || r == '\t' || r == '\r' {
			continue
		}
		if unicode.IsControl(r) {
			return fmt.Errorf("value contains a control character (U+%04X) that can't be used as an environment variable or written to a .env file; if this is binary, base64-encode it first", r)
		}
	}
	return nil
}

// encodeField and decodeField are the blob's value/description encoding (since
// blobVersion 2): base64, so a field carries any byte sequence through the JSON
// blob verbatim, with no U+FFFD coercion of invalid UTF-8. An empty field encodes
// to the empty string and back, so omitempty on a description still elides it.
func encodeField(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

func decodeField(s string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", fmt.Errorf("field is not valid base64: %w", err)
	}
	return string(b), nil
}

// stampMeta turns a namespace's in-memory metadata into its on-storage form,
// applying this write's stamp at the single write chokepoint. Updated/UpdatedBy
// are set on every write, so the namespace's last-modification time has one
// drift-free source. Created/CreatedBy are set only when not already recorded:
// the first write to the namespace (a `namespace create` or a lazy first `set`)
// stamps the birth time, and later writes preserve it. Description is base64 like
// a record's; the reserved sensitivity/egress defaults ride through unchanged. A
// zero stamp (no WithStamp, e.g. a test) leaves the times at zero (= unknown).
func (n *Namespace) stampMeta(m NamespaceMeta) nsMeta {
	if m.Created == 0 {
		m.Created = n.stamp.TS
		m.CreatedBy = n.stamp.By
	}
	m.Updated = n.stamp.TS
	m.UpdatedBy = n.stamp.By
	return nsMeta{
		Description: encodeField(m.Description),
		Created:     m.Created,
		CreatedBy:   m.CreatedBy,
		Updated:     m.Updated,
		UpdatedBy:   m.UpdatedBy,
		Sensitivity: m.Sensitivity,
		Egress:      m.Egress,
	}
}

// WriteBlob seals state into a fresh, uniquely named blob and returns its object
// key and the manifest entry that records it, carrying prev forward as the
// one-generation backup. It is the low-level primitive Commit and Rewrite build
// on (they own the header swap and the cleanup of superseded blobs). The blob is
// read back after writing (putVerified) so a corrupt write never reaches the
// manifest.
func (n *Namespace) WriteBlob(ctx context.Context, state *State, prev crypto.ManifestEntry) (string, crypto.ManifestEntry, error) {
	b := blob{Version: blobVersion, NS: n.name, Meta: n.stampMeta(state.Namespace), Entries: make(map[string]record, len(state.Secrets))}
	for k, v := range state.Secrets {
		// The authoritative gate: no value the command layer missed reaches
		// storage. Commands validate earlier for a friendlier error; this is the
		// chokepoint every write path (including the handoff copy) funnels through.
		if err := ValidateValue(v); err != nil {
			return "", crypto.ManifestEntry{}, fmt.Errorf("secret %q: %w", k, err)
		}
		m := state.Meta[k]
		b.Entries[k] = record{Value: encodeField(v), Description: encodeField(m.Description), TS: m.TS, By: m.By, Sensitivity: m.Sensitivity, Egress: m.Egress}
	}
	plain := mustMarshal(b)
	mac, err := n.master.BlobMAC(plain)
	if err != nil {
		return "", crypto.ManifestEntry{}, err
	}
	sealed, err := n.master.Encrypt(plain)
	if err != nil {
		return "", crypto.ManifestEntry{}, err
	}
	key, err := n.blobKey()
	if err != nil {
		return "", crypto.ManifestEntry{}, err
	}
	if err := putVerified(ctx, n.store, key, sealed); err != nil {
		return "", crypto.ManifestEntry{}, err
	}
	return key, crypto.ManifestEntry{Blob: key, MAC: mac, Prev: prev.Blob, PrevMAC: prev.MAC}, nil
}

// commitPlan is what a commit attempt's build callback decides: the namespace's
// new manifest entry (nil to remove the namespace), the blob this attempt wrote
// (an orphan if the attempt is superseded or fails), and the blobs the committed
// entry orphans.
type commitPlan struct {
	entry *crypto.ManifestEntry
	wrote string
	dead  []string
}

// Commit performs a read-modify-write of the namespace blob under the header
// compare-and-swap. apply computes the new in-memory state from the current one;
// it is re-run on each swap retry against the freshly re-read blob, so two
// writers' changes to different keys both survive and only same-key writes
// resolve last-writer-wins. Commit writes a new uniquely-named blob, points the
// header at it carrying the prior blob forward as the one-generation backup, and
// once the swap commits deletes the generation that fell off and calls pin with
// the committed header. A blob a superseded or failed attempt wrote is cleaned
// up; errors (including keymgmt.ErrEpochChanged) propagate after that cleanup.
//
// A commit whose result holds zero secrets is NOT special-cased: it records a
// normal blob with an empty entry set and keeps the manifest entry, so a
// namespace persists once it exists (created by Create or by a first set) even
// after its last secret is removed. Removal of the namespace itself is the
// deliberate, separate Delete; emptying it is just another write. This is what
// makes a namespace a first-class container rather than a side effect of holding
// secrets.
func (n *Namespace) Commit(ctx context.Context, apply func(*State) (*State, error), pin func(*crypto.Header)) (*State, *crypto.Header, error) {
	var result *State
	h, err := n.commit(ctx, func(cur crypto.ManifestEntry) (commitPlan, error) {
		state, err := n.Read(ctx, cur)
		if err != nil {
			return commitPlan{}, err
		}
		if state, err = apply(state); err != nil {
			return commitPlan{}, err
		}
		result = state
		key, entry, err := n.WriteBlob(ctx, state, cur)
		if err != nil {
			return commitPlan{}, err
		}
		return commitPlan{entry: &entry, wrote: key, dead: []string{cur.Prev}}, nil
	}, pin)
	if err != nil {
		return nil, nil, err
	}
	return result, h, nil
}

// ErrNamespaceExists reports that Create was asked to create a namespace that
// already has a manifest entry. The check is made inside the header swap, so it
// reflects the namespace's state at the instant of the write, not a stale read.
var ErrNamespaceExists = errors.New("namespace already exists")

// Create records a namespace that holds no secrets: a fresh empty blob (carrying
// the given description and this write's creation stamp) plus its manifest entry,
// so a namespace can be brought into existence deliberately rather than only as a
// side effect of the first set (which still works). If the namespace already has
// an entry it returns ErrNamespaceExists and touches nothing: the guard is
// evaluated against the freshly re-read header inside the swap, so a concurrent
// first write cannot be clobbered by a racing Create. Same swap, cleanup, and pin
// contract as Commit.
func (n *Namespace) Create(ctx context.Context, pin func(*crypto.Header), description string) error {
	_, err := n.commit(ctx, func(cur crypto.ManifestEntry) (commitPlan, error) {
		if cur.Blob != "" {
			return commitPlan{}, ErrNamespaceExists
		}
		state := emptyState(true)
		state.Namespace.Description = description
		key, entry, err := n.WriteBlob(ctx, state, cur)
		if err != nil {
			return commitPlan{}, err
		}
		return commitPlan{entry: &entry, wrote: key}, nil
	}, pin)
	return err
}

// Delete removes a namespace entirely: it drops the manifest entry and reclaims
// every blob under the namespace prefix. It is the deliberate counterpart to the
// persistent-namespace model, where emptying a namespace (Commit to zero
// secrets) keeps it; this is how a namespace actually goes away. It never reads
// or decrypts the blob, so it removes a namespace whose current blob is corrupt
// or missing exactly as readily as a healthy one, doubling as a recovery tool.
// Deleting a namespace that has no entry is a harmless no-op (callers that want
// a "not found" error check the manifest first). Same swap, cleanup, and pin
// contract as Commit: the entry is dropped under the header compare-and-swap and
// the namespace's blobs are reclaimed once it commits.
func (n *Namespace) Delete(ctx context.Context, pin func(*crypto.Header)) error {
	_, err := n.commit(ctx, func(cur crypto.ManifestEntry) (commitPlan, error) {
		return commitPlan{dead: []string{cur.Blob, cur.Prev}}, nil
	}, pin)
	return err
}

// ErrNamespaceChanged reports that a namespace's current blob moved between the
// read an operation planned against and the swap it tried to commit: another
// writer landed in between. Rewrite (the evict recovery path) returns it rather
// than clobber that concurrent write.
var ErrNamespaceChanged = errors.New("the namespace changed since it was read")

// Rewrite replaces the namespace blob with a fresh one sealed from state, its
// backup reset: the recovery path, where state came from a salvage read so the
// corrupt generations are dropped rather than carried. If state holds no secrets
// the namespace entry is removed entirely. expected is the manifest entry the
// state was salvaged under; if the live entry no longer matches it (a concurrent
// write, perhaps a legitimate repair, landed since), Rewrite aborts with
// ErrNamespaceChanged rather than overwrite that write with the older salvaged
// state. Same swap, cleanup, and pin contract as Commit.
func (n *Namespace) Rewrite(ctx context.Context, state *State, expected crypto.ManifestEntry, pin func(*crypto.Header)) (*crypto.Header, error) {
	return n.commit(ctx, func(cur crypto.ManifestEntry) (commitPlan, error) {
		if cur.Blob != expected.Blob {
			return commitPlan{}, fmt.Errorf("%w (namespace %q): re-run to recover against the current state", ErrNamespaceChanged, n.name)
		}
		dead := []string{cur.Blob, cur.Prev}
		if len(state.Secrets) == 0 {
			return commitPlan{dead: dead}, nil // nothing survives: drop the namespace entry
		}
		key, entry, err := n.WriteBlob(ctx, state, crypto.ManifestEntry{})
		if err != nil {
			return commitPlan{}, err
		}
		return commitPlan{entry: &entry, wrote: key, dead: dead}, nil
	}, pin)
}

// commit runs build under the header compare-and-swap. build is given the
// namespace's current manifest entry and returns a commitPlan. commit deletes
// the blob a superseded attempt wrote before each retry and after a failure, and
// on success deletes the generations this write retired and reclaims any orphan
// blob a past write left in the namespace (see reclaim), then calls pin. It needs
// the backend's header side: the store a namespace reads/writes blobs through
// must also be a HeaderStore for the swap (every real vault store is).
func (n *Namespace) commit(ctx context.Context, build func(cur crypto.ManifestEntry) (commitPlan, error), pin func(*crypto.Header)) (*crypto.Header, error) {
	hs, ok := n.store.(backend.HeaderStore)
	if !ok {
		return nil, errors.New("this backend does not support header writes")
	}
	// Snapshot the namespace's blobs before any write. After a successful commit,
	// reclaim deletes only blobs that were already present here and the committed
	// header no longer references. A blob a concurrent writer creates during this
	// commit is absent from the snapshot, so it is never swept: deleting one would
	// strand the header that writer is about to commit. Best-effort (a listing
	// error just skips reclamation); the next successful write reclaims anything
	// missed.
	preexisting, _ := n.store.List(ctx, n.name+"/")
	var plan commitPlan
	h, err := keymgmt.UpdateHeader(ctx, hs, n.master, func(h *crypto.Header) error {
		if plan.wrote != "" { // a superseded attempt's blob is now an orphan
			_ = n.store.Delete(ctx, plan.wrote)
		}
		cur, _ := h.NamespaceEntry(n.name)
		p, berr := build(cur)
		// Capture the plan even on error: if a build ever writes a blob and then
		// fails, plan.wrote carries it so the cleanup below reclaims it instead of
		// leaking it. Today every build returns an empty plan on error, so this is a
		// guard against future build logic, not a change in current behavior.
		plan = p
		if berr != nil {
			return berr
		}
		if p.entry == nil {
			h.RemoveNamespace(n.name)
		} else {
			h.SetNamespace(n.name, *p.entry)
		}
		return nil
	})
	if err != nil {
		// Only reclaim the blob this attempt wrote when the swap is known NOT to
		// have committed. On backend.ErrCommitUncertain the header may already
		// reference it, so deleting it would strand the committed header (the blob
		// stays as a harmless orphan `doctor` reports instead).
		if plan.wrote != "" && !errors.Is(err, backend.ErrCommitUncertain) {
			_ = n.store.Delete(ctx, plan.wrote)
		}
		return nil, err
	}
	for _, k := range plan.dead {
		if k != "" && k != plan.wrote {
			_ = n.store.Delete(ctx, k)
		}
	}
	n.reclaim(ctx, h, preexisting, plan.wrote)
	if pin != nil {
		pin(h)
	}
	return h, nil
}

// reclaim deletes the namespace's orphan blobs after a successful commit: objects
// that were present before this write began (preexisting) and that the committed
// header no longer references. That is the backup this write retired plus any
// blob a past write crashed before recording. Because preexisting was listed
// before the write, a blob a concurrent writer created during it is absent and
// never deleted, even though it is unreferenced now (that writer is about to
// record it). Deletes are idempotent and best-effort; a failure leaves a harmless
// orphan the next write reclaims. This is why notenv needs no separate
// garbage-collect step: orphan cleanup rides every write.
func (n *Namespace) reclaim(ctx context.Context, h *crypto.Header, preexisting []string, wrote string) {
	keep := make(map[string]bool, 2)
	if e, ok := h.NamespaceEntry(n.name); ok {
		keep[e.Blob] = true
		if e.Prev != "" {
			keep[e.Prev] = true
		}
	}
	for _, k := range preexisting {
		if k == wrote || keep[k] {
			continue
		}
		_ = n.store.Delete(ctx, k)
	}
}

// blobKey builds a unique key under the namespace, so no two writes ever collide
// on a name and a crash before the header swap leaves an orphan rather than
// clobbering the live blob.
func (n *Namespace) blobKey() (string, error) {
	buf := make([]byte, 8) // 64 bits: collision-safe past any realistic write count
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s/data-%s.age", n.name, hex.EncodeToString(buf)), nil
}

// putVerified writes sealed at key and reads it back. Because reads fail closed
// on any untrustable blob (a dropped or tampered write must not be silently
// skipped), a botched write would otherwise poison every later read; this stops
// a genuinely corrupt blob from reaching the manifest. It deletes only on a real
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
		_ = store.Delete(ctx, key)
		return fmt.Errorf("value %s read back corrupted after write; the change was not recorded", key)
	}
	return nil
}

func emptyState(has bool) *State {
	return &State{Secrets: map[string]string{}, Meta: map[string]Meta{}, has: has}
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
