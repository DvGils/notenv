package secrets_test

import (
	"context"
	"errors"
	"testing"

	"github.com/DvGils/notenv/internal/backend"
	"github.com/DvGils/notenv/internal/backend/memstore"
	"github.com/DvGils/notenv/internal/crypto"
	"github.com/DvGils/notenv/internal/keymgmt"
	"github.com/DvGils/notenv/internal/secrets"
)

// vault is a memstore plus a master and the "proj" namespace's manifest entry,
// the state the command layer keeps in the header. Writes go through the same
// read-modify-write app.writeNamespace runs: read the current blob, apply,
// write a fresh blob, advance the recorded entry, drop the fallen-off backup.
type vault struct {
	store *memstore.Store
	mk    *crypto.MasterKey
	entry crypto.ManifestEntry
}

func newVault(t *testing.T) *vault {
	t.Helper()
	mk, err := crypto.GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	return &vault{store: memstore.New(), mk: mk}
}

func (v *vault) ns() *secrets.Namespace { return secrets.For(v.store, "proj", v.mk) }

func (v *vault) read(t *testing.T) *secrets.State {
	t.Helper()
	s, err := v.ns().Read(context.Background(), v.entry)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return s
}

func (v *vault) write(t *testing.T, ws ...secrets.Write) *secrets.State {
	t.Helper()
	ctx := context.Background()
	cur, err := v.ns().Read(ctx, v.entry)
	if err != nil {
		t.Fatalf("read before write: %v", err)
	}
	next := cur.Apply(ws)
	_, entry, err := v.ns().WriteBlob(ctx, next, v.entry)
	if err != nil {
		t.Fatalf("write blob: %v", err)
	}
	if v.entry.Prev != "" { // mirror the command layer dropping the generation that fell off
		_ = v.store.Delete(ctx, v.entry.Prev)
	}
	v.entry = entry
	return next
}

func TestReadEmptyNamespace(t *testing.T) {
	v := newVault(t)
	state := v.read(t)
	if state.HasHistory() {
		t.Fatal("empty namespace should report no history")
	}
	if len(state.Secrets) != 0 {
		t.Fatalf("empty namespace should have no secrets, got %v", state.Secrets)
	}
}

func TestWriteThenRead(t *testing.T) {
	v := newVault(t)
	v.write(t, secrets.Write{Key: "API_KEY", Value: "abc", Description: "the key", TS: 42})

	state := v.read(t)
	if !state.HasHistory() {
		t.Fatal("namespace with a write should report history")
	}
	if state.Secrets["API_KEY"] != "abc" {
		t.Fatalf("API_KEY = %q, want abc", state.Secrets["API_KEY"])
	}
	if m := state.Meta["API_KEY"]; m.Description != "the key" || m.TS != 42 {
		t.Fatalf("meta = %+v, want {the key 42}", m)
	}
}

func TestLastWriteWins(t *testing.T) {
	v := newVault(t)
	v.write(t, secrets.Write{Key: "K", Value: "v1"})
	v.write(t, secrets.Write{Key: "K", Value: "v2"})
	if got := v.read(t).Secrets["K"]; got != "v2" {
		t.Fatalf("K = %q, want v2 (last write wins)", got)
	}
}

func TestDeleteRemovesKey(t *testing.T) {
	v := newVault(t)
	v.write(t, secrets.Write{Key: "K", Value: "v"})
	v.write(t, secrets.Write{Key: "K", Deleted: true})

	state := v.read(t)
	if _, present := state.Secrets["K"]; present {
		t.Fatalf("deleted key should be absent, got %v", state.Secrets)
	}
	if !state.HasHistory() {
		t.Fatal("a namespace emptied by deletes still has a blob, so it has history")
	}
}

// TestDifferentKeysAccumulate is the property the read-modify-write retry relies
// on: each write re-reads the current blob and applies its change, so writes to
// different keys all survive.
func TestDifferentKeysAccumulate(t *testing.T) {
	v := newVault(t)
	v.write(t, secrets.Write{Key: "API_KEY", Value: "a"})
	v.write(t, secrets.Write{Key: "DB_URL", Value: "b"})
	v.write(t, secrets.Write{Key: "TOKEN", Value: "c"})

	state := v.read(t)
	for k, want := range map[string]string{"API_KEY": "a", "DB_URL": "b", "TOKEN": "c"} {
		if state.Secrets[k] != want {
			t.Fatalf("%s = %q, want %q (every key should survive)", k, state.Secrets[k], want)
		}
	}
}

func TestApplyDoesNotMutateReceiver(t *testing.T) {
	v := newVault(t)
	base := v.write(t, secrets.Write{Key: "K", Value: "v1"})
	next := base.Apply([]secrets.Write{{Key: "K", Value: "v2"}})
	if base.Secrets["K"] != "v1" {
		t.Fatalf("Apply mutated its receiver: K = %q, want v1", base.Secrets["K"])
	}
	if next.Secrets["K"] != "v2" {
		t.Fatalf("Apply result K = %q, want v2", next.Secrets["K"])
	}
}

// TestBackupCarriedForward checks the one-generation backup: after two writes the
// manifest's Prev names the first blob, and it still decrypts to the first state.
func TestBackupCarriedForward(t *testing.T) {
	v := newVault(t)
	v.write(t, secrets.Write{Key: "K", Value: "v1"})
	first := v.entry
	v.write(t, secrets.Write{Key: "K", Value: "v2"})

	if v.entry.Prev != first.Blob {
		t.Fatalf("Prev = %q, want the first blob %q", v.entry.Prev, first.Blob)
	}
	prev, err := v.ns().Read(context.Background(), crypto.ManifestEntry{Blob: v.entry.Prev, MAC: v.entry.PrevMAC})
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}
	if prev.Secrets["K"] != "v1" {
		t.Fatalf("backup K = %q, want v1 (the superseded write)", prev.Secrets["K"])
	}
}

func TestTamperedMACFailsClosed(t *testing.T) {
	v := newVault(t)
	v.write(t, secrets.Write{Key: "K", Value: "v"})
	bad := v.entry
	bad.MAC = "00" // a MAC that won't match the blob's plaintext
	if _, err := v.ns().Read(context.Background(), bad); err == nil {
		t.Fatal("a blob whose recorded MAC does not match must fail the read closed")
	}
}

func TestCorruptBytesFailClosed(t *testing.T) {
	v := newVault(t)
	v.write(t, secrets.Write{Key: "K", Value: "v"})
	if err := v.store.Put(context.Background(), v.entry.Blob, []byte("not age ciphertext")); err != nil {
		t.Fatal(err)
	}
	if _, err := v.ns().Read(context.Background(), v.entry); err == nil {
		t.Fatal("a blob that does not decrypt must fail the read closed")
	}
}

func TestMissingBlobFailsClosed(t *testing.T) {
	v := newVault(t)
	v.write(t, secrets.Write{Key: "K", Value: "v"})
	if err := v.store.Delete(context.Background(), v.entry.Blob); err != nil {
		t.Fatal(err)
	}
	if _, err := v.ns().Read(context.Background(), v.entry); err == nil {
		t.Fatal("a recorded blob missing from storage must fail the read closed")
	}
}

// TestNamespaceIsolation: a blob written for one namespace must not read as
// another, even with a matching MAC (the blob self-identifies its namespace).
func TestNamespaceIsolation(t *testing.T) {
	v := newVault(t)
	v.write(t, secrets.Write{Key: "K", Value: "v"})
	other := secrets.For(v.store, "other", v.mk)
	if _, err := other.Read(context.Background(), v.entry); err == nil {
		t.Fatal("a blob from namespace \"proj\" must not read as namespace \"other\"")
	}
}

// lagOnceStore makes the first Get return not-found, simulating read-after-write
// lag on an eventually-consistent backend.
type lagOnceStore struct {
	*memstore.Store
	lagged bool
}

func (s *lagOnceStore) Get(ctx context.Context, key string) ([]byte, error) {
	if !s.lagged {
		s.lagged = true
		return nil, backend.ErrNotFound
	}
	return s.Store.Get(ctx, key)
}

// TestWriteKeepsLaggedBlob: when the verify read-back lags (the write may
// actually have landed), the blob must not be deleted. WriteBlob fails so the
// caller can retry, but the object stays.
func TestWriteKeepsLaggedBlob(t *testing.T) {
	ctx := context.Background()
	v := newVault(t)
	store := &lagOnceStore{Store: v.store}
	ns := secrets.For(store, "proj", v.mk)

	empty, err := ns.Read(ctx, crypto.ManifestEntry{})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ns.WriteBlob(ctx, empty.Apply([]secrets.Write{{Key: "K", Value: "v"}}), crypto.ManifestEntry{}); err == nil {
		t.Fatal("write should surface the lagged read-back as an error")
	}
	keys, err := v.store.List(ctx, "proj/")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Fatalf("a lagged write must survive (not be deleted), got %d objects", len(keys))
	}
}

// seeded returns a memstore with a real sealed header wrapping the returned
// master, so Commit/Rewrite/Exists (which need the authenticated header) can run.
func seeded(t *testing.T) (*memstore.Store, *crypto.MasterKey) {
	t.Helper()
	ctx := context.Background()
	mem := memstore.New()
	header, mk, err := crypto.NewHeader("p", "owner")
	if err != nil {
		t.Fatal(err)
	}
	verify := func(h *crypto.Header) (*crypto.MasterKey, error) { m, _, _, e := h.Unlock("p"); return m, e }
	if err := keymgmt.SafePut(ctx, mem, header, nil, mk, verify); err != nil {
		t.Fatal(err)
	}
	return mem, mk
}

// TestExists checks namespace existence against the authenticated manifest, not
// the raw object listing: a committed write makes it true, but an orphan blob
// from a crashed write (no manifest entry) must not, and virgin storage is false.
func TestExists(t *testing.T) {
	ctx := context.Background()
	mem, mk := seeded(t)

	if ok, err := secrets.Exists(ctx, mem, "proj"); err != nil || ok {
		t.Fatalf("Exists before any write = %v,%v, want false,nil", ok, err)
	}
	if _, _, err := secrets.For(mem, "proj", mk).Commit(ctx,
		func(cur *secrets.State) (*secrets.State, error) {
			return cur.Apply([]secrets.Write{{Key: "K", Value: "v"}}), nil
		}, nil); err != nil {
		t.Fatal(err)
	}
	if ok, err := secrets.Exists(ctx, mem, "proj"); err != nil || !ok {
		t.Fatalf("Exists after a committed write = %v,%v, want true,nil", ok, err)
	}
	// An orphan blob under a namespace with no manifest entry must not count.
	if err := mem.Put(ctx, "ghost/data-orphan.age", []byte("junk")); err != nil {
		t.Fatal(err)
	}
	if ok, err := secrets.Exists(ctx, mem, "ghost"); err != nil || ok {
		t.Fatalf("Exists must ignore an orphan blob, got %v,%v", ok, err)
	}
	// Virgin storage (no header at all) is false, not an error.
	if ok, err := secrets.Exists(ctx, memstore.New(), "proj"); err != nil || ok {
		t.Fatalf("Exists on headerless storage = %v,%v, want false,nil", ok, err)
	}
}

// TestRewriteAbortsOnConcurrentChange: evict's Rewrite must refuse if the
// namespace's current blob moved since the state was salvaged (a concurrent
// repair landed), rather than clobber that write with the older salvaged state.
func TestRewriteAbortsOnConcurrentChange(t *testing.T) {
	ctx := context.Background()
	mem, mk := seeded(t)
	ns := secrets.For(mem, "proj", mk)

	if _, _, err := ns.Commit(ctx,
		func(cur *secrets.State) (*secrets.State, error) {
			return cur.Apply([]secrets.Write{{Key: "K", Value: "v1"}}), nil
		}, nil); err != nil {
		t.Fatal(err)
	}
	stale, _ := mustEntryFor(t, mem, "proj") // the entry an evict would salvage under
	salvaged, err := ns.Read(ctx, stale)
	if err != nil {
		t.Fatal(err)
	}
	// A concurrent write lands, moving the namespace's current blob.
	if _, _, err := ns.Commit(ctx,
		func(cur *secrets.State) (*secrets.State, error) {
			return cur.Apply([]secrets.Write{{Key: "K", Value: "v2"}}), nil
		}, nil); err != nil {
		t.Fatal(err)
	}

	if _, err := ns.Rewrite(ctx, salvaged, stale, nil); !errors.Is(err, secrets.ErrNamespaceChanged) {
		t.Fatalf("Rewrite against a stale entry must abort with ErrNamespaceChanged, got %v", err)
	}
	// The concurrent write survives untouched.
	cur, _ := mustEntryFor(t, mem, "proj")
	state, err := ns.Read(ctx, cur)
	if err != nil {
		t.Fatal(err)
	}
	if state.Secrets["K"] != "v2" {
		t.Fatalf("the concurrent repair must survive, got K=%q", state.Secrets["K"])
	}
}

// TestKeepDescriptionCarriesLiveValue: a write with KeepDescription preserves
// the key's current description (read against the live blob inside Commit), so
// re-stating a value never reverts the description.
func TestKeepDescriptionCarriesLiveValue(t *testing.T) {
	ctx := context.Background()
	mem, mk := seeded(t)
	ns := secrets.For(mem, "proj", mk)

	if _, _, err := ns.Commit(ctx,
		func(cur *secrets.State) (*secrets.State, error) {
			return cur.Apply([]secrets.Write{{Key: "K", Value: "v1", Description: "the key"}}), nil
		}, nil); err != nil {
		t.Fatal(err)
	}
	state, _, err := ns.Commit(ctx,
		func(cur *secrets.State) (*secrets.State, error) {
			return cur.Apply([]secrets.Write{{Key: "K", Value: "v2", KeepDescription: true}}), nil
		}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if state.Secrets["K"] != "v2" {
		t.Fatalf("value not updated: K=%q, want v2", state.Secrets["K"])
	}
	if got := state.Meta["K"].Description; got != "the key" {
		t.Fatalf("KeepDescription must carry the live description, got %q", got)
	}
}

func mustEntryFor(t *testing.T, mem *memstore.Store, ns string) (crypto.ManifestEntry, bool) {
	t.Helper()
	h, err := crypto.ParseHeader(mem.Header())
	if err != nil {
		t.Fatal(err)
	}
	return h.NamespaceEntry(ns)
}

// racingVault lands a competing Commit (a different key) in the window between a
// Commit's header read and its swap, once, so the original loses the swap and
// must retry. The competing Commit runs against the inner store, never the
// wrapper, so it does not recurse.
type racingVault struct {
	*memstore.Store
	t     *testing.T
	mk    *crypto.MasterKey
	raced bool
}

func (s *racingVault) SwapHeader(ctx context.Context, base, updated []byte) error {
	if !s.raced {
		s.raced = true
		_, _, err := secrets.For(s.Store, "proj", s.mk).Commit(ctx,
			func(cur *secrets.State) (*secrets.State, error) {
				return cur.Apply([]secrets.Write{{Key: "RACER", Value: "r"}}), nil
			}, nil)
		if err != nil {
			s.t.Fatalf("competing commit: %v", err)
		}
	}
	return s.Store.SwapHeader(ctx, base, updated)
}

// TestCommitCleansOrphanOnSwapRace: when a Commit loses the swap race, it
// re-reads and re-applies (so both writers' distinct keys survive) and deletes
// the blob its superseded attempt wrote, leaving no orphan behind: the namespace
// ends with exactly its current blob and one-generation backup.
func TestCommitCleansOrphanOnSwapRace(t *testing.T) {
	ctx := context.Background()
	store := memstore.New()
	header, mk, err := crypto.NewHeader("p", "owner")
	if err != nil {
		t.Fatal(err)
	}
	verify := func(h *crypto.Header) (*crypto.MasterKey, error) { m, _, _, e := h.Unlock("p"); return m, e }
	if err := keymgmt.SafePut(ctx, store, header, nil, mk, verify); err != nil {
		t.Fatal(err)
	}

	racing := &racingVault{Store: store, t: t, mk: mk}
	state, _, err := secrets.For(racing, "proj", mk).Commit(ctx,
		func(cur *secrets.State) (*secrets.State, error) {
			return cur.Apply([]secrets.Write{{Key: "OWN", Value: "o"}}), nil
		}, nil)
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	if !racing.raced {
		t.Fatal("the competing commit never ran")
	}
	if state.Secrets["OWN"] != "o" || state.Secrets["RACER"] != "r" {
		t.Fatalf("both writers' keys must survive the race, got %v", state.Secrets)
	}
	keys, err := store.List(ctx, "proj/")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected exactly 2 blobs (current + one-generation backup), got %d: %v (a superseded attempt's orphan leaked)", len(keys), keys)
	}
}

// uncertainStore makes SafePut's post-swap read-back fail once, right after a
// SwapHeader commits, simulating read-after-write lag on an eventually-consistent
// remote: the write has landed but cannot be confirmed.
type uncertainStore struct {
	*memstore.Store
	failNextGet bool
}

func (s *uncertainStore) SwapHeader(ctx context.Context, base, updated []byte) error {
	err := s.Store.SwapHeader(ctx, base, updated)
	if err == nil {
		s.failNextGet = true // the swap committed; make the verifying read-back fail
	}
	return err
}

func (s *uncertainStore) GetHeader(ctx context.Context) ([]byte, error) {
	if s.failNextGet {
		s.failNextGet = false
		return nil, errors.New("transient read flake")
	}
	return s.Store.GetHeader(ctx)
}

// TestCommitKeepsBlobWhenSwapUncertain: if the swap commits but the post-swap
// verification can't confirm it (backend.ErrCommitUncertain), Commit must NOT
// delete the blob it wrote, because the committed header now references it.
// Deleting it would strand the header (the bug this guards). The namespace must
// remain readable.
func TestCommitKeepsBlobWhenSwapUncertain(t *testing.T) {
	ctx := context.Background()
	mem := memstore.New()
	header, mk, err := crypto.NewHeader("p", "owner")
	if err != nil {
		t.Fatal(err)
	}
	verify := func(h *crypto.Header) (*crypto.MasterKey, error) { m, _, _, e := h.Unlock("p"); return m, e }
	if err := keymgmt.SafePut(ctx, mem, header, nil, mk, verify); err != nil {
		t.Fatal(err)
	}

	store := &uncertainStore{Store: mem}
	_, _, err = secrets.For(store, "proj", mk).Commit(ctx,
		func(cur *secrets.State) (*secrets.State, error) {
			return cur.Apply([]secrets.Write{{Key: "K", Value: "v"}}), nil
		}, nil)
	if !errors.Is(err, backend.ErrCommitUncertain) {
		t.Fatalf("want ErrCommitUncertain (the swap landed but couldn't be confirmed), got %v", err)
	}

	// The header committed and points at a blob that must still exist.
	h, err := crypto.ParseHeader(mem.Header())
	if err != nil {
		t.Fatal(err)
	}
	entry, ok := h.NamespaceEntry("proj")
	if !ok {
		t.Fatal("the swap committed, so the namespace must have a manifest entry")
	}
	state, err := secrets.For(mem, "proj", mk).Read(ctx, entry)
	if err != nil {
		t.Fatalf("the committed blob must still be readable, not deleted: %v", err)
	}
	if state.Secrets["K"] != "v" {
		t.Fatalf("K = %q, want v", state.Secrets["K"])
	}
}

// TestCommitKeepsEmptiedNamespace: removing the last secret keeps the namespace
// as a persistent empty blob rather than dropping it, so Exists still reports
// true and a later read resolves to no secrets (not "untouched"). A namespace is
// a first-class container that outlives its secrets; removing it is the separate
// Delete. The standard no-orphan invariant still holds across the emptying write.
func TestCommitKeepsEmptiedNamespace(t *testing.T) {
	ctx := context.Background()
	mem, mk := seeded(t)
	ns := secrets.For(mem, "proj", mk)

	if _, _, err := ns.Commit(ctx,
		func(cur *secrets.State) (*secrets.State, error) {
			return cur.Apply([]secrets.Write{{Key: "K", Value: "v"}}), nil
		}, nil); err != nil {
		t.Fatal(err)
	}
	if ok, err := secrets.Exists(ctx, mem, "proj"); err != nil || !ok {
		t.Fatalf("Exists after a write = %v,%v, want true,nil", ok, err)
	}

	// Remove the only key.
	if _, _, err := ns.Commit(ctx,
		func(cur *secrets.State) (*secrets.State, error) {
			return cur.Apply([]secrets.Write{{Key: "K", Deleted: true}}), nil
		}, nil); err != nil {
		t.Fatal(err)
	}
	if ok, err := secrets.Exists(ctx, mem, "proj"); err != nil || !ok {
		t.Fatalf("Exists after emptying = %v,%v, want true,nil (a namespace persists once it exists)", ok, err)
	}

	// The manifest still carries the entry, and a read resolves it as "exists,
	// no secrets" (history true, zero secrets).
	entry, ok := mustEntryFor(t, mem, "proj")
	if !ok {
		t.Fatal("the manifest must keep an entry for an emptied (persistent) namespace")
	}
	state, err := ns.Read(ctx, entry)
	if err != nil {
		t.Fatalf("read emptied namespace: %v", err)
	}
	if !state.HasHistory() || len(state.Secrets) != 0 {
		t.Fatalf("emptied namespace read = history %v, %d secrets; want history true, 0 secrets", state.HasHistory(), len(state.Secrets))
	}

	// No orphan leaks: every blob under the prefix is the current blob or its
	// one-generation backup.
	keys, err := mem.List(ctx, "proj/")
	if err != nil {
		t.Fatal(err)
	}
	referenced := map[string]bool{entry.Blob: true}
	if entry.Prev != "" {
		referenced[entry.Prev] = true
	}
	for _, k := range keys {
		if !referenced[k] {
			t.Fatalf("unreferenced blob %s lingers after emptying (referenced: %v)", k, referenced)
		}
	}
}

// TestCreateEmptyNamespace: Create brings a namespace into existence holding no
// secrets, and refuses (ErrNamespaceExists, touching nothing) a second create.
func TestCreateEmptyNamespace(t *testing.T) {
	ctx := context.Background()
	mem, mk := seeded(t)
	ns := secrets.For(mem, "fresh", mk)

	if err := ns.Create(ctx, nil, ""); err != nil {
		t.Fatalf("create: %v", err)
	}
	if ok, err := secrets.Exists(ctx, mem, "fresh"); err != nil || !ok {
		t.Fatalf("Exists after create = %v,%v, want true,nil", ok, err)
	}
	entry, ok := mustEntryFor(t, mem, "fresh")
	if !ok {
		t.Fatal("create must record a manifest entry")
	}
	state, err := ns.Read(ctx, entry)
	if err != nil {
		t.Fatalf("read created namespace: %v", err)
	}
	if !state.HasHistory() || len(state.Secrets) != 0 {
		t.Fatalf("created namespace = history %v, %d secrets; want history true, 0 secrets", state.HasHistory(), len(state.Secrets))
	}
	if err := ns.Create(ctx, nil, ""); !errors.Is(err, secrets.ErrNamespaceExists) {
		t.Fatalf("second create err = %v, want ErrNamespaceExists", err)
	}
}

// TestDeleteRemovesNamespace: Delete drops the manifest entry and reclaims every
// blob under the namespace prefix.
func TestDeleteRemovesNamespace(t *testing.T) {
	ctx := context.Background()
	mem, mk := seeded(t)
	ns := secrets.For(mem, "proj", mk)
	if _, _, err := ns.Commit(ctx, func(cur *secrets.State) (*secrets.State, error) {
		return cur.Apply([]secrets.Write{{Key: "K", Value: "v"}}), nil
	}, nil); err != nil {
		t.Fatal(err)
	}
	if err := ns.Delete(ctx, nil); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if ok, err := secrets.Exists(ctx, mem, "proj"); err != nil || ok {
		t.Fatalf("Exists after delete = %v,%v, want false,nil", ok, err)
	}
	if _, ok := mustEntryFor(t, mem, "proj"); ok {
		t.Fatal("delete must drop the manifest entry")
	}
	keys, err := mem.List(ctx, "proj/")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Fatalf("delete must reclaim every namespace blob, got %v", keys)
	}
}

// TestDeleteToleratesMissingBlob: Delete never reads the blob, so a namespace
// whose blob has been lost (honest media loss, where a strict read fails closed)
// is still removed cleanly. This is what lets delete double as a recovery tool.
func TestDeleteToleratesMissingBlob(t *testing.T) {
	ctx := context.Background()
	mem, mk := seeded(t)
	ns := secrets.For(mem, "proj", mk)
	if _, _, err := ns.Commit(ctx, func(cur *secrets.State) (*secrets.State, error) {
		return cur.Apply([]secrets.Write{{Key: "K", Value: "v"}}), nil
	}, nil); err != nil {
		t.Fatal(err)
	}
	entry, _ := mustEntryFor(t, mem, "proj")
	if err := mem.Delete(ctx, entry.Blob); err != nil {
		t.Fatal(err)
	}
	if _, err := ns.Read(ctx, entry); err == nil {
		t.Fatal("precondition: a strict read should fail closed on the missing blob")
	}
	if err := ns.Delete(ctx, nil); err != nil {
		t.Fatalf("delete over a missing blob: %v", err)
	}
	if _, ok := mustEntryFor(t, mem, "proj"); ok {
		t.Fatal("delete must drop the manifest entry even when the blob is gone")
	}
}

// TestNamespaceMetadataStamps: a write under a Stamp records the namespace's
// created/updated (who+when) and each written secret's `by`; a later write under
// a different stamp advances `updated` but preserves `created`, and leaves an
// untouched secret's `by` alone.
func TestNamespaceMetadataStamps(t *testing.T) {
	ctx := context.Background()
	mem, mk := seeded(t)

	ns := secrets.For(mem, "proj", mk).WithStamp(secrets.Stamp{By: "alice@host", TS: 100})
	if _, _, err := ns.Commit(ctx, func(cur *secrets.State) (*secrets.State, error) {
		return cur.Apply([]secrets.Write{{Key: "K", Value: "v", By: "alice@host", TS: 100}}), nil
	}, nil); err != nil {
		t.Fatal(err)
	}

	st := readProj(t, mem, mk)
	if st.Namespace.Created != 100 || st.Namespace.CreatedBy != "alice@host" {
		t.Fatalf("created = %d/%q, want 100/alice@host", st.Namespace.Created, st.Namespace.CreatedBy)
	}
	if st.Namespace.Updated != 100 || st.Namespace.UpdatedBy != "alice@host" {
		t.Fatalf("updated = %d/%q, want 100/alice@host", st.Namespace.Updated, st.Namespace.UpdatedBy)
	}
	if st.Meta["K"].By != "alice@host" {
		t.Fatalf("secret K by = %q, want alice@host", st.Meta["K"].By)
	}

	ns2 := secrets.For(mem, "proj", mk).WithStamp(secrets.Stamp{By: "bob@host", TS: 200})
	if _, _, err := ns2.Commit(ctx, func(cur *secrets.State) (*secrets.State, error) {
		return cur.Apply([]secrets.Write{{Key: "K2", Value: "v2", By: "bob@host", TS: 200}}), nil
	}, nil); err != nil {
		t.Fatal(err)
	}

	st = readProj(t, mem, mk)
	if st.Namespace.Created != 100 || st.Namespace.CreatedBy != "alice@host" {
		t.Fatalf("created changed to %d/%q, want 100/alice@host preserved", st.Namespace.Created, st.Namespace.CreatedBy)
	}
	if st.Namespace.Updated != 200 || st.Namespace.UpdatedBy != "bob@host" {
		t.Fatalf("updated = %d/%q, want 200/bob@host", st.Namespace.Updated, st.Namespace.UpdatedBy)
	}
	if st.Meta["K"].By != "alice@host" {
		t.Fatalf("untouched K by = %q, want alice@host preserved", st.Meta["K"].By)
	}
	if st.Meta["K2"].By != "bob@host" {
		t.Fatalf("K2 by = %q, want bob@host", st.Meta["K2"].By)
	}
}

// TestNamespaceDescriptionRoundTrips: Create's description (and so the
// namespace-level base64 desc path) round-trips byte-for-byte, including a
// newline that the encoding exists to preserve.
func TestNamespaceDescriptionRoundTrips(t *testing.T) {
	ctx := context.Background()
	mem, mk := seeded(t)
	ns := secrets.For(mem, "proj", mk).WithStamp(secrets.Stamp{By: "x", TS: 1})
	const desc = "prod secrets\nline two"
	if err := ns.Create(ctx, nil, desc); err != nil {
		t.Fatal(err)
	}
	if got := readProj(t, mem, mk).Namespace.Description; got != desc {
		t.Fatalf("namespace description = %q, want %q", got, desc)
	}
}

// readProj reads the "proj" namespace's current state via its manifest entry.
func readProj(t *testing.T, mem *memstore.Store, mk *crypto.MasterKey) *secrets.State {
	t.Helper()
	entry, ok := mustEntryFor(t, mem, "proj")
	if !ok {
		t.Fatal("proj has no manifest entry")
	}
	st, err := secrets.For(mem, "proj", mk).Read(context.Background(), entry)
	if err != nil {
		t.Fatalf("read proj: %v", err)
	}
	return st
}

// TestCommitReclaimsOrphanFromCrashedWrite: a blob a past write left behind (it
// crashed after writing the blob but before recording it in the manifest) is
// reclaimed by the next write to the namespace, so notenv needs no separate
// garbage-collect step. The orphan predates this write, so the pre-read snapshot
// includes it and the post-commit sweep deletes it.
func TestCommitReclaimsOrphanFromCrashedWrite(t *testing.T) {
	ctx := context.Background()
	mem, mk := seeded(t)
	ns := secrets.For(mem, "proj", mk)

	if _, _, err := ns.Commit(ctx,
		func(cur *secrets.State) (*secrets.State, error) {
			return cur.Apply([]secrets.Write{{Key: "K", Value: "v1"}}), nil
		}, nil); err != nil {
		t.Fatal(err)
	}
	// A previous write crashed after writing its blob but before recording it.
	if err := mem.Put(ctx, "proj/data-orphan.age", []byte("never recorded")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ns.Commit(ctx,
		func(cur *secrets.State) (*secrets.State, error) {
			return cur.Apply([]secrets.Write{{Key: "K", Value: "v2"}}), nil
		}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := mem.Get(ctx, "proj/data-orphan.age"); !errors.Is(err, backend.ErrNotFound) {
		t.Fatalf("the orphan must be reclaimed by the next write, got %v", err)
	}
	// Only the current blob and its one-generation backup remain.
	keys, err := mem.List(ctx, "proj/")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Fatalf("want exactly current + backup, got %d: %v", len(keys), keys)
	}
}

// inflightVault injects a raw blob into the namespace the first time SwapHeader
// runs, modeling a concurrent writer that lands an in-flight blob after our
// commit took its pre-read snapshot but before our swap. The reclaim sweep must
// not touch such a blob (it is absent from the snapshot), because that writer is
// about to commit a header referencing it and deleting it would strand the
// header.
type inflightVault struct {
	*memstore.Store
	injected bool
}

func (s *inflightVault) SwapHeader(ctx context.Context, base, updated []byte) error {
	if !s.injected {
		s.injected = true
		_ = s.Store.Put(ctx, "proj/data-inflight.age", []byte("concurrent in-flight blob"))
	}
	return s.Store.SwapHeader(ctx, base, updated)
}

// TestCommitSparesConcurrentInflightThenReclaimsIt is the safety property of the
// no-gc design: a blob created during a commit (after its pre-read snapshot) is
// never reclaimed by that commit, even though it is unreferenced, and a later
// write whose snapshot does include it reclaims it. Cleanup is
// eventually-consistent, never racing a concurrent writer's uncommitted blob.
func TestCommitSparesConcurrentInflightThenReclaimsIt(t *testing.T) {
	ctx := context.Background()
	mem, mk := seeded(t)

	// An established namespace, so later pre-read snapshots are non-empty.
	if _, _, err := secrets.For(mem, "proj", mk).Commit(ctx,
		func(cur *secrets.State) (*secrets.State, error) {
			return cur.Apply([]secrets.Write{{Key: "K", Value: "v1"}}), nil
		}, nil); err != nil {
		t.Fatal(err)
	}

	store := &inflightVault{Store: mem}
	if _, _, err := secrets.For(store, "proj", mk).Commit(ctx,
		func(cur *secrets.State) (*secrets.State, error) {
			return cur.Apply([]secrets.Write{{Key: "K", Value: "v2"}}), nil
		}, nil); err != nil {
		t.Fatalf("commit during which a blob was injected: %v", err)
	}
	if !store.injected {
		t.Fatal("the in-flight blob was never injected")
	}
	// Survives: it was created after this commit's pre-read snapshot.
	if _, err := mem.Get(ctx, "proj/data-inflight.age"); err != nil {
		t.Fatalf("a blob created during the commit must not be reclaimed: %v", err)
	}

	// A later write (no injection: inflightVault is one-shot) now has it in its
	// snapshot and reclaims it.
	if _, _, err := secrets.For(store, "proj", mk).Commit(ctx,
		func(cur *secrets.State) (*secrets.State, error) {
			return cur.Apply([]secrets.Write{{Key: "K", Value: "v3"}}), nil
		}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := mem.Get(ctx, "proj/data-inflight.age"); !errors.Is(err, backend.ErrNotFound) {
		t.Fatalf("a later write must reclaim the now-stale orphan, got %v", err)
	}
}
