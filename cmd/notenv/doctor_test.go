package main

import (
	"context"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/DvGils/notenv/internal/backend/memstore"
	"github.com/DvGils/notenv/internal/config"
	"github.com/DvGils/notenv/internal/crypto"
	"github.com/DvGils/notenv/internal/keymgmt"
)

// doctorStore adapts a memstore to the vaultStorage interface; doctor must
// never write, so reachability probes are trivially healthy.
type doctorStore struct{ *memstore.Store }

func (doctorStore) Preflight(context.Context) error { return nil }
func (doctorStore) Probe(context.Context) error     { return nil }

func doctorCmdCtx(t *testing.T) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	return cmd
}

// TestDoctorCleanVault: a healthy vault yields zero findings.
func TestDoctorCleanVault(t *testing.T) {
	isolateConfig(t)
	ctx := context.Background()
	store := memstore.New()

	header, mk, err := crypto.NewHeader("owner pass", "owner")
	if err != nil {
		t.Fatal(err)
	}
	header.Revision = 0
	verify := func(h *crypto.Header) (*crypto.MasterKey, error) { m, _, _, e := h.Unlock("owner pass"); return m, e }
	if err := keymgmt.SafePut(ctx, store, header, nil, mk, verify); err != nil {
		t.Fatal(err)
	}

	c := &checkup{}
	runDoctor(doctorCmdCtx(t), &headerTarget{vaultStorage: doctorStore{store}, scope: "scope"}, c)
	if c.problems != 0 {
		t.Fatalf("clean vault must have no findings, got %d", c.problems)
	}
}

// TestDoctorNamesEveryPlantedFault: a vault with a stale provisional slot, a
// namespace whose current blob is missing, and a rolled-back pin must surface
// exactly those problems (and an orphan blob as a note), with storage untouched.
func TestDoctorNamesEveryPlantedFault(t *testing.T) {
	isolateConfig(t)
	ctx := context.Background()
	store := memstore.New()

	header, mk, err := crypto.NewHeader("owner pass", "owner")
	if err != nil {
		t.Fatal(err)
	}
	if err := header.AddPassphraseSlot("temp", "ghost", mk); err != nil {
		t.Fatal(err)
	}
	header.Slots[1].Provisional = true
	header.Slots[1].TS = time.Now().Add(-9 * 24 * time.Hour).Unix()
	// A namespace whose current blob is missing from storage.
	header.Manifest = map[string]crypto.ManifestEntry{
		"gone": {Blob: "gone/data.age", MAC: "x"},
	}
	header.Revision = 0
	verify := func(h *crypto.Header) (*crypto.MasterKey, error) { m, _, _, e := h.Unlock("owner pass"); return m, e }
	if err := keymgmt.SafePut(ctx, store, header, nil, mk, verify); err != nil {
		t.Fatal(err)
	}
	// A blob no manifest entry references (a crashed write): a note, not a problem.
	if err := store.Put(ctx, "stray/data-orphan.age", []byte("x")); err != nil {
		t.Fatal(err)
	}
	// A pin ahead of the served header (a rollback).
	if err := config.WritePin("scope", header.VaultID, config.Pin{Revision: header.Revision + 3, MasterPub: mk.PublicKey()}); err != nil {
		t.Fatal(err)
	}
	before := store.Header()

	c := &checkup{}
	runDoctor(doctorCmdCtx(t), &headerTarget{vaultStorage: doctorStore{store}, scope: "scope"}, c)
	// stale provisional + missing blob + rollback
	if c.problems != 3 {
		t.Fatalf("want exactly 3 problems, got %d", c.problems)
	}
	if notes := countLevel(c, "note"); notes < 1 {
		t.Fatalf("the orphan blob must surface as a note, got %d notes", notes)
	}
	if string(store.Header()) != string(before) {
		t.Fatal("doctor must not write")
	}
}

// TestDoctorVerifiesBlobContent: with a session master, doctor reads every
// namespace's current blob and flags one that does not decrypt or whose manifest
// MAC does not match (a read would fail closed on either). A corrupt
// one-generation backup is only a note (it is never served on the happy path).
func TestDoctorVerifiesBlobContent(t *testing.T) {
	isolateConfig(t)
	ctx := context.Background()
	store := memstore.New()
	header, mk, err := crypto.NewHeader("owner pass", "owner")
	if err != nil {
		t.Fatal(err)
	}

	plain := []byte("a secret payload")
	mac, err := mk.BlobMAC(plain)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := mk.Encrypt(plain)
	if err != nil {
		t.Fatal(err)
	}
	put := func(key string, data []byte) {
		if err := store.Put(ctx, key, data); err != nil {
			t.Fatal(err)
		}
	}
	put("nsok/data.age", sealed)
	put("nsbad/data.age", []byte("not an age message"))
	put("nsmac/data.age", sealed)
	put("nsbk/data.age", sealed)
	put("nsbk/old.age", []byte("rotted backup"))
	header.Manifest = map[string]crypto.ManifestEntry{
		"nsok":  {Blob: "nsok/data.age", MAC: mac},
		"nsbad": {Blob: "nsbad/data.age", MAC: mac},                                       // correct MAC, but the bytes do not decrypt
		"nsmac": {Blob: "nsmac/data.age", MAC: "0000"},                                    // decrypts, but the MAC will not match
		"nsbk":  {Blob: "nsbk/data.age", MAC: mac, Prev: "nsbk/old.age", PrevMAC: "ffff"}, // current ok, backup corrupt
	}

	c := &checkup{}
	checkBlobs(doctorCmdCtx(t), &headerTarget{vaultStorage: doctorStore{store}, scope: "scope"}, c, header, mk)
	if c.problems != 2 {
		t.Fatalf("want 2 problems (does-not-decrypt + MAC-mismatch), got %d", c.problems)
	}
	if notes := countLevel(c, "note"); notes < 1 {
		t.Fatalf("the corrupt backup must surface as a note, got %d notes", notes)
	}
}

func countLevel(c *checkup, level string) int {
	n := 0
	for _, f := range c.findings {
		if f.Level == level {
			n++
		}
	}
	return n
}

// TestReferencedBlobs: the manifest's referenced set is exactly each namespace's
// current blob and its one-generation backup. An object outside it is an orphan
// doctor reports and the next write reclaims; nothing else may land in the set.
func TestReferencedBlobs(t *testing.T) {
	header, _, err := crypto.NewHeader("p", "owner")
	if err != nil {
		t.Fatal(err)
	}
	header.SetNamespace("a", crypto.ManifestEntry{Blob: "a/data-1.age", MAC: "x", Prev: "a/data-0.age", PrevMAC: "y"})
	ref := referencedBlobs(header)
	for _, k := range []string{"a/data-1.age", "a/data-0.age"} {
		if !ref[k] {
			t.Fatalf("referencedBlobs missing %s", k)
		}
	}
	if ref["a/data-orphan.age"] {
		t.Fatalf("an orphan blob must not be in the referenced set")
	}
	if len(ref) != 2 {
		t.Fatalf("referencedBlobs = %d entries, want 2 (current + backup)", len(ref))
	}
}
