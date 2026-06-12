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
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
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

// TestDoctorNamesEveryPlantedFault: a vault with a stale provisional slot, an
// unrecorded object, a missing recorded object, and a rolled-back pin must
// surface exactly those findings, and the storage must be untouched.
func TestDoctorNamesEveryPlantedFault(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
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
	// One recorded object that exists, one recorded object that is missing.
	header.Manifest = map[string]crypto.ManifestEntry{
		"proj/seg-m1-aa.age":   {},
		"proj/seg-m1-gone.age": {},
	}
	header.Revision = 0
	verify := func(h *crypto.Header) (*crypto.MasterKey, error) { m, _, _, e := h.Unlock("owner pass"); return m, e }
	if err := keymgmt.SafePut(ctx, store, header, nil, mk, verify); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(ctx, "proj/seg-m1-aa.age", []byte("x")); err != nil {
		t.Fatal(err)
	}
	// An object no manifest entry records (a crashed write).
	if err := store.Put(ctx, "proj/seg-m1-orphan.age", []byte("x")); err != nil {
		t.Fatal(err)
	}
	// A pin ahead of the served header (a rollback).
	if err := config.WritePin("scope", header.VaultID, config.Pin{Revision: header.Revision + 3, MasterPub: mk.PublicKey()}); err != nil {
		t.Fatal(err)
	}
	before := store.Header()

	c := &checkup{}
	runDoctor(doctorCmdCtx(t), &headerTarget{vaultStorage: doctorStore{store}, scope: "scope"}, c)
	// stale provisional + unrecorded + missing + rollback
	if c.problems != 4 {
		t.Fatalf("want exactly 4 findings, got %d", c.problems)
	}
	if string(store.Header()) != string(before) {
		t.Fatal("doctor must not write")
	}
}
