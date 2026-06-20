package main

import (
	"context"
	"strings"
	"testing"

	"github.com/DvGils/notenv/internal/backend/memstore"
	"github.com/DvGils/notenv/internal/crypto"
	"github.com/DvGils/notenv/internal/keymgmt"
	"github.com/DvGils/notenv/internal/secrets"
)

// freshVault seeds a healthy, empty vault (a sealed header, no namespaces) and
// returns it as a headerTarget plus its master, the state the namespace commands
// operate against once unlockHeader has run.
func freshVault(t *testing.T) (*headerTarget, *crypto.MasterKey) {
	t.Helper()
	ctx := context.Background()
	store := memstore.New()
	header, mk, err := crypto.NewHeader("owner pass", "owner")
	if err != nil {
		t.Fatal(err)
	}
	verify := func(h *crypto.Header) (*crypto.MasterKey, error) { m, _, _, e := h.Unlock("owner pass"); return m, e }
	if err := keymgmt.SafePut(ctx, store, header, nil, mk, verify); err != nil {
		t.Fatal(err)
	}
	return &headerTarget{vaultStorage: doctorStore{store}, scope: "scope", cache: newMapCache()}, mk
}

// headerEntry reads a namespace's manifest entry from the stored header the way a
// fresh command would.
func headerEntry(t *testing.T, store *headerTarget, ns string) (crypto.ManifestEntry, bool) {
	t.Helper()
	raw, err := store.GetHeader(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	h, err := crypto.ParseHeader(raw)
	if err != nil {
		t.Fatal(err)
	}
	return h.NamespaceEntry(ns)
}

// TestCreateNamespace: create stands up an empty, persistent namespace, and a
// second create refuses rather than touching it.
func TestCreateNamespace(t *testing.T) {
	ctx := context.Background()
	target, mk := freshVault(t)

	if err := createNamespace(ctx, target, mk, "newns", ""); err != nil {
		t.Fatalf("create: %v", err)
	}
	if ok, err := secrets.Exists(ctx, target, "newns"); err != nil || !ok {
		t.Fatalf("Exists after create = %v,%v, want true,nil", ok, err)
	}
	entry, ok := headerEntry(t, target, "newns")
	if !ok {
		t.Fatal("create must record a manifest entry")
	}
	state, err := secrets.For(target, "newns", mk).Read(ctx, entry)
	if err != nil {
		t.Fatalf("read created namespace: %v", err)
	}
	if !state.HasHistory() || len(state.Secrets) != 0 {
		t.Fatalf("created namespace = history %v, %d secrets; want history true, 0 secrets", state.HasHistory(), len(state.Secrets))
	}

	if err := createNamespace(ctx, target, mk, "newns", ""); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("second create: err = %v, want an 'already exists' error", err)
	}
}

// TestDeleteNamespace: delete drops the namespace's manifest entry and its
// secrets.
func TestDeleteNamespace(t *testing.T) {
	ctx := context.Background()
	target, mk := freshVault(t)

	if _, _, err := secrets.For(target, "proj", mk).Commit(ctx,
		func(cur *secrets.State) (*secrets.State, error) {
			return cur.Apply([]secrets.Write{{Key: "K", Value: "v"}}), nil
		}, nil); err != nil {
		t.Fatalf("seed secret: %v", err)
	}
	if ok, _ := secrets.Exists(ctx, target, "proj"); !ok {
		t.Fatal("setup: the namespace should exist before delete")
	}

	if err := deleteNamespace(ctx, target, mk, "proj"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if ok, err := secrets.Exists(ctx, target, "proj"); err != nil || ok {
		t.Fatalf("Exists after delete = %v,%v, want false,nil", ok, err)
	}
	if _, ok := headerEntry(t, target, "proj"); ok {
		t.Fatal("delete must drop the manifest entry")
	}
}

// readNamespaceMeta reads a namespace's resolved namespace-level metadata.
func readNamespaceMeta(t *testing.T, target *headerTarget, mk *crypto.MasterKey, ns string) secrets.NamespaceMeta {
	t.Helper()
	entry, ok := headerEntry(t, target, ns)
	if !ok {
		t.Fatalf("namespace %q has no entry", ns)
	}
	st, err := secrets.For(target, ns, mk).Read(context.Background(), entry)
	if err != nil {
		t.Fatalf("read %q: %v", ns, err)
	}
	return st.Namespace
}

// TestNamespaceDescription: create stamps an initial description and a creation
// time; update changes the description (and clears it on "") while preserving the
// creation stamp; the namespace's secrets survive an update.
func TestNamespaceDescription(t *testing.T) {
	ctx := context.Background()
	target, mk := freshVault(t)

	if err := createNamespace(ctx, target, mk, "proj", "prod secrets"); err != nil {
		t.Fatalf("create: %v", err)
	}
	created := readNamespaceMeta(t, target, mk, "proj")
	if created.Description != "prod secrets" {
		t.Fatalf("created description = %q, want 'prod secrets'", created.Description)
	}
	if created.Created == 0 || created.CreatedBy == "" {
		t.Fatalf("create must stamp created (got %d/%q)", created.Created, created.CreatedBy)
	}

	// A secret in the namespace must survive a description update.
	if _, _, err := secrets.For(target, "proj", mk).WithStamp(writeStamp()).Commit(ctx,
		func(cur *secrets.State) (*secrets.State, error) {
			return cur.Apply([]secrets.Write{{Key: "K", Value: "v"}}), nil
		}, nil); err != nil {
		t.Fatalf("seed secret: %v", err)
	}

	if err := updateNamespaceDescription(ctx, target, mk, "proj", "staging secrets"); err != nil {
		t.Fatalf("update: %v", err)
	}
	updated := readNamespaceMeta(t, target, mk, "proj")
	if updated.Description != "staging secrets" {
		t.Fatalf("updated description = %q, want 'staging secrets'", updated.Description)
	}
	if updated.Created != created.Created || updated.CreatedBy != created.CreatedBy {
		t.Fatalf("update must preserve created: %d/%q -> %d/%q", created.Created, created.CreatedBy, updated.Created, updated.CreatedBy)
	}
	entry, _ := headerEntry(t, target, "proj")
	st, _ := secrets.For(target, "proj", mk).Read(ctx, entry)
	if st.Secrets["K"] != "v" {
		t.Fatalf("update dropped the namespace's secret: K = %q, want v", st.Secrets["K"])
	}

	// Clearing round-trips to empty.
	if err := updateNamespaceDescription(ctx, target, mk, "proj", ""); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if got := readNamespaceMeta(t, target, mk, "proj").Description; got != "" {
		t.Fatalf("cleared description = %q, want empty", got)
	}
}
