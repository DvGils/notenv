package main

import (
	"context"
	"encoding/json"
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

// TestListNamespaceNames: the names come from the header manifest (sorted, no
// master), and virgin storage is a friendly error rather than a crash.
func TestListNamespaceNames(t *testing.T) {
	ctx := context.Background()
	store := memstore.New()
	seedNamespaceHeader(t, store, "beta", "alpha") // recorded out of order
	target := &headerTarget{vaultStorage: doctorStore{store}, scope: "scope", cache: newMapCache()}

	names, err := listNamespaceNames(ctx, target)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(names) != 2 || names[0] != "alpha" || names[1] != "beta" {
		t.Fatalf("names = %v, want [alpha beta] sorted", names)
	}

	empty := &headerTarget{vaultStorage: doctorStore{memstore.New()}, scope: "scope", cache: newMapCache()}
	if _, err := listNamespaceNames(ctx, empty); err == nil || !strings.Contains(err.Error(), "no vault") {
		t.Fatalf("virgin storage: err = %v, want a 'no vault' error", err)
	}
}

// TestNamespaceListJSONShape pins the frozen `namespace list --json` shape: a
// versioned envelope around named-field objects.
func TestNamespaceListJSONShape(t *testing.T) {
	data, err := json.Marshal(newNamespaceList([]string{"a", "b"}))
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"version":1,"namespaces":[{"name":"a"},{"name":"b"}]}`
	if string(data) != want {
		t.Fatalf("json = %s, want %s", data, want)
	}
	// An empty vault still emits an array, never null, so consumers need no
	// sentinel handling.
	data, _ = json.Marshal(newNamespaceList(nil))
	if string(data) != `{"version":1,"namespaces":[]}` {
		t.Fatalf("empty json = %s, want an empty array", data)
	}
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
// time; edit changes the description (and clears it on "") while preserving the
// creation stamp; the namespace's secrets survive an edit.
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

	// A secret in the namespace must survive a description edit.
	if _, _, err := secrets.For(target, "proj", mk).WithStamp(writeStamp()).Commit(ctx,
		func(cur *secrets.State) (*secrets.State, error) {
			return cur.Apply([]secrets.Write{{Key: "K", Value: "v"}}), nil
		}, nil); err != nil {
		t.Fatalf("seed secret: %v", err)
	}

	if err := editNamespaceDescription(ctx, target, mk, "proj", "staging secrets"); err != nil {
		t.Fatalf("edit: %v", err)
	}
	edited := readNamespaceMeta(t, target, mk, "proj")
	if edited.Description != "staging secrets" {
		t.Fatalf("edited description = %q, want 'staging secrets'", edited.Description)
	}
	if edited.Created != created.Created || edited.CreatedBy != created.CreatedBy {
		t.Fatalf("edit must preserve created: %d/%q -> %d/%q", created.Created, created.CreatedBy, edited.Created, edited.CreatedBy)
	}
	entry, _ := headerEntry(t, target, "proj")
	st, _ := secrets.For(target, "proj", mk).Read(ctx, entry)
	if st.Secrets["K"] != "v" {
		t.Fatalf("edit dropped the namespace's secret: K = %q, want v", st.Secrets["K"])
	}

	// Clearing round-trips to empty.
	if err := editNamespaceDescription(ctx, target, mk, "proj", ""); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if got := readNamespaceMeta(t, target, mk, "proj").Description; got != "" {
		t.Fatalf("cleared description = %q, want empty", got)
	}
}
