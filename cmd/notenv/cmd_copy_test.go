package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/DvGils/notenv/internal/backend/memstore"
	"github.com/DvGils/notenv/internal/blobcache"
	"github.com/DvGils/notenv/internal/config"
	"github.com/DvGils/notenv/internal/crypto"
	"github.com/DvGils/notenv/internal/keymgmt"
	"github.com/DvGils/notenv/internal/secrets"
)

// copyApp builds an app over a memstore vault bound to the destination namespace
// "dst", seeds the source namespace "src" with srcKV, and pre-caches the master
// so unlockView is warm (no prompt). Both namespaces are pre-accepted so the
// first-use guard is out of the way; tests that exercise the guard or the
// session refusal set the relevant state themselves. Returns the app, store, and
// master.
func copyApp(t *testing.T, srcKV map[string]secrets.Write) (*app, *memstore.Store, *crypto.MasterKey) {
	t.Helper()
	isolateConfig(t)
	ctx := context.Background()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	store := memstore.New()
	header, mk, err := crypto.NewRecipientHeader(id.Recipient(), "owner")
	if err != nil {
		t.Fatal(err)
	}
	header.Revision = 0
	verify := func(hh *crypto.Header) (*crypto.MasterKey, error) { m, _, e := hh.UnlockIdentity(id); return m, e }
	if err := keymgmt.SafePut(ctx, store, header, nil, mk, verify); err != nil {
		t.Fatal(err)
	}
	if len(srcKV) > 0 {
		writes := make([]secrets.Write, 0, len(srcKV))
		for _, w := range srcKV {
			writes = append(writes, w)
		}
		if _, _, err := secrets.For(store, "src", mk).Commit(ctx,
			func(cur *secrets.State) (*secrets.State, error) { return cur.Apply(writes), nil }, nil); err != nil {
			t.Fatalf("seed src: %v", err)
		}
	}
	a := &app{
		namespace:  "dst",
		store:      store,
		cache:      newMapCache(),
		blobs:      blobcache.New(0),
		cacheScope: "test-scope",
		cacheTTL:   time.Hour,
	}
	a.cache.Store(a.cacheScope, mk.String(), time.Hour)
	if err := config.AcceptNamespace(a.cacheScope, "src"); err != nil {
		t.Fatal(err)
	}
	if err := config.AcceptNamespace(a.cacheScope, "dst"); err != nil {
		t.Fatal(err)
	}
	return a, store, mk
}

// readNamespace resolves a namespace's secrets straight from the store, the way
// a fresh read would, so a test checks what actually landed on storage.
func readNamespace(t *testing.T, store *memstore.Store, mk *crypto.MasterKey, ns string) *secrets.State {
	t.Helper()
	ctx := context.Background()
	raw, err := store.GetHeader(ctx)
	if err != nil {
		t.Fatal(err)
	}
	header, err := crypto.ParseHeader(raw)
	if err != nil {
		t.Fatal(err)
	}
	entry, _ := header.NamespaceEntry(ns)
	st, err := secrets.For(store, ns, mk).Read(ctx, entry)
	if err != nil {
		t.Fatalf("read namespace %q: %v", ns, err)
	}
	return st
}

// TestCopyHappyPath: the value (and its description) lands in the destination,
// and the source is left untouched, with nothing printed.
func TestCopyHappyPath(t *testing.T) {
	ctx := context.Background()
	a, store, mk := copyApp(t, map[string]secrets.Write{
		"API_KEY": {Key: "API_KEY", Value: "s3cr3t", Description: "the API key", TS: 100},
	})
	if err := runCopy(ctx, a, "API_KEY", "src", false); err != nil {
		t.Fatalf("runCopy: %v", err)
	}
	dst := readNamespace(t, store, mk, "dst")
	if dst.Secrets["API_KEY"] != "s3cr3t" {
		t.Fatalf("destination value = %q, want the copied value", dst.Secrets["API_KEY"])
	}
	if dst.Meta["API_KEY"].Description != "the API key" {
		t.Fatalf("description not carried: %q", dst.Meta["API_KEY"].Description)
	}
	src := readNamespace(t, store, mk, "src")
	if src.Secrets["API_KEY"] != "s3cr3t" {
		t.Fatal("source must be left intact (copy, not move)")
	}
}

// TestCopyMissingSourceKey: copying a key the source does not hold fails with a
// precise error and writes nothing.
func TestCopyMissingSourceKey(t *testing.T) {
	ctx := context.Background()
	a, store, mk := copyApp(t, map[string]secrets.Write{
		"OTHER": {Key: "OTHER", Value: "x", TS: 100},
	})
	err := runCopy(ctx, a, "API_KEY", "src", false)
	if err == nil || !strings.Contains(err.Error(), "not set in source") {
		t.Fatalf("err = %v, want a not-set-in-source error", err)
	}
	if dst := readNamespace(t, store, mk, "dst"); dst.Secrets["API_KEY"] != "" {
		t.Fatal("nothing should have been written to the destination")
	}
}

// TestCopyRefusesExisting: an existing destination key is preserved unless
// --force is given, then overwritten.
func TestCopyRefusesExisting(t *testing.T) {
	ctx := context.Background()
	a, store, mk := copyApp(t, map[string]secrets.Write{
		"API_KEY": {Key: "API_KEY", Value: "new", TS: 200},
	})
	// Pre-seed the destination with a different value.
	if _, _, err := secrets.For(store, "dst", mk).Commit(ctx,
		func(cur *secrets.State) (*secrets.State, error) {
			return cur.Apply([]secrets.Write{{Key: "API_KEY", Value: "old", TS: 100}}), nil
		}, nil); err != nil {
		t.Fatal(err)
	}

	err := runCopy(ctx, a, "API_KEY", "src", false)
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("err = %v, want an already-exists refusal", err)
	}
	if got := readNamespace(t, store, mk, "dst").Secrets["API_KEY"]; got != "old" {
		t.Fatalf("destination clobbered without --force: %q", got)
	}

	if err := runCopy(ctx, a, "API_KEY", "src", true); err != nil {
		t.Fatalf("runCopy --force: %v", err)
	}
	if got := readNamespace(t, store, mk, "dst").Secrets["API_KEY"]; got != "new" {
		t.Fatalf("--force did not overwrite: %q", got)
	}
}

// TestCopySessionGuardRefusesForeignVault is the handoff regression: inside a
// session for some other vault, copy must refuse to unlock this one even though
// its master is warm in the cache. This is what stops an in-session agent from
// using copy to reach a vault it was not handed.
func TestCopySessionGuardRefusesForeignVault(t *testing.T) {
	ctx := context.Background()
	a, store, mk := copyApp(t, map[string]secrets.Write{
		"API_KEY": {Key: "API_KEY", Value: "s3cr3t", TS: 100},
	})
	// The session is bound to a different scope than this app's vault.
	t.Setenv(sessionEnv, "some-other-vault-scope")

	err := runCopy(ctx, a, "API_KEY", "src", false)
	if err == nil || !strings.Contains(err.Error(), "handoff session") {
		t.Fatalf("err = %v, want a handoff-session refusal", err)
	}
	if dst := readNamespace(t, store, mk, "dst"); dst.Secrets["API_KEY"] != "" {
		t.Fatal("a refused copy must write nothing")
	}
}

// TestCopyWithinSessionAllowed: when the session is bound to this very vault (the
// agent copying between two namespaces it was handed), copy proceeds.
func TestCopyWithinSessionAllowed(t *testing.T) {
	ctx := context.Background()
	a, store, mk := copyApp(t, map[string]secrets.Write{
		"API_KEY": {Key: "API_KEY", Value: "s3cr3t", TS: 100},
	})
	t.Setenv(sessionEnv, a.cacheScope)
	if err := runCopy(ctx, a, "API_KEY", "src", false); err != nil {
		t.Fatalf("in-session copy of the handed-off vault must work: %v", err)
	}
	if got := readNamespace(t, store, mk, "dst").Secrets["API_KEY"]; got != "s3cr3t" {
		t.Fatalf("destination value = %q, want the copied value", got)
	}
}

// TestCopyCmdRejectsContradictoryFlags exercises the RunE-level argument checks
// that never reach runCopy.
func TestCopyCmdRejectsContradictoryFlags(t *testing.T) {
	cases := []struct {
		name      string
		from, to  string
		namespace string
		want      string
	}{
		{"missing from", "", "dst", "", "both --from and --to"},
		{"missing to", "src", "", "", "both --from and --to"},
		{"same namespace", "x", "x", "", "same namespace"},
		{"namespace flag", "src", "dst", "ns", "not --namespace"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			copyFrom, copyTo, namespaceFlag = c.from, c.to, c.namespace
			t.Cleanup(func() { copyFrom, copyTo, namespaceFlag = "", "", "" })
			err := copyCmd.RunE(copyCmd, []string{"API_KEY"})
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
}
