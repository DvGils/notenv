package main

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/DvGils/notenv/internal/config"
	"github.com/DvGils/notenv/internal/crypto"
	"github.com/DvGils/notenv/internal/keymgmt"
	"github.com/DvGils/notenv/internal/keyring"
	"github.com/DvGils/notenv/internal/secrets"
)

// These cover the builder-subprocess orchestration that mints the scoped
// ephemeral vault: splitNamespaces and storageSpec (the spec the child reads
// back), the unlockSource preconditions, and runHandoffBuild copying only the
// requested namespaces. The crypto isolation of the result is covered by
// TestBuildEphemeralReadableViaIdentityOnly.

func TestSplitNamespaces(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"app", []string{"app"}},
		{"app,other", []string{"app", "other"}},
		{"  app , other  ", []string{"app", "other"}},
		{"app,,other", []string{"app", "other"}},
		{"app, ,other", []string{"app", "other"}},
		{" , ", nil},
	}
	for _, c := range cases {
		if got := splitNamespaces(c.in); !slices.Equal(got, c.want) {
			t.Errorf("splitNamespaces(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestStorageSpecRoundTrips(t *testing.T) {
	dir := t.TempDir()
	local := config.Effective{Path: dir}
	if got := storageSpec(local); got != "local:"+dir {
		t.Errorf("storageSpec(local) = %q, want %q", got, "local:"+dir)
	}
	remote := config.Effective{Remote: "b2", Base: "bucket/notenv"}
	if got := storageSpec(remote); got != "rclone:b2:bucket/notenv" {
		t.Errorf("storageSpec(remote) = %q, want rclone:b2:bucket/notenv", got)
	}
	// The spec must be one the resolver accepts back: it is what the child reads
	// from NOTENV_STORAGE.
	for _, eff := range []config.Effective{local, remote} {
		spec := storageSpec(eff)
		back, err := config.ResolveStorage(&config.User{}, spec)
		if err != nil {
			t.Fatalf("ResolveStorage(%q): %v", spec, err)
		}
		if back.Path != eff.Path || back.Remote != eff.Remote || back.Base != eff.Base {
			t.Errorf("round trip of %+v via %q gave %+v", eff, spec, back)
		}
	}
}

// TestUnlockSourceRefusesIdentityUnlockableSource: handoff must not hand the
// agent a vault that the agent's own configured identity could reopen, since
// the agent runs as you and could replay it to reach your real vault.
func TestUnlockSourceRefusesIdentityUnlockableSource(t *testing.T) {
	ctx := context.Background()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	// A recipient-slot vault is exactly an identity-unlockable source.
	srcDir := t.TempDir()
	if err := buildEphemeral(ctx, srcDir, id.Recipient(), map[string]*secrets.State{
		"app": stateOf(map[string]string{"K": "vvvvvv"}),
	}); err != nil {
		t.Fatal(err)
	}

	t.Setenv(identityEnv, id.String())
	_, _, err = unlockSource(ctx, openStorage(config.Effective{Path: srcDir}), config.Effective{Path: srcDir}, newMapCache())
	if err == nil {
		t.Fatal("unlockSource accepted a source the configured identity can unlock")
	}
	if !strings.Contains(err.Error(), identityEnv) {
		t.Errorf("refusal did not mention %s: %v", identityEnv, err)
	}
}

// TestUnlockSourceMissingHeader: an empty source storage is a clear "nothing to
// hand off", not an opaque backend error.
func TestUnlockSourceMissingHeader(t *testing.T) {
	ctx := context.Background()
	t.Setenv(identityEnv, "")
	_, _, err := unlockSource(ctx, openStorage(config.Effective{Path: t.TempDir()}), config.Effective{Path: "/x"}, newMapCache())
	if err == nil || !strings.Contains(err.Error(), "no vault found") {
		t.Fatalf("expected no-vault error, got %v", err)
	}
}

// TestRunHandoffBuildCopiesOnlyRequestedNamespaces is the builder's core security
// property: it reads the source under the cached master and re-encrypts ONLY the
// handed-off namespace into the ephemeral vault, then drops the source master
// from the cache before the agent runs (R1).
func TestRunHandoffBuildCopiesOnlyRequestedNamespaces(t *testing.T) {
	isolateConfig(t)
	ctx := context.Background()
	// A passphrase source vault with two namespaces; only "app" is handed off.
	cache := newMapCache()
	srcEff := seedCachedSource(t, cache, "app", "other")

	me, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	eDir := t.TempDir()
	withBuildFlags(t, storageSpec(srcEff), "app", eDir, me.Recipient().String())
	t.Setenv(identityEnv, "")

	if err := runHandoffBuild(ctx, cache); err != nil {
		t.Fatalf("runHandoffBuild: %v", err)
	}

	// The ephemeral vault holds only "app", readable by the ephemeral identity.
	estore := openStorage(config.Effective{Path: eDir})
	raw, err := estore.GetHeader(ctx)
	if err != nil {
		t.Fatal(err)
	}
	eHeader, err := crypto.ParseHeader(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := eHeader.NamespaceEntry("other"); ok {
		t.Error("handoff over-shared: 'other' reached the ephemeral vault")
	}
	entry, ok := eHeader.NamespaceEntry("app")
	if !ok {
		t.Fatal("handed-off namespace 'app' missing from the ephemeral vault")
	}
	emk, _, err := eHeader.UnlockIdentity(me)
	if err != nil {
		t.Fatal(err)
	}
	st, err := secrets.For(estore, "app", emk).Read(ctx, entry)
	if err != nil {
		t.Fatal(err)
	}
	if st.Secrets["K"] != "value-app" {
		t.Errorf("app[K] = %q, want value-app", st.Secrets["K"])
	}

	// R1: the build drops the source master from the shared cache before the
	// agent runs, so no agent-readable entry for your master survives.
	if _, ok := cache.Get(srcEff.Scope()); ok {
		t.Error("source master left in the cache after build (R1)")
	}
}

// TestRunHandoffBuildRefusedInForeignSession is the master-protection guard: an
// agent runs with NOTENV_SESSION set, and must not be able to drive the builder
// against a different (real) vault to re-encrypt it under its own recipient. The
// source master is warm in the cache here, which is the path that slips past
// ensureMaster's own session guard, so this pins the guard at the builder entry.
func TestRunHandoffBuildRefusedInForeignSession(t *testing.T) {
	isolateConfig(t)
	ctx := context.Background()
	cache := newMapCache()
	srcEff := seedCachedSource(t, cache, "app") // a real source, master cached (warm)

	me, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	eDir := t.TempDir()
	withBuildFlags(t, storageSpec(srcEff), "app", eDir, me.Recipient().String())
	t.Setenv(identityEnv, "")
	// Inside a handoff session scoped to some OTHER ephemeral vault (what a
	// compromised agent's environment carries).
	t.Setenv(sessionEnv, "9::local:/some/other/ephemeral")

	if err := runHandoffBuild(ctx, cache); err == nil {
		t.Fatal("builder must refuse a foreign vault from inside a handoff session")
	}
	// The refusal must precede any extraction: no ephemeral vault was written.
	if _, err := openStorage(config.Effective{Path: eDir}).GetHeader(ctx); err == nil {
		t.Error("builder wrote an ephemeral vault despite refusing the source (extraction leaked)")
	}
}

// countingCache is an in-memory cache that records Store calls, so a test can
// assert the handoff builder never caches the source master.
type countingCache struct {
	*mapCache
	stores int
}

func (c *countingCache) Store(scope, secret string, ttl time.Duration) error {
	c.stores++
	return c.mapCache.Store(scope, secret, ttl)
}

// TestUnlockSourceNeverCachesSourceMaster is the handoff caching guarantee: the
// builder unlocks the source, but a cached source master is exactly what would let
// the agent (which runs as you) open your real vault. Even on the cold path (empty
// cache, so the unlock prompts and reaches the caching code) and with a positive
// storage TTL, unlockSource must pass ttl 0 so the master is never stored. No lease
// is taken here, so this proves the no-caching is structural, not lease-dependent.
func TestUnlockSourceNeverCachesSourceMaster(t *testing.T) {
	isolateConfig(t)
	ctx := context.Background()
	t.Setenv(identityEnv, "")

	srcDir := t.TempDir()
	const pass = "correct horse battery staple"
	header, mk, err := crypto.NewHeader(pass, "owner")
	if err != nil {
		t.Fatal(err)
	}
	header.Revision = 0 // SafePut owns the revision
	store := openStorage(config.Effective{Path: srcDir})
	verify := func(h *crypto.Header) (*crypto.MasterKey, error) { m, _, _, e := h.Unlock(pass); return m, e }
	if err := keymgmt.SafePut(ctx, store, header, nil, mk, verify); err != nil {
		t.Fatal(err)
	}

	// Drive the cold unlock without a terminal.
	prev := promptPassphraseFn
	promptPassphraseFn = func(string) (string, error) { return pass, nil }
	t.Cleanup(func() { promptPassphraseFn = prev })

	cache := &countingCache{mapCache: newMapCache()}
	// CacheTTL > 0: without the ttl-0 hardening, the cold unlock would cache here.
	eff := config.Effective{Path: srcDir, CacheTTL: time.Hour}
	if _, _, err := unlockSource(ctx, store, eff, cache); err != nil {
		t.Fatalf("unlockSource: %v", err)
	}
	if cache.stores != 0 {
		t.Errorf("builder cached the source master (%d Store calls); it must never cache, even with a positive TTL", cache.stores)
	}
}

// seedCachedSource builds a passphrase source vault holding each namespace with
// one secret (K=value-<ns>) and seeds its master into the given cache, so
// unlockSource resolves it warm instead of prompting. An in-memory cache is
// sufficient because the builder runs in-process in these tests; the keyring
// package's own tests cover the real native caches.
func seedCachedSource(t *testing.T, cache keyring.Cache, namespaces ...string) config.Effective {
	t.Helper()
	ctx := context.Background()
	srcEff, err := config.ResolveStorage(&config.User{}, "local:"+t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	const pass = "correct horse battery staple"
	header, mk, err := crypto.NewHeader(pass, "owner")
	if err != nil {
		t.Fatal(err)
	}
	header.Revision = 0 // SafePut owns the revision; the stored header starts at 1
	src := openStorage(srcEff)
	verify := func(h *crypto.Header) (*crypto.MasterKey, error) {
		m, _, _, e := h.Unlock(pass)
		return m, e
	}
	if err := keymgmt.SafePut(ctx, src, header, nil, mk, verify); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	for _, ns := range namespaces {
		writes := []secrets.Write{{Key: "K", Value: "value-" + ns, TS: now}}
		if _, _, err := secrets.For(src, ns, mk).Commit(ctx,
			func(cur *secrets.State) (*secrets.State, error) { return cur.Apply(writes), nil },
			nil); err != nil {
			t.Fatalf("seed %s: %v", ns, err)
		}
	}
	if err := cache.Store(srcEff.Scope(), mk.String(), time.Minute); err != nil {
		t.Fatalf("seed cache: %v", err)
	}
	if _, ok := cache.Get(srcEff.Scope()); !ok {
		t.Fatal("seed cache: miss after store")
	}
	t.Cleanup(func() { cache.Drop(srcEff.Scope()) })
	return srcEff
}

// TestRunHandoffBuildMissingArgs: the builder is internal, so absent arguments
// are an internal error, caught before any vault is touched.
func TestRunHandoffBuildMissingArgs(t *testing.T) {
	withBuildFlags(t, "", "", "", "")
	if err := runHandoffBuild(context.Background(), newMapCache()); err == nil || !strings.Contains(err.Error(), "missing arguments") {
		t.Fatalf("expected missing-arguments error, got %v", err)
	}
}

// TestRunHandoffBuildRejectsBadRecipient: a malformed ephemeral recipient is
// rejected before the source is unlocked, so a build never proceeds toward a
// vault no one can open.
func TestRunHandoffBuildRejectsBadRecipient(t *testing.T) {
	withBuildFlags(t, "local:/src", "app", t.TempDir(), "not-a-recipient")
	if err := runHandoffBuild(context.Background(), newMapCache()); err == nil || !strings.Contains(err.Error(), "recipient") {
		t.Fatalf("expected bad-recipient error, got %v", err)
	}
}

// withBuildFlags sets the package-level builder flags for one test and restores
// them after; runHandoffBuild reads them as globals.
func withBuildFlags(t *testing.T, source, namespaces, vault, recipient string) {
	t.Helper()
	origSource, origNS, origVault, origRecip := buildSource, buildNamespaces, buildVault, buildRecipient
	buildSource, buildNamespaces, buildVault, buildRecipient = source, namespaces, vault, recipient
	t.Cleanup(func() {
		buildSource, buildNamespaces, buildVault, buildRecipient = origSource, origNS, origVault, origRecip
	})
}
