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
	_, _, err = unlockSource(ctx, openStorage(config.Effective{Path: srcDir}), config.Effective{Path: srcDir})
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
	_, _, err := unlockSource(ctx, openStorage(config.Effective{Path: t.TempDir()}), config.Effective{Path: "/x"})
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
	srcEff := seedCachedSource(t, "app", "other")

	me, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	eDir := t.TempDir()
	withBuildFlags(t, storageSpec(srcEff), "app", eDir, me.Recipient().String())
	t.Setenv(identityEnv, "")

	if err := runHandoffBuild(ctx); err != nil {
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
	if _, ok := cacheProvider().Get(srcEff.Scope()); ok {
		t.Error("source master left in the cache after build (R1)")
	}
}

// useInProcessCache points the build path at an in-memory cache for the test. The
// handoff builder runs in-process in these tests, so it needs no cross-process
// platform store; the real macOS Keychain only added a headless-CI hang.
func useInProcessCache(t *testing.T) {
	t.Helper()
	prev := cacheProvider
	c := newMapCache()
	cacheProvider = func() keyring.Cache { return c }
	t.Cleanup(func() { cacheProvider = prev })
}

// seedCachedSource builds a passphrase source vault holding each namespace with
// one secret (K=value-<ns>) and seeds its master into an in-process cache, so
// unlockSource resolves it warm instead of prompting. The builder runs in-process
// in these tests, so an in-memory cache is sufficient and avoids the real platform
// store (the macOS Keychain hung headlessly in CI). The keyring package's own
// tests cover the real native caches.
func seedCachedSource(t *testing.T, namespaces ...string) config.Effective {
	t.Helper()
	useInProcessCache(t)
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
	cache := cacheProvider()
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
	if err := runHandoffBuild(context.Background()); err == nil || !strings.Contains(err.Error(), "missing arguments") {
		t.Fatalf("expected missing-arguments error, got %v", err)
	}
}

// TestRunHandoffBuildRejectsBadRecipient: a malformed ephemeral recipient is
// rejected before the source is unlocked, so a build never proceeds toward a
// vault no one can open.
func TestRunHandoffBuildRejectsBadRecipient(t *testing.T) {
	withBuildFlags(t, "local:/src", "app", t.TempDir(), "not-a-recipient")
	if err := runHandoffBuild(context.Background()); err == nil || !strings.Contains(err.Error(), "recipient") {
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
