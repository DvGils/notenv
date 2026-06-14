package main

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/DvGils/notenv/internal/backend/memstore"
	"github.com/DvGils/notenv/internal/config"
	"github.com/DvGils/notenv/internal/crypto"
)

// seedNamespaceHeader gives store a sealed header whose manifest records the
// named namespaces, the authenticated "this namespace holds committed secrets"
// signal the guard now checks (a raw blob with no manifest entry is an orphan
// and must not count).
func seedNamespaceHeader(t *testing.T, store *memstore.Store, namespaces ...string) {
	t.Helper()
	header, mk, err := crypto.NewHeader("p", "owner")
	if err != nil {
		t.Fatal(err)
	}
	for _, ns := range namespaces {
		header.SetNamespace(ns, crypto.ManifestEntry{Blob: ns + "/data-x.age", MAC: "x"})
	}
	if err := header.Seal(mk); err != nil {
		t.Fatal(err)
	}
	raw, err := header.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutHeader(context.Background(), raw); err != nil {
		t.Fatal(err)
	}
}

// forceNonInteractive pins the prompt seam for a test: the real check opens
// /dev/tty, which exists when tests run from a terminal and not in CI, so
// tests must not depend on it.
func forceNonInteractive(t *testing.T) {
	t.Helper()
	prev := interactiveFn
	interactiveFn = func() bool { return false }
	t.Cleanup(func() { interactiveFn = prev })
}

// TestGuardFlagNamespace: a virgin namespace is accepted without ceremony and
// recorded; joining a namespace that already holds secrets fails closed when
// nobody can answer, unless the environment names it; once recorded, the
// guard passes without listing.
func TestGuardFlagNamespace(t *testing.T) {
	ctx := context.Background()
	isolateConfig(t)
	forceNonInteractive(t)
	store := memstore.New()

	if err := guardFlagNamespace(ctx, store, "scope", "fresh"); err != nil {
		t.Fatalf("virgin namespace: %v", err)
	}
	if ok, _ := config.NamespaceAccepted("scope", "fresh"); !ok {
		t.Fatal("virgin acceptance must be recorded")
	}

	seedNamespaceHeader(t, store, "ops")
	// The join must refuse without a terminal and without the env opt-in.
	err := guardFlagNamespace(ctx, store, "scope", "ops")
	if err == nil || !strings.Contains(err.Error(), acceptNamespaceEnv) {
		t.Fatalf("existing namespace, non-interactive: err = %v, want a refusal naming %s", err, acceptNamespaceEnv)
	}
	if ok, _ := config.NamespaceAccepted("scope", "ops"); ok {
		t.Fatal("a refused namespace must not be recorded")
	}
	// The operator's environment naming the namespace is the opt-in, but only for
	// this invocation: NOTENV_ACCEPT_NAMESPACE is a per-run override, not a durable
	// grant, so it must NOT be persisted.
	t.Setenv(acceptNamespaceEnv, "other, ops")
	if err := guardFlagNamespace(ctx, store, "scope", "ops"); err != nil {
		t.Fatalf("env-accepted namespace: %v", err)
	}
	if ok, _ := config.NamespaceAccepted("scope", "ops"); ok {
		t.Fatal("an env-accepted namespace must not be persisted (it is a per-invocation override)")
	}
	// With the env cleared, the next run has no durable acceptance to lean on and
	// must re-confirm (here: refuse, since there is no terminal and no env).
	t.Setenv(acceptNamespaceEnv, "")
	err = guardFlagNamespace(ctx, store, "scope", "ops")
	if err == nil || !strings.Contains(err.Error(), acceptNamespaceEnv) {
		t.Fatalf("a non-persisted env accept must re-confirm next run: err = %v, want a refusal naming %s", err, acceptNamespaceEnv)
	}
}

// TestGuardNamespaceCheckoutFailsClosed: the committed-contract path, the
// audited exploit. A contract naming another project's namespace on a runner
// with no terminal must refuse, not warn and pin.
func TestGuardNamespaceCheckoutFailsClosed(t *testing.T) {
	ctx := context.Background()
	isolateConfig(t)
	forceNonInteractive(t)
	store := memstore.New()
	seedNamespaceHeader(t, store, "victim")

	dir := t.TempDir() // base name is never "victim", so this is the mismatch case
	err := guardNamespace(ctx, store, dir, config.LocalBinding{}, "victim")
	if err == nil || !strings.Contains(err.Error(), acceptNamespaceEnv) {
		t.Fatalf("err = %v, want a refusal naming %s", err, acceptNamespaceEnv)
	}

	t.Setenv(acceptNamespaceEnv, "victim")
	if err := guardNamespace(ctx, store, dir, config.LocalBinding{}, "victim"); err != nil {
		t.Fatalf("env-accepted checkout namespace: %v", err)
	}
}

func TestEnvAcceptedNamespace(t *testing.T) {
	t.Setenv(acceptNamespaceEnv, "")
	if envAcceptedNamespace("ops") {
		t.Fatal("empty env must accept nothing")
	}
	t.Setenv(acceptNamespaceEnv, "ops")
	if !envAcceptedNamespace("ops") || envAcceptedNamespace("op") {
		t.Fatal("exact-name matching")
	}
	t.Setenv(acceptNamespaceEnv, " a , ops ,b")
	if !envAcceptedNamespace("ops") || !envAcceptedNamespace("a") || envAcceptedNamespace("c") {
		t.Fatal("comma-separated names")
	}
}

// TestProjectlessEnv: without a contract, buildEnv injects every secret under
// its storage key (skipping non-env-var names), and the masker gets the same
// set.
func TestProjectlessEnv(t *testing.T) {
	a := &app{} // contract deliberately nil
	secretMap := map[string]string{
		"DB_URL":   "postgres://x",
		"API_KEY":  "k",
		"bad-name": "v",
	}
	env, err := a.buildEnv([]string{"HOME=/home/u"}, secretMap)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"HOME=/home/u", "API_KEY=k", "DB_URL=postgres://x"}
	if !slices.Equal(env, want) {
		t.Fatalf("env = %v, want %v", env, want)
	}

	injected := a.injectedSecrets(secretMap)
	names := make([]string, 0, len(injected))
	for _, s := range injected {
		names = append(names, s.Name)
	}
	slices.Sort(names)
	if !slices.Equal(names, []string{"API_KEY", "DB_URL"}) {
		t.Fatalf("injected = %v, want the two valid env names", names)
	}
}
