package main

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/DvGils/notenv/internal/backend/memstore"
	"github.com/DvGils/notenv/internal/config"
)

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

	if err := store.Put(ctx, "ops/seg-m1-aaaaaaaaaaaa.age", []byte("x")); err != nil {
		t.Fatal(err)
	}
	// The join must refuse without a terminal and without the env opt-in.
	err := guardFlagNamespace(ctx, store, "scope", "ops")
	if err == nil || !strings.Contains(err.Error(), acceptNamespaceEnv) {
		t.Fatalf("existing namespace, non-interactive: err = %v, want a refusal naming %s", err, acceptNamespaceEnv)
	}
	if ok, _ := config.NamespaceAccepted("scope", "ops"); ok {
		t.Fatal("a refused namespace must not be recorded")
	}
	// The operator's environment naming the namespace is the opt-in.
	t.Setenv(acceptNamespaceEnv, "other, ops")
	if err := guardFlagNamespace(ctx, store, "scope", "ops"); err != nil {
		t.Fatalf("env-accepted namespace: %v", err)
	}
	if ok, _ := config.NamespaceAccepted("scope", "ops"); !ok {
		t.Fatal("join acceptance must be recorded")
	}
	t.Setenv(acceptNamespaceEnv, "")
	// Accepted: the guard must not even list storage again.
	if err := guardFlagNamespace(ctx, nil, "scope", "ops"); err != nil {
		t.Fatalf("accepted namespace must short-circuit: %v", err)
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
	if err := store.Put(ctx, "victim/seg-m1-aaaaaaaaaaaa.age", []byte("x")); err != nil {
		t.Fatal(err)
	}

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
