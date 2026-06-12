package main

import (
	"context"
	"slices"
	"testing"

	"github.com/DvGils/notenv/internal/backend/memstore"
	"github.com/DvGils/notenv/internal/config"
)

// TestGuardFlagNamespace: a virgin namespace is accepted without ceremony and
// recorded; a namespace already holding secrets warns (non-interactive) but
// proceeds and records; once recorded, the guard passes without listing.
func TestGuardFlagNamespace(t *testing.T) {
	ctx := context.Background()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
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
	// Non-interactive (test binary): the join warns instead of prompting.
	if err := guardFlagNamespace(ctx, store, "scope", "ops"); err != nil {
		t.Fatalf("existing namespace, non-interactive: %v", err)
	}
	if ok, _ := config.NamespaceAccepted("scope", "ops"); !ok {
		t.Fatal("join acceptance must be recorded")
	}
	// Accepted: the guard must not even list storage again.
	if err := guardFlagNamespace(ctx, nil, "scope", "ops"); err != nil {
		t.Fatalf("accepted namespace must short-circuit: %v", err)
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
