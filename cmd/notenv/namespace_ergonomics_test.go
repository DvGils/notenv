package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/DvGils/notenv/internal/backend/memstore"
)

// TestResolveNamespaceArg: a positional NAME and the --namespace flag are
// equivalent and interchangeable; giving both with different values is refused as
// ambiguous; giving neither yields the empty name for the caller to handle.
func TestResolveNamespaceArg(t *testing.T) {
	prev := namespaceFlag
	t.Cleanup(func() { namespaceFlag = prev })

	cases := []struct {
		name    string
		args    []string
		flag    string
		want    string
		wantErr string
	}{
		{"positional only", []string{"foo"}, "", "foo", ""},
		{"flag only", nil, "foo", "foo", ""},
		{"both, identical", []string{"foo"}, "foo", "foo", ""},
		{"both, conflict", []string{"foo"}, "bar", "", "twice and differently"},
		{"neither", nil, "", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			namespaceFlag = tc.flag
			got, err := resolveNamespaceArg(tc.args)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want one containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestRequireNamespaceArg: the lifecycle verbs must be given an explicit name
// (positional or flag) and never fall back to a contract, so a missing name is a
// clear, verb-named error.
func TestRequireNamespaceArg(t *testing.T) {
	prev := namespaceFlag
	t.Cleanup(func() { namespaceFlag = prev })

	namespaceFlag = ""
	if _, err := requireNamespaceArg(nil, "delete"); err == nil || !strings.Contains(err.Error(), "name the namespace to delete") {
		t.Fatalf("missing name: err = %v, want a 'name the namespace to delete' error", err)
	}

	namespaceFlag = "foo"
	if got, err := requireNamespaceArg(nil, "delete"); err != nil || got != "foo" {
		t.Fatalf("flag-supplied name: got %q, err %v; want foo, nil", got, err)
	}

	namespaceFlag = ""
	if got, err := requireNamespaceArg([]string{"bar"}, "create"); err != nil || got != "bar" {
		t.Fatalf("positional name: got %q, err %v; want bar, nil", got, err)
	}
}

// TestSelectorShortFlags: -n and -s are the persistent shorthands for the two
// universal selectors, available on every command.
func TestSelectorShortFlags(t *testing.T) {
	if f := rootCmd.PersistentFlags().ShorthandLookup("n"); f == nil || f.Name != "namespace" {
		t.Fatalf("-n should resolve to --namespace, got %v", f)
	}
	if f := rootCmd.PersistentFlags().ShorthandLookup("s"); f == nil || f.Name != "storage" {
		t.Fatalf("-s should resolve to --storage, got %v", f)
	}
}

// TestUnlockHeaderCachedServesWarmCache: the non-destructive data path
// (create/update) serves the warm master-key cache and never prompts for a
// passphrase, the same model as `secret set`.
func TestUnlockHeaderCachedServesWarmCache(t *testing.T) {
	isolateConfig(t) // trustHeader reads/writes local pin state
	ctx := context.Background()
	target, mk := freshVault(t)
	target.cacheTTL = time.Hour
	if err := target.cache.Store(target.scope, mk.String(), time.Hour); err != nil {
		t.Fatalf("seed warm cache: %v", err)
	}

	prev := promptPassphraseFn
	promptPassphraseFn = func(string) (string, error) {
		t.Fatal("unlockHeaderCached prompted for a passphrase on a warm cache")
		return "", nil
	}
	t.Cleanup(func() { promptPassphraseFn = prev })

	gotMk, header, err := unlockHeaderCached(ctx, target)
	if err != nil {
		t.Fatalf("unlockHeaderCached: %v", err)
	}
	if gotMk.String() != mk.String() {
		t.Fatal("warm cache returned the wrong master")
	}
	if header == nil {
		t.Fatal("expected the verified header")
	}
}

// TestUnlockHeaderCachedMissingVault: a missing header is an error, never an
// invitation to bootstrap a fresh vault from what should land in an existing one.
func TestUnlockHeaderCachedMissingVault(t *testing.T) {
	isolateConfig(t)
	target := &headerTarget{vaultStorage: doctorStore{memstore.New()}, scope: "scope", cache: newMapCache()}
	_, _, err := unlockHeaderCached(context.Background(), target)
	if err == nil || !strings.Contains(err.Error(), "notenv setup") {
		t.Fatalf("missing vault: err = %v, want a 'run notenv setup' error", err)
	}
}

// TestUnlockHeaderCachedRefusesReadOnly: the data path refuses to touch a
// read-only vault before reading or prompting anything.
func TestUnlockHeaderCachedRefusesReadOnly(t *testing.T) {
	target, _ := freshVault(t)
	target.readOnly = "this storage is configured read-only"
	_, _, err := unlockHeaderCached(context.Background(), target)
	if err == nil || !strings.Contains(err.Error(), "refusing to modify") {
		t.Fatalf("read-only: err = %v, want a refusal to modify the header", err)
	}
}

// TestUnlockHeaderKeepsBarrierOnWarmCache: the destructive verbs (delete,
// recover) go through unlockHeader, which always demands a freshly typed
// passphrase even when the master-key cache is warm.
func TestUnlockHeaderKeepsBarrierOnWarmCache(t *testing.T) {
	isolateConfig(t)
	ctx := context.Background()
	target, mk := freshVault(t)
	if err := target.cache.Store(target.scope, mk.String(), time.Hour); err != nil {
		t.Fatalf("seed warm cache: %v", err)
	}

	prompted := false
	prev := promptPassphraseFn
	promptPassphraseFn = func(string) (string, error) { prompted = true; return "owner pass", nil }
	t.Cleanup(func() { promptPassphraseFn = prev })

	u, err := unlockHeader(ctx, target, true)
	if err != nil {
		t.Fatalf("unlockHeader: %v", err)
	}
	if !prompted {
		t.Fatal("unlockHeader served the warm cache; destructive ops must demand a fresh passphrase")
	}
	if u.mk.String() != mk.String() {
		t.Fatal("unlockHeader returned the wrong master")
	}
}
