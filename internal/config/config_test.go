package config_test

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/DvGils/notenv/internal/config"
	"github.com/DvGils/notenv/internal/contract"
)

// TestNextSeqConcurrent hammers NextSeq from many goroutines at once; with the
// read-modify-write locked, every returned sequence number must be distinct.
func TestNextSeqConcurrent(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	const workers, perWorker = 16, 5

	results := make(chan int, workers*perWorker)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range perWorker {
				n, err := config.NextSeq("scope", "ns")
				if err != nil {
					t.Errorf("NextSeq: %v", err)
					return
				}
				results <- n
			}
		}()
	}
	wg.Wait()
	close(results)

	seen := map[int]bool{}
	for n := range results {
		if seen[n] {
			t.Fatalf("duplicate sequence number %d under concurrency", n)
		}
		seen[n] = true
	}
	if len(seen) != workers*perWorker {
		t.Fatalf("got %d distinct sequence numbers, want %d", len(seen), workers*perWorker)
	}
}

func TestSelectStorage(t *testing.T) {
	two := &config.User{
		Default: "personal",
		Storage: map[string]config.StorageEntry{
			"personal": {Remote: "b2", Base: "p"},
			"acme":     {Remote: "s3", Base: "a"},
		},
	}

	// Explicit name wins.
	if name, st, err := two.SelectStorage("acme"); err != nil || name != "acme" || st.Remote != "s3" {
		t.Fatalf("explicit: name=%q st=%+v err=%v", name, st, err)
	}
	// Explicit unknown errors.
	if _, _, err := two.SelectStorage("nope"); err == nil {
		t.Fatal("unknown storage should error")
	}
	// Default when no explicit.
	if name, _, err := two.SelectStorage(""); err != nil || name != "personal" {
		t.Fatalf("default: name=%q err=%v", name, err)
	}

	// Sole storage, no default.
	sole := &config.User{Storage: map[string]config.StorageEntry{"only": {Remote: "r"}}}
	if name, _, err := sole.SelectStorage(""); err != nil || name != "only" {
		t.Fatalf("sole: name=%q err=%v", name, err)
	}

	// Multiple, no default, no explicit -> error.
	ambiguous := &config.User{Storage: map[string]config.StorageEntry{"a": {}, "b": {}}}
	if _, _, err := ambiguous.SelectStorage(""); err == nil {
		t.Fatal("ambiguous selection should error")
	}

	// None configured -> error.
	if _, _, err := (&config.User{}).SelectStorage(""); err == nil {
		t.Fatal("no storage should error")
	}
}

func TestUpsertStorageRoundTrip(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	// First storage becomes the default.
	if _, err := config.UpsertStorage("personal", config.StorageEntry{Remote: "b2", Base: "p", Versioned: true}, false); err != nil {
		t.Fatalf("UpsertStorage: %v", err)
	}
	u, err := config.LoadUser()
	if err != nil {
		t.Fatal(err)
	}
	if u.Default != "personal" {
		t.Fatalf("first storage should be default, got %q", u.Default)
	}
	if u.Storage["personal"].Remote != "b2" || !u.Storage["personal"].Versioned {
		t.Fatalf("round-trip lost fields: %+v", u.Storage["personal"])
	}

	// Second storage does not steal default unless asked.
	if _, err := config.UpsertStorage("acme", config.StorageEntry{Remote: "s3", Base: "a"}, false); err != nil {
		t.Fatal(err)
	}
	u, _ = config.LoadUser()
	if u.Default != "personal" {
		t.Fatalf("default should be unchanged, got %q", u.Default)
	}
	if len(u.Storage) != 2 {
		t.Fatalf("expected 2 storages, got %d", len(u.Storage))
	}

	// makeDefault switches it.
	if _, err := config.UpsertStorage("acme", config.StorageEntry{Remote: "s3", Base: "a"}, true); err != nil {
		t.Fatal(err)
	}
	u, _ = config.LoadUser()
	if u.Default != "acme" {
		t.Fatalf("makeDefault should switch default, got %q", u.Default)
	}
}

func TestUpsertStorageRejectsBadNames(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	for _, bad := range []string{"vault.prod", "has space", "a/b", "", ".x", "-x"} {
		if _, err := config.UpsertStorage(bad, config.StorageEntry{Remote: "r"}, false); err == nil {
			t.Errorf("UpsertStorage(%q) should be rejected", bad)
		}
	}
	// A valid name round-trips (the TOML key is quoted, so it parses back intact).
	if _, err := config.UpsertStorage("acme-prod_2", config.StorageEntry{Remote: "b2", Base: "x"}, false); err != nil {
		t.Fatalf("valid name rejected: %v", err)
	}
	u, err := config.LoadUser()
	if err != nil {
		t.Fatal(err)
	}
	if u.Storage["acme-prod_2"].Remote != "b2" {
		t.Fatalf("valid storage not round-tripped: %+v", u.Storage)
	}
}

const (
	pinTestScope = "1:b2:bucket/x"
	pinTestVault = "vault-1"
)

// seedPin writes the pin the pin tests start from and reads it back.
func seedPin(t *testing.T) (config.Pin, bool) {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	if err := config.WritePin(pinTestScope, pinTestVault, config.Pin{Revision: 5, MasterPub: "age1master", SignPub: "ed1"}); err != nil {
		t.Fatal(err)
	}
	stored, have, err := config.ReadPin(pinTestVault)
	if err != nil || !have || stored.Revision != 5 || stored.SignPub != "ed1" {
		t.Fatalf("read back: %+v have=%v err=%v", stored, have, err)
	}
	return stored, have
}

func TestPinFirstContactAdvances(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	stored, have, err := config.ReadPin(pinTestVault)
	if err != nil {
		t.Fatal(err)
	}
	if have {
		t.Fatal("expected no pin initially")
	}
	advance, err := config.CheckPin(stored, have, 5, "age1master")
	if err != nil || !advance {
		t.Fatalf("first contact should advance: advance=%v err=%v", advance, err)
	}
}

func TestPinScopeRemembersVault(t *testing.T) {
	seedPin(t)
	if id, bound, _ := config.ScopeVault(pinTestScope); !bound || id != pinTestVault {
		t.Fatalf("scope binding: id=%q bound=%v", id, bound)
	}
}

// TestPinRevisionRules: higher and equal revisions advance (reads are
// idempotent); lower is the rollback alarm.
func TestPinRevisionRules(t *testing.T) {
	stored, have := seedPin(t)
	if ok, err := config.CheckPin(stored, have, 6, "age1master"); err != nil || !ok {
		t.Fatalf("higher revision should advance: %v %v", ok, err)
	}
	if ok, err := config.CheckPin(stored, have, 5, "age1master"); err != nil || !ok {
		t.Fatalf("equal revision should advance: %v %v", ok, err)
	}
	if _, err := config.CheckPin(stored, have, 4, "age1master"); err == nil {
		t.Fatal("lower revision should alarm (rollback)")
	}
}

// TestPinMasterChangeIsDistinguishable: a changed master is its own error, so
// callers try signed transitions before treating it as an attack.
func TestPinMasterChangeIsDistinguishable(t *testing.T) {
	stored, have := seedPin(t)
	if _, err := config.CheckPin(stored, have, 7, "age1other"); !errors.Is(err, config.ErrMasterChanged) {
		t.Fatalf("changed master should report ErrMasterChanged, got %v", err)
	}
}

func TestForgetScope(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	if err := config.WritePin("s1", "vaultA", config.Pin{Revision: 3, MasterPub: "age1x"}); err != nil {
		t.Fatal(err)
	}
	if err := config.WritePin("s2", "vaultB", config.Pin{Revision: 7, MasterPub: "age1y"}); err != nil {
		t.Fatal(err)
	}
	// The same vault reachable through a second storage configuration.
	if err := config.WritePin("s3", "vaultA", config.Pin{Revision: 3, MasterPub: "age1x"}); err != nil {
		t.Fatal(err)
	}

	// Forgetting s1 unbinds the scope but keeps vaultA's pin: s3 still uses it.
	if err := config.ForgetScope("s1"); err != nil {
		t.Fatal(err)
	}
	if _, bound, _ := config.ScopeVault("s1"); bound {
		t.Fatal("s1 binding should be gone")
	}
	if _, have, _ := config.ReadPin("vaultA"); !have {
		t.Fatal("vaultA pin must survive while s3 references it")
	}

	// Forgetting the last reference removes the pin too.
	if err := config.ForgetScope("s3"); err != nil {
		t.Fatal(err)
	}
	if _, have, _ := config.ReadPin("vaultA"); have {
		t.Fatal("vaultA pin should be gone with its last reference")
	}
	if p, have, _ := config.ReadPin("vaultB"); !have || p.Revision != 7 {
		t.Fatalf("vaultB must survive: have=%v %+v", have, p)
	}

	if err := config.ForgetScope("unbound"); err != nil {
		t.Fatalf("forgetting an unbound scope is a no-op, got %v", err)
	}
}

func TestLocalBindingRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if b, err := config.ReadLocalBinding(dir); err != nil || b != (config.LocalBinding{}) {
		t.Fatalf("empty dir: binding=%+v err=%v", b, err)
	}
	want := config.LocalBinding{Storage: "acme", Namespace: "proj"}
	if _, err := config.WriteLocalBinding(dir, want); err != nil {
		t.Fatal(err)
	}
	got, err := config.ReadLocalBinding(dir)
	if err != nil || got != want {
		t.Fatalf("round trip: binding=%+v err=%v", got, err)
	}

	// A storage-only binding (the pre-pin layout, or a multi-storage bind
	// before first use) reads back with an empty namespace.
	if _, err := config.WriteLocalBinding(dir, config.LocalBinding{Storage: "acme"}); err != nil {
		t.Fatal(err)
	}
	got, err = config.ReadLocalBinding(dir)
	if err != nil || got.Storage != "acme" || got.Namespace != "" {
		t.Fatalf("storage-only binding: %+v err=%v", got, err)
	}
}

func TestCheckNamespacePin(t *testing.T) {
	// Already pinned to the resolved namespace: proceed.
	d, err := config.CheckNamespacePin(config.LocalBinding{Namespace: "proj"}, "proj", "proj")
	if err != nil || d != config.NamespaceOK {
		t.Fatalf("pinned match: %v %v", d, err)
	}
	// Pinned to something else: the contract changed underneath the checkout.
	if _, err := config.CheckNamespacePin(config.LocalBinding{Namespace: "proj"}, "other-project", "proj"); err == nil {
		t.Fatal("a pinned checkout must refuse a contract that renames the namespace")
	}
	// First use, namespace is the directory default: pin silently.
	d, err = config.CheckNamespacePin(config.LocalBinding{}, "proj", "proj")
	if err != nil || d != config.NamespacePin {
		t.Fatalf("first use, derived: %v %v", d, err)
	}
	// First use, explicitly chosen namespace: needs the user to see it.
	d, err = config.CheckNamespacePin(config.LocalBinding{}, "other-project", "proj")
	if err != nil || d != config.NamespaceConfirm {
		t.Fatalf("first use, explicit: %v %v", d, err)
	}
	// A storage-only binding does not count as a namespace pin.
	d, err = config.CheckNamespacePin(config.LocalBinding{Storage: "acme"}, "proj", "proj")
	if err != nil || d != config.NamespacePin {
		t.Fatalf("storage-only binding: %v %v", d, err)
	}
}

func TestResolveSelectsStorage(t *testing.T) {
	u := &config.User{
		Default: "personal",
		Storage: map[string]config.StorageEntry{
			"personal": {Remote: "b2", Base: "p"},
			"acme":     {Remote: "s3", Base: "a"},
		},
	}
	cf := &contract.File{Namespace: "proj"}

	eff, err := config.Resolve(u, cf, "/tmp/proj", "acme")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if eff.StorageName != "acme" || eff.Remote != "s3" || eff.Base != "a" {
		t.Fatalf("resolved wrong storage: %+v", eff)
	}
	if eff.Namespace != "proj" {
		t.Fatalf("namespace = %q, want proj", eff.Namespace)
	}

	// Auto-select falls to default.
	eff, err = config.Resolve(u, cf, "/tmp/proj", "")
	if err != nil || eff.StorageName != "personal" {
		t.Fatalf("auto-select: %+v err=%v", eff, err)
	}
}

// TestLocalStorageEntry: a path entry round-trips through the rendered
// config, resolves to an absolute local Effective with its own scope class,
// and contradictory or empty entries are refused.
func TestLocalStorageEntry(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	vaultDir := t.TempDir()
	if _, err := config.UpsertStorage("local", config.StorageEntry{Path: vaultDir}, false); err != nil {
		t.Fatal(err)
	}
	u, err := config.LoadUser()
	if err != nil {
		t.Fatal(err)
	}
	if u.Storage["local"].Path != vaultDir {
		t.Fatalf("path entry not round-tripped: %+v", u.Storage["local"])
	}

	eff, err := config.ResolveStorage(u, "local")
	if err != nil {
		t.Fatal(err)
	}
	if !eff.Local() || eff.Path != vaultDir || eff.Remote != "" {
		t.Fatalf("resolved local entry wrong: %+v", eff)
	}
	// The scope class can never collide with a remote-backed storage's, even
	// one whose remote is literally named "local".
	remoteAlike := config.CacheScope("local", vaultDir)
	if eff.Scope() == remoteAlike {
		t.Fatalf("local scope %q must differ from a remote named \"local\"", eff.Scope())
	}
}

func TestStorageEntryValidation(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	// A contradictory or empty entry can't even be written...
	for name, entry := range map[string]config.StorageEntry{
		"both":    {Path: "/somewhere", Remote: "b2", Base: "bucket/x"},
		"neither": {},
	} {
		if _, err := config.UpsertStorage(name, entry, false); err == nil {
			t.Errorf("UpsertStorage must refuse entry %q", name)
		}
	}
	// ...and a hand-edited config that smuggles one in fails at resolution.
	dir, err := config.Dir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	raw := "[storage.\"both\"]\npath = \"/somewhere\"\nremote = \"b2\"\nbase = \"bucket/x\"\n"
	if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	u, err := config.LoadUser()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := config.ResolveStorage(u, "both"); err == nil {
		t.Error("resolution must refuse a both-kinds entry")
	}
}

func TestAbsPathExpandsHome(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	got, err := config.AbsPath("~/vaults/x")
	if err != nil {
		t.Fatal(err)
	}
	if got != filepath.Join(home, "vaults", "x") {
		t.Fatalf("AbsPath(~/vaults/x) = %q", got)
	}
}

func TestDefaultVaultDirIsNamePartitioned(t *testing.T) {
	a, err := config.DefaultVaultDir("work")
	if err != nil {
		t.Fatal(err)
	}
	b, err := config.DefaultVaultDir("personal")
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("distinct vault names must yield distinct directories")
	}
	if filepath.Base(a) != "work" {
		t.Fatalf("vault dir %q must end in its name", a)
	}
}
