package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DvGils/notenv/internal/backend/memstore"
	"github.com/DvGils/notenv/internal/config"
	"github.com/DvGils/notenv/internal/crypto"
	"github.com/DvGils/notenv/internal/dotenv"
	"github.com/DvGils/notenv/internal/secrets"
)

// TestFormatEnvValueRoundTrips is the export-then-import contract: every value
// notenv writes parses back to itself through the dotenv reader.
func TestFormatEnvValueRoundTrips(t *testing.T) {
	values := []string{
		"token123", "with space", `has"quote`, "with\nnewline", "",
		"a=b", "trailing ", " leading", "tab\there", `back\slash`,
		"hash#inside", "p@ss/w0rd:x+y,z", "unikøde",
	}
	for _, v := range values {
		line := "K=" + formatEnvValue(v) + "\n"
		pairs, err := dotenv.Parse(strings.NewReader(line))
		if err != nil {
			t.Fatalf("value %q produced unparseable line %q: %v", v, line, err)
		}
		if len(pairs) != 1 || pairs[0].Value != v {
			t.Fatalf("round-trip of %q via %q gave %+v", v, line, pairs)
		}
	}
}

// TestWriteExportRoundTrips: a folded namespace written as .env parses back to
// the same secrets (descriptions ride as comments the reader skips).
func TestWriteExportRoundTrips(t *testing.T) {
	state := &secrets.State{
		Secrets: map[string]string{"A": "alpha", "B": "two words", "C": "x\ny"},
		Meta:    map[string]secrets.Meta{"A": {Description: "the alpha key"}},
	}
	var buf bytes.Buffer
	if err := writeExport(&buf, map[string]*secrets.State{"proj": state}, false, false); err != nil {
		t.Fatal(err)
	}
	pairs, err := dotenv.Parse(&buf)
	if err != nil {
		t.Fatalf("export output must parse: %v", err)
	}
	got := map[string]string{}
	for _, p := range pairs {
		got[p.Key] = p.Value
	}
	for k, want := range state.Secrets {
		if got[k] != want {
			t.Fatalf("key %s round-trip: got %q want %q", k, got[k], want)
		}
	}
}

// TestRequirePrimarySlot: export and delete refuse a non-primary unlock.
func TestRequirePrimarySlot(t *testing.T) {
	h, _, err := crypto.NewHeader("pass", "owner")
	if err != nil {
		t.Fatal(err)
	}
	if err := requirePrimarySlot(h, h.PrimarySlot(), "export"); err != nil {
		t.Fatalf("the primary slot must be allowed: %v", err)
	}
	if err := requirePrimarySlot(h, h.PrimarySlot()+1, "export"); err == nil {
		t.Fatal("a non-primary slot must be refused")
	}
}

// TestVaultNamespaces lists namespaces from the authenticated header manifest.
func TestVaultNamespaces(t *testing.T) {
	header := &crypto.Header{Manifest: map[string]crypto.ManifestEntry{
		"ns2": {Blob: "ns2/data.age", MAC: "c"},
		"ns1": {Blob: "ns1/data.age", MAC: "a"},
	}}
	got := vaultNamespaces(header)
	if len(got) != 2 || got[0] != "ns1" || got[1] != "ns2" {
		t.Fatalf("vaultNamespaces = %v, want [ns1 ns2] (sorted)", got)
	}
}

// TestHumanUnlockNonInteractive: the export/delete gate refuses without a
// terminal, so bulk plaintext egress and deletion need a human.
func TestHumanUnlockNonInteractive(t *testing.T) {
	forceNonInteractive(t)
	_, _, _, err := humanUnlock(context.Background(), memstore.New(), "scope", "exporting plaintext")
	if err == nil || !strings.Contains(err.Error(), "no terminal") {
		t.Fatalf("humanUnlock must refuse non-interactively, got %v", err)
	}
}

// TestHumanUnlockRefusesForeignSessionVault: inside a handoff session the gate
// fails closed against any vault but the session's ephemeral one, even with a
// terminal present, rather than prompting and re-authenticating elsewhere.
func TestHumanUnlockRefusesForeignSessionVault(t *testing.T) {
	prev := interactiveFn
	interactiveFn = func() bool { return true } // a terminal is present
	t.Cleanup(func() { interactiveFn = prev })
	t.Setenv(sessionEnv, "1::local:/tmp/ephemeral")

	_, _, _, err := humanUnlock(context.Background(), memstore.New(), "2:b2:notenv", "exporting plaintext")
	if err == nil || !strings.Contains(err.Error(), "handoff session") {
		t.Fatalf("humanUnlock must fail closed for a non-session vault, got %v", err)
	}
}

// TestDestroyVaultLocal: a local vault is removed by deleting its directory.
func TestDestroyVaultLocal(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "vault")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "obj"), []byte("y"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := destroyVault(context.Background(), config.Effective{Path: dir}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("the local vault directory must be gone, stat err = %v", err)
	}
}

// TestDestroyVaultRemote: a remote vault is removed by deleting every object it
// lists (rclone lists the header artifacts too, so they go with it).
func TestDestroyVaultRemote(t *testing.T) {
	ctx := context.Background()
	ms := memstore.New()
	for _, k := range []string{"ns/seg-a.age", "ns/snap-b.age", ".header.json"} {
		if err := ms.Put(ctx, k, []byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	if err := destroyVault(ctx, config.Effective{Remote: "r", Base: "b"}, doctorStore{ms}); err != nil {
		t.Fatal(err)
	}
	keys, err := ms.List(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Fatalf("every object must be deleted, remaining: %v", keys)
	}
}
