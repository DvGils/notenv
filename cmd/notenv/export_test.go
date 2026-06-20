package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DvGils/notenv/internal/backend"
	"github.com/DvGils/notenv/internal/backend/local"
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
		"carriage\rreturn", "crlf\r\npair", "all\r\n\tmix",
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

// TestFormatEnvValueNoRawControlBytes: no matter what (validated) value is
// exported, the .env line carries no raw control byte that a third-party parser
// could read as a line break or that could inject a terminal escape sequence.
func TestFormatEnvValueNoRawControlBytes(t *testing.T) {
	for _, v := range []string{"a\rb", "x\ny", "t\tb", "\r\n\t", "mix\r\n\tend", "plain"} {
		out := formatEnvValue(v)
		for i := 0; i < len(out); i++ {
			if c := out[i]; c < 0x20 || c == 0x7f {
				t.Errorf("formatEnvValue(%q) emitted raw control byte 0x%02x in %q", v, c, out)
			}
		}
	}
}

// TestSanitizeDisplay: descriptions render with every control byte as a visible
// escape, so a description cannot break the inspect columns or inject a
// terminal escape sequence; ordinary text (including multibyte UTF-8) is untouched.
func TestSanitizeDisplay(t *testing.T) {
	cases := map[string]string{
		"plain text": "plain text",
		"unikøde 世界": "unikøde 世界",
		"new\nline":  `new\nline`,
		"tab\tsep":   `tab\tsep`,
		"cr\rret":    `cr\rret`,
		"esc\x1bseq": `esc\x1bseq`,
		"bell\x07":   `bell\x07`,
		"del\x7f":    `del\x7f`,
	}
	for in, want := range cases {
		if got := sanitizeDisplay(in); got != want {
			t.Errorf("sanitizeDisplay(%q) = %q, want %q", in, got, want)
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

// TestWriteExportJSONShape pins the frozen, versioned export --json envelopes:
// `namespace export` (a single namespace) and `vault export` (the whole vault).
func TestWriteExportJSONShape(t *testing.T) {
	var buf bytes.Buffer
	single := &secrets.State{Secrets: map[string]string{"A": "alpha", "B": "beta"}}
	if err := writeExport(&buf, map[string]*secrets.State{"proj": single}, true, false); err != nil {
		t.Fatal(err)
	}
	wantSingle := `{
  "version": 1,
  "namespace": "proj",
  "secrets": {
    "A": "alpha",
    "B": "beta"
  }
}
`
	if buf.String() != wantSingle {
		t.Fatalf("export --json shape drifted:\n%s\nwant:\n%s", buf.String(), wantSingle)
	}

	buf.Reset()
	all := map[string]*secrets.State{"proj": {Secrets: map[string]string{"A": "alpha"}}}
	if err := writeExport(&buf, all, true, true); err != nil {
		t.Fatal(err)
	}
	wantAll := `{
  "version": 1,
  "namespaces": {
    "proj": {
      "A": "alpha"
    }
  }
}
`
	if buf.String() != wantAll {
		t.Fatalf("vault export --json shape drifted:\n%s\nwant:\n%s", buf.String(), wantAll)
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

// TestDestroyVaultLocal: a clean local vault (only notenv's own objects) is
// removed by deleting its directory.
func TestDestroyVaultLocal(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "vault")
	store := &local.Storage{Path: dir}
	if err := store.Put(ctx, "api/data-0123456789abcdef.age", []byte("y")); err != nil {
		t.Fatal(err)
	}
	if err := destroyVault(ctx, config.Effective{Path: dir}, store); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("the local vault directory must be gone, stat err = %v", err)
	}
}

// TestDestroyVaultRemote: a remote vault is removed by deleting its namespace
// blobs and its fixed-name plumbing (header and backup), leaving nothing behind.
func TestDestroyVaultRemote(t *testing.T) {
	ctx := context.Background()
	ms := memstore.New()
	objects := []string{
		"ns/data-0123456789abcdef.age",
		"ns2/data-fedcba9876543210.age",
		".header.json",
		".header.json.prev",
	}
	for _, k := range objects {
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
		t.Fatalf("every namespace blob must be deleted, remaining: %v", keys)
	}
	for _, artifact := range []string{backend.HeaderName, backend.HeaderBackupName} {
		if _, err := ms.Get(ctx, artifact); !errors.Is(err, backend.ErrNotFound) {
			t.Errorf("plumbing object %q must be deleted too, got err %v", artifact, err)
		}
	}
}

// TestDestroyVaultRemoteRefusesForeign: a shared remote whose prefix also holds a
// non-notenv object is refused, and nothing is deleted (the refusal is atomic).
func TestDestroyVaultRemoteRefusesForeign(t *testing.T) {
	ctx := context.Background()
	ms := memstore.New()
	objects := []string{"ns/data-0123456789abcdef.age", "backups/photos.tar"}
	for _, k := range objects {
		if err := ms.Put(ctx, k, []byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	if err := destroyVault(ctx, config.Effective{Remote: "r", Base: "b"}, doctorStore{ms}); err == nil {
		t.Fatal("destroyVault must refuse a remote prefix holding a foreign object")
	}
	for _, k := range objects {
		if _, err := ms.Get(ctx, k); err != nil {
			t.Errorf("object %q must survive a refused delete, got err %v", k, err)
		}
	}
}
