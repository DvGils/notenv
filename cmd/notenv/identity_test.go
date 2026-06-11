package main

import (
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"

	"github.com/DvGils/notenv/internal/crypto"
)

// TestResolveUnlockWithIdentity proves the teammate seam: with a configured
// identity that matches a recipient slot, resolveUnlock unlocks the header
// without ever reaching the passphrase prompt.
func TestResolveUnlockWithIdentity(t *testing.T) {
	header, mk, err := crypto.NewHeader("owner-pass", "owner@laptop")
	if err != nil {
		t.Fatal(err)
	}
	teammate, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	if err := header.AddRecipientSlot(teammate.Recipient(), "alice", mk); err != nil {
		t.Fatal(err)
	}
	t.Setenv(identityEnv, teammate.String())

	res, err := resolveUnlock(header, false)
	if err != nil {
		t.Fatalf("resolveUnlock: %v", err)
	}
	if res.slot != 1 {
		t.Fatalf("matched slot = %d, want 1 (the recipient slot)", res.slot)
	}
	if res.mk.String() != mk.String() {
		t.Fatal("unlocked a different master key")
	}
	if res.reverify == nil {
		t.Fatal("expected a reverify closure")
	}
	// Identity unlock has no passphrase slot key.
	if res.slotKey != nil {
		t.Fatal("identity unlock should not yield a slot key")
	}
}

func TestConfiguredIdentitiesInline(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(identityEnv, id.String())

	ids, err := configuredIdentities()
	if err != nil {
		t.Fatalf("configuredIdentities: %v", err)
	}
	if len(ids) != 1 {
		t.Fatalf("got %d identities, want 1", len(ids))
	}
	if rs := identityRecipients(ids); len(rs) != 1 || rs[0] != id.Recipient().String() {
		t.Fatalf("recipient mismatch: %v", rs)
	}
}

func TestConfiguredIdentitiesFromEnvPath(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "id")
	if err := os.WriteFile(path, []byte("# public key: "+id.Recipient().String()+"\n"+id.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(identityEnv, path)

	ids, err := configuredIdentities()
	if err != nil {
		t.Fatalf("configuredIdentities: %v", err)
	}
	if len(ids) != 1 {
		t.Fatalf("got %d identities, want 1", len(ids))
	}
}

func TestConfiguredIdentitiesDefaultFile(t *testing.T) {
	cfg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", cfg)
	t.Setenv(identityEnv, "") // force the default-file path

	// No file yet: not an error, just empty.
	ids, err := configuredIdentities()
	if err != nil {
		t.Fatalf("configuredIdentities (missing): %v", err)
	}
	if len(ids) != 0 {
		t.Fatalf("expected no identities, got %d", len(ids))
	}

	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(cfg, "notenv")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "identity"), []byte(id.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	ids, err = configuredIdentities()
	if err != nil {
		t.Fatalf("configuredIdentities (present): %v", err)
	}
	if len(ids) != 1 {
		t.Fatalf("got %d identities, want 1", len(ids))
	}
}
