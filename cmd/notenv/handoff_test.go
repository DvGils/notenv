package main

import (
	"context"
	"slices"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/DvGils/notenv/internal/config"
	"github.com/DvGils/notenv/internal/crypto"
	"github.com/DvGils/notenv/internal/secrets"
)

// stateOf builds a namespace state literal for the builder to copy.
func stateOf(kv map[string]string) *secrets.State {
	st := &secrets.State{Secrets: map[string]string{}, Meta: map[string]secrets.Meta{}}
	for k, v := range kv {
		st.Secrets[k] = v
		st.Meta[k] = secrets.Meta{}
	}
	return st
}

// TestBuildEphemeralReadableViaIdentityOnly is the core security assertion: the
// ephemeral vault holds the handed-off secrets, the agent reads them with the
// ephemeral identity exactly as a normal local vault, and nothing else opens it.
func TestBuildEphemeralReadableViaIdentityOnly(t *testing.T) {
	ctx := context.Background()
	me, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"DB_URL": "postgres://secret", "API_KEY": "sk-live-123"}
	states := map[string]*secrets.State{"app": stateOf(want)}

	eDir := t.TempDir()
	if err := buildEphemeral(ctx, eDir, me.Recipient(), states); err != nil {
		t.Fatalf("buildEphemeral: %v", err)
	}

	// Read E back exactly as the agent's notenv would: open the local vault,
	// unlock the header with the ephemeral identity, read the namespace.
	store := openStorage(config.Effective{Path: eDir})
	raw, err := store.GetHeader(ctx)
	if err != nil {
		t.Fatalf("GetHeader(E): %v", err)
	}
	header, err := crypto.ParseHeader(raw)
	if err != nil {
		t.Fatalf("ParseHeader(E): %v", err)
	}
	mk, _, err := header.UnlockIdentity(me)
	if err != nil {
		t.Fatalf("the ephemeral identity could not unlock E: %v", err)
	}
	entry, _ := header.NamespaceEntry("app")
	st, err := secrets.For(store, "app", mk).Read(ctx, entry)
	if err != nil {
		t.Fatalf("read namespace from E: %v", err)
	}
	for k, v := range want {
		if st.Secrets[k] != v {
			t.Errorf("E[app][%s] = %q, want %q", k, st.Secrets[k], v)
		}
	}

	// A different identity must not open E: it is bound to the ephemeral key alone,
	// so handing the agent that key reveals nothing about any other vault.
	other, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := header.UnlockIdentity(other); err == nil {
		t.Fatal("an unrelated identity unlocked the ephemeral vault")
	}
}

// TestIdentityUnlocksGuardsSource confirms the precondition fires for an
// identity-gated source (one the agent could replay) and not otherwise.
func TestIdentityUnlocksGuardsSource(t *testing.T) {
	ctx := context.Background()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	// An identity-gated vault is exactly a recipient-slot vault, which buildEphemeral
	// produces; reuse it to stand in as the source.
	srcDir := t.TempDir()
	if err := buildEphemeral(ctx, srcDir, id.Recipient(), map[string]*secrets.State{
		"app": stateOf(map[string]string{"K": "v"}),
	}); err != nil {
		t.Fatal(err)
	}
	store := openStorage(config.Effective{Path: srcDir})
	raw, err := store.GetHeader(ctx)
	if err != nil {
		t.Fatal(err)
	}
	header, err := crypto.ParseHeader(raw)
	if err != nil {
		t.Fatal(err)
	}

	t.Setenv(identityEnv, "")
	if identityUnlocks(header) {
		t.Fatal("identityUnlocks reported true with no identity configured")
	}
	t.Setenv(identityEnv, id.String())
	if !identityUnlocks(header) {
		t.Fatal("identityUnlocks did not detect an identity-gated source the agent could replay")
	}
}

// TestHandoffEnvPointsOnlyAtEphemeral confirms the agent's environment is
// stripped of the real credential and pointed only at the ephemeral vault.
func TestHandoffEnvPointsOnlyAtEphemeral(t *testing.T) {
	base := []string{
		"PATH=/usr/bin",
		identityEnv + "=AGE-SECRET-KEY-REAL-MASTER",
		storageEnv + "=stale",
		"FOO=bar",
	}
	env := handoffEnv(base, "/run/u/e", "escope", "AGE-SECRET-KEY-EPHEMERAL", "app")

	get := func(key string) (string, bool) {
		for _, kv := range env {
			if name, val, ok := strings.Cut(kv, "="); ok && name == key {
				return val, true
			}
		}
		return "", false
	}
	// The real credential is gone, replaced by the ephemeral one.
	if v, _ := get(identityEnv); v != "AGE-SECRET-KEY-EPHEMERAL" {
		t.Errorf("%s = %q, want the ephemeral identity", identityEnv, v)
	}
	if count := slices.IndexFunc(env, func(kv string) bool { return strings.Contains(kv, "REAL-MASTER") }); count != -1 {
		t.Error("the real master credential leaked into the agent environment")
	}
	if v, _ := get(storageEnv); v != "local:/run/u/e" {
		t.Errorf("%s = %q, want local:/run/u/e", storageEnv, v)
	}
	if v, _ := get(sessionEnv); v != "escope" {
		t.Errorf("%s = %q, want escope", sessionEnv, v)
	}
	if v, _ := get(acceptNamespaceEnv); v != "app" {
		t.Errorf("%s = %q, want app", acceptNamespaceEnv, v)
	}
	// Unrelated env is preserved.
	if v, ok := get("FOO"); !ok || v != "bar" {
		t.Error("unrelated environment was not preserved")
	}
}
