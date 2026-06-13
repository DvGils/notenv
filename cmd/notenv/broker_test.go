package main

import (
	"slices"
	"strings"
	"testing"
)

// TestStripCredentialEnv: notenv's vault-decrypting identity is removed from a
// child's environment, while the other NOTENV_* vars, which are non-secret
// policy, ride through so a nested notenv keeps its mode. The caller's slice
// must not be mutated.
func TestStripCredentialEnv(t *testing.T) {
	in := []string{
		"HOME=/home/u",
		identityEnv + "=AGE-SECRET-KEY-1EXAMPLE",
		"NOTENV_READONLY=1",
		acceptNamespaceEnv + "=ops",
		"PATH=/usr/bin",
	}
	got := stripCredentialEnv(in)
	want := []string{"HOME=/home/u", "NOTENV_READONLY=1", acceptNamespaceEnv + "=ops", "PATH=/usr/bin"}
	if !slices.Equal(got, want) {
		t.Fatalf("stripCredentialEnv = %v, want %v", got, want)
	}
	if !slices.Contains(in, identityEnv+"=AGE-SECRET-KEY-1EXAMPLE") {
		t.Fatal("stripCredentialEnv mutated its input slice")
	}
}

// TestStripCredentialEnvExactName: only the exact NOTENV_IDENTITY var is
// stripped, never a var that merely contains the name as a prefix/substring.
func TestStripCredentialEnvExactName(t *testing.T) {
	in := []string{
		identityEnv + "=secret",
		identityEnv + "_FILE=/run/id", // not the credential: must survive
		"X_" + identityEnv + "=v",     // not the credential: must survive
	}
	got := stripCredentialEnv(in)
	want := []string{identityEnv + "_FILE=/run/id", "X_" + identityEnv + "=v"}
	if !slices.Equal(got, want) {
		t.Fatalf("stripCredentialEnv = %v, want %v", got, want)
	}
}

// TestBuildEnvStripsIdentity: the identity never reaches a child through
// buildEnv, even though injected secrets do. The strip runs before the contract
// branch, so this projectless case covers both paths.
func TestBuildEnvStripsIdentity(t *testing.T) {
	a := &app{} // contract deliberately nil
	base := []string{"HOME=/home/u", identityEnv + "=AGE-SECRET-KEY-1ZZZZ"}
	env, err := a.buildEnv(base, map[string]string{"API_KEY": "k"})
	if err != nil {
		t.Fatal(err)
	}
	for _, kv := range env {
		if strings.HasPrefix(kv, identityEnv+"=") {
			t.Fatalf("buildEnv leaked the identity into the child env: %q", kv)
		}
	}
	if !slices.Contains(env, "API_KEY=k") {
		t.Fatalf("buildEnv dropped an injected secret: %v", env)
	}
	if !slices.Contains(env, "HOME=/home/u") {
		t.Fatalf("buildEnv dropped a base var: %v", env)
	}
}
