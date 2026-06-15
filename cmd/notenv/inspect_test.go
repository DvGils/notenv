package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/DvGils/notenv/internal/secrets"
)

func inspectState() *secrets.State {
	return &secrets.State{
		Secrets: map[string]string{
			"DB_URL":  "postgres://u:pw@h/db",
			"API_KEY": "sk-live-abc",
		},
		Meta: map[string]secrets.Meta{
			"DB_URL": {Description: "prod database", TS: 1700000000},
		},
	}
}

func TestKeyInspectOf(t *testing.T) {
	state := inspectState()

	got := keyInspectOf("app", "DB_URL", "DB_URL", state)
	if !got.Exists {
		t.Fatal("DB_URL should exist")
	}
	if got.Length != len("postgres://u:pw@h/db") {
		t.Errorf("length = %d, want %d", got.Length, len("postgres://u:pw@h/db"))
	}
	if got.Description != "prod database" {
		t.Errorf("description = %q, want %q", got.Description, "prod database")
	}
	if got.Modified == "" {
		t.Error("modified should be set when TS is present")
	}

	missing := keyInspectOf("app", "NOPE", "NOPE", state)
	if missing.Exists || missing.Length != 0 {
		t.Errorf("absent key should be exists=false length=0, got %+v", missing)
	}
}

// TestInspectNeverEmitsValues is the load-bearing assertion: nothing the
// inspect surface serializes contains a secret value.
func TestInspectNeverEmitsValues(t *testing.T) {
	state := inspectState()
	values := []string{"postgres://u:pw@h/db", "sk-live-abc"}

	key, err := json.Marshal(keyInspectOf("app", "DB_URL", "DB_URL", state))
	if err != nil {
		t.Fatal(err)
	}
	ns, err := json.Marshal(namespaceInspectOf("app", state))
	if err != nil {
		t.Fatal(err)
	}
	for _, blob := range [][]byte{key, ns} {
		for _, v := range values {
			if strings.Contains(string(blob), v) {
				t.Fatalf("inspect output leaked a secret value %q: %s", v, blob)
			}
		}
	}
}

func TestNamespaceInspectOf(t *testing.T) {
	got := namespaceInspectOf("app", inspectState())
	if got.Count != 2 {
		t.Fatalf("count = %d, want 2", got.Count)
	}
	// Sorted by name: API_KEY before DB_URL.
	if got.Secrets[0].Name != "API_KEY" || got.Secrets[1].Name != "DB_URL" {
		t.Fatalf("secrets not sorted by name: %+v", got.Secrets)
	}
	if got.Secrets[1].Length != len("postgres://u:pw@h/db") {
		t.Errorf("DB_URL length = %d, want %d", got.Secrets[1].Length, len("postgres://u:pw@h/db"))
	}
}
