package main

import (
	"context"
	"strings"
	"testing"

	"github.com/DvGils/notenv/internal/secrets"
)

// TestRunUpdateAmendsDescriptionKeepingValue: update changes a secret's
// description (and clears it on "") while leaving its value untouched.
func TestRunUpdateAmendsDescriptionKeepingValue(t *testing.T) {
	ctx := context.Background()
	a, store, mk := copyApp(t, nil) // app bound to namespace "dst"

	if _, _, err := secrets.For(store, "dst", mk).WithStamp(writeStamp()).Commit(ctx,
		func(cur *secrets.State) (*secrets.State, error) {
			return cur.Apply([]secrets.Write{{Key: "API", Value: "v1", Description: "old", By: "tester"}}), nil
		}, nil); err != nil {
		t.Fatalf("seed: %v", err)
	}

	if err := runUpdate(ctx, a, "API", "new note"); err != nil {
		t.Fatalf("update: %v", err)
	}
	st := readNamespace(t, store, mk, "dst")
	if st.Secrets["API"] != "v1" {
		t.Fatalf("value changed by a metadata update: got %q, want v1", st.Secrets["API"])
	}
	if st.Meta["API"].Description != "new note" {
		t.Fatalf("description = %q, want 'new note'", st.Meta["API"].Description)
	}

	// Clearing round-trips to empty, with the value still intact.
	if err := runUpdate(ctx, a, "API", ""); err != nil {
		t.Fatalf("clear: %v", err)
	}
	st = readNamespace(t, store, mk, "dst")
	if st.Meta["API"].Description != "" {
		t.Fatalf("cleared description = %q, want empty", st.Meta["API"].Description)
	}
	if st.Secrets["API"] != "v1" {
		t.Fatalf("value changed when clearing the description: got %q, want v1", st.Secrets["API"])
	}
}

// TestRunUpdateRefusesMissingSecret: update amends an existing secret and never
// creates one, so a missing key is a clear error (not a silent create).
func TestRunUpdateRefusesMissingSecret(t *testing.T) {
	ctx := context.Background()
	a, _, _ := copyApp(t, nil)
	err := runUpdate(ctx, a, "NOPE", "x")
	if err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("update of a missing secret: err = %v, want a 'does not exist' error", err)
	}
}
