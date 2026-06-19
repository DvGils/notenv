package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/DvGils/notenv/internal/backend/memstore"
	"github.com/DvGils/notenv/internal/config"
)

// TestEnsureMasterAlarmsOnVanishedHeader: a missing header on a storage this
// machine has pinned is a wipe/substitution alarm, not virgin storage — it
// must refuse before any "choose a new passphrase" ceremony (which would also
// have overwritten the pin and silenced the alarm).
func TestEnsureMasterAlarmsOnVanishedHeader(t *testing.T) {
	isolateConfig(t)
	scope := "test-scope"
	if err := config.WritePin(scope, "vault-1", config.Pin{Revision: 4, MasterPub: "age1pinned"}); err != nil {
		t.Fatal(err)
	}

	store := memstore.New() // no header: "virgin" as far as the storage shows
	_, created, err := ensureMaster(context.Background(), store, newMapCache(), scope, time.Hour, "")
	if err == nil {
		t.Fatal("a vanished header with an existing pin must alarm, not re-initialize")
	}
	if created {
		t.Fatal("nothing may be created on this path")
	}
	if !strings.Contains(err.Error(), "credential forget") {
		t.Fatalf("the alarm should name the deliberate-reset escape hatch, got: %v", err)
	}
	if store.Header() != nil {
		t.Fatal("storage must be untouched")
	}
	if _, bound, _ := config.ScopeVault(scope); !bound {
		t.Fatal("the scope binding must survive the alarm")
	}
}

// TestEnsureMasterRefusesCreationOnReadOnlyStorage: a read command against a
// virgin read-only storage must report the missing vault, never write one.
func TestEnsureMasterRefusesCreationOnReadOnlyStorage(t *testing.T) {
	isolateConfig(t)
	store := memstore.New()
	_, _, err := ensureMaster(context.Background(), store, newMapCache(), "scope", time.Hour, `storage "ro" is read-only`)
	if err == nil || !strings.Contains(err.Error(), "refusing to create") {
		t.Fatalf("err = %v, want a creation refusal", err)
	}
	if _, err := store.GetHeader(context.Background()); err == nil {
		t.Fatal("no header may be written to read-only storage")
	}
}

// TestRequireWritable: the guard names the reason and the refused action.
func TestRequireWritable(t *testing.T) {
	writable := &app{}
	if err := writable.requireWritable("set a secret"); err != nil {
		t.Fatalf("writable app must pass: %v", err)
	}
	ro := &app{readOnly: "NOTENV_READONLY is set"}
	err := ro.requireWritable("set a secret")
	if err == nil || !strings.Contains(err.Error(), "NOTENV_READONLY") || !strings.Contains(err.Error(), "set a secret") {
		t.Fatalf("err = %v, want reason and action", err)
	}
}
