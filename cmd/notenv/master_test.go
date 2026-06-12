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
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	scope := "test-scope"
	if err := config.WritePin(scope, "vault-1", config.Pin{Revision: 4, MasterPub: "age1pinned"}); err != nil {
		t.Fatal(err)
	}

	store := memstore.New() // no header: "virgin" as far as the storage shows
	_, created, err := ensureMaster(context.Background(), store, newMapCache(), scope, time.Hour)
	if err == nil {
		t.Fatal("a vanished header with an existing pin must alarm, not re-initialize")
	}
	if created {
		t.Fatal("nothing may be created on this path")
	}
	if !strings.Contains(err.Error(), "key forget") {
		t.Fatalf("the alarm should name the deliberate-reset escape hatch, got: %v", err)
	}
	if store.Header() != nil {
		t.Fatal("storage must be untouched")
	}
	if _, bound, _ := config.ScopeVault(scope); !bound {
		t.Fatal("the scope binding must survive the alarm")
	}
}
