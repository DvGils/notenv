package secrets_test

import (
	"context"
	"testing"

	"github.com/DvGils/notenv/internal/crypto"
	"github.com/DvGils/notenv/internal/secrets"
)

// TestSalvageFallsBackToBackup: when the current blob is untrustable, a salvage
// read serves the one-generation backup and reports the dropped blob, losing
// only the most recent write.
func TestSalvageFallsBackToBackup(t *testing.T) {
	ctx := context.Background()
	v := newVault(t)
	v.write(t, secrets.Write{Key: "K", Value: "v1"})
	v.write(t, secrets.Write{Key: "K", Value: "v2"}) // current; v1 is the backup

	// Corrupt the current blob's bytes.
	if err := v.store.Put(ctx, v.entry.Blob, []byte("rot")); err != nil {
		t.Fatal(err)
	}

	// Strict read fails closed.
	if _, err := v.ns().Read(ctx, v.entry); err == nil {
		t.Fatal("strict read must fail closed on a corrupt current blob")
	}

	// Salvage falls back to the backup (v1) and names the dropped blob.
	state, err := v.ns().ReadSalvage(ctx, v.entry)
	if err != nil {
		t.Fatalf("salvage: %v", err)
	}
	if state.Secrets["K"] != "v1" {
		t.Fatalf("salvaged K = %q, want v1 (the backup)", state.Secrets["K"])
	}
	if len(state.Corrupt) != 1 || state.Corrupt[0].Blob != v.entry.Blob {
		t.Fatalf("Corrupt = %+v, want exactly the current blob %q", state.Corrupt, v.entry.Blob)
	}
}

// TestSalvageBothGenerationsCorrupt: with current and backup both untrustable,
// salvage resolves empty but still reports history and lists both losses.
func TestSalvageBothGenerationsCorrupt(t *testing.T) {
	ctx := context.Background()
	v := newVault(t)
	v.write(t, secrets.Write{Key: "K", Value: "v1"})
	v.write(t, secrets.Write{Key: "K", Value: "v2"})
	if err := v.store.Put(ctx, v.entry.Blob, []byte("rot")); err != nil {
		t.Fatal(err)
	}
	if err := v.store.Put(ctx, v.entry.Prev, []byte("rot")); err != nil {
		t.Fatal(err)
	}

	state, err := v.ns().ReadSalvage(ctx, v.entry)
	if err != nil {
		t.Fatalf("salvage: %v", err)
	}
	if len(state.Secrets) != 0 {
		t.Fatalf("both generations corrupt should resolve empty, got %v", state.Secrets)
	}
	if !state.HasHistory() {
		t.Fatal("the namespace held secrets, so it still has history even when both blobs are gone")
	}
	if len(state.Corrupt) != 2 {
		t.Fatalf("Corrupt = %+v, want both blobs", state.Corrupt)
	}
}

// TestSalvageDoesNotMaskVersionSkew: a newer-format blob is "upgrade notenv",
// not corruption, so even a salvage read stops on it rather than falling back.
func TestSalvageDoesNotMaskVersionSkew(t *testing.T) {
	ctx := context.Background()
	v := newVault(t)

	// Craft a blob stamped with a future format version, sealed under the master.
	raw := []byte(`{"v":999,"ns":"proj","entries":{}}`)
	mac, err := v.mk.BlobMAC(raw)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := v.mk.Encrypt(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.store.Put(ctx, "proj/data-future.age", sealed); err != nil {
		t.Fatal(err)
	}
	entry := crypto.ManifestEntry{Blob: "proj/data-future.age", MAC: mac}

	if _, err := v.ns().ReadSalvage(ctx, entry); err == nil {
		t.Fatal("a future-format blob must stop even a salvage read (upgrade notenv), not be skipped")
	}
}

// TestSalvageCleanReadHasNoCorrupt: salvage on a healthy namespace returns the
// same state with nothing reported, so the command layer can tell "nothing to
// evict" from a real fallback.
func TestSalvageCleanReadHasNoCorrupt(t *testing.T) {
	ctx := context.Background()
	v := newVault(t)
	v.write(t, secrets.Write{Key: "K", Value: "v"})
	state, err := v.ns().ReadSalvage(ctx, v.entry)
	if err != nil {
		t.Fatalf("salvage: %v", err)
	}
	if len(state.Corrupt) != 0 {
		t.Fatalf("a healthy namespace should report no corruption, got %+v", state.Corrupt)
	}
	if state.Secrets["K"] != "v" {
		t.Fatalf("K = %q, want v", state.Secrets["K"])
	}
}

// TestSalvageMissingCurrentFallsBack: a current blob missing from storage (not
// just corrupt) is also recoverable from the backup.
func TestSalvageMissingCurrentFallsBack(t *testing.T) {
	ctx := context.Background()
	v := newVault(t)
	v.write(t, secrets.Write{Key: "K", Value: "v1"})
	v.write(t, secrets.Write{Key: "K", Value: "v2"})
	if err := v.store.Delete(ctx, v.entry.Blob); err != nil {
		t.Fatal(err)
	}
	state, err := v.ns().ReadSalvage(ctx, v.entry)
	if err != nil {
		t.Fatalf("salvage: %v", err)
	}
	if state.Secrets["K"] != "v1" {
		t.Fatalf("salvaged K = %q, want v1", state.Secrets["K"])
	}
}
