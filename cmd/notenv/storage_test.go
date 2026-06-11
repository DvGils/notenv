package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DvGils/notenv/internal/config"
)

func TestEnsureGitignore(t *testing.T) {
	// Creates the file when absent.
	dir := t.TempDir()
	if err := ensureGitignore(dir, config.LocalBindingFile); err != nil {
		t.Fatal(err)
	}
	gi := filepath.Join(dir, ".gitignore")
	data, _ := os.ReadFile(gi)
	if !strings.Contains(string(data), config.LocalBindingFile) {
		t.Fatalf("entry not written: %q", data)
	}

	// Idempotent: no duplicate on a second call.
	if err := ensureGitignore(dir, config.LocalBindingFile); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(gi)
	if strings.Count(string(data), config.LocalBindingFile) != 1 {
		t.Fatalf("entry duplicated: %q", data)
	}

	// Appends to existing content without clobbering it.
	other := t.TempDir()
	giPath := filepath.Join(other, ".gitignore")
	if err := os.WriteFile(giPath, []byte("node_modules/\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ensureGitignore(other, config.LocalBindingFile); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(giPath)
	if !strings.Contains(string(got), "node_modules/") || !strings.Contains(string(got), config.LocalBindingFile) {
		t.Fatalf("append clobbered or missing: %q", got)
	}
}

func TestSelectProjectStorage(t *testing.T) {
	user := &config.User{
		Default: "personal",
		Storage: map[string]config.StorageEntry{
			"personal": {Remote: "b2"},
			"acme":     {Remote: "s3"},
		},
	}
	defer func(prev string) { storageFlag = prev }(storageFlag)

	// --storage selects and persists a binding when multiple storages exist.
	dir := t.TempDir()
	storageFlag = "acme"
	got, err := selectProjectStorage(user, dir)
	if err != nil || got != "acme" {
		t.Fatalf("flag select: got %q err %v", got, err)
	}
	if binding, _ := config.ReadLocalBinding(dir); binding.Storage != "acme" {
		t.Fatalf("binding not written: %q", binding.Storage)
	}

	// An unknown --storage is rejected.
	storageFlag = "nope"
	if _, err := selectProjectStorage(user, t.TempDir()); err == nil {
		t.Fatal("unknown storage flag should error")
	}

	// Sole storage: no flag, resolves on its own, no binding file written.
	storageFlag = ""
	soleDir := t.TempDir()
	sole := &config.User{Storage: map[string]config.StorageEntry{"only": {Remote: "r"}}}
	got, err = selectProjectStorage(sole, soleDir)
	if err != nil || got != "only" {
		t.Fatalf("sole: got %q err %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(soleDir, config.LocalBindingFile)); !os.IsNotExist(err) {
		t.Fatal("sole storage should not write a binding")
	}
}
