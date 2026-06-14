package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DvGils/notenv/internal/contract"
)

// TestWriteContractDefaultsNamespaceSilently: with no --namespace, init writes
// the contract using the directory-name default and never prompts (a prompt
// would block on stdin and hang this test), with the default left commented.
func TestWriteContractDefaultsNamespaceSilently(t *testing.T) {
	dir := t.TempDir()
	defer setInitNamespace("")()

	if err := writeContract(dir); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, contract.FileName))
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("# namespace = %q", filepath.Base(dir))
	if !strings.Contains(string(data), want) {
		t.Fatalf("expected commented default %q, got:\n%s", want, data)
	}
	if strings.Contains(string(data), "\nnamespace = ") {
		t.Fatalf("the directory-name default must not be written as an active line:\n%s", data)
	}
}

// TestWriteContractExplicitNamespace: a --namespace that differs from the
// directory name is written as an active line.
func TestWriteContractExplicitNamespace(t *testing.T) {
	dir := t.TempDir()
	defer setInitNamespace("myproj")()

	if err := writeContract(dir); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, contract.FileName))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `namespace = "myproj"`) {
		t.Fatalf("expected an active namespace line, got:\n%s", data)
	}
}

// TestWriteContractLeavesExistingAlone: a second init does not clobber a
// committed contract.
func TestWriteContractLeavesExistingAlone(t *testing.T) {
	dir := t.TempDir()
	defer setInitNamespace("")()
	path := filepath.Join(dir, contract.FileName)
	if err := os.WriteFile(path, []byte("# mine\n[secrets]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeContract(dir); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "# mine") {
		t.Fatalf("an existing contract must be left untouched, got:\n%s", data)
	}
}

// TestGuardProjectDirAllowsOrdinaryDir: the wrong-place guard must never fire on
// an ordinary project directory; annoying every init would be worse than the
// footgun it prevents.
func TestGuardProjectDirAllowsOrdinaryDir(t *testing.T) {
	if err := guardProjectDir(t.TempDir()); err != nil {
		t.Fatalf("an ordinary directory must not be guarded: %v", err)
	}
}

// TestGuardProjectDirAllowsExistingProject: a directory that already holds a
// contract is a real project and is never re-guarded, even at a risky path.
func TestGuardProjectDirAllowsExistingProject(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, contract.FileName), []byte("[secrets]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := guardProjectDir(dir); err != nil {
		t.Fatalf("an existing project must not be guarded: %v", err)
	}
}

// setInitNamespace sets the init --namespace flag global for a test and returns
// a restore func.
func setInitNamespace(v string) func() {
	old := initNamespace
	initNamespace = v
	return func() { initNamespace = old }
}
