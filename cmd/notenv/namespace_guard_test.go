package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DvGils/notenv/internal/backend/memstore"
	"github.com/DvGils/notenv/internal/config"
)

// forceInteractive pins the prompt seam to "a terminal is present" and supplies
// the answer, so the interactive accept/decline branches are testable off a TTY.
func forceInteractive(t *testing.T, answer bool, err error) {
	t.Helper()
	prevI, prevC := interactiveFn, confirmFn
	interactiveFn = func() bool { return true }
	confirmFn = func(string, bool) (bool, error) { return answer, err }
	t.Cleanup(func() { interactiveFn, confirmFn = prevI, prevC })
}

// neverPrompt pins the seam so any prompt attempt fails the test: used to prove a
// path resolves without asking.
func neverPrompt(t *testing.T) {
	t.Helper()
	prevI, prevC := interactiveFn, confirmFn
	interactiveFn = func() bool { return true }
	confirmFn = func(string, bool) (bool, error) {
		t.Error("confirmNamespace prompted when it should not have")
		return false, nil
	}
	t.Cleanup(func() { interactiveFn, confirmFn = prevI, prevC })
}

func TestConfirmNamespaceInteractive(t *testing.T) {
	t.Run("accept", func(t *testing.T) {
		forceInteractive(t, true, nil)
		if err := confirmNamespace("ops", "q?", "declined"); err != nil {
			t.Fatalf("accept should pass: %v", err)
		}
	})
	t.Run("decline", func(t *testing.T) {
		forceInteractive(t, false, nil)
		err := confirmNamespace("ops", "q?", "namespace declined here")
		if err == nil || !strings.Contains(err.Error(), "namespace declined here") {
			t.Fatalf("decline should surface the decline message, got %v", err)
		}
	})
	t.Run("prompt error", func(t *testing.T) {
		boom := errors.New("tty exploded")
		forceInteractive(t, false, boom)
		if err := confirmNamespace("ops", "q?", "declined"); !errors.Is(err, boom) {
			t.Fatalf("a prompt error should propagate, got %v", err)
		}
	})
}

// TestGuardNamespaceJoinDeclineWritesNoPin: declining the join of a namespace
// that already holds secrets must abort and leave no local pin behind, so a
// "no" is not silently converted into a binding.
func TestGuardNamespaceJoinDeclineWritesNoPin(t *testing.T) {
	ctx := context.Background()
	isolateConfig(t)
	store := memstore.New()
	seedNamespaceHeader(t, store, "ops")

	// base name == "ops" == resolved makes this a first-use pin; the seeded
	// secrets make it a join, so the guard confirms before pinning.
	dir := filepath.Join(t.TempDir(), "ops")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	forceInteractive(t, false, nil) // decline

	err := guardNamespace(ctx, store, dir, config.LocalBinding{}, "ops")
	if err == nil {
		t.Fatal("a declined join must return an error")
	}
	if b, _ := config.ReadLocalBinding(dir); b.Namespace != "" {
		t.Fatalf("a declined join must not write a pin, got namespace %q", b.Namespace)
	}
}

// TestGuardNamespacePinIdempotent: a virgin namespace pins without ceremony, and
// a later run reads that pin back and proceeds without re-prompting.
func TestGuardNamespacePinIdempotent(t *testing.T) {
	ctx := context.Background()
	isolateConfig(t)
	neverPrompt(t) // a virgin pin and a matching pin must never ask
	store := memstore.New()

	dir := filepath.Join(t.TempDir(), "newproj")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}

	// First use: namespace == directory name and holds no secrets, so it pins.
	if err := guardNamespace(ctx, store, dir, config.LocalBinding{}, "newproj"); err != nil {
		t.Fatalf("virgin pin: %v", err)
	}
	binding, err := config.ReadLocalBinding(dir)
	if err != nil {
		t.Fatal(err)
	}
	if binding.Namespace != "newproj" {
		t.Fatalf("virgin pin did not record the namespace, got %q", binding.Namespace)
	}
	// The pin is gitignored so it does not get committed.
	gi, err := os.ReadFile(filepath.Join(dir, ".gitignore"))
	if err != nil || !strings.Contains(string(gi), config.LocalBindingFile) {
		t.Fatalf(".gitignore missing the binding file: %q, err=%v", gi, err)
	}

	// Second run: the recorded pin matches, so the guard passes silently.
	if err := guardNamespace(ctx, store, dir, binding, "newproj"); err != nil {
		t.Fatalf("matching pin should pass: %v", err)
	}
}

// TestPinNamespaceToleratesUnwritableCheckout: pinning is best-effort, so a
// checkout it cannot write to warns and carries on rather than failing the run.
func TestPinNamespaceToleratesUnwritableCheckout(t *testing.T) {
	// A regular file in place of the directory makes the binding write fail.
	f := filepath.Join(t.TempDir(), "afile")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := captureStderr(t, func() {
		pinNamespace(f, config.LocalBinding{}, "ns")
	})
	if !strings.Contains(out, "could not pin namespace") {
		t.Fatalf("expected a warning on an unwritable checkout, got %q", out)
	}
}

// TestGuardNamespacePinnedToDifferentErrors: a contract that renames the
// namespace out from under an existing pin is treated as suspect, not followed.
func TestGuardNamespacePinnedToDifferentErrors(t *testing.T) {
	ctx := context.Background()
	store := memstore.New()
	dir := t.TempDir()
	err := guardNamespace(ctx, store, dir, config.LocalBinding{Namespace: "old"}, "new")
	if err == nil || !strings.Contains(err.Error(), "old") {
		t.Fatalf("a contract rename off the pin must error and name the pin, got %v", err)
	}
}
