package main

import (
	"encoding/base64"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/DvGils/notenv/internal/runner"
)

// The masking engine itself is covered in internal/runner; these tests cover the
// wiring in cmd_run.go that decides which streams get a masker and that the held
// tail is flushed. maskedStream needs a real *os.File for its terminal check, so
// a pipe stands in for a captured stream: a pipe is never a terminal, which is
// exactly the "output is being captured" case masking exists for.

// withMaskFlags sets the package-level --mask/--no-mask state for one test and
// restores it after, since maskedStream reads them as globals.
func withMaskFlags(t *testing.T, mask, noMask bool) {
	t.Helper()
	om, onm := runMask, runNoMask
	runMask, runNoMask = mask, noMask
	t.Cleanup(func() { runMask, runNoMask = om, onm })
}

// captureMasked wires a pipe's write end through maskedStream, runs write, then
// flushes through flushMasker exactly as runChild does, and returns everything
// that reached the read end.
func captureMasked(t *testing.T, injected []runner.Secret, write func(w io.Writer)) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	out, m := maskedStream(w, injected)
	write(out)
	flushMasker(m)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestMaskedStreamMasksCapturedStream(t *testing.T) {
	withMaskFlags(t, false, false)
	secret := []runner.Secret{{Name: "API_KEY", Value: "supersecretvalue"}}
	got := captureMasked(t, secret, func(w io.Writer) {
		io.WriteString(w, "connecting with token=supersecretvalue done\n")
	})
	want := "connecting with token=<notenv-masked:API_KEY> done\n"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if strings.Contains(got, "supersecretvalue") {
		t.Fatalf("secret value leaked into captured stream: %q", got)
	}
}

func TestMaskedStreamNoMaskPassesThrough(t *testing.T) {
	withMaskFlags(t, false, true)
	secret := []runner.Secret{{Name: "API_KEY", Value: "supersecretvalue"}}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	out, m := maskedStream(w, secret)
	if m != nil {
		t.Fatal("--no-mask must return no masker")
	}
	if out != w {
		t.Fatal("--no-mask must wire the stream through untouched")
	}
	io.WriteString(out, "token=supersecretvalue")
	w.Close()
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "token=supersecretvalue" {
		t.Fatalf("--no-mask altered the stream: %q", data)
	}
}

func TestMaskedStreamForceMaskReturnsMasker(t *testing.T) {
	withMaskFlags(t, true, false)
	secret := []runner.Secret{{Name: "API_KEY", Value: "supersecretvalue"}}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	out, m := maskedStream(w, secret)
	if m == nil {
		t.Fatal("--mask must return a masker")
	}
	if out != io.Writer(m) {
		t.Fatal("--mask must return the masker as the write target")
	}
	io.WriteString(out, "token=supersecretvalue")
	flushMasker(m)
	w.Close()
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "token=<notenv-masked:API_KEY>" {
		t.Fatalf("--mask did not mask: %q", data)
	}
}

func TestMaskedStreamMasksEncodedForm(t *testing.T) {
	withMaskFlags(t, false, false)
	value := "supersecretvalue"
	secret := []runner.Secret{{Name: "API_KEY", Value: value}}
	enc := base64.StdEncoding.EncodeToString([]byte(value))
	got := captureMasked(t, secret, func(w io.Writer) {
		io.WriteString(w, "Authorization: Basic "+enc+"\n")
	})
	if !strings.Contains(got, "<notenv-masked:API_KEY>") {
		t.Fatalf("base64-encoded secret not masked: %q", got)
	}
	if strings.Contains(got, enc) {
		t.Fatalf("base64-encoded secret leaked: %q", got)
	}
}

func TestMaskedStreamSplitAcrossWrites(t *testing.T) {
	withMaskFlags(t, false, false)
	secret := []runner.Secret{{Name: "API_KEY", Value: "supersecretvalue"}}
	got := captureMasked(t, secret, func(w io.Writer) {
		io.WriteString(w, "supersecr")
		io.WriteString(w, "etvalue!")
	})
	if got != "<notenv-masked:API_KEY>!" {
		t.Fatalf("secret split across writes not masked: %q", got)
	}
}

func TestFlushMaskerEmitsHeldTailNoTruncation(t *testing.T) {
	withMaskFlags(t, false, false)
	secret := []runner.Secret{{Name: "API_KEY", Value: "supersecretvalue"}}
	// "superse" is a prefix of the secret, so the masker holds it pending more
	// bytes that never arrive. Flush must emit it raw, not drop it.
	got := captureMasked(t, secret, func(w io.Writer) {
		io.WriteString(w, "balance=superse")
	})
	if got != "balance=superse" {
		t.Fatalf("held tail was truncated or altered on flush: %q", got)
	}
}

func TestMaskedStreamEmptyInjectedPassesThrough(t *testing.T) {
	withMaskFlags(t, false, false)
	// No injected secrets: maskedStream still returns a masker (the stream is
	// captured), but with no patterns it must forward bytes verbatim.
	got := captureMasked(t, nil, func(w io.Writer) {
		io.WriteString(w, "AKIAEXAMPLE not actually a secret\n")
	})
	if got != "AKIAEXAMPLE not actually a secret\n" {
		t.Fatalf("empty injected set altered the stream: %q", got)
	}
}

func TestFlushMaskerNilIsNoop(t *testing.T) {
	flushMasker(nil) // a passthrough stream has no masker; must not panic
}

// TestEmptyOnlyError: a --only that resolves to zero names must fail closed, so
// an empty selector (a templated value that came out empty) never silently
// widens to injecting the whole namespace.
func TestEmptyOnlyError(t *testing.T) {
	if err := emptyOnlyError(false, nil); err != nil {
		t.Fatalf("flag absent must be fine: %v", err)
	}
	if err := emptyOnlyError(true, []string{"API_KEY"}); err != nil {
		t.Fatalf("flag with names must be fine: %v", err)
	}
	if err := emptyOnlyError(true, nil); err == nil {
		t.Fatal("--only given but empty must error (fail closed), not inject everything")
	}
}

func TestFlushMaskerWarnsOnWriteError(t *testing.T) {
	withMaskFlags(t, false, false)
	secret := []runner.Secret{{Name: "API_KEY", Value: "supersecretvalue"}}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	out, m := maskedStream(w, secret)
	io.WriteString(out, "superse") // held, nothing written to the pipe yet
	r.Close()                      // closing the read end makes the flush write fail

	stderr := captureStderr(t, func() {
		flushMasker(m) // Flush tries to write the held tail to a broken pipe
	})
	w.Close()
	if !strings.Contains(stderr, "could not finish writing masked output") {
		t.Fatalf("flushMasker did not warn on write failure: %q", stderr)
	}
}

// captureStderr swaps os.Stderr for a pipe around fn and returns what was
// written. ui.Warnf reads os.Stderr at call time, so the swap captures it.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	fn()
	os.Stderr = old
	w.Close()
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
	return string(data)
}
