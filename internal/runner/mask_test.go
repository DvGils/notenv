package runner

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// write feeds chunks through a fresh masker and returns the final output.
func write(t *testing.T, secrets []Secret, chunks ...string) string {
	t.Helper()
	var buf bytes.Buffer
	m := NewMasker(&buf, secrets)
	for _, c := range chunks {
		if n, err := m.Write([]byte(c)); err != nil || n != len(c) {
			t.Fatalf("write %q: n=%d err=%v", c, n, err)
		}
	}
	if err := m.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	return buf.String()
}

func TestMaskerReplacesValue(t *testing.T) {
	got := write(t, []Secret{{Name: "API_KEY", Value: "s3cretvalue"}},
		"token is s3cretvalue, use it\n")
	want := "token is <notenv-masked:API_KEY>, use it\n"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestMaskerCatchesValueSplitAcrossWrites(t *testing.T) {
	got := write(t, []Secret{{Name: "K", Value: "s3cretvalue"}},
		"x=s3c", "retva", "lue;done")
	if strings.Contains(got, "s3cretvalue") || !strings.Contains(got, "<notenv-masked:K>") {
		t.Fatalf("split value leaked: %q", got)
	}
}

func TestMaskerReleasesFalsePrefix(t *testing.T) {
	// A held tail that turns out not to be the secret must be emitted intact.
	got := write(t, []Secret{{Name: "K", Value: "s3cretvalue"}},
		"x=s3cret", "OOPS not it\n")
	want := "x=s3cretOOPS not it\n"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestMaskerFlushScansHeldTailForShorterSecret(t *testing.T) {
	// The stream ends mid-prefix of the LONG secret, but the held tail
	// contains the SHORT secret in full — flush must still mask it.
	secrets := []Secret{
		{Name: "LONG", Value: "abcdefghij"},
		{Name: "SHORT", Value: "abcdef"},
	}
	got := write(t, secrets, "x=abcdefgh") // prefix of LONG, contains SHORT
	want := "x=<notenv-masked:SHORT>gh"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestMaskerPrefersLongestMatch(t *testing.T) {
	secrets := []Secret{
		{Name: "LONG", Value: "abcdefghij"},
		{Name: "SHORT", Value: "abcdef"},
	}
	got := write(t, secrets, "x=abcdefghij;done")
	want := "x=<notenv-masked:LONG>;done"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestMaskerSkipsShortValues(t *testing.T) {
	got := write(t, []Secret{{Name: "PORT", Value: "8080"}}, "listening on 8080\n")
	if got != "listening on 8080\n" {
		t.Fatalf("short value must pass through, got %q", got)
	}
}

func TestMaskerDeduplicatesSharedValue(t *testing.T) {
	secrets := []Secret{
		{Name: "DB_URL", Value: "postgres://x:y@h/db"},
		{Name: "DATABASE_URL", Value: "postgres://x:y@h/db"},
	}
	got := write(t, secrets, "postgres://x:y@h/db")
	// First name alphabetically wins.
	if got != "<notenv-masked:DATABASE_URL>" {
		t.Fatalf("got %q", got)
	}
}

func TestMaskerRepeatedAndAdjacent(t *testing.T) {
	got := write(t, []Secret{{Name: "K", Value: "s3cretvalue"}},
		"s3cretvalues3cretvalue and s3cretvalue")
	want := "<notenv-masked:K><notenv-masked:K> and <notenv-masked:K>"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestMaskerNoPatternsPassesThrough(t *testing.T) {
	got := write(t, nil, "anything ", "at all\n")
	if got != "anything at all\n" {
		t.Fatalf("got %q", got)
	}
}

// TestRunMasksChildOutput is the end-to-end check: a child that echoes an
// injected secret to a captured (non-terminal) stream must be masked.
func TestRunMasksChildOutput(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh on this platform")
	}
	var buf bytes.Buffer
	m := NewMasker(&buf, []Secret{{Name: "TOKEN", Value: "s3cretvalue"}})
	code, err := Run(
		[]string{"sh", "-c", `echo "leaking $TOKEN now"`},
		[]string{"TOKEN=s3cretvalue", "PATH=" + getPATH()},
		nil, m, m,
	)
	if err != nil || code != 0 {
		t.Fatalf("run: code=%d err=%v", code, err)
	}
	if err := m.Flush(); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	if strings.Contains(got, "s3cretvalue") || !strings.Contains(got, "<notenv-masked:TOKEN>") {
		t.Fatalf("child output not masked: %q", got)
	}
}

// TestRunExitCodeSurvivesMasking pins exit-code propagation through the
// pipe-backed (masked) path, which exercises Wait's ErrWaitDelay handling.
func TestRunExitCodeSurvivesMasking(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh on this platform")
	}
	var buf bytes.Buffer
	m := NewMasker(&buf, nil)
	code, err := Run([]string{"sh", "-c", "exit 42"}, []string{"PATH=" + getPATH()}, nil, m, m)
	if err != nil {
		t.Fatal(err)
	}
	if code != 42 {
		t.Fatalf("exit code = %d, want 42", code)
	}
}

// getPATH passes the test process's own PATH through to the child, which
// needs one to resolve sh and anything sh invokes.
func getPATH() string {
	return os.Getenv("PATH")
}

// TestMaskerFloor: the default floor passes a short value through (avoiding
// shredding ordinary output), while a floor of 1 masks it (the MCP surface,
// where a short secret in a model's context is the worse outcome).
func TestMaskerFloor(t *testing.T) {
	secrets := []Secret{{Name: "PIN", Value: "123"}}

	var cli bytes.Buffer
	m := NewMasker(&cli, secrets)
	_, _ = m.Write([]byte("the pin is 123"))
	if err := m.Flush(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cli.String(), "123") {
		t.Fatalf("default masker must pass a sub-floor value through: %q", cli.String())
	}

	var mcp bytes.Buffer
	m2 := NewMaskerFloor(&mcp, secrets, 1)
	_, _ = m2.Write([]byte("the pin is 123"))
	if err := m2.Flush(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(mcp.String(), "123") {
		t.Fatalf("floor-1 masker must mask a short value: %q", mcp.String())
	}
}
