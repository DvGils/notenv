package contract

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sample = `
namespace = "myproject"

[secrets]
DATABASE_URL = { required = true }
SENTRY_DSN   = { required = false }
STRIPE_KEY   = { name = "stripe-secret-key" }
`

func writeContract(t *testing.T, dir, content string) string {
	t.Helper()
	path := filepath.Join(dir, FileName)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestParse(t *testing.T) {
	f, err := Parse(writeContract(t, t.TempDir(), sample))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if f.Namespace != "myproject" {
		t.Errorf("namespace = %q", f.Namespace)
	}
	if !f.Secrets["DATABASE_URL"].IsRequired() {
		t.Error("DATABASE_URL should be required")
	}
	if f.Secrets["SENTRY_DSN"].IsRequired() {
		t.Error("SENTRY_DSN should be optional")
	}
	// Omitted required defaults to true: declaring a secret means you need it.
	if !f.Secrets["STRIPE_KEY"].IsRequired() {
		t.Error("STRIPE_KEY (no required key) should default to required")
	}
	if got := f.StorageKey("STRIPE_KEY"); got != "stripe-secret-key" {
		t.Errorf("StorageKey override = %q", got)
	}
	if got := f.StorageKey("DATABASE_URL"); got != "DATABASE_URL" {
		t.Errorf("StorageKey default = %q", got)
	}
}

func TestParseRejectsBadEnvName(t *testing.T) {
	_, err := Parse(writeContract(t, t.TempDir(), "[secrets]\n\"BAD-NAME\" = { required = true }\n"))
	if err == nil {
		t.Fatal("want error for invalid env var name")
	}
}

func TestParseRejectsStorageBlock(t *testing.T) {
	// A committed contract must not be able to redirect the storage target.
	c := "[storage]\nremote = \"attacker\"\nbase = \"evil\"\n\n[secrets]\nX = {}\n"
	_, err := Parse(writeContract(t, t.TempDir(), c))
	if err == nil || !strings.Contains(err.Error(), "storage") {
		t.Fatalf("want [storage] rejection, got %v", err)
	}
}

func TestNamespaceValidation(t *testing.T) {
	valid := []string{"myproject", "my-proj_1", "a.b.c", "_internal", "ns123"}
	invalid := []string{".", "..", ".hidden", "-flag", "", "a/b", "a b"}
	for _, ns := range valid {
		if !NamespaceName.MatchString(ns) {
			t.Errorf("%q should be a valid namespace", ns)
		}
	}
	for _, ns := range invalid {
		if NamespaceName.MatchString(ns) {
			t.Errorf("%q should be rejected", ns)
		}
	}
}

func TestFindWalksUp(t *testing.T) {
	root := t.TempDir()
	writeContract(t, root, sample)
	nested := filepath.Join(root, "a", "b")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}

	f, dir, err := Find(nested)
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if f.Namespace != "myproject" || dir != root {
		t.Errorf("got namespace %q in %q, want myproject in %q", f.Namespace, dir, root)
	}
}

func TestDeclare(t *testing.T) {
	dir := t.TempDir()
	path := writeContract(t, dir, sample)

	if err := Declare(path, "NEW_KEY"); err != nil {
		t.Fatalf("Declare: %v", err)
	}
	f, err := Parse(path)
	if err != nil {
		t.Fatalf("Parse after Declare: %v", err)
	}
	if !f.Secrets["NEW_KEY"].IsRequired() {
		t.Error("declared key should be required")
	}
	// Pre-existing declarations and comments must survive.
	if _, ok := f.Secrets["DATABASE_URL"]; !ok {
		t.Error("existing declarations lost")
	}
	raw, _ := os.ReadFile(path)
	if !strings.Contains(string(raw), `namespace = "myproject"`) {
		t.Error("file layout not preserved")
	}

	// No [secrets] section yet, so it is created.
	bare := writeContract(t, t.TempDir(), "namespace = \"x\"\n")
	if err := Declare(bare, "FIRST"); err != nil {
		t.Fatalf("Declare into bare contract: %v", err)
	}
	f, err = Parse(bare)
	if err != nil {
		t.Fatalf("Parse bare after Declare: %v", err)
	}
	if _, ok := f.Secrets["FIRST"]; !ok {
		t.Error("FIRST not declared in bare contract")
	}

	if err := Declare(path, "bad-name"); err == nil {
		t.Error("want error for invalid env var name")
	}
}

func TestBuildEnv(t *testing.T) {
	f, err := Parse(writeContract(t, t.TempDir(), sample))
	if err != nil {
		t.Fatal(err)
	}

	secrets := map[string]string{
		"DATABASE_URL":      "postgres://x",
		"stripe-secret-key": "sk_live_1",
		// SENTRY_DSN absent: optional, skipped
	}
	env, err := f.BuildEnv([]string{"HOME=/home/u"}, secrets)
	if err != nil {
		t.Fatalf("BuildEnv: %v", err)
	}
	joined := strings.Join(env, "\n")
	for _, want := range []string{"HOME=/home/u", "DATABASE_URL=postgres://x", "STRIPE_KEY=sk_live_1"} {
		if !strings.Contains(joined, want) {
			t.Errorf("env missing %q:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "SENTRY_DSN") {
		t.Error("optional missing secret should be skipped, not injected")
	}

	// Required missing: error naming the key.
	_, err = f.BuildEnv(nil, map[string]string{"stripe-secret-key": "x"})
	if err == nil || !strings.Contains(err.Error(), "DATABASE_URL") {
		t.Fatalf("want missing-required error naming DATABASE_URL, got %v", err)
	}
}
