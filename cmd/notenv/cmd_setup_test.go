package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/DvGils/notenv/internal/ui"
)

// TestRenderVaultSummaryCreated: the end-of-setup panel for a freshly created
// vault states it is ready, shows where it lives, and lists the next steps, all
// inside a delimited block.
func TestRenderVaultSummaryCreated(t *testing.T) {
	out := captureStderr(t, func() {
		renderVaultSummary(vaultSummary{
			name:     "local",
			created:  true,
			location: "/home/u/.local/share/notenv/local",
			locNote:  "on this machine, encrypted at rest",
			next: []string{
				"back up the vault directory, or attach a cloud remote: notenv vault copy",
				"start using it in a project: notenv init",
			},
		})
	})
	for _, want := range []string{
		`Vault "local" is ready`,
		"/home/u/.local/share/notenv/local",
		"on this machine, encrypted at rest",
		"Next steps:",
		"notenv vault copy",
		"notenv init",
		"────", // the framing rule
	} {
		if !strings.Contains(out, want) {
			t.Errorf("summary is missing %q\n--- got ---\n%s", want, out)
		}
	}
	// The credential disclosure (passphrase, escrow) must never live in the
	// summary: it belongs to the key ceremony, the one path that always runs on
	// creation, so a skipped or failing summary can never swallow the only key.
	for _, forbidden := range []string{"passphrase", "escrow"} {
		if strings.Contains(strings.ToLower(out), forbidden) {
			t.Errorf("summary must not contain %q (that disclosure belongs to the ceremony)\n%s", forbidden, out)
		}
	}
}

// TestRenderVaultSummaryVerified: an existing vault reports as verified, not
// created, and prints no next-step block when none were supplied.
func TestRenderVaultSummaryVerified(t *testing.T) {
	out := captureStderr(t, func() {
		renderVaultSummary(vaultSummary{
			name:     "main",
			created:  false,
			location: `remote "b2", base "bucket/notenv"`,
		})
	})
	if !strings.Contains(out, `Vault "main" verified`) {
		t.Errorf("verified summary is missing its status line\n%s", out)
	}
	if strings.Contains(out, "is ready") {
		t.Errorf("an existing vault must not report as freshly created\n%s", out)
	}
	if strings.Contains(out, "Next steps") {
		t.Errorf("no next steps were supplied, so none should print\n%s", out)
	}
}

// TestSubstepOutput: a sub-step renders as an indented check, distinct from a
// top-level Successf line.
func TestSubstepOutput(t *testing.T) {
	out := captureStderr(t, func() { ui.Substep("wrote config (%s)", "/tmp/c.toml") })
	if !strings.Contains(out, "  ✓ wrote config (/tmp/c.toml)") {
		t.Errorf("Substep should print an indented check, got %q", out)
	}
}

// TestSpinSubLeavesSubstep: off-TTY, a sub-step spinner leaves the same indented
// check on success (and animates, untested here, on a TTY).
func TestSpinSubLeavesSubstep(t *testing.T) {
	out := captureStderr(t, func() {
		_ = ui.SpinSub("validated the vault directory", func() error { return nil })
	})
	if !strings.Contains(out, "  ✓ validated the vault directory") {
		t.Errorf("SpinSub should leave an indented check on success, got %q", out)
	}
}

// TestSpinSubFailureSurfaces: a failing sub-step returns its error and reports at
// full weight (not as a dim, easy-to-miss sub-step), since a setup step that
// fails is exactly what the user must notice.
func TestSpinSubFailureSurfaces(t *testing.T) {
	wantErr := errors.New("probe failed")
	var gotErr error
	out := captureStderr(t, func() {
		gotErr = ui.SpinSub("validated the vault directory", func() error { return wantErr })
	})
	if !errors.Is(gotErr, wantErr) {
		t.Fatalf("SpinSub should return the fn error, got %v", gotErr)
	}
	if !strings.Contains(out, "✗ validated the vault directory") {
		t.Errorf("a failed sub-step should surface at full weight (✗), got %q", out)
	}
}
