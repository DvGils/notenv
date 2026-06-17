package main

import (
	"runtime"
	"strings"
	"testing"
)

// TestConfirmDiskFallbackHeadless: with no terminal to ask on, the disk-fallback
// gate fails closed and names the actionable fix rather than silently proceeding.
func TestConfirmDiskFallbackHeadless(t *testing.T) {
	forceNonInteractive(t)
	err := confirmDiskFallback("the values you type", "removed when you're done")
	if err == nil || !strings.Contains(err.Error(), "XDG_RUNTIME_DIR") {
		t.Fatalf("headless confirmDiskFallback must refuse with the actionable hint, got %v", err)
	}
}

// TestEphemeralLocalSourceNeedsNoConsent: a local source already keeps vault
// ciphertext on this disk, so handoff never prompts for it, even with no
// RAM-backed dir available.
func TestEphemeralLocalSourceNeedsNoConsent(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the disk-consent gate is Linux-only")
	}
	if ephemeralNeedsDiskConsent("local:/home/u/vault", "/nonexistent/not-ram-backed") {
		t.Fatal("a local source must never prompt; its ciphertext is already on disk")
	}
}

// TestEphemeralRemoteSourceNeedsConsentWhenNotRAMBacked: a remote source keeps no
// ciphertext on this disk, so handoff prompts before placing the ephemeral vault
// on persistent disk when no RAM-backed dir is available.
func TestEphemeralRemoteSourceNeedsConsentWhenNotRAMBacked(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the disk-consent gate is Linux-only")
	}
	// A non-existent base is reliably not RAM-backed (stat fails).
	if !ephemeralNeedsDiskConsent("rclone:remote:base", "/nonexistent/not-ram-backed") {
		t.Fatal("a remote source with no RAM-backed dir must prompt")
	}
}
