package main

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"github.com/DvGils/notenv/internal/backend"
	"github.com/DvGils/notenv/internal/crypto"
	"github.com/DvGils/notenv/internal/keymgmt"
	"github.com/DvGils/notenv/internal/keyring"
	"github.com/DvGils/notenv/internal/ui"
)

// onboardingStringRe matches the string `key add` prints: the generated
// eight-word passphrase, a slash, and the vault fingerprint. Only generated
// passphrases have this shape (the wordlist is pure lowercase letters), so a
// prompt entry matching it is split; a chosen passphrase that happens to
// match is covered by the retry in resolveUnlock.
var onboardingStringRe = regexp.MustCompile(`^([a-z]+(?:-[a-z]+){7})/([a-z2-7]{16})$`)

// splitOnboardingString splits a prompt entry into passphrase and
// fingerprint; the fingerprint is empty when the entry is a plain passphrase.
func splitOnboardingString(s string) (pass, fingerprint string) {
	m := onboardingStringRe.FindStringSubmatch(s)
	if m == nil {
		return s, ""
	}
	return m[1], m[2]
}

// verifyOnboardingFingerprint checks the header storage served against the
// code from the onboarding string: it must digest the vault's identity and
// current signing key, or an ancestor signing key connected to the unlocked
// master by valid signed transitions (a rotation between `key add` and first
// contact is legitimate and proves itself). Runs before the first pin is
// written, so a substituted vault is refused instead of trusted on first use.
func verifyOnboardingFingerprint(h *crypto.Header, mk *crypto.MasterKey, code string) error {
	if crypto.Fingerprint(h.VaultID, h.SignPub) == code {
		ui.Successf("onboarding code verified: this is the vault you were invited to")
		return nil
	}
	if err := keymgmt.Descends(h, mk, func(signPub string) bool {
		return crypto.Fingerprint(h.VaultID, signPub) == code
	}); err != nil {
		return fmt.Errorf("the onboarding code does not match this vault, and no signed rotation connects this vault to one it matches. The storage may be presenting a substituted vault; verify with whoever onboarded you before trusting anything here")
	}
	ui.Successf("onboarding code verified: the vault was re-keyed since your invite, and the rotation proves itself")
	return nil
}

// requireHumanPassphrase re-authenticates before plaintext egress: the
// operation named by action sends raw secret values somewhere persistent, so
// it demands a freshly typed passphrase even when the master key is cached,
// the same stance the mutating key commands take. The prompt reads the
// terminal device, so the confirmation reaches a human; an agent holding a
// warm session cache cannot complete it. Deliberately strict: no identity
// satisfies it and no environment variable bypasses it, so a vault that
// unlocks only by machine identity cannot perform these operations at all.
// Policy for cooperating clients, not containment: a same-user adversary can
// read the cache and decrypt with their own tooling.
func (a *app) requireHumanPassphrase(ctx context.Context, action string) error {
	if !interactiveFn() {
		return fmt.Errorf("%s, so it needs a human to confirm with a passphrase, but no terminal is available; run this command interactively", action)
	}
	v, err := a.vault()
	if err != nil {
		return err
	}
	_, _, _, err = humanUnlock(ctx, v, a.cacheScope, action)
	return err
}

// humanUnlock prompts for a freshly typed passphrase (ignoring any warm cache),
// unlocks the header, and runs the full trust check (tag + rollback/substitution
// continuity, keyed by scope), returning the master, the matched slot index, and
// the parsed header. It refuses non-interactively (the prompt reads the terminal
// device, so it reaches a human, not an agent on a warm cache) and rejects any
// non-passphrase unlock, so a vault that opens only by machine identity cannot
// perform an operation gated this way. It is the shared gate for deliberate
// plaintext egress (`run --no-mask`, `export`) and destructive owner acts
// (`vault delete`), all of which must refuse a rolled-back or replaced vault.
func humanUnlock(ctx context.Context, store backend.HeaderStore, scope, action string) (*crypto.MasterKey, int, *crypto.Header, error) {
	// Inside a handoff session, refuse any vault but the session's ephemeral one:
	// fail closed rather than prompt for a passphrase against a different vault.
	// humanUnlock never caches, so this is a defense-in-depth layer over the
	// master-protection guarantee, not the thing that provides it.
	if err := sessionGuard(scope); err != nil {
		return nil, -1, nil, err
	}
	if !interactiveFn() {
		return nil, -1, nil, fmt.Errorf("%s, so it needs a human to confirm with a passphrase, but no terminal is available; run this command interactively", action)
	}
	raw, err := store.GetHeader(ctx)
	if err != nil {
		return nil, -1, nil, err
	}
	header, err := crypto.ParseHeader(raw)
	if err != nil {
		return nil, -1, nil, err
	}
	ui.Infof("%s; confirm with your passphrase", action)
	pass, err := keyring.PromptPassphrase("Passphrase: ")
	if err != nil {
		return nil, -1, nil, err
	}
	var mk *crypto.MasterKey
	var slot int
	if err := ui.Spin("Unlocking key slot (scrypt)", func() error {
		var unlockErr error
		mk, slot, _, unlockErr = header.Unlock(pass)
		return unlockErr
	}); err != nil {
		return nil, -1, nil, err
	}
	// trustHeader verifies the tag AND runs the rollback/substitution continuity
	// check (advancing the local pin when warranted), so plaintext egress and
	// vault deletion can't quietly operate on a rolled-back or replaced vault.
	if err := trustHeader(scope, header, mk); err != nil {
		return nil, -1, nil, err
	}
	return mk, slot, header, nil
}

// enforceProvisional is the onboarding gate. A provisional slot is still
// wrapped under the temporary passphrase its issuer generated and therefore
// knows, so no command proceeds under one: the holder replaces it with a
// passphrase of their own right here, or the command fails. Returns whether
// the header was rewritten; on rotation, res.reverify is replaced with a
// closure holding the new credential.
//
// readOnly carries the refusal reason when the storage cannot be written
// (rotation is a header write); callers that already refused read-only
// storage pass "".
func enforceProvisional(ctx context.Context, store keymgmt.Vault, scope, readOnly string, header *crypto.Header, raw []byte, res *unlockResult) (bool, error) {
	if res.slot < 0 || !header.Slots[res.slot].Provisional {
		return false, nil
	}
	if res.slotKey == nil {
		// Only passphrase slots carry the flag, and a passphrase unlock always
		// yields the slot key, so this cannot happen; refuse rather than skip.
		return false, errors.New("provisional slot unlocked without its slot key")
	}
	if readOnly != "" {
		return false, fmt.Errorf("your key slot still holds the temporary onboarding passphrase; replacing it requires writing to storage, but %s. Onboard once with a write-capable credential, then switch back", readOnly)
	}
	if !interactiveFn() {
		return false, errors.New("your key slot still holds the temporary onboarding passphrase; run any notenv command interactively once to replace it with your own")
	}
	ui.Warnf("you unlocked with a temporary onboarding passphrase; whoever issued it knows it")
	ui.Infof("choose your own passphrase now (the temporary one stops working)")
	newPass, err := keyring.PromptNewPassphrase("Choose your own passphrase: ")
	if err != nil {
		return false, err
	}
	warnShortPassphrase(newPass)
	if err := header.RotateSlot(res.slot, newPass, res.slotKey); err != nil {
		return false, err
	}
	verify := func(h *crypto.Header) (*crypto.MasterKey, error) { m, _, _, e := h.Unlock(newPass); return m, e }
	if err := ui.Spin("Writing header", func() error {
		return keymgmt.SafePut(ctx, store, header, raw, res.mk, verify)
	}); err != nil {
		return false, err
	}
	pinCurrent(scope, header, res.mk)
	res.reverify = verify
	ui.Warnf("escrow this passphrase in your password manager NOW; it is your only credential for this vault")
	ui.Successf("replaced the temporary onboarding passphrase for slot %q", header.Slots[res.slot].Name)
	return true, nil
}
