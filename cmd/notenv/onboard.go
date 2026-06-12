package main

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"github.com/DvGils/notenv/internal/crypto"
	"github.com/DvGils/notenv/internal/keymgmt"
	"github.com/DvGils/notenv/internal/keyring"
	"github.com/DvGils/notenv/internal/ui"
)

// onboardingStringRe matches the string `key add` prints: the generated
// six-word passphrase, a slash, and the vault fingerprint. Only generated
// passphrases have this shape (the wordlist is pure lowercase letters), so a
// prompt entry matching it is split; a chosen passphrase that happens to
// match is covered by the retry in resolveUnlock.
var onboardingStringRe = regexp.MustCompile(`^([a-z]+(?:-[a-z]+){5})/([a-z2-7]{12})$`)

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
func verifyOnboardingFingerprint(ctx context.Context, store keymgmt.Vault, h *crypto.Header, mk *crypto.MasterKey, code string) error {
	if crypto.Fingerprint(h.VaultID, h.SignPub) == code {
		ui.Successf("onboarding code verified: this is the vault you were invited to")
		return nil
	}
	if err := keymgmt.Descends(ctx, store, h, mk, func(signPub string) bool {
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
		return fmt.Errorf("%s, so it needs a human to confirm with a passphrase, and there is no terminal to ask on", action)
	}
	v, err := a.vault()
	if err != nil {
		return err
	}
	raw, err := v.GetHeader(ctx)
	if err != nil {
		return err
	}
	header, err := crypto.ParseHeader(raw)
	if err != nil {
		return err
	}
	ui.Infof("%s; confirm with your passphrase", action)
	pass, err := keyring.PromptPassphrase("Passphrase: ")
	if err != nil {
		return err
	}
	var mk *crypto.MasterKey
	if err := ui.Spin("Unlocking key slot (scrypt)", func() error {
		var unlockErr error
		mk, _, _, unlockErr = header.Unlock(pass)
		return unlockErr
	}); err != nil {
		return err
	}
	return header.Verify(mk)
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
		return false, fmt.Errorf("your key slot still holds the temporary onboarding passphrase, and replacing it is a header write, but %s. Onboard once with a write-capable storage credential, then switch back", readOnly)
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
