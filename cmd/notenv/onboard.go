package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/DvGils/notenv/internal/crypto"
	"github.com/DvGils/notenv/internal/keymgmt"
	"github.com/DvGils/notenv/internal/keyring"
	"github.com/DvGils/notenv/internal/ui"
)

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
	if !ui.Interactive() {
		return false, errors.New("your key slot still holds the temporary onboarding passphrase; run any notenv command interactively once to replace it with your own")
	}
	ui.Warnf("you unlocked with a temporary onboarding passphrase; whoever issued it knows it")
	ui.Infof("choose your own passphrase now (the temporary one stops working)")
	newPass, err := keyring.PromptNewPassphrase("Choose your own passphrase: ")
	if err != nil {
		return false, err
	}
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
