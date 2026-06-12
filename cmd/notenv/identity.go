package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"filippo.io/age"

	"github.com/DvGils/notenv/internal/config"
	"github.com/DvGils/notenv/internal/crypto"
	"github.com/DvGils/notenv/internal/keyring"
	"github.com/DvGils/notenv/internal/ui"
)

const (
	identityEnv       = "NOTENV_IDENTITY"
	ageSecretKeyStart = "AGE-SECRET-KEY-1"
)

// configuredIdentities returns the age identities available for unlocking a
// recipient slot. NOTENV_IDENTITY takes precedence: an inline AGE-SECRET-KEY...
// value, or a path to an identity file. Otherwise the default identity file is
// used if present. No configured identity is not an error (an empty slice);
// a configured-but-unreadable source is.
func configuredIdentities() ([]age.Identity, error) {
	if env := strings.TrimSpace(os.Getenv(identityEnv)); env != "" {
		if strings.HasPrefix(env, ageSecretKeyStart) {
			ids, err := age.ParseIdentities(strings.NewReader(env))
			if err != nil {
				return nil, fmt.Errorf("%s (inline): %w", identityEnv, err)
			}
			return ids, nil
		}
		return identitiesFromFile(env)
	}
	path, err := config.IdentityPath()
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	return identitiesFromFile(path)
}

// creationIdentity returns the X25519 identity NOTENV_IDENTITY explicitly
// supplies, for promptless vault creation; nil when the variable is unset.
// Only the environment variable counts here: a default identity file on disk
// exists for unlocking vaults this machine was invited to, and must never
// silently change what `setup` creates for a human.
func creationIdentity() (*age.X25519Identity, error) {
	if strings.TrimSpace(os.Getenv(identityEnv)) == "" {
		return nil, nil
	}
	ids, err := configuredIdentities()
	if err != nil {
		return nil, err
	}
	for _, id := range ids {
		if x, ok := id.(*age.X25519Identity); ok {
			return x, nil
		}
	}
	return nil, fmt.Errorf("%s holds no X25519 identity usable for vault creation", identityEnv)
}

func identitiesFromFile(path string) ([]age.Identity, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open identity %s: %w", path, err)
	}
	defer f.Close()
	ids, err := age.ParseIdentities(f)
	if err != nil {
		return nil, fmt.Errorf("parse identity %s: %w", path, err)
	}
	return ids, nil
}

// identityRecipients returns the public keys of the X25519 identities in ids,
// for telling a not-yet-added teammate what to send the vault owner.
func identityRecipients(ids []age.Identity) []string {
	var recipients []string
	for _, id := range ids {
		if x, ok := id.(*age.X25519Identity); ok {
			recipients = append(recipients, x.Recipient().String())
		}
	}
	return recipients
}

// unlockResult is what resolveUnlock returns: the master key, the slot that
// opened, a reverify closure (re-unlocks a possibly-rewritten header with the
// same credential, for SafePut's post-write check), and, for a passphrase
// unlock, the slot private key (needed by `key rotate`).
type unlockResult struct {
	mk       *crypto.MasterKey
	slot     int
	reverify func(*crypto.Header) (*crypto.MasterKey, error)
	slotKey  *age.X25519Identity // set only for passphrase unlock
}

// resolveUnlock unlocks an existing header with whatever credential is
// available: a configured age identity first (the teammate's seamless path),
// then an interactive passphrase prompt. joinHint controls whether a
// non-matching identity prints the team-onboarding hint; it is useful on the
// read path (a teammate running `run` before being added) but misleading on the
// admin path (`key …`), where the operator is managing the vault.
func resolveUnlock(header *crypto.Header, joinHint bool) (*unlockResult, error) {
	ids, err := configuredIdentities()
	if err != nil {
		return nil, err
	}
	for _, id := range ids {
		x, ok := id.(*age.X25519Identity)
		if !ok {
			continue // only X25519 identities unlock recipient slots
		}
		mk, slot, err := header.UnlockIdentity(x)
		if err == nil {
			held := x
			return &unlockResult{
				mk:       mk,
				slot:     slot,
				reverify: func(h *crypto.Header) (*crypto.MasterKey, error) { m, _, e := h.UnlockIdentity(held); return m, e },
			}, nil
		}
		if !errors.Is(err, crypto.ErrWrongPassphrase) {
			return nil, err
		}
	}
	if len(ids) > 0 {
		if joinHint {
			// Likely a teammate who has not been added yet: point them at the
			// fix, then fall back to a passphrase in case they hold one.
			ui.Warnf("your identity matches no slot in this vault")
			for _, r := range identityRecipients(ids) {
				ui.Notef("if you are joining a team, ask the owner to run: notenv key add --recipient %s", r)
			}
			ui.Infof("otherwise, enter your passphrase")
		} else {
			ui.Infof("configured identity matches no slot here; using your passphrase")
		}
	}
	pass, err := keyring.PromptPassphrase("Passphrase: ")
	if err != nil {
		return nil, err
	}
	var mk *crypto.MasterKey
	var slot int
	var slotKey *age.X25519Identity
	if err := ui.Spin("Unlocking key slot (scrypt)", func() error {
		var unlockErr error
		mk, slot, slotKey, unlockErr = header.Unlock(pass)
		return unlockErr
	}); err != nil {
		return nil, err
	}
	held := pass
	return &unlockResult{
		mk:       mk,
		slot:     slot,
		slotKey:  slotKey,
		reverify: func(h *crypto.Header) (*crypto.MasterKey, error) { m, _, _, e := h.Unlock(held); return m, e },
	}, nil
}
