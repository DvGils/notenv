package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"filippo.io/age"

	"github.com/DvGils/notenv/internal/crypto"
	"github.com/DvGils/notenv/internal/ui"
)

const (
	identityEnv       = "NOTENV_IDENTITY"
	ageSecretKeyStart = "AGE-SECRET-KEY-1"
)

// configuredIdentities returns the age identities available for unlocking a
// recipient slot, from NOTENV_IDENTITY only: an inline AGE-SECRET-KEY...
// value, or a path to a file the platform materialized (a CI runner's tmpfs).
// Identities are machine credentials; there is deliberately no notenv-owned
// file location for one, so a filesystem sweep of a human's machine finds
// nothing that unlocks a vault. An unset variable is not an error (an empty
// slice); a set-but-unreadable one is.
func configuredIdentities() ([]age.Identity, error) {
	env := strings.TrimSpace(os.Getenv(identityEnv))
	if env == "" {
		return nil, nil
	}
	if strings.HasPrefix(env, ageSecretKeyStart) {
		ids, err := age.ParseIdentities(strings.NewReader(env))
		if err != nil {
			return nil, fmt.Errorf("%s (inline): %w", identityEnv, err)
		}
		return ids, nil
	}
	return identitiesFromFile(env)
}

// creationIdentity returns the X25519 identity NOTENV_IDENTITY explicitly
// supplies, for promptless vault creation; nil when the variable is unset.
// A machine that presents an identity owns the vault it creates; a human
// without one gets the passphrase ceremony.
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
	return nil, fmt.Errorf("%s holds no X25519 identity usable for vault creation; set it to an AGE-SECRET-KEY-1... value or a file containing one", identityEnv)
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
// for telling a not-yet-enrolled machine's operator what the vault owner
// needs to enroll it.
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
// unlock, the slot private key (needed by `key rotate`). fingerprint carries
// the vault code parsed off an onboarding string, for the caller to verify
// against the served header before trusting it.
type unlockResult struct {
	mk          *crypto.MasterKey
	slot        int
	reverify    func(*crypto.Header) (*crypto.MasterKey, error)
	slotKey     *age.X25519Identity // set only for passphrase unlock
	fingerprint string
}

// resolveUnlock unlocks an existing header with whatever credential is
// available: a configured age identity first (the machine path), then an
// interactive passphrase prompt (the human path). joinHint controls whether a
// non-matching identity prints the enrollment hint; it is useful on the read
// path (a machine running `run` before being enrolled) but misleading on the
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
			// Likely a machine that has not been enrolled yet: point its
			// operator at the fix, then fall back to a passphrase prompt in
			// case a human holds one.
			ui.Warnf("the %s identity matches no slot in this vault", identityEnv)
			for _, r := range identityRecipients(ids) {
				ui.Notef("to enroll this machine, the vault owner runs: notenv key add --machine <name> --recipient %s", r)
			}
			ui.Infof("otherwise, enter your passphrase")
		} else {
			ui.Infof("configured identity matches no slot here; using your passphrase")
		}
	}
	entered, err := promptPassphraseFn("Passphrase: ")
	if err != nil {
		return nil, err
	}
	// An onboarding string carries the vault fingerprint after a slash; a
	// chosen passphrase that merely looks like one is covered by retrying
	// the full entry when the split half opens nothing.
	pass, fingerprint := splitOnboardingString(entered)
	var mk *crypto.MasterKey
	var slot int
	var slotKey *age.X25519Identity
	if err := ui.Spin("Unlocking key slot (scrypt)", func() error {
		var unlockErr error
		mk, slot, slotKey, unlockErr = header.Unlock(pass)
		if errors.Is(unlockErr, crypto.ErrWrongPassphrase) && fingerprint != "" {
			pass, fingerprint = entered, ""
			mk, slot, slotKey, unlockErr = header.Unlock(pass)
		}
		return unlockErr
	}); err != nil {
		return nil, err
	}
	held := pass
	return &unlockResult{
		mk:          mk,
		slot:        slot,
		slotKey:     slotKey,
		fingerprint: fingerprint,
		reverify:    func(h *crypto.Header) (*crypto.MasterKey, error) { m, _, _, e := h.Unlock(held); return m, e },
	}, nil
}
