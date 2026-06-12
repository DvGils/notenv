package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"filippo.io/age"

	"github.com/DvGils/notenv/internal/backend"
	"github.com/DvGils/notenv/internal/config"
	"github.com/DvGils/notenv/internal/crypto"
	"github.com/DvGils/notenv/internal/keymgmt"
	"github.com/DvGils/notenv/internal/keyring"
	"github.com/DvGils/notenv/internal/ui"
)

// ensureMaster is the header ceremony, shared by `setup` and any command
// that needs the master key on a cold cache:
//
//   - header exists: prompt for the escrowed passphrase, unlock a slot.
//     This doubles as verification on a new machine.
//   - no header (virgin storage): generate a master key, wrap it under a
//     newly chosen passphrase (confirmed twice), write the header. This is
//     the one moment escrow matters, so the warning lives here.
//
// The unwrapped master key (never the passphrase) is cached best-effort in
// the session keyring. Returns created=true when a header was written.
func ensureMaster(ctx context.Context, store keymgmt.Vault, cache keyring.Cache, scope string, ttl time.Duration) (*crypto.MasterKey, bool, error) {
	var raw []byte
	var missing bool
	if err := ui.Spin("Reading key header", func() error {
		var err error
		raw, err = store.GetHeader(ctx)
		if errors.Is(err, backend.ErrNotFound) {
			missing = true
			return nil
		}
		return err
	}); err != nil {
		return nil, false, err
	}

	if !missing {
		header, err := crypto.ParseHeader(raw)
		if err != nil {
			return nil, false, err
		}
		// Unlock with a configured age identity if present (teammate path),
		// otherwise prompt for the escrowed passphrase. On a new machine this
		// doubles as verification.
		res, err := resolveUnlock(header, true) // read path: a teammate may not be added yet
		if err != nil {
			return nil, false, err
		}
		if err := trustHeader(ctx, store, scope, header, res.mk); err != nil {
			return nil, false, err
		}
		cacheMaster(cache, scope, res.mk, ttl)
		return res.mk, false, nil
	}

	// No header. If this machine has pinned a vault at this storage before,
	// its absence is the loudest alarm the pin system can raise — a wiped or
	// replaced vault — not an invitation to quietly initialize a fresh one
	// (which would also overwrite the pin and silence the alarm forever).
	if vaultID, bound, err := config.ScopeVault(scope); err != nil {
		return nil, false, err
	} else if bound {
		pin, _, _ := config.ReadPin(vaultID)
		return nil, false, fmt.Errorf("no key header found, but this machine pinned vault %s at this storage (revision %d, master %s): the vault may have been wiped or replaced. Restore the header (`notenv key restore-backup`, or the remote's version history), or, ONLY if you deliberately reset this storage, run `notenv key forget` and set up again", vaultID, pin.Revision, pin.MasterPub)
	}

	mk, header, err := createMaster(ctx, store)
	if err != nil {
		return nil, false, err
	}
	cacheMaster(cache, scope, mk, ttl)
	pinCurrent(scope, header, mk) // anchor the rollback pin at creation
	return mk, true, nil
}

// createMaster runs the creation ceremony on virgin storage. An identity
// supplied explicitly via the environment creates the vault promptless, with
// that identity's recipient as the only slot — the agent/CI path. Humans get
// the passphrase ceremony and its escrow moment.
func createMaster(ctx context.Context, store keymgmt.Vault) (*crypto.MasterKey, *crypto.Header, error) {
	if id, err := creationIdentity(); err != nil {
		return nil, nil, err
	} else if id != nil {
		mk, header, err := createWithIdentity(ctx, store, id)
		if err != nil {
			return nil, nil, err
		}
		ui.Warnf("this vault unlocks ONLY with the %s key; protect and back up that identity — lose it and the ciphertext is unrecoverable by design", identityEnv)
		return mk, header, nil
	}

	pass, err := keyring.PromptNewPassphrase("Choose a passphrase for this storage: ")
	if err != nil {
		return nil, nil, err
	}
	var mk *crypto.MasterKey
	var header *crypto.Header
	if err := ui.Spin("Generating master key, writing and verifying header", func() error {
		h, key, err := crypto.NewHeader(pass, userAtHost())
		if err != nil {
			return err
		}
		// Creation goes through the same safe-write protocol as every other
		// header write: read back, authenticate, and re-unlock with the new
		// passphrase before the user walks away believing escrow is done.
		// SafePut owns the revision (reset so the stored header starts at 1);
		// its freshness check also refuses to clobber a header another setup
		// wrote in the meantime.
		h.Revision = 0
		verify := func(hh *crypto.Header) (*crypto.MasterKey, error) { m, _, _, e := hh.Unlock(pass); return m, e }
		if err := keymgmt.SafePut(ctx, store, h, nil, key, verify); err != nil {
			return err
		}
		header, mk = h, key
		return nil
	}); err != nil {
		return nil, nil, err
	}
	ui.Warnf("escrow this passphrase in your password manager NOW. It is the only key to your secrets; lose it and the ciphertext is unrecoverable by design")
	return mk, header, nil
}

// createWithIdentity writes a fresh recipient-slot header through the same
// safe-write protocol as the passphrase ceremony, verifying the identity can
// unlock the result before anything trusts it.
func createWithIdentity(ctx context.Context, store keymgmt.Vault, id *age.X25519Identity) (*crypto.MasterKey, *crypto.Header, error) {
	var mk *crypto.MasterKey
	var header *crypto.Header
	err := ui.Spin("Generating master key, writing and verifying header", func() error {
		h, key, err := crypto.NewRecipientHeader(id.Recipient(), userAtHost())
		if err != nil {
			return err
		}
		h.Revision = 0 // SafePut owns the revision; the stored header starts at 1
		verify := func(hh *crypto.Header) (*crypto.MasterKey, error) { m, _, e := hh.UnlockIdentity(id); return m, e }
		if err := keymgmt.SafePut(ctx, store, h, nil, key, verify); err != nil {
			return err
		}
		header, mk = h, key
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return mk, header, nil
}

// cacheMaster stores best-effort: a cache failure must never fail the
// command, the user just gets prompted again next time.
func cacheMaster(cache keyring.Cache, scope string, mk *crypto.MasterKey, ttl time.Duration) {
	if ttl > 0 {
		_ = cache.Store(scope, mk.String(), ttl)
	}
}

// userAtHost names a key slot after its owner, e.g. "demian@legion". The
// identity hook for future per-user features (TOTP, slot governance).
func userAtHost() string {
	user := os.Getenv("USER")
	if user == "" {
		user = os.Getenv("USERNAME") // windows
	}
	if user == "" {
		user = "user"
	}
	host, err := os.Hostname()
	if err != nil || host == "" {
		return user
	}
	return user + "@" + host
}
