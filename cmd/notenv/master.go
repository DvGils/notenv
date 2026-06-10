package main

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/DvGils/notenv/internal/backend"
	"github.com/DvGils/notenv/internal/crypto"
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
func ensureMaster(ctx context.Context, store backend.HeaderStore, cache keyring.Cache, scope string, ttl time.Duration) (*crypto.MasterKey, bool, error) {
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
		pass, err := keyring.PromptPassphrase("Passphrase: ")
		if err != nil {
			return nil, false, err
		}
		var mk *crypto.MasterKey
		if err := ui.Spin("Unlocking key slot (scrypt)", func() error {
			mk, err = header.Unlock(pass)
			return err
		}); err != nil {
			return nil, false, err
		}
		cacheMaster(cache, scope, mk, ttl)
		return mk, false, nil
	}

	pass, err := keyring.PromptNewPassphrase("Choose a passphrase for this storage: ")
	if err != nil {
		return nil, false, err
	}
	var mk *crypto.MasterKey
	if err := ui.Spin("Generating master key, writing header", func() error {
		header, key, err := crypto.NewHeader(pass, userAtHost())
		if err != nil {
			return err
		}
		raw, err := header.Marshal()
		if err != nil {
			return err
		}
		if err := store.PutHeader(ctx, raw); err != nil {
			return err
		}
		mk = key
		return nil
	}); err != nil {
		return nil, false, err
	}
	ui.Warnf("escrow this passphrase in your password manager NOW. It is the only key to your secrets; lose it and the ciphertext is unrecoverable by design")
	cacheMaster(cache, scope, mk, ttl)
	return mk, true, nil
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
