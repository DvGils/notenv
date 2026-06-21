package main

import (
	"github.com/spf13/cobra"

	"github.com/DvGils/notenv/internal/blobcache"
	"github.com/DvGils/notenv/internal/config"
	"github.com/DvGils/notenv/internal/keyring"
	"github.com/DvGils/notenv/internal/ui"
)

var cacheCmd = &cobra.Command{
	Use:   "cache",
	Short: "Manage the local ciphertext and key caches",
}

// cacheClearCmd wipes all cached blobs on this machine. Deliberately needs
// no project/config; it works anywhere (e.g. before handing off a machine).
var cacheClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "Remove all locally cached ciphertext blobs on this machine",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		n, err := blobcache.Clear()
		if err != nil {
			return err
		}
		ui.Successf("cleared %d cached blob(s)", n)
		return nil
	},
}

// cacheLockCmd drops cached master keys, re-locking the vaults so the next
// operation prompts for the passphrase (or unlocks with an identity) again. This
// is the counterpart to `cache clear`: clear removes cached ciphertext blobs (no
// re-auth afterwards), lock removes the unwrapped master from the OS key store
// (kernel keyring on Linux, Keychain on macOS, DPAPI on Windows), which forces
// re-auth. It touches local state only: storage, the header, pins, and secrets
// are untouched, and no unlock is needed to run it.
//
// With no flag it locks every vault this machine has set up (every pinned
// scope); `-s` locks just one. Enumeration is pin-driven rather than a scan of
// the OS key store, since Keychain and DPAPI cannot be enumerated portably, so it
// covers every persistent vault. An ephemeral handoff scope is never pinned and
// self-evicts when its session ends, so it needs no entry here.
var cacheLockCmd = &cobra.Command{
	Use:   "lock",
	Short: "Drop cached vault keys on this machine, so the next use prompts again",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		cache := keyring.DefaultCache()

		// -s targets one configured storage. It resolves the storage half only
		// (no trust state), so it still works when the pin store is unreadable,
		// which is exactly when the all-scopes path below cannot enumerate.
		if storageFlag != "" {
			user, err := config.LoadUser()
			if err != nil {
				return err
			}
			eff, err := config.ResolveStorage(user, storageFlag)
			if err != nil {
				return err
			}
			cache.Drop(eff.Scope())
			ui.Successf("re-locked storage %q; the next use will prompt again", storageFlag)
			return nil
		}

		scopes, err := config.PinnedScopes()
		if err != nil {
			return err
		}
		for _, s := range scopes {
			cache.Drop(s)
		}
		if len(scopes) == 0 {
			ui.Infof("no vaults set up on this machine; nothing to lock")
			return nil
		}
		ui.Successf("re-locked %d vault(s); the next use of each will prompt again", len(scopes))
		return nil
	},
}

func init() {
	cacheCmd.AddCommand(cacheClearCmd)
	cacheCmd.AddCommand(cacheLockCmd)
}
