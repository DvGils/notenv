package main

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/DvGils/notenv/internal/backend"
	"github.com/DvGils/notenv/internal/crypto"
	"github.com/DvGils/notenv/internal/keymgmt"
	"github.com/DvGils/notenv/internal/ui"
)

// keyMigrateCmd upgrades a version-1 header in place. Version 2 added the
// vault ID and the master's signing public key; both are computable from the
// unlocked master and a fresh random ID, so the upgrade is one lossless header
// rewrite — no blob is touched and every slot keeps working. The command is
// transitional and will be removed once no version-1 vaults remain; this whole
// file goes with it.
var keyMigrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Upgrade this vault's key header to the current format (lossless)",
	Long: `Upgrade a vault written by an older notenv to the current header format.

The rewrite happens under your unlocked master key: no secret is re-encrypted,
no slot changes, and the upgrade is verified end-to-end before anything is
trusted. Run it once per vault; newer notenv versions refuse the old format.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		store, err := loadHeaderStore()
		if err != nil {
			return err
		}
		if err := store.Preflight(ctx); err != nil {
			return err
		}
		raw, err := store.GetHeader(ctx)
		if err != nil {
			if errors.Is(err, backend.ErrNotFound) {
				return errors.New("no key header found in storage; run `notenv setup` first")
			}
			return err
		}

		// Decode without ParseHeader: its job is to refuse old versions, and
		// upgrading them is exactly this command's job.
		var header crypto.Header
		if err := json.Unmarshal(raw, &header); err != nil {
			return fmt.Errorf("corrupt header: %w", err)
		}
		switch {
		case header.VaultID != "" && header.SignPub != "":
			ui.Notef("header is already in the current format; nothing to do")
			return nil
		case header.Version != 1:
			return fmt.Errorf("don't know how to migrate a version %d header", header.Version)
		}

		res, err := resolveUnlock(&header, false)
		if err != nil {
			return err
		}
		if err := header.Verify(res.mk); err != nil {
			return fmt.Errorf("%w; refusing to migrate an unauthenticated header", err)
		}

		header.Version = 2
		if header.VaultID, err = crypto.NewVaultID(); err != nil {
			return err
		}
		if header.SignPub, err = res.mk.SignPub(); err != nil {
			return err
		}
		if err := ui.Spin("Rewriting header in the current format", func() error {
			return keymgmt.SafePut(ctx, store, &header, raw, res.mk, res.reverify)
		}); err != nil {
			return err
		}
		pinCurrent(storeScope(store), &header, res.mk)
		ui.Successf("header upgraded (vault %s); every slot and secret is unchanged", header.VaultID)
		return nil
	},
}

func init() {
	keyCmd.AddCommand(keyMigrateCmd)
}
