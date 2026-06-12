package main

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/DvGils/notenv/internal/backend"
	"github.com/DvGils/notenv/internal/crypto"
	"github.com/DvGils/notenv/internal/keymgmt"
	"github.com/DvGils/notenv/internal/secrets"
	"github.com/DvGils/notenv/internal/ui"
)

// keyMigrateCmd upgrades a version-2 vault in place. Version 3 added the
// object manifest to the header and the self-naming object field to every
// payload, so the upgrade rewrites each stored object under the same master
// (no value changes, no slot changes) and records the result in one header
// write. The command is transitional and will be removed once no version-2
// vaults remain; this whole file goes with it.
var keyMigrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Upgrade this vault to the current storage format (lossless)",
	Long: `Upgrade a vault written by an older notenv to the current storage format.

The rewrite happens under your unlocked master key: every secret keeps its
value, every slot keeps working, and the upgrade is verified end-to-end before
anything is trusted. Run it once per vault; newer notenv versions refuse the
old format.`,
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
		case header.Version >= 3:
			ui.Notef("vault is already in the current format; nothing to do")
			return nil
		case header.Version != 2:
			return fmt.Errorf("don't know how to migrate a version %d header (upgrade it with notenv 0.7 first)", header.Version)
		}

		res, err := resolveUnlock(&header, false)
		if err != nil {
			return err
		}
		if err := header.Verify(res.mk); err != nil {
			return fmt.Errorf("%w; refusing to migrate an unauthenticated header", err)
		}

		var manifest map[string]crypto.ManifestEntry
		if err := ui.Spin("Rewriting stored objects in the current format", func() error {
			manifest, err = secrets.UpgradeObjects(ctx, store, res.mk)
			return err
		}); err != nil {
			return err
		}
		header.Version = 3
		header.Manifest = manifest
		if err := ui.Spin("Recording the manifest in the header", func() error {
			return keymgmt.SafePut(ctx, store, &header, raw, res.mk, res.reverify)
		}); err != nil {
			return err
		}
		pinCurrent(storeScope(store), &header, res.mk)
		ui.Successf("vault upgraded: %d objects recorded in the manifest; every slot and secret is unchanged", len(manifest))
		return nil
	},
}

func init() {
	keyCmd.AddCommand(keyMigrateCmd)
}
