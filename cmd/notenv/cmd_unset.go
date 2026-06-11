package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/DvGils/notenv/internal/config"
	"github.com/DvGils/notenv/internal/contract"
	"github.com/DvGils/notenv/internal/secrets"
	"github.com/DvGils/notenv/internal/ui"
)

var unsetCmd = &cobra.Command{
	Use:   "unset KEY",
	Short: "Remove a stored secret value",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		key := args[0]
		if !contract.ValidEnvName(key) {
			return fmt.Errorf("%q is not a valid environment variable name", key)
		}
		a, err := loadApp()
		if err != nil {
			return err
		}
		ctx := cmd.Context()

		// Fold fresh so we only write a tombstone for a key that is actually set,
		// and so the removal is ordered after every write it supersedes.
		state, mk, err := a.foldState(ctx)
		if err != nil {
			return err
		}
		storageKey := a.contract.StorageKey(key)
		if _, present := state.Secrets[storageKey]; !present {
			return fmt.Errorf("%q is not set in namespace %q", key, a.namespace)
		}
		seq, err := config.NextSeq(a.cacheScope, a.namespace)
		if err != nil {
			return err
		}

		var updated *secrets.State
		if err := ui.Spin("Uploading removal", func() error {
			var aerr error
			updated, aerr = a.appendGuarded(ctx, mk, state, seq, storageKey, "", true)
			return aerr
		}); err != nil {
			return err
		}
		a.cacheFolded(mk, updated.Secrets)
		ui.Successf("%s removed from namespace %q", key, a.namespace)
		// Post-write state: this tombstone settles its own key's conflict.
		reportConflicts(updated.Conflicts)
		a.maybeCompact(ctx, mk, state.SegmentCount())

		// The committed contract is a separate decision from the stored value, so
		// removal never edits it; warn if `run` will now report the key missing.
		if spec, declared := a.contract.Secrets[key]; declared && spec.IsRequired() {
			ui.Warnf("%s is still declared required in %s; `notenv run` will report it missing until you re-set it or remove the declaration", key, contract.FileName)
		}
		return nil
	},
}
