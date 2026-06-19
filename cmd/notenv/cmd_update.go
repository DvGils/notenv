package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/DvGils/notenv/internal/contract"
	"github.com/DvGils/notenv/internal/secrets"
	"github.com/DvGils/notenv/internal/ui"
)

var updateDescription string

var updateCmd = &cobra.Command{
	Use:   "update KEY",
	Short: "Update an existing secret's metadata (today, its description) without changing its value",
	Long: `Change what a secret is for without touching its value.

Pass --description "new text" to set the description, or --description "" to
clear it. The secret must already exist; create one (with a value) using
"notenv set KEY".

This is the metadata-only counterpart to "set" (which sets a value) and "edit"
(which bulk-edits values and descriptions in $EDITOR). The value is re-sealed
unchanged and is never displayed.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		key := args[0]
		if !contract.ValidEnvName(key) {
			return fmt.Errorf("%q is not a valid environment variable name (use letters, digits, and underscores; cannot start with a digit)", key)
		}
		// Tri-state like `set --description`: only an explicitly-passed --description
		// changes anything, so updating without it is a no-op error rather than a
		// silent clear.
		if !cmd.Flags().Changed("description") {
			return errors.New("nothing to update; pass --description (the only field today)")
		}
		a, err := loadApp(cmd.Context())
		if err != nil {
			return err
		}
		return runUpdate(cmd.Context(), a, key, updateDescription)
	},
}

// runUpdate amends an existing secret's metadata (today, its description) without
// changing its value. The value is read from the state actually being committed,
// not a separate pre-read, so a concurrent value change on another machine is
// preserved rather than clobbered with a stale value.
func runUpdate(ctx context.Context, a *app, key, description string) error {
	if err := a.requireWritable("update a secret"); err != nil {
		return err
	}
	// Read the namespace first only to give a friendly "does not exist" error
	// before any spinner or write; the authoritative value still comes from the
	// committed state inside commitNamespace below, so this pre-read can never
	// clobber a concurrent value change.
	state, view, err := a.readState(ctx)
	if err != nil {
		return err
	}
	storageKey := a.storageKey(key)
	if _, ok := state.Secrets[storageKey]; !ok {
		// update amends an existing secret; it never creates one (that is `set`).
		return fmt.Errorf("secret %q does not exist in namespace %q; set it first with `notenv set %s`", key, a.namespace, key)
	}

	var updated *secrets.State
	if err := ui.Spin("Uploading encrypted blob", func() error {
		var aerr error
		updated, aerr = a.commitNamespace(ctx, view, func(cur *secrets.State) (*secrets.State, error) {
			value, ok := cur.Secrets[storageKey]
			if !ok {
				return nil, fmt.Errorf("secret %q vanished from namespace %q before the update committed", key, a.namespace)
			}
			// Re-seal the existing value with the new description. By/TS record this
			// metadata write's actor and time.
			return cur.Apply([]secrets.Write{{
				Key:         storageKey,
				Value:       value,
				Description: description,
				TS:          time.Now().Unix(),
				By:          userAtHost(),
			}}), nil
		})
		return aerr
	}); err != nil {
		return err
	}
	a.cacheState(view.mk, updated)
	ui.Successf("updated %s in namespace %q", key, a.namespace)
	return nil
}

func init() {
	updateCmd.Flags().StringVar(&updateDescription, "description", "", "what this secret is and how to use it, shown by `list` (\"\" clears it)")
	rootCmd.AddCommand(updateCmd)
}
