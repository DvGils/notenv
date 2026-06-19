package main

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/DvGils/notenv/internal/contract"
	"github.com/DvGils/notenv/internal/secrets"
	"github.com/DvGils/notenv/internal/ui"
)

var (
	copyFrom  string
	copyTo    string
	copyForce bool
)

// secretCopyCmd moves one secret between two namespaces of the SAME vault without ever
// surfacing its plaintext: the value is read under the master and written back
// under the same master in one process, never printed, never put on disk. It is
// deliberately within-vault only (no source/target storage flags): a copy across
// vaults would have to bridge two masters, and the namespace name is bound into
// each blob's MAC, so the safe primitive is "re-encrypt under this vault's
// master", which only makes sense inside one vault. Both namespaces resolve
// through one app bound to a single storage, so the within-vault property is
// structural, not a runtime check.
var secretCopyCmd = &cobra.Command{
	Use:   "copy KEY --from NS1 --to NS2",
	Short: "Copy one secret from one namespace to another in the same vault, without exposing its value",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		key := args[0]
		if !contract.ValidEnvName(key) {
			return fmt.Errorf("%q is not a valid environment variable name (use letters, digits, and underscores; cannot start with a digit)", key)
		}
		if copyFrom == "" || copyTo == "" {
			return fmt.Errorf("copy needs both --from and --to")
		}
		if copyFrom == copyTo {
			return fmt.Errorf("--from and --to are the same namespace (%q); nothing to copy", copyFrom)
		}
		// --namespace addresses a single namespace; copy names two with --from/--to,
		// so an extra --namespace is a contradiction we surface rather than ignore.
		if namespaceFlag != "" {
			return fmt.Errorf("copy uses --from and --to, not --namespace")
		}

		ctx := cmd.Context()
		// One app bound to the destination namespace, on one storage. Reading the
		// source goes through this same app's store and master, so source and
		// destination are guaranteed to be the same vault: copy can never bridge two.
		a, err := projectlessApp(ctx, storageSelector(""), copyTo)
		if err != nil {
			return err
		}
		return runCopy(ctx, a, key, copyFrom, copyForce)
	},
}

// runCopy copies key from the namespace named by from into a's bound namespace
// (the destination), both in a's single vault. a is bound to the destination so
// the unlock, the master, and the cache scope are all the destination's, and the
// source is read through the same store: there is no second vault to reach.
func runCopy(ctx context.Context, a *app, key, from string, force bool) error {
	dst := a.namespace
	if err := a.requireWritable("copy a secret"); err != nil {
		return err
	}
	// Hold the source namespace to the user-level acceptance record too: copy reads
	// its secrets, so it deserves the same first-use confirmation a direct
	// --namespace read of it would get. (The destination was already held when
	// projectlessApp resolved it.) This is a header-only check, no unlock and no
	// plaintext; the handoff-session confidentiality boundary is enforced by the
	// unlock below (master() refuses a foreign vault before reading any secret), not
	// here, so this stays the plain accident guard against pulling another project's
	// secrets, in or out of a session.
	v, err := a.vault()
	if err != nil {
		return err
	}
	if err := guardFlagNamespace(ctx, v, a.cacheScope, from); err != nil {
		return err
	}

	// Unlock and verify the header. master() runs sessionGuard before any cache
	// read, so an in-session agent pointed at a foreign vault is refused here,
	// before a single secret is read: the one master this resolves is the session's
	// ephemeral vault, whose namespaces are exactly the ones the agent was handed,
	// so it can only ever copy keys it already holds.
	view, err := a.unlockView(ctx)
	if err != nil {
		return err
	}

	// Read the source value under the unlocked master. NamespaceEntry returns the
	// zero entry for a namespace with no blob yet; Read then resolves empty, and the
	// not-set check below gives the precise error.
	srcEntry, _ := view.header.NamespaceEntry(from)
	var srcState *secrets.State
	if err := ui.Spin(fmt.Sprintf("Reading namespace %q", from), func() error {
		var rerr error
		srcState, rerr = secrets.For(a.store, from, view.mk).Read(ctx, srcEntry)
		return rerr
	}); err != nil {
		return err
	}
	value, present := srcState.Secrets[key]
	if !present {
		return fmt.Errorf("%q is not set in source namespace %q", key, from)
	}
	meta := srcState.Meta[key]

	now := time.Now().Unix()
	// Carry the description forward; stamp a fresh write time and actor (this is a
	// new write into the destination, not a clone of the source's history).
	w := secrets.Write{Key: key, Value: value, Description: meta.Description, TS: now, By: userAtHost()}

	apply := func(cur *secrets.State) (*secrets.State, error) {
		// Refuse-if-exists decided against the state actually being committed: a
		// concurrent writer that created the key first still trips this.
		if _, exists := cur.Secrets[key]; exists && !force {
			return nil, fmt.Errorf("%q already exists in namespace %q; pass --force to overwrite", key, dst)
		}
		return cur.Apply([]secrets.Write{w}), nil
	}
	var updated *secrets.State
	if err := ui.Spin("Uploading encrypted blob", func() error {
		var cerr error
		updated, cerr = a.commitNamespace(ctx, view, apply)
		return cerr
	}); err != nil {
		return err
	}
	a.cacheState(view.mk, updated)
	ui.Successf("copied %s from namespace %q to %q", key, from, dst)
	ui.Notef("declare %s in the destination project's %s so `notenv run` injects it", key, contract.FileName)
	return nil
}

func init() {
	secretCopyCmd.Flags().StringVar(&copyFrom, "from", "", "source namespace to copy the secret from")
	secretCopyCmd.Flags().StringVar(&copyTo, "to", "", "destination namespace to copy the secret into (same vault)")
	secretCopyCmd.Flags().BoolVar(&copyForce, "force", false, "overwrite the key if it already exists in the destination")
}
