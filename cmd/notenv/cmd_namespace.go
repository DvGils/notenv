package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/DvGils/notenv/internal/backend"
	"github.com/DvGils/notenv/internal/blobcache"
	"github.com/DvGils/notenv/internal/config"
	"github.com/DvGils/notenv/internal/contract"
	"github.com/DvGils/notenv/internal/crypto"
	"github.com/DvGils/notenv/internal/keymgmt"
	"github.com/DvGils/notenv/internal/secrets"
	"github.com/DvGils/notenv/internal/ui"
)

var namespaceCmd = &cobra.Command{
	Use:   "namespace",
	Short: "Create, list, update, and remove the namespaces in your vault",
	Long: `A namespace is a named, independently encrypted group of secrets in your vault
(a project's secrets, a machine's credentials). These commands operate on
namespaces as containers: list what the vault holds, create one deliberately,
update its metadata, recover one from backup, or remove one along with its secrets.

Reading and writing the secrets INSIDE a namespace uses the top-level commands
(set, unset, list, run, ...), with the namespace chosen by your project's
notenv.toml or the --namespace flag. A namespace persists once it exists, even
after its last secret is removed; "namespace delete" is how it goes away.`,
}

var namespaceListJSON bool

var namespaceListCmd = &cobra.Command{
	Use:   "list",
	Short: "List the namespaces the vault holds (names only, no passphrase needed)",
	Long: `List every namespace recorded in the vault header, read with no passphrase.

It shows names only: never values, and never whether a namespace is empty, since
emptiness lives inside the encrypted blob and reading it needs the master key.
Run "notenv doctor" (with a key cached) to surface empty namespaces.

This differs from "notenv list", which lists the secret NAMES inside a single
selected namespace.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		store, err := loadHeaderStore()
		if err != nil {
			return err
		}
		// Honor the handoff session guard: an agent in a session must not enumerate
		// another vault's namespaces via a stray --storage, the same rule every other
		// vault-touching command follows. The listing reads no secret, but the guard
		// is about which vault a session may address at all.
		if err := sessionGuard(store.scope); err != nil {
			return err
		}
		names, err := listNamespaceNames(ctx, store)
		if err != nil {
			return err
		}
		if namespaceListJSON {
			return printJSON(newNamespaceList(names))
		}
		if len(names) == 0 {
			if term.IsTerminal(int(os.Stdout.Fd())) {
				ui.Infof("the vault holds no namespaces yet")
			}
			return nil
		}
		// Piped output is the stable scripting surface: one name per line, nothing
		// else. A header is added only for a human terminal.
		if term.IsTerminal(int(os.Stdout.Fd())) {
			fmt.Println("NAMESPACE")
		}
		for _, n := range names {
			fmt.Println(n)
		}
		return nil
	},
}

// listNamespaceNames reads the vault's namespace names from the header manifest.
// It needs no master: the names are cleartext in the manifest. A missing header
// (virgin storage) is a friendly error, not a crash.
func listNamespaceNames(ctx context.Context, store *headerTarget) ([]string, error) {
	raw, err := store.GetHeader(ctx)
	if errors.Is(err, backend.ErrNotFound) {
		return nil, errors.New("no vault on this storage yet; run `notenv setup` to create one")
	}
	if err != nil {
		return nil, err
	}
	header, err := crypto.ParseHeader(raw)
	if err != nil {
		return nil, err
	}
	return vaultNamespaces(header), nil
}

// namespaceListOutput is the frozen shape of `namespace list --json`: a versioned
// envelope around an array of named-field objects, so the per-namespace shape can
// grow additively (a count or a created time, once metadata lands) without a
// breaking change.
type namespaceListOutput struct {
	Version    int                  `json:"version"`
	Namespaces []namespaceListEntry `json:"namespaces"`
}

type namespaceListEntry struct {
	Name string `json:"name"`
}

func newNamespaceList(names []string) namespaceListOutput {
	out := namespaceListOutput{Version: 1, Namespaces: make([]namespaceListEntry, 0, len(names))}
	for _, n := range names {
		out.Namespaces = append(out.Namespaces, namespaceListEntry{Name: n})
	}
	return out
}

var namespaceCreateDescription string

var namespaceCreateCmd = &cobra.Command{
	Use:   "create NAME",
	Short: "Create an empty namespace before it holds any secret",
	Long: `Create a namespace that holds no secrets yet.

Setting the first secret already creates a namespace, so this is the deliberate
path: reserve a name, or stand a namespace up before its first secret lands. It
fails if the namespace already exists, and never touches an existing one.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		name := args[0]
		if !contract.NamespaceName.MatchString(name) {
			return fmt.Errorf("invalid namespace name %q: it must match %s", name, contract.NamespaceName)
		}
		store, err := loadHeaderStore()
		if err != nil {
			return err
		}
		u, err := unlockHeader(ctx, store, true)
		if err != nil {
			return err
		}
		// Friendly early exit before any write; createNamespace re-checks atomically
		// inside the swap, so a racing create still cannot clobber an existing one.
		if _, exists := u.header.NamespaceEntry(name); exists {
			return fmt.Errorf("namespace %q already exists", name)
		}
		err = createNamespace(ctx, store, u.mk, name, namespaceCreateDescription)
		// Drop any stale warm cache from an earlier incarnation of this name when the
		// write may have landed (clean success OR an uncertain commit), so a later
		// run cannot serve old secrets instead of the new empty state.
		if err == nil || errors.Is(err, backend.ErrCommitUncertain) {
			invalidateNamespaceCache(store.scope, name)
		}
		if err != nil {
			return err
		}
		// Creating a namespace is a deliberate, authenticated naming of it by the
		// operator, which is exactly what the projectless first-use guard asks them
		// to confirm. Record that acceptance now (per storage+namespace, user-level)
		// so the first `--namespace NAME` use is not redundantly re-confirmed. The
		// pin and handoff guards are separate mechanisms and untouched. Best-effort:
		// a read-only config dir just means the first use re-confirms.
		if err := config.AcceptNamespace(store.scope, name); err != nil {
			ui.Warnf("could not record acceptance of namespace %q: %v (you may be asked to confirm it on first use)", name, err)
		}
		ui.Successf("created empty namespace %q; add a secret with `notenv --namespace %s set KEY`", name, name)
		return nil
	},
}

// createNamespace records a new empty namespace under the header swap, mapping
// the package errors to friendly command-layer messages. ErrNamespaceExists can
// still surface here (not just from the caller's pre-check) if another writer
// created the namespace between that check and the swap.
func createNamespace(ctx context.Context, store *headerTarget, mk *crypto.MasterKey, name, description string) error {
	err := secrets.For(store, name, mk).WithStamp(writeStamp()).Create(ctx,
		func(h *crypto.Header) { pinCurrent(store.scope, h, mk) }, description)
	switch {
	case errors.Is(err, secrets.ErrNamespaceExists):
		return fmt.Errorf("namespace %q already exists", name)
	case errors.Is(err, backend.ErrCommitUncertain):
		return fmt.Errorf("%w; the namespace may have been created. Run `notenv doctor` to check before relying on it", err)
	case errors.Is(err, keymgmt.ErrEpochChanged):
		return fmt.Errorf("%w; nothing was created. Re-run to create under the current key", err)
	}
	return err
}

var namespaceDeleteYes bool

var namespaceDeleteCmd = &cobra.Command{
	Use:   "delete NAME",
	Short: "Permanently remove a namespace and all of its secrets",
	Long: `Permanently remove a namespace: its manifest entry and every secret it holds.

This is irreversible here (a versioned remote's history and your own backups are
yours to recover from). It works even on a namespace whose data is corrupt or
missing, since it never reads the blob, so it also clears a namespace that can no
longer be read.

It requires the vault passphrase (to rewrite the header) and a confirmation; pass
--yes to skip the confirmation (the passphrase is still required).`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		name := args[0]
		store, err := loadHeaderStore()
		if err != nil {
			return err
		}
		u, err := unlockHeader(ctx, store, true)
		if err != nil {
			return err
		}
		if _, exists := u.header.NamespaceEntry(name); !exists {
			return fmt.Errorf("namespace %q is not in the vault; nothing to delete", name)
		}
		ui.Warnf("about to permanently delete namespace %q and all of its secrets; this removes the live data only (a versioned remote's history and your own backups are yours to purge)", name)
		if !namespaceDeleteYes {
			if !ui.Interactive() {
				return errors.New("refusing to delete a namespace non-interactively without --yes")
			}
			ok, err := ui.Confirm(fmt.Sprintf("Delete namespace %q and everything in it?", name), false)
			if err != nil {
				return err
			}
			if !ok {
				return errors.New("aborted; nothing was deleted")
			}
		}
		err = deleteNamespace(ctx, store, u.mk, name)
		// Drop the warm ciphertext cache for the namespace whenever the delete may
		// have landed (clean success OR an uncertain commit): the master is unchanged
		// by a namespace delete, so otherwise a later run on this machine would pass
		// the cache's master-keyed MAC check and serve the just-deleted secrets. Only
		// a definite failure (epoch change, rollback) leaves the namespace untouched.
		if err == nil || errors.Is(err, backend.ErrCommitUncertain) {
			invalidateNamespaceCache(store.scope, name)
		}
		if err != nil {
			return err
		}
		ui.Successf("deleted namespace %q", name)
		return nil
	},
}

// deleteNamespace removes a namespace and reclaims its blobs under the header
// swap, mapping a concurrent epoch change to a friendly retry message. It does
// not read the blob, so it removes a corrupt or missing namespace just as well.
func deleteNamespace(ctx context.Context, store *headerTarget, mk *crypto.MasterKey, name string) error {
	err := secrets.For(store, name, mk).Delete(ctx,
		func(h *crypto.Header) { pinCurrent(store.scope, h, mk) })
	switch {
	case errors.Is(err, backend.ErrCommitUncertain):
		return fmt.Errorf("%w; the delete may have landed. Run `notenv doctor` to check before relying on it", err)
	case errors.Is(err, keymgmt.ErrEpochChanged):
		return fmt.Errorf("%w; nothing was deleted. Re-unlock under the current key and re-run", err)
	}
	return err
}

var namespaceUpdateDescription string

var namespaceUpdateCmd = &cobra.Command{
	Use:   "update NAME",
	Short: "Update a namespace's metadata (today, its description)",
	Long: `Update an existing namespace's metadata. Today that is its description: pass
--description "new text" to set it, or --description "" to clear it. The
namespace must already exist (create it with ` + "`notenv namespace create`" + `).`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		name := args[0]
		// Tri-state like `set --description`: only an explicitly-passed --description
		// changes anything, so updating without it is a no-op error rather than a
		// silent clear.
		if !cmd.Flags().Changed("description") {
			return errors.New("nothing to update; pass --description (the only field today)")
		}
		store, err := loadHeaderStore()
		if err != nil {
			return err
		}
		u, err := unlockHeader(ctx, store, true)
		if err != nil {
			return err
		}
		if _, exists := u.header.NamespaceEntry(name); !exists {
			return fmt.Errorf("namespace %q is not in the vault; create it first with `notenv namespace create %s`", name, name)
		}
		if err := updateNamespaceDescription(ctx, store, u.mk, name, namespaceUpdateDescription); err != nil {
			return err
		}
		ui.Successf("updated namespace %q", name)
		return nil
	},
}

// updateNamespaceDescription rewrites a namespace's blob with a new description,
// preserving its secrets and created stamp (WriteBlob keeps Created and advances
// Updated). It works on an empty namespace too, since the blob persists.
func updateNamespaceDescription(ctx context.Context, store *headerTarget, mk *crypto.MasterKey, name, description string) error {
	_, _, err := secrets.For(store, name, mk).WithStamp(writeStamp()).Commit(ctx,
		func(cur *secrets.State) (*secrets.State, error) {
			cur.Namespace.Description = description
			return cur, nil
		},
		func(h *crypto.Header) { pinCurrent(store.scope, h, mk) })
	switch {
	case errors.Is(err, backend.ErrCommitUncertain):
		return fmt.Errorf("%w; the update may have landed. Run `notenv doctor` to check before relying on it", err)
	case errors.Is(err, keymgmt.ErrEpochChanged):
		return fmt.Errorf("%w; nothing was changed. Re-unlock under the current key and re-run", err)
	}
	return err
}

var namespaceRecoverYes bool

var namespaceRecoverCmd = &cobra.Command{
	Use:   "recover NAME",
	Short: "Rebuild a namespace whose blob is unreadable from its last good backup (accepts data loss)",
	Long: `Recover a namespace a normal read refuses because its current blob is missing or
corrupt (bit-rot, a truncated upload, an unrecoverable remote). notenv rebuilds
the namespace from its one-generation backup, losing only the most recent
write(s), and drops the corrupt blobs.

If nothing readable survives (the backup is gone or corrupt too), recover cannot
rebuild the namespace and stops without changing anything; remove it with
"notenv namespace delete NAME" if you want it gone. This is a last resort for
honest media loss: prefer your remote's version history if it keeps one, or
"notenv run --skip-corrupt" to read what survives without changing anything.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		name := args[0]
		store, err := loadHeaderStore()
		if err != nil {
			return err
		}
		u, err := unlockHeader(ctx, store, true)
		if err != nil {
			return err
		}
		entry, recorded := u.header.NamespaceEntry(name)
		if !recorded {
			return fmt.Errorf("namespace %q is not in the vault; nothing to recover", name)
		}
		state, err := secrets.For(store, name, u.mk).ReadSalvage(ctx, entry)
		if err != nil {
			return err
		}
		if len(state.Corrupt) == 0 {
			return fmt.Errorf("namespace %q reads cleanly; nothing to recover", name)
		}
		for _, c := range state.Corrupt {
			ui.Warnf("unreadable blob %s: %s", c.Blob, c.Reason)
		}
		// Nothing readable survives (both generations are gone or corrupt), so there
		// is no older version to restore. Refuse before prompting rather than rewrite
		// an empty namespace: clearing it is a separate, explicit decision the
		// operator makes with `namespace delete`.
		if len(state.Secrets) == 0 {
			return fmt.Errorf("cannot recover namespace %q: no readable data survives (its current blob and one-generation backup are both unreadable). To remove it entirely, run `notenv namespace delete %s`", name, name)
		}
		survivors := len(state.Secrets)
		ui.Warnf("recover rebuilds namespace %q from its last good backup (%d secret(s)); the most recent write(s) are lost", name, survivors)
		if !namespaceRecoverYes {
			if !ui.Interactive() {
				return errors.New("refusing to recover non-interactively without --yes")
			}
			ok, err := ui.Confirm("Rebuild this namespace from its last good backup?", false)
			if err != nil {
				return err
			}
			if !ok {
				return errors.New("aborted; nothing was changed")
			}
		}
		err = recoverNamespace(ctx, store, u.mk, name, state, entry)
		// Drop any stale warm cache whenever the rewrite may have landed (clean
		// success OR an uncertain commit): the master is unchanged by a recover, so a
		// later read on this machine could otherwise pass the cache's master-keyed MAC
		// check and serve the pre-recovery content, re-surfacing the very write the
		// rebuild just dropped.
		if err == nil || errors.Is(err, backend.ErrCommitUncertain) {
			invalidateNamespaceCache(store.scope, name)
		}
		switch {
		case err == nil:
		case errors.Is(err, backend.ErrCommitUncertain):
			return fmt.Errorf("%w; the rebuild may have landed. Run `notenv doctor` to check before relying on it", err)
		case errors.Is(err, keymgmt.ErrEpochChanged):
			return fmt.Errorf("%w; nothing was changed. Re-unlock under the current key (verify the rotation is legitimate) and re-run", err)
		default:
			return err
		}
		ui.Successf("recovered namespace %q to its last good state (%d secret(s))", name, survivors)
		return nil
	},
}

// recoverNamespace rewrites a namespace from its salvaged survivors, dropping the
// corrupt blobs it replaces as part of the same commit (secrets.Rewrite handles
// the header swap and blob cleanup). expected is the manifest entry the state was
// salvaged under, so a concurrent repair that landed since aborts this one rather
// than being clobbered. It must be called only with surviving secrets: an empty
// state would make Rewrite drop the namespace entry entirely, which is
// `namespace delete`, a separate explicit decision, so it refuses instead.
func recoverNamespace(ctx context.Context, store *headerTarget, mk *crypto.MasterKey, name string, state *secrets.State, expected crypto.ManifestEntry) error {
	if len(state.Secrets) == 0 {
		return fmt.Errorf("refusing to recover namespace %q to empty: nothing survives to rebuild from (use `notenv namespace delete` to remove it)", name)
	}
	_, err := secrets.For(store, name, mk).WithStamp(writeStamp()).Rewrite(ctx, state, expected,
		func(h *crypto.Header) { pinCurrent(store.scope, h, mk) })
	return err
}

// invalidateNamespaceCache drops any warm local ciphertext cache for one
// namespace after its existence or content changed. The TTL passed to New does
// not affect Drop (it removes the keyed file unconditionally); it just has to be
// positive so New returns the real platform cache rather than the no-op one.
// Where blob caching is off or unsupported, Drop is a harmless no-op.
func invalidateNamespaceCache(scope, name string) {
	blobcache.New(config.DefaultBlobCacheTTL).Drop(scope, name)
}

func init() {
	namespaceListCmd.Flags().BoolVar(&namespaceListJSON, "json", false, "machine-readable output: a versioned object listing namespace names")
	namespaceCreateCmd.Flags().StringVar(&namespaceCreateDescription, "description", "", "a description for the namespace, shown by `notenv inspect`")
	namespaceUpdateCmd.Flags().StringVar(&namespaceUpdateDescription, "description", "", "set the namespace's description (\"\" clears it)")
	namespaceDeleteCmd.Flags().BoolVar(&namespaceDeleteYes, "yes", false, "skip the confirmation (the passphrase is still required)")
	namespaceRecoverCmd.Flags().BoolVar(&namespaceRecoverYes, "yes", false, "rebuild without the interactive confirmation (you have accepted the data loss)")
	namespaceCmd.AddCommand(namespaceListCmd, namespaceCreateCmd, namespaceDeleteCmd, namespaceUpdateCmd, namespaceRecoverCmd)
	rootCmd.AddCommand(namespaceCmd)
}
