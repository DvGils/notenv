package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/DvGils/notenv/internal/backend"
	"github.com/DvGils/notenv/internal/config"
	"github.com/DvGils/notenv/internal/keyring"
	"github.com/DvGils/notenv/internal/ui"
)

var (
	vaultCopyToPath   string
	vaultCopyToRemote string
	vaultCopyToBase   string
	vaultCopyName     string
	vaultCopyDefault  bool
	vaultCopyForce    bool
)

var vaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Operate on a vault as a whole",
}

var vaultCopyCmd = &cobra.Command{
	Use:   "copy",
	Short: "Copy this vault to new storage (e.g. local to cloud) and register it",
	Long: `Copy the selected vault (header, every encrypted object) to a new storage
location, verify the copy byte for byte, and register it as a named storage on
this machine. The typical move: a vault that started on this machine, copied
to a cloud remote once syncing across machines matters.

It is the same vault afterwards, not a new one: nothing is re-encrypted, every
credential keeps working, and this machine's trust state follows the vault's
own identity. The source is never modified or deleted; the destination must
not already hold a vault (copies never merge).`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		// The destination is always a freshly named storage (never one with a
		// read_only entry), so only the process-wide switch applies here.
		if config.ReadOnlyEnv() {
			return errors.New("NOTENV_READONLY is set, which blocks all writes; copy writes a full vault to the destination, so unset NOTENV_READONLY to proceed")
		}
		src, err := loadHeaderStore()
		if err != nil {
			return err
		}
		name, entry, err := copyDestination(ctx)
		if err != nil {
			return err
		}
		// Refuse a name that already points elsewhere BEFORE copying, so a large
		// copy is never spent only to fail at registration (or to silently repoint
		// the name). UpsertStorage re-checks at write time; this is the early exit.
		if existing, have, err := config.LookupStorage(name); err != nil {
			return err
		} else if have && !entry.SameTarget(existing) && !vaultCopyForce {
			return fmt.Errorf("storage %q already points at %s; choose another --name, or pass --force to repoint it to %s", name, existing.Target(), entry.Target())
		}
		eff, err := destinationEffective(name, entry, src.scope)
		if err != nil {
			return err
		}
		dst := openStorage(eff)
		if err := dst.Preflight(ctx); err != nil {
			return err
		}
		if err := ui.Spin("Validating destination (write, read back, delete probe)", func() error {
			return dst.Probe(ctx)
		}); err != nil {
			return err
		}
		if err := copyVault(ctx, src, dst); err != nil {
			return err
		}
		confPath, err := config.UpsertStorage(name, entry, vaultCopyDefault, vaultCopyForce)
		if err != nil {
			return err
		}
		ui.Successf("vault copied and registered as storage %q (%s)", name, confPath)
		ui.Notef("the source is untouched; point a project at the copy with `storage = %q` in its %s, or re-run with --make-default", name, config.LocalBindingFile)
		return offerPromoteDefault(name)
	},
}

// copyDestination resolves where the copy goes (flags first, prompts when
// interactive) and the storage name it will be registered under.
func copyDestination(ctx context.Context) (string, config.StorageEntry, error) {
	if vaultCopyToPath != "" && vaultCopyToRemote != "" {
		return "", config.StorageEntry{}, errors.New("--to-path and --to-remote are mutually exclusive")
	}
	var entry config.StorageEntry
	switch {
	case vaultCopyToPath != "":
		path, err := config.AbsPath(vaultCopyToPath)
		if err != nil {
			return "", config.StorageEntry{}, err
		}
		entry = config.StorageEntry{Path: path}
	case vaultCopyToRemote != "":
		base := vaultCopyToBase
		if base == "" {
			base = config.DefaultBase
		}
		entry = config.StorageEntry{Remote: vaultCopyToRemote, Base: base}
	case !ui.Interactive():
		return "", config.StorageEntry{}, errors.New("destination required: --to-remote (with --to-base) or --to-path")
	default:
		var err error
		if entry, err = promptDestination(ctx); err != nil {
			return "", config.StorageEntry{}, err
		}
	}

	name := vaultCopyName
	if name == "" {
		if !ui.Interactive() {
			return "", config.StorageEntry{}, errors.New("--name required: the copy is registered as a named storage")
		}
		var err error
		if name, err = ui.Input("Name for the new storage", suggestedCopyName(entry)); err != nil {
			return "", config.StorageEntry{}, err
		}
	}
	if !config.ValidStorageName(name) {
		return "", config.StorageEntry{}, fmt.Errorf("invalid storage name %q: use letters, digits, '-' or '_'", name)
	}
	if reason, bad := dangerousVaultPath(entry.Path); bad {
		return "", config.StorageEntry{}, fmt.Errorf("refusing %q as a copy destination: %s; a vault directory is owned by notenv, so point --to-path at a dedicated, empty directory instead", entry.Path, reason)
	}
	return name, entry, nil
}

// dangerousVaultPath flags a local destination that must never be treated as a
// vault directory: the filesystem root or the user's home directory. notenv owns a
// vault directory (copy reconciles it, delete removes it), so handing it a
// populated tree puts that tree's other contents at risk. This is the fast, clear
// guard for the two paths that are both catastrophic and expensive to walk;
// refuseForeignDestination is the general backstop for any other populated dir. The
// empty path (a remote destination) is never flagged.
func dangerousVaultPath(path string) (string, bool) {
	if path == "" {
		return "", false
	}
	clean := filepath.Clean(path)
	if clean == filepath.VolumeName(clean)+string(filepath.Separator) {
		return "it is a filesystem root", true
	}
	if home, err := os.UserHomeDir(); err == nil && filepath.Clean(home) == clean {
		return "it is your home directory", true
	}
	return "", false
}

func promptDestination(ctx context.Context) (config.StorageEntry, error) {
	choice, err := ui.Select("Where should the copy live?", []ui.Option{
		{Label: "On a cloud remote", Detail: "via rclone: Backblaze B2, S3, SFTP, WebDAV…"},
		{Label: "In a local directory", Detail: "another disk, removable media"},
	})
	if err != nil {
		return config.StorageEntry{}, err
	}
	if choice == 1 {
		raw, err := requireInput("Directory for the copy", "e.g. /mnt/backup/notenv-vault")
		if err != nil {
			return config.StorageEntry{}, err
		}
		path, err := config.AbsPath(raw)
		if err != nil {
			return config.StorageEntry{}, err
		}
		return config.StorageEntry{Path: path}, nil
	}
	if !backend.RcloneInstalled() {
		ui.Infof("rclone is required for cloud remotes; install it with %s", ui.Bold(installHint()))
		return config.StorageEntry{}, errors.New("rclone missing")
	}
	remote, err := chooseRemote(ctx)
	if err != nil {
		return config.StorageEntry{}, err
	}
	base, err := requireInput("Bucket/path for encrypted secrets", "e.g. my-bucket/notenv")
	if err != nil {
		return config.StorageEntry{}, err
	}
	return config.StorageEntry{Remote: remote, Base: base}, nil
}

func suggestedCopyName(entry config.StorageEntry) string {
	if entry.Path != "" {
		return "copy"
	}
	return "remote"
}

// destinationEffective resolves the destination entry and refuses copying a
// vault onto itself (same local-state scope means same storage).
func destinationEffective(name string, entry config.StorageEntry, srcScope string) (config.Effective, error) {
	u := &config.User{Storage: map[string]config.StorageEntry{name: entry}}
	eff, err := config.ResolveStorage(u, name)
	if err != nil {
		return eff, err
	}
	if eff.Scope() == srcScope {
		return eff, errors.New("the destination is the source storage; nothing to copy")
	}
	return eff, nil
}

// copyVault replicates src's vault into dst: every object byte-verified, the
// header installed last (the destination holds a live vault only once it is
// complete) and the source header re-checked afterwards so a copy that raced
// a write is redone rather than registered torn. The destination must hold no
// vault yet; leftover objects from an interrupted earlier copy are overwritten
// or reconciled away.
func copyVault(ctx context.Context, src, dst vaultStorage) error {
	header, err := src.GetHeader(ctx)
	if errors.Is(err, backend.ErrNotFound) {
		return errors.New("the source storage holds no vault (no key header); run `notenv setup` first")
	}
	if err != nil {
		return err
	}
	if _, err := dst.GetHeader(ctx); err == nil {
		return errors.New("the destination already holds a vault; copies never merge or overwrite; pick an empty destination")
	} else if !errors.Is(err, backend.ErrNotFound) {
		return err
	}
	if err := refuseForeignDestination(ctx, dst); err != nil {
		return err
	}

	for range 3 {
		if err := ui.Spin("Copying and verifying objects", func() error {
			return copyObjects(ctx, src, dst)
		}); err != nil {
			return err
		}
		current, err := src.GetHeader(ctx)
		if err != nil {
			return err
		}
		if !bytes.Equal(current, header) {
			header = current // a write landed mid-copy; reconcile again
			continue
		}
		if err := dst.PutHeader(ctx, header); err != nil {
			return fmt.Errorf("install the copied header: %w", err)
		}
		got, err := dst.GetHeader(ctx)
		if err != nil || !bytes.Equal(got, header) {
			return fmt.Errorf("the copied header read back differently than written: %v", err)
		}
		return nil
	}
	return errors.New("the source vault kept changing during the copy; retry when writes pause")
}

// copyObjects mirrors src's object set into dst byte for byte: everything
// copied and verified, anything in dst that src no longer has removed.
func copyObjects(ctx context.Context, src, dst vaultStorage) error {
	keys, err := src.List(ctx, "")
	if err != nil {
		return err
	}
	srcSet := map[string]bool{}
	for _, key := range keys {
		if reservedCopyName(key) {
			continue
		}
		srcSet[key] = true
		blob, err := src.Get(ctx, key)
		if errors.Is(err, backend.ErrNotFound) {
			continue // deleted since the listing; the reconcile pass handles it
		}
		if err != nil {
			return fmt.Errorf("read %s: %w", key, err)
		}
		if err := dst.Put(ctx, key, blob); err != nil {
			return fmt.Errorf("write %s: %w", key, err)
		}
		got, err := dst.Get(ctx, key)
		if err != nil || !bytes.Equal(got, blob) {
			return fmt.Errorf("object %s read back differently than written: %v", key, err)
		}
	}
	dstKeys, err := dst.List(ctx, "")
	if err != nil {
		return err
	}
	for _, key := range dstKeys {
		// Delete only a stale namespace blob the source no longer has. A key that
		// is not a namespace blob is a file notenv did not write (the destination
		// precheck should have refused such a destination, but the whitelist makes
		// the delete safe by construction even if that check is ever bypassed).
		if srcSet[key] || !backend.IsNamespaceBlob(key) {
			continue
		}
		if err := dst.Delete(ctx, key); err != nil {
			return fmt.Errorf("reconcile stale %s: %w", key, err)
		}
	}
	return nil
}

// refuseForeignDestination fails, before any write, if the destination already
// holds a file notenv did not create. A copy goes to an empty directory or to one
// holding only the blobs of an interrupted earlier copy; a directory full of
// unrelated files (a home directory, a project, "/") is a mispointed destination,
// and copying there would later delete those files in the reconcile pass. Turning
// that into an early error is what keeps a stray --to-path from becoming data loss.
func refuseForeignDestination(ctx context.Context, dst vaultStorage) error {
	keys, err := dst.List(ctx, "")
	if err != nil {
		return err
	}
	for _, key := range keys {
		if !backend.IsNotenvObject(key) {
			return fmt.Errorf("the destination already holds files notenv did not create (e.g. %q); copy writes only to an empty directory or a fresh location, never one with unrelated files in it", key)
		}
	}
	return nil
}

// reservedCopyName filters storage plumbing out of the object copy: header
// artifacts travel through the header calls, not the blob copy. It defers to the
// backend package so the reserved-name set has one definition (the divergence
// that let orphan cleanup delete the header lived in two copies of this list).
func reservedCopyName(key string) bool {
	return backend.IsReserved(key)
}

var vaultDeleteYes bool

var vaultDeleteCmd = &cobra.Command{
	Use:   "delete <name>",
	Short: "Permanently delete a vault, its data, and this machine's record of it",
	Long: `Permanently delete a configured vault.

Removes the vault's encrypted objects, this machine's trust state for it (the
rollback pin and cached key), and its entry in the machine config. Gated by the
Deletion requires the vault's primary passphrase plus typing the name to
confirm, so notenv only destroys a vault you can prove you own.

notenv removes the LIVE vault. A versioned remote's history and your own backups
are the provider's to purge, so "deleted" here does not mean the ciphertext is
gone everywhere. There is deliberately no --force: if you have lost the
passphrase, delete the storage yourself (a local vault is its directory, a
remote's objects are yours to delete) and run ` + "`notenv key forget`" + ` to clear the
local trust state.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		name := args[0]
		if config.ReadOnlyEnv() {
			return errors.New("NOTENV_READONLY is set; refusing to delete a vault")
		}
		user, err := config.LoadUser()
		if err != nil {
			return err
		}
		eff, err := config.ResolveStorage(user, name)
		if err != nil {
			return err
		}
		store := openStorage(eff)
		scope := eff.Scope()

		_, slot, header, err := humanUnlock(ctx, store, scope, fmt.Sprintf("permanently deleting vault %q", name))
		if err != nil {
			return err
		}
		if err := requirePrimarySlot(header, slot, "vault delete"); err != nil {
			return err
		}

		ui.Warnf("about to permanently delete vault %s on storage %q. This removes the live vault only; a versioned remote's history and your own backups are yours to purge separately", header.VaultID, name)
		if !vaultDeleteYes {
			if !ui.Interactive() {
				return errors.New("refusing to delete non-interactively without --yes")
			}
			typed, err := ui.Input(fmt.Sprintf("Type the storage name %q to confirm", name), "")
			if err != nil {
				return err
			}
			if typed != name {
				return errors.New("aborted; the name did not match")
			}
		}

		if err := ui.Spin("Deleting vault", func() error {
			return destroyVault(ctx, eff, store)
		}); err != nil {
			return err
		}
		if err := config.ForgetScope(scope); err != nil {
			ui.Warnf("could not clear local trust state: %v", err)
		}
		keyring.DefaultCache().Drop(scope)
		if _, err := config.RemoveStorage(name); err != nil {
			ui.Warnf("could not remove the storage entry from config (remove %q by hand): %v", name, err)
		}
		ui.Successf("deleted vault %q; its trust state and config entry are gone too", name)
		return nil
	},
}

// reservedArtifacts are the fixed-name plumbing objects a remote vault may hold
// besides its namespace blobs. List omits them (they are not data), so a remote
// teardown deletes them by name to leave nothing of the vault behind. A local
// teardown removes the whole directory instead and never needs this.
var reservedArtifacts = []string{
	backend.HeaderName,
	backend.HeaderBackupName,
	backend.HeaderLockName,
	backend.ProbeName,
}

// destroyVault removes a vault's bytes, but only once it is sure the storage holds
// nothing notenv did not write: a local vault is its directory (removed whole); a
// remote vault is its namespace blobs plus its fixed-name plumbing.
func destroyVault(ctx context.Context, eff config.Effective, store vaultStorage) error {
	keys, err := store.List(ctx, "")
	if err != nil {
		return err
	}
	if err := refuseForeignVault(keys, eff); err != nil {
		return err
	}
	if eff.Local() {
		return os.RemoveAll(eff.Path)
	}
	// A remote has no directory to remove, so delete every object the vault holds:
	// the namespace blobs from the listing, then the plumbing List omits because it
	// is not data. Delete is idempotent, so naming an artifact the vault never wrote
	// is a harmless no-op.
	for _, k := range append(keys, reservedArtifacts...) {
		if err := store.Delete(ctx, k); err != nil {
			return fmt.Errorf("delete %s: %w", k, err)
		}
	}
	return nil
}

// refuseForeignVault fails, before anything is deleted, when the storage holds an
// object notenv did not write. That stops a vault delete from taking out a user's
// unrelated data: neither an os.RemoveAll of a local path mispointed at a populated
// directory, nor the delete loop over a remote prefix a shared bucket also uses for
// other things. The refusal is atomic because it runs before the first delete.
func refuseForeignVault(keys []string, eff config.Effective) error {
	for _, key := range keys {
		if backend.IsNamespaceBlob(key) {
			continue
		}
		return fmt.Errorf("refusing to delete the vault at %s: its storage holds %q, which notenv did not create; vault delete removes only notenv's own objects, so remove that yourself if you are certain it should go", vaultLocation(eff), key)
	}
	return nil
}

// vaultLocation names a storage for an error message: the directory for a local
// vault, "remote:base" for a remote one.
func vaultLocation(eff config.Effective) string {
	if eff.Local() {
		return eff.Path
	}
	return eff.Remote + ":" + eff.Base
}

func init() {
	vaultCopyCmd.Flags().StringVar(&vaultCopyToPath, "to-path", "", "destination directory for a local copy")
	vaultCopyCmd.Flags().StringVar(&vaultCopyToRemote, "to-remote", "", "destination rclone remote")
	vaultCopyCmd.Flags().StringVar(&vaultCopyToBase, "to-base", "", "path within the destination remote (default \""+config.DefaultBase+"\")")
	vaultCopyCmd.Flags().StringVar(&vaultCopyName, "name", "", "name to register the copy under")
	vaultCopyCmd.Flags().BoolVar(&vaultCopyDefault, "make-default", false, "make the copy this machine's default storage")
	vaultCopyCmd.Flags().BoolVar(&vaultCopyForce, "force", false, "repoint --name even if it already names a different storage")
	vaultDeleteCmd.Flags().BoolVar(&vaultDeleteYes, "yes", false, "skip the type-the-name confirmation (the passphrase is still required)")
	vaultCmd.AddCommand(vaultCopyCmd, vaultDeleteCmd)
}
