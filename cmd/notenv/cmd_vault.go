package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/DvGils/notenv/internal/backend"
	"github.com/DvGils/notenv/internal/config"
	"github.com/DvGils/notenv/internal/ui"
)

var (
	vaultCopyToPath   string
	vaultCopyToRemote string
	vaultCopyToBase   string
	vaultCopyName     string
	vaultCopyDefault  bool
)

var vaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Operate on a vault as a whole",
}

var vaultCopyCmd = &cobra.Command{
	Use:   "copy",
	Short: "Replicate this vault to new storage (the local→cloud ramp) and register it",
	Long: `Copy the selected vault — header, every encrypted object — to a new storage
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
		src, err := loadHeaderStore()
		if err != nil {
			return err
		}
		name, entry, err := copyDestination(ctx)
		if err != nil {
			return err
		}
		eff, err := destinationEffective(name, entry, src.scope)
		if err != nil {
			return err
		}
		dst := openStorage(eff)
		if err := dst.Preflight(ctx); err != nil {
			return err
		}
		if err := ui.Spin("Validating destination: write, read back, delete probe", func() error {
			return dst.Probe(ctx)
		}); err != nil {
			return err
		}
		if err := copyVault(ctx, src, dst); err != nil {
			return err
		}
		confPath, err := config.UpsertStorage(name, entry, vaultCopyDefault)
		if err != nil {
			return err
		}
		ui.Successf("vault copied and registered as storage %q (%s)", name, confPath)
		ui.Notef("the source is untouched; point a project at the copy with `storage = %q` in its %s, or re-run with --make-default", name, config.LocalBindingFile)
		return offerPromoteDefault(name)
	},
}

// copyDestination resolves where the copy goes — flags first, prompts when
// interactive — and the storage name it will be registered under.
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
		entry = config.StorageEntry{Remote: vaultCopyToRemote, Base: base, Versioned: remoteIsVersioned(ctx, vaultCopyToRemote)}
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
	return name, entry, nil
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
	base, err := requireInput("Bucket/path for encrypted blobs", "e.g. my-bucket/notenv")
	if err != nil {
		return config.StorageEntry{}, err
	}
	return config.StorageEntry{Remote: remote, Base: base, Versioned: remoteIsVersioned(ctx, remote)}, nil
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
// header installed last — the destination holds a live vault only once it is
// complete — and the source header re-checked afterwards so a copy that raced
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
		return errors.New("the destination already holds a vault; copies never merge or overwrite — pick an empty destination")
	} else if !errors.Is(err, backend.ErrNotFound) {
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
		if !srcSet[key] && !reservedCopyName(key) {
			if err := dst.Delete(ctx, key); err != nil {
				return fmt.Errorf("reconcile stale %s: %w", key, err)
			}
		}
	}
	return nil
}

// reservedCopyName filters storage plumbing out of the object copy: header
// artifacts travel through the header calls (rclone's listing includes them as
// plain files; the local backend's never does).
func reservedCopyName(key string) bool {
	switch key {
	case ".header.json", ".header.json.prev", ".header.lock", ".notenv-probe":
		return true
	}
	return false
}

func init() {
	vaultCopyCmd.Flags().StringVar(&vaultCopyToPath, "to-path", "", "destination directory for a local copy")
	vaultCopyCmd.Flags().StringVar(&vaultCopyToRemote, "to-remote", "", "destination rclone remote")
	vaultCopyCmd.Flags().StringVar(&vaultCopyToBase, "to-base", "", "path within the destination remote (default \""+config.DefaultBase+"\")")
	vaultCopyCmd.Flags().StringVar(&vaultCopyName, "name", "", "name to register the copy under")
	vaultCopyCmd.Flags().BoolVar(&vaultCopyDefault, "make-default", false, "make the copy this machine's default storage")
	vaultCmd.AddCommand(vaultCopyCmd)
}
