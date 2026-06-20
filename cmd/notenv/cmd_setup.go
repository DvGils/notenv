package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/DvGils/notenv/internal/backend"
	"github.com/DvGils/notenv/internal/config"
	"github.com/DvGils/notenv/internal/keyring"
	"github.com/DvGils/notenv/internal/ui"
)

var (
	setupName        string
	setupMakeDefault bool
	setupStorageType string
	setupPath        string
)

var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Set up this machine: pick or create a storage remote, write the user config",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return setupFlow(cmd.Context())
	},
}

func init() {
	setupCmd.Flags().StringVar(&setupName, "name", "", "name for this storage (use distinct names for separate vaults)")
	setupCmd.Flags().BoolVar(&setupMakeDefault, "make-default", false, "make this the default storage")
	setupCmd.Flags().StringVar(&setupStorageType, "storage-type", "", "what kind of storage to create: \"local\" (this machine; the default, no accounts or rclone) or \"remote\" (a cloud remote via rclone)")
	setupCmd.Flags().StringVar(&setupPath, "path", "", "directory for a local vault (default: the per-name data dir)")
}

// setupFlow is the machine installer. Also chained into by `notenv init` on an
// unconfigured machine. It adds one or more named storages: each is an
// independent vault with its own master key, so each gets its own key ceremony.
// Storage-only by design beyond that: a namespace's secrets don't exist until
// the first `set`.
func setupFlow(ctx context.Context) error {
	user, err := config.LoadUser()
	if err != nil {
		return err
	}
	// A first-ever setup adds one storage and finishes: a newcomer is never asked
	// the confusing "add another?" right after creating their first vault.
	// Re-running setup with storages already configured is a deliberate "add
	// another vault", so the loop offers it only there.
	hadStorage := len(user.Storage) > 0
	if hadStorage {
		ui.Notef("configured storages: %s (default: %s)", strings.Join(user.StorageNames(), ", "), user.Default)
	}

	first := true
	for {
		added, err := addStorage(ctx, user, first)
		if err != nil {
			return err
		}
		if added {
			first = false
			if user, err = config.LoadUser(); err != nil { // reflect the new storage
				return err
			}
		}
		if !hadStorage || !ui.Interactive() {
			break // first-time setup adds one; non-interactive callers rely on flags
		}
		more, err := ui.Confirm("Add another storage?", false)
		if err != nil {
			return err
		}
		if !more {
			break
		}
	}

	ui.Infof("next: run `notenv init` inside a project to start using this storage")
	return nil
}

// addStorage runs one storage's setup. The structural question comes first:
// a local vault on this machine (the default) or a cloud remote. The local
// path asks nothing further: name, directory, then straight into the
// key ceremony. first seeds name suggestions. Returns false (no error) when
// the user declines to replace an existing storage, so the loop can continue.
func addStorage(ctx context.Context, user *config.User, first bool) (bool, error) {
	isLocal, err := chooseVaultKind()
	if err != nil {
		return false, err
	}
	if isLocal {
		return addLocalStorage(ctx, user, first)
	}
	return addRemoteStorage(ctx, user, first)
}

// chooseVaultKind decides local vs remote: --storage-type first, then the
// prompt, and promptless runs default to local: the zero-account,
// zero-dependency path.
func chooseVaultKind() (bool, error) {
	switch setupStorageType {
	case "local":
		return true, nil
	case "remote":
		return false, nil
	case "":
		// No explicit choice: prompt below, or default to local on a promptless run.
	default:
		return false, fmt.Errorf("invalid --storage-type %q: use \"local\" or \"remote\"", setupStorageType)
	}
	if !ui.Interactive() {
		return true, nil
	}
	choice, err := ui.Select("Where should this vault live?", []ui.Option{
		{Label: "On this machine", Detail: "no accounts; attach a cloud remote later"},
		{Label: "On a cloud remote", Detail: "via rclone: Backblaze B2, S3, SFTP, WebDAV…"},
	})
	if err != nil {
		return false, err
	}
	return choice == 0, nil
}

// localStorageTarget resolves the local vault's name and directory: the
// defaults ("local", the per-name data dir) unless flags or a name conflict
// say otherwise. ok is false (no error) when the user declines a replacement.
func localStorageTarget(user *config.User, first bool) (name, path string, ok bool, err error) {
	name = setupName
	if name == "" {
		name = "local"
	}
	if existing, exists := user.Storage[name]; exists {
		if same, target := sameLocalTarget(existing, name); same {
			// A re-run pointing at the vault that already exists is idempotent:
			// the ceremony below verifies the credential instead of creating.
			// Agents and scripts re-run setup as an "ensure", so this must not
			// require a prompt.
			return name, target, true, nil
		}
		if !ui.Interactive() {
			return "", "", false, fmt.Errorf("storage %q already exists (%s); pass --name to add a separate vault", name, describeEntry(existing))
		}
		if name, ok, err = chooseStorageName(user, first); err != nil || !ok {
			return "", "", ok, err
		}
	}
	path = setupPath
	if path == "" {
		if path, err = config.DefaultVaultDir(name); err != nil {
			return "", "", false, err
		}
	}
	if path, err = config.AbsPath(path); err != nil {
		return "", "", false, err
	}
	return name, path, true, nil
}

// sameLocalTarget reports whether the existing entry is a local vault at the
// directory this setup run would use anyway, returning that resolved path.
func sameLocalTarget(existing config.StorageEntry, name string) (bool, string) {
	if existing.Path == "" {
		return false, ""
	}
	want := setupPath
	if want == "" {
		var err error
		if want, err = config.DefaultVaultDir(name); err != nil {
			return false, ""
		}
	}
	want, err := config.AbsPath(want)
	if err != nil {
		return false, ""
	}
	have, err := config.AbsPath(existing.Path)
	if err != nil {
		return false, ""
	}
	return have == want, want
}

// addLocalStorage creates a local vault: directory, probe, config entry, key
// ceremony. With no name conflict there is nothing to ask: the credential
// prompt inside the ceremony is the whole interaction.
func addLocalStorage(ctx context.Context, user *config.User, first bool) (bool, error) {
	name, path, ok, err := localStorageTarget(user, first)
	if err != nil || !ok {
		return false, err
	}

	// force: localStorageTarget already resolved a fresh name, the same target, or
	// a replacement the user confirmed, so the collision is decided by here.
	confPath, err := config.UpsertStorage(name, config.StorageEntry{Path: path}, setupMakeDefault && first, true)
	if err != nil {
		return false, err
	}
	fresh, err := config.LoadUser()
	if err != nil {
		return false, err
	}
	eff, err := config.ResolveStorage(fresh, name)
	if err != nil {
		return false, err
	}
	store := openStorage(eff)
	if err := store.Preflight(ctx); err != nil {
		return false, err
	}
	if err := ui.Spin("Validating vault directory (write, read back, delete probe)", func() error {
		return store.Probe(ctx)
	}); err != nil {
		return false, err
	}
	ui.Successf("saved storage %q to config (%s)", name, confPath)

	_, created, err := ensureMaster(ctx, store, keyring.DefaultCache(), eff.Scope(), config.DefaultCacheTTL, readOnlyReason(name, false))
	if err != nil {
		return false, err
	}
	if created {
		ui.Successf("vault created at %s", path)
	} else {
		ui.Successf("existing vault at %s: credential verified; this machine can decrypt its secrets", path)
	}
	ui.Notef("this vault is encrypted at rest but lives on this machine only; back up the directory or attach a cloud remote later with `notenv vault copy`")

	if err := offerPromoteDefault(name); err != nil {
		return false, err
	}
	return true, nil
}

// addRemoteStorage runs the rclone-backed setup: remote, base, probe, write,
// and key ceremony.
func addRemoteStorage(ctx context.Context, user *config.User, first bool) (bool, error) {
	if !backend.RcloneInstalled() {
		ui.Failf("rclone is not installed; notenv moves ciphertext to remotes through it")
		ui.Infof("install it with %s and rerun, or use a local vault (no rclone needed)", ui.Bold(installHint()))
		ui.Infof("all options: https://rclone.org/install/")
		return false, errors.New("rclone missing")
	}
	name, ok, err := chooseStorageName(user, first)
	if err != nil || !ok {
		return false, err
	}

	remote, err := chooseRemote(ctx)
	if err != nil {
		return false, err
	}
	base, err := requireInput("Bucket/path for encrypted secrets", "e.g. my-bucket/notenv")
	if err != nil {
		return false, err
	}

	// Fail here, with context, not at the first real `set` days later.
	store := &backend.RcloneStorage{Remote: remote, Base: base}
	if err := ui.Spin("Validating storage: write, read back, delete probe", func() error {
		return store.Probe(ctx)
	}); err != nil {
		ui.Infof("check the credentials and that the bucket/path exists and is writable")
		return false, err
	}

	makeDefault := setupMakeDefault && first
	// force: chooseStorageName already confirmed any replacement above.
	path, err := config.UpsertStorage(name, config.StorageEntry{Remote: remote, Base: base}, makeDefault, true)
	if err != nil {
		return false, err
	}
	ui.Successf("saved storage %q to config (%s)", name, path)

	// Key ceremony (LUKS2-style header): virgin storage gets a master key
	// wrapped under a newly chosen passphrase; existing storage verifies the
	// escrowed passphrase by unlocking a slot, the new-machine recovery flow.
	scope := config.CacheScope(remote, base)
	_, created, err := ensureMaster(ctx, store, keyring.DefaultCache(), scope, config.DefaultCacheTTL, readOnlyReason(name, false))
	if err != nil {
		return false, err
	}
	if created {
		ui.Successf("storage %q initialized", name)
	} else {
		ui.Successf("storage %q: credential verified; this machine can decrypt its secrets", name)
	}

	if err := offerPromoteDefault(name); err != nil {
		return false, err
	}
	return true, nil
}

// describeEntry names a storage entry's target for prompts.
func describeEntry(st config.StorageEntry) string {
	if st.Path != "" {
		return fmt.Sprintf("local vault at %s", st.Path)
	}
	return fmt.Sprintf("remote %q, base %q", st.Remote, st.Base)
}

// offerPromoteDefault asks, when other storages exist, whether this one should
// become the machine default.
func offerPromoteDefault(name string) error {
	cur, _ := config.LoadUser()
	if cur == nil || cur.Default == name || !ui.Interactive() {
		return nil
	}
	promote, err := ui.Confirm(fmt.Sprintf("Make %q the default storage (currently %q)?", name, cur.Default), false)
	if err != nil || !promote {
		return err
	}
	if err := config.SetDefault(name); err != nil {
		return err
	}
	ui.Successf("default storage is now %q", name)
	return nil
}

// chooseStorageName prompts for a valid, non-colliding storage name. ok is
// false (no error) when the user declines to replace an existing one.
func chooseStorageName(user *config.User, first bool) (name string, ok bool, err error) {
	suggested := ""
	if first && len(user.Storage) == 0 {
		suggested = config.DefaultStorage
	}
	if setupName != "" {
		suggested = setupName
	}
	for {
		n, err := ui.Input("Name for this storage", suggested)
		if err != nil {
			return "", false, err
		}
		n = strings.TrimSpace(n)
		if n == "" {
			ui.Warnf("a storage name is required")
			continue
		}
		if !config.ValidStorageName(n) {
			ui.Warnf("storage name %q may use only letters, digits, '-' or '_' (no dots or spaces)", n)
			continue
		}
		if existing, exists := user.Storage[n]; exists {
			replace, err := ui.Confirm(fmt.Sprintf("Storage %q already exists (%s). Replace it?", n, describeEntry(existing)), false)
			if err != nil {
				return "", false, err
			}
			if !replace {
				return "", false, nil
			}
		}
		return n, true, nil
	}
}

// chooseRemote is the tiered remote picker: existing remotes first (the
// rclone-comfortable user's whole flow), curated creation, or the
// `rclone config` escape hatch.
func chooseRemote(ctx context.Context) (string, error) {
	remotes, err := backend.ListRemotes(ctx)
	if err != nil {
		return "", err
	}

	options := make([]ui.Option, 0, len(remotes)+2)
	for _, remote := range remotes {
		options = append(options, ui.Option{Label: remote, Detail: "existing rclone remote"})
	}
	options = append(options,
		ui.Option{Label: "Create a new remote…", Detail: "Backblaze B2, S3-compatible, SFTP, WebDAV"},
		ui.Option{Label: "I'll run `rclone config` myself", Detail: "all ~70 backends, incl. OAuth (Drive, Dropbox…)"},
	)

	choice, err := ui.Select("Where should encrypted secrets live?", options)
	if err != nil {
		return "", err
	}
	switch {
	case choice < len(remotes):
		return remotes[choice], nil
	case choice == len(remotes):
		return createRemote(ctx)
	default:
		return manualRcloneConfig(ctx, remotes)
	}
}

// createRemote drives `rclone config create` for curated key-based
// providers: 2-3 questions in notenv's language instead of rclone's
// 20-question wizard. Each provider's prompts live in its own builder.
func createRemote(ctx context.Context) (string, error) {
	providers := []struct {
		opt         ui.Option
		defaultName string
		build       func() (string, map[string]string, error)
	}{
		{ui.Option{Label: "Backblaze B2", Detail: "application key"}, "notenv-b2", b2Params},
		{ui.Option{Label: "S3-compatible", Detail: "AWS, Cloudflare R2, MinIO…"}, "notenv-s3", s3Params},
		{ui.Option{Label: "SFTP", Detail: "any SSH server"}, "notenv-sftp", sftpParams},
		{ui.Option{Label: "WebDAV", Detail: "Nextcloud, ownCloud…"}, "notenv-webdav", webdavParams},
	}
	opts := make([]ui.Option, len(providers))
	for i, p := range providers {
		opts[i] = p.opt
	}

	choice, err := ui.Select("Provider", opts)
	if err != nil {
		return "", err
	}
	provider := providers[choice]

	name, err := ui.Input("Name for the new remote", provider.defaultName)
	if err != nil {
		return "", err
	}
	kind, params, err := provider.build()
	if err != nil {
		return "", err
	}

	if err := backend.CreateRemote(ctx, name, kind, params); err != nil {
		return "", err
	}
	ui.Successf("created rclone remote %q", name)
	return name, nil
}

func b2Params() (string, map[string]string, error) {
	// hard_delete=false keeps B2's native versioning, which backs Put's
	// retain-prior-versions contract.
	params := map[string]string{"hard_delete": "false"}
	var err error
	if params["account"], err = requireInput("Backblaze keyID", ""); err != nil {
		return "", nil, err
	}
	if params["key"], err = keyring.ReadSecret("applicationKey (hidden): "); err != nil {
		return "", nil, err
	}
	return "b2", params, nil
}

func s3Params() (string, map[string]string, error) {
	params := map[string]string{}
	flavor, err := ui.Select("Which S3", []ui.Option{
		{Label: "AWS S3"},
		{Label: "Cloudflare R2"},
		{Label: "MinIO"},
		{Label: "Other S3-compatible"},
	})
	if err != nil {
		return "", nil, err
	}
	params["provider"] = []string{"AWS", "Cloudflare", "Minio", "Other"}[flavor]
	if params["access_key_id"], err = requireInput("Access key ID", ""); err != nil {
		return "", nil, err
	}
	if params["secret_access_key"], err = keyring.ReadSecret("Secret access key (hidden): "); err != nil {
		return "", nil, err
	}
	// AWS resolves by region; everything else needs an explicit endpoint.
	if flavor == 0 {
		if params["region"], err = requireInput("Region", "e.g. eu-central-1"); err != nil {
			return "", nil, err
		}
	} else if params["endpoint"], err = requireInput("Endpoint URL", ""); err != nil {
		return "", nil, err
	}
	return "s3", params, nil
}

func sftpParams() (string, map[string]string, error) {
	params := map[string]string{}
	var err error
	if params["host"], err = requireInput("Host", ""); err != nil {
		return "", nil, err
	}
	if params["user"], err = ui.Input("User", os.Getenv("USER")); err != nil {
		return "", nil, err
	}
	auth, err := ui.Select("Authentication", []ui.Option{
		{Label: "ssh-agent / default keys", Detail: "no credentials stored"},
		{Label: "password"},
	})
	if err != nil {
		return "", nil, err
	}
	if auth == 1 {
		if params["pass"], err = keyring.ReadSecret("Password (hidden): "); err != nil {
			return "", nil, err
		}
	}
	return "sftp", params, nil
}

func webdavParams() (string, map[string]string, error) {
	params := map[string]string{}
	var err error
	if params["url"], err = requireInput("WebDAV URL", ""); err != nil {
		return "", nil, err
	}
	vendor, err := ui.Select("Server", []ui.Option{
		{Label: "Nextcloud"}, {Label: "ownCloud"}, {Label: "Other"},
	})
	if err != nil {
		return "", nil, err
	}
	params["vendor"] = []string{"nextcloud", "owncloud", "other"}[vendor]
	if params["user"], err = requireInput("User", ""); err != nil {
		return "", nil, err
	}
	if params["pass"], err = keyring.ReadSecret("Password (hidden): "); err != nil {
		return "", nil, err
	}
	return "webdav", params, nil
}

// manualRcloneConfig is the escape hatch: hand the terminal to rclone's
// own wizard, then detect what appeared.
func manualRcloneConfig(ctx context.Context, before []string) (string, error) {
	ui.Infof("dropping you into `rclone config`; create your remote, then quit (q)")
	cmd := exec.CommandContext(ctx, "rclone", "config")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("rclone config: %w", err)
	}

	after, err := backend.ListRemotes(ctx)
	if err != nil {
		return "", err
	}
	var created []string
	for _, remote := range after {
		if !slices.Contains(before, remote) {
			created = append(created, remote)
		}
	}
	switch {
	case len(created) == 1:
		ui.Successf("found new remote %q", created[0])
		return created[0], nil
	case len(after) == 0:
		return "", errors.New("no rclone remotes configured")
	default:
		options := make([]ui.Option, len(after))
		for i, remote := range after {
			options[i] = ui.Option{Label: remote}
		}
		choice, err := ui.Select("Which remote should notenv use?", options)
		if err != nil {
			return "", err
		}
		return after[choice], nil
	}
}

func requireInput(label, hint string) (string, error) {
	for {
		value, err := ui.Input(label, hint)
		if err != nil {
			return "", err
		}
		if value != "" && value != hint {
			return value, nil
		}
	}
}

func installHint() string {
	switch runtime.GOOS {
	case "linux":
		return "your package manager (pacman -S rclone / apt install rclone / dnf install rclone)"
	case "darwin":
		return "brew install rclone"
	case "windows":
		return "winget install Rclone.Rclone"
	default:
		return "your package manager"
	}
}
