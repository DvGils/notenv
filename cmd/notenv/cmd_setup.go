package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"slices"

	"github.com/spf13/cobra"

	"github.com/DvGils/notenv/internal/backend"
	"github.com/DvGils/notenv/internal/config"
	"github.com/DvGils/notenv/internal/keyring"
	"github.com/DvGils/notenv/internal/ui"
)

var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Set up this machine: pick or create a storage remote, write the user config",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return setupFlow(cmd.Context())
	},
}

// setupFlow is the machine installer. Also chained into by
// `notenv init` on an unconfigured machine. Storage-only by design: the
// passphrase doesn't exist until the first `set` of a namespace creates it.
func setupFlow(ctx context.Context) error {
	if config.Exists() {
		user, err := config.LoadUser()
		if err != nil {
			return err
		}
		ui.Notef("this machine is already set up: remote %q, base %q",
			user.Storage.Remote, user.Storage.Base)
		redo, err := ui.Confirm("Reconfigure?", false)
		if err != nil {
			return err
		}
		if !redo {
			return nil
		}
	}

	// Tier 0: no rclone at all.
	if !backend.RcloneInstalled() {
		ui.Failf("rclone is not installed; notenv moves ciphertext through it")
		ui.Infof("install it with %s, then rerun `notenv setup`", ui.Bold(installHint()))
		ui.Infof("all options: https://rclone.org/install/")
		return errors.New("rclone missing")
	}

	remote, err := chooseRemote(ctx)
	if err != nil {
		return err
	}

	base, err := requireInput("Bucket/path for encrypted blobs", "e.g. my-bucket/notenv")
	if err != nil {
		return err
	}

	// Fail here, with context, not at the first real `set` days later.
	versioned := remoteIsVersioned(ctx, remote)
	store := &backend.RcloneStorage{Remote: remote, Base: base, Versioned: versioned}
	if err := ui.Spin("Validating storage: write, read back, delete probe", func() error {
		return store.Probe(ctx)
	}); err != nil {
		ui.Infof("check the credentials and that the bucket/path exists and is writable")
		return err
	}

	path, err := config.WriteUser(remote, base, versioned)
	if err != nil {
		return err
	}
	ui.Successf("wrote %s", path)

	// Key ceremony (LUKS2-style header): virgin storage gets a master key
	// wrapped under a newly chosen passphrase; existing storage verifies
	// the escrowed passphrase by unlocking a slot, which is exactly the
	// new-machine recovery flow.
	scope := config.CacheScope(remote, base)
	_, created, err := ensureMaster(ctx, store, keyring.DefaultCache(), scope, config.DefaultCacheTTL)
	if err != nil {
		return err
	}
	if created {
		ui.Successf("storage initialized: master key generated, locked by your passphrase")
	} else {
		ui.Successf("passphrase verified; this machine can decrypt your secrets")
	}

	ui.Infof("next: `notenv init` inside a project, then `notenv set KEY`")
	return nil
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
// 20-question wizard.
func createRemote(ctx context.Context) (string, error) {
	providers := []ui.Option{
		{Label: "Backblaze B2", Detail: "application key"},
		{Label: "S3-compatible", Detail: "AWS, Cloudflare R2, MinIO…"},
		{Label: "SFTP", Detail: "any SSH server"},
		{Label: "WebDAV", Detail: "Nextcloud, ownCloud…"},
	}
	provider, err := ui.Select("Provider", providers)
	if err != nil {
		return "", err
	}

	defaults := []string{"notenv-b2", "notenv-s3", "notenv-sftp", "notenv-webdav"}
	name, err := ui.Input("Name for the new remote", defaults[provider])
	if err != nil {
		return "", err
	}

	var kind string
	params := map[string]string{}
	switch provider {
	case 0: // Backblaze B2
		kind = "b2"
		if params["account"], err = requireInput("Backblaze keyID", ""); err != nil {
			return "", err
		}
		if params["key"], err = keyring.ReadSecret("applicationKey (hidden): "); err != nil {
			return "", err
		}
		// Keep B2's native versioning: it's what backs Put's
		// retain-prior-versions contract.
		params["hard_delete"] = "false"
	case 1: // S3-compatible
		kind = "s3"
		flavors := []ui.Option{
			{Label: "AWS S3"},
			{Label: "Cloudflare R2"},
			{Label: "MinIO"},
			{Label: "Other S3-compatible"},
		}
		flavor, err := ui.Select("Which S3", flavors)
		if err != nil {
			return "", err
		}
		params["provider"] = []string{"AWS", "Cloudflare", "Minio", "Other"}[flavor]
		if params["access_key_id"], err = requireInput("Access key ID", ""); err != nil {
			return "", err
		}
		if params["secret_access_key"], err = keyring.ReadSecret("Secret access key (hidden): "); err != nil {
			return "", err
		}
		if flavor == 0 {
			if params["region"], err = requireInput("Region", "e.g. eu-central-1"); err != nil {
				return "", err
			}
		} else {
			if params["endpoint"], err = requireInput("Endpoint URL", ""); err != nil {
				return "", err
			}
		}
	case 2: // SFTP
		kind = "sftp"
		if params["host"], err = requireInput("Host", ""); err != nil {
			return "", err
		}
		if params["user"], err = ui.Input("User", os.Getenv("USER")); err != nil {
			return "", err
		}
		auth, err := ui.Select("Authentication", []ui.Option{
			{Label: "ssh-agent / default keys", Detail: "no credentials stored"},
			{Label: "password"},
		})
		if err != nil {
			return "", err
		}
		if auth == 1 {
			if params["pass"], err = keyring.ReadSecret("Password (hidden): "); err != nil {
				return "", err
			}
		}
	case 3: // WebDAV
		kind = "webdav"
		if params["url"], err = requireInput("WebDAV URL", ""); err != nil {
			return "", err
		}
		vendor, err := ui.Select("Server", []ui.Option{
			{Label: "Nextcloud"}, {Label: "ownCloud"}, {Label: "Other"},
		})
		if err != nil {
			return "", err
		}
		params["vendor"] = []string{"nextcloud", "owncloud", "other"}[vendor]
		if params["user"], err = requireInput("User", ""); err != nil {
			return "", err
		}
		if params["pass"], err = keyring.ReadSecret("Password (hidden): "); err != nil {
			return "", err
		}
	}

	if err := backend.CreateRemote(ctx, name, kind, params); err != nil {
		return "", err
	}
	ui.Successf("created rclone remote %q", name)
	return name, nil
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

// remoteIsVersioned: B2 retains every overwritten version natively, so the
// .prev backup copy is redundant there. Conservative for everything else
// (S3 versioning is a bucket-level opt-in that is not visible from here).
// Local config lookup only: failure just means the safe default.
func remoteIsVersioned(ctx context.Context, remote string) bool {
	kind, err := backend.RemoteType(ctx, remote)
	return err == nil && kind == "b2"
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
