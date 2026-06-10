package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/DvGils/notenv/internal/backend"
	"github.com/DvGils/notenv/internal/config"
	"github.com/DvGils/notenv/internal/contract"
	"github.com/DvGils/notenv/internal/ui"
)

var (
	initRemote    string
	initBase      string
	initNamespace string
)

const contractTemplate = `# notenv contract (committed). Declares which env vars this project needs.
# It contains NO secret values; those live encrypted on your storage remote.
%s
[secrets]
# DATABASE_URL = { required = true }
# SENTRY_DSN   = { required = false }
# STRIPE_KEY   = { name = "stripe-secret-key" }   # override the storage key name
`

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Set up notenv for this project (chains into machine setup on first run)",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		// Machine not set up yet: chain into the setup flow, so the
		// first-ever init is still one command end to end. Flags keep the
		// non-interactive path for scripts/CI.
		if !config.Exists() {
			if initRemote != "" {
				if err := writeUserConfigFromFlags(ctx); err != nil {
					return err
				}
			} else if ui.Interactive() {
				ui.Infof("this machine isn't set up for notenv yet; running setup first")
				if err := setupFlow(ctx); err != nil {
					return err
				}
			} else {
				return errors.New("machine not set up: run `notenv setup`, or pass --remote/--base")
			}
		}

		cwd, err := os.Getwd()
		if err != nil {
			return err
		}
		if err := writeContract(cwd); err != nil {
			return err
		}

		// Join detection: an existing blob for this namespace means a
		// new-machine join, with nothing left to do but run.
		user, err := config.LoadUser()
		if err != nil {
			return err
		}
		cf, dir, err := contract.Find(cwd)
		if err != nil {
			return err
		}
		eff, err := config.Resolve(user, cf, dir)
		if err != nil {
			return err
		}
		store := &backend.RcloneStorage{Remote: eff.Remote, Base: eff.Base, Versioned: eff.Versioned}
		var joined bool
		if err := ui.Spin(fmt.Sprintf("Checking for existing secrets (namespace %q)", eff.Namespace), func() error {
			_, getErr := store.Get(ctx, eff.Namespace)
			if getErr == nil {
				joined = true
				return nil
			}
			if errors.Is(getErr, backend.ErrNotFound) {
				return nil
			}
			return getErr
		}); err != nil {
			return err
		}
		if joined {
			ui.Successf("found existing secrets for namespace %q; you're ready: `notenv run -- <cmd>` (it will ask for your escrowed passphrase)", eff.Namespace)
			return nil
		}

		ui.Infof("next: `notenv set KEY` stores the value encrypted and declares the key in %s", contract.FileName)
		return nil
	},
}

// writeContract creates notenv.toml if missing, prompting for the
// namespace when interactive (default: directory name).
func writeContract(cwd string) error {
	path := filepath.Join(cwd, contract.FileName)
	if _, err := os.Stat(path); err == nil {
		ui.Notef("%s already exists, leaving it alone", contract.FileName)
		return nil
	}

	namespace := initNamespace
	if namespace == "" && ui.Interactive() {
		var err error
		if namespace, err = ui.Input("Namespace for this project", filepath.Base(cwd)); err != nil {
			return err
		}
	}

	nsLine := fmt.Sprintf("\n# namespace = %q   # default: this directory's name\n", filepath.Base(cwd))
	if namespace != "" {
		if !contract.NamespaceName.MatchString(namespace) {
			return fmt.Errorf("namespace %q must match %s", namespace, contract.NamespaceName)
		}
		// Only write an explicit namespace line when it differs from the
		// directory-name default; otherwise leave the default commented out.
		if namespace != filepath.Base(cwd) {
			nsLine = fmt.Sprintf("\nnamespace = %q\n", namespace)
		}
	}

	if err := os.WriteFile(path, fmt.Appendf(nil, contractTemplate, nsLine), 0o644); err != nil {
		return err
	}
	ui.Successf("wrote ./%s. Commit this; it's the secret *contract*, no values", contract.FileName)
	return nil
}

// writeUserConfigFromFlags is init's non-interactive machine setup.
func writeUserConfigFromFlags(ctx context.Context) error {
	base := initBase
	if base == "" {
		base = config.DefaultBase
	}
	store := &backend.RcloneStorage{Remote: initRemote, Base: base}
	if err := store.Preflight(ctx); err != nil {
		return err
	}
	if err := store.Probe(ctx); err != nil {
		return err
	}
	path, err := config.WriteUser(initRemote, base, remoteIsVersioned(ctx, initRemote))
	if err != nil {
		return err
	}
	ui.Successf("wrote %s", path)
	return nil
}

func init() {
	initCmd.Flags().StringVar(&initRemote, "remote", "", "rclone remote name (non-interactive machine setup)")
	initCmd.Flags().StringVar(&initBase, "base", "", "path within the remote (default \""+config.DefaultBase+"\")")
	initCmd.Flags().StringVar(&initNamespace, "namespace", "", "namespace for this project (default: directory name)")
}
