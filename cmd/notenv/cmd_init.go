package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/DvGils/notenv/internal/backend"
	"github.com/DvGils/notenv/internal/config"
	"github.com/DvGils/notenv/internal/contract"
	"github.com/DvGils/notenv/internal/secrets"
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

		cwd, err := os.Getwd()
		if err != nil {
			return err
		}
		// Confirm before scaffolding a project somewhere that almost never is one
		// (the home directory, a filesystem root), so a mistyped `cd` does not
		// quietly turn $HOME into a notenv project.
		if err := guardProjectDir(cwd); err != nil {
			return err
		}

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
		selected, err := selectProjectStorage(user, dir)
		if err != nil {
			return err
		}
		eff, err := config.Resolve(user, cf, dir, selected)
		if err != nil {
			return err
		}
		// init IS the explicit acceptance of the contract's namespace, so it
		// (re)pins without the first-use confirmation other commands run.
		binding, err := config.ReadLocalBinding(dir)
		if err != nil {
			return err
		}
		if binding.Namespace != eff.Namespace {
			if binding.Namespace != "" {
				ui.Notef("re-pinning this checkout from namespace %q to %q", binding.Namespace, eff.Namespace)
			}
			pinNamespace(dir, binding, eff.Namespace)
		}
		store := openStorage(eff)
		var joined bool
		if err := ui.Spin(fmt.Sprintf("Checking for existing secrets (namespace %q)", eff.Namespace), func() error {
			exists, existsErr := secrets.Exists(ctx, store, eff.Namespace)
			joined = exists
			return existsErr
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

// guardProjectDir confirms before scaffolding a project in a place that almost
// never is one: the home directory or a filesystem root. It fires only when
// notenv.toml does not already exist (re-running init in a real project is fine)
// and only interactively (an explicit non-interactive operator is trusted). This
// is where the "I ran it in the wrong directory" footgun is caught, at the one
// command that creates project state.
func guardProjectDir(cwd string) error {
	if _, err := os.Stat(filepath.Join(cwd, contract.FileName)); err == nil {
		return nil // already a project here
	}
	home, _ := os.UserHomeDir()
	if cwd != home && cwd != filepath.Dir(cwd) {
		return nil // not the home dir or a filesystem root: an ordinary location
	}
	if !ui.Interactive() {
		return nil // an explicit non-interactive operator knows what they are doing
	}
	ok, err := ui.Confirm(fmt.Sprintf("%s is not a typical project location. Make it a notenv project (writes %s here)?", cwd, contract.FileName), false)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("aborted; run `notenv init` inside your project directory")
	}
	return nil
}

// writeContract creates notenv.toml if missing. The namespace defaults silently
// to the directory name; --namespace overrides it. No prompt: a first-time user
// does not need to meet the concept to start, and the chosen namespace is shown
// in the success line either way.
func writeContract(cwd string) error {
	path := filepath.Join(cwd, contract.FileName)
	if _, err := os.Stat(path); err == nil {
		ui.Notef("%s already exists, leaving it alone", contract.FileName)
		return nil
	}

	namespace := initNamespace

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
	effective := namespace
	if effective == "" {
		effective = filepath.Base(cwd)
	}
	ui.Successf("wrote ./%s (namespace %q). Commit this; it's the secret *contract*, no values", contract.FileName, effective)
	return nil
}

// selectProjectStorage decides which storage this project uses and persists the
// choice as a local binding when the machine has more than one storage. A
// single storage needs no binding (it resolves on its own). --storage always
// wins and is persisted so future runs need no flag.
func selectProjectStorage(user *config.User, dir string) (string, error) {
	if storageFlag != "" {
		if _, _, err := user.SelectStorage(storageFlag); err != nil {
			return "", err
		}
		if len(user.Storage) > 1 {
			if err := bindProject(dir, storageFlag); err != nil {
				return "", err
			}
		}
		return storageFlag, nil
	}

	names := user.StorageNames()
	switch len(names) {
	case 0:
		path, _ := config.Path()
		return "", fmt.Errorf("no storage configured; run `notenv setup` (config: %s)", path)
	case 1:
		return names[0], nil // sole storage resolves on its own; no binding needed
	}

	if !ui.Interactive() {
		return "", fmt.Errorf("multiple storages configured (%s); pass --storage NAME", strings.Join(names, ", "))
	}
	options := make([]ui.Option, len(names))
	for i, name := range names {
		detail := "configured storage"
		if name == user.Default {
			detail = "configured storage (default)"
		}
		options[i] = ui.Option{Label: name, Detail: detail}
	}
	choice, err := ui.Select("Which storage should this project use?", options)
	if err != nil {
		return "", err
	}
	selected := names[choice]
	if err := bindProject(dir, selected); err != nil {
		return "", err
	}
	return selected, nil
}

// bindProject writes the local storage binding (preserving an existing
// namespace pin) and keeps it out of version control.
func bindProject(dir, name string) error {
	existing, err := config.ReadLocalBinding(dir)
	if err != nil {
		return err
	}
	existing.Storage = name
	path, err := config.WriteLocalBinding(dir, existing)
	if err != nil {
		return err
	}
	ui.Successf("bound this project to storage %q (%s)", name, filepath.Base(path))
	if err := ensureGitignore(dir, config.LocalBindingFile); err != nil {
		ui.Warnf("could not update .gitignore (add %q yourself): %v", config.LocalBindingFile, err)
	}
	return nil
}

// ensureGitignore makes sure entry is ignored in dir/.gitignore, creating the
// file if needed and leaving an existing one otherwise untouched.
func ensureGitignore(dir, entry string) error {
	path := filepath.Join(dir, ".gitignore")
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == entry {
			return nil // already ignored
		}
	}
	var b strings.Builder
	if len(data) > 0 {
		b.Write(data)
		if !strings.HasSuffix(string(data), "\n") {
			b.WriteByte('\n')
		}
		b.WriteByte('\n')
	}
	b.WriteString("# notenv project-local storage binding\n")
	b.WriteString(entry + "\n")
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		return err
	}
	ui.Notef("added %q to .gitignore", entry)
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
	name := storageFlag
	if name == "" {
		name = config.DefaultStorage
	}
	entry := config.StorageEntry{Remote: initRemote, Base: base, Versioned: remoteIsVersioned(ctx, initRemote)}
	path, err := config.UpsertStorage(name, entry, false)
	if err != nil {
		return err
	}
	ui.Successf("wrote storage %q to %s", name, path)
	return nil
}

func init() {
	initCmd.Flags().StringVar(&initRemote, "remote", "", "rclone remote name (non-interactive machine setup)")
	initCmd.Flags().StringVar(&initBase, "base", "", "path within the remote (default \""+config.DefaultBase+"\")")
	initCmd.Flags().StringVar(&initNamespace, "namespace", "", "namespace for this project (default: directory name)")
}
