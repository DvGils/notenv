package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/DvGils/notenv/internal/config"
	"github.com/DvGils/notenv/internal/contract"
	"github.com/DvGils/notenv/internal/keyring"
	"github.com/DvGils/notenv/internal/secrets"
	"github.com/DvGils/notenv/internal/ui"
)

var setStdin bool

var setCmd = &cobra.Command{
	Use:   "set KEY",
	Short: "Set a secret value (prompted hidden, encrypted, uploaded; never echoed, never on disk)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		key := args[0]
		// Validate before any work: an invalid name can never be injected
		// (BuildEnv only iterates declared secrets, and Declare would reject
		// it), so it must not reach storage as an orphan blob entry.
		if !contract.ValidEnvName(key) {
			return fmt.Errorf("%q is not a valid environment variable name", key)
		}
		a, err := loadApp(cmd.Context())
		if err != nil {
			return err
		}

		ctx := cmd.Context()

		// Fold fresh from storage (the master ceremony runs here on virgin
		// storage). A new write appends a segment, so it never has to win a
		// read-modify-write race against another machine.
		state, mk, err := a.foldState(ctx)
		if err != nil {
			return err
		}

		value, err := readValue(key)
		if err != nil {
			return err
		}
		seq, err := config.NextSeq(a.cacheScope, a.namespace)
		if err != nil {
			return err
		}

		var updated *secrets.State
		if err := ui.Spin("Uploading encrypted segment", func() error {
			var aerr error
			updated, aerr = a.appendGuarded(ctx, mk, state, seq, a.contract.StorageKey(key), value, false)
			return aerr
		}); err != nil {
			return err
		}
		// Refresh the local cache with the new folded state, so the next `run`
		// on this machine is instant and coherent.
		a.cacheFolded(mk, updated.Secrets)
		ui.Successf("%s set in namespace %q", key, a.namespace)
		// Report from the post-write state: this write settles its own key's
		// conflict, so only genuinely unresolved ones surface.
		reportConflicts(updated.Conflicts)
		a.maybeCompact(ctx, mk, state.SegmentCount())

		// Convenience: keep the committed contract in sync with reality.
		if _, declared := a.contract.Secrets[key]; !declared {
			if err := contract.Declare(a.contractPath, key); err != nil {
				ui.Warnf("could not declare %s in %s: %v; add it by hand or `notenv run` won't inject it", key, contract.FileName, err)
			} else {
				ui.Successf("declared %s in %s (required); commit it", key, contract.FileName)
			}
		}
		return nil
	},
}

func readValue(key string) (string, error) {
	if setStdin {
		raw, err := io.ReadAll(os.Stdin)
		if err != nil {
			return "", err
		}
		value := strings.TrimSuffix(string(raw), "\n")
		if value == "" {
			return "", errors.New("empty value on stdin")
		}
		return value, nil
	}
	value, err := keyring.ReadSecret(fmt.Sprintf("Value for %s: ", key))
	if err != nil {
		return "", err
	}
	if value == "" {
		return "", errors.New("empty value")
	}
	return value, nil
}

func init() {
	setCmd.Flags().BoolVar(&setStdin, "stdin", false, "read the value from stdin (for multiline or piped values)")
}
