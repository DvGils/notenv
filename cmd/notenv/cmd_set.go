package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/DvGils/notenv/internal/contract"
	"github.com/DvGils/notenv/internal/keyring"
	"github.com/DvGils/notenv/internal/secrets"
	"github.com/DvGils/notenv/internal/ui"
)

var (
	setStdin       bool
	setDescription string
)

var setCmd = &cobra.Command{
	Use:   "set KEY",
	Short: "Set a secret value (entered hidden, encrypted, never echoed or written to disk)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		key := args[0]
		// Validate before any work: an invalid name can never be injected
		// (BuildEnv only iterates declared secrets, and Declare would reject
		// it), so it must not reach storage as an orphan blob entry.
		if !contract.ValidEnvName(key) {
			return fmt.Errorf("%q is not a valid environment variable name (use letters, digits, and underscores; cannot start with a digit)", key)
		}
		a, err := loadApp(cmd.Context())
		if err != nil {
			return err
		}
		if err := a.requireWritable("set a secret"); err != nil {
			return err
		}

		ctx := cmd.Context()

		// Unlock and verify the header (the master ceremony runs here on virgin
		// storage). The write re-reads the current blob under the header swap, so
		// no separate read of the namespace is needed.
		view, err := a.unlockView(ctx)
		if err != nil {
			return err
		}

		value, err := readValue(key)
		if err != nil {
			return err
		}

		if err := secrets.ValidateValue(value); err != nil {
			return fmt.Errorf("%s: %w", key, err)
		}

		storageKey := a.storageKey(key)
		// A set without --description re-states the value, not what the key means:
		// the existing description rides along (KeepDescription carries the live
		// one). --description (including "") sets it explicitly.
		w := secrets.Write{Key: storageKey, Value: value, TS: time.Now().Unix()}
		if cmd.Flags().Changed("description") {
			w.Description = setDescription
		} else {
			w.KeepDescription = true
		}

		var updated *secrets.State
		if err := ui.Spin("Uploading encrypted blob", func() error {
			var aerr error
			updated, aerr = a.writeNamespace(ctx, view, []secrets.Write{w})
			return aerr
		}); err != nil {
			return err
		}
		// Refresh the local cache with the new state, so the next `run` on this
		// machine is instant and coherent.
		a.cacheState(view.mk, updated)
		ui.Successf("%s set in namespace %q", key, a.namespace)

		// Convenience: keep the committed contract in sync with reality.
		// Projectless writes have no contract to sync.
		if a.contract != nil {
			if _, declared := a.contract.Secrets[key]; !declared {
				if err := contract.Declare(a.contractPath, key); err != nil {
					ui.Warnf("could not declare %s in %s: %v; add it by hand or `notenv run` won't inject it", key, contract.FileName, err)
				} else {
					ui.Successf("declared %s in %s (required); commit it", key, contract.FileName)
				}
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
		value := trimStdinTerminator(string(raw))
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

// trimStdinTerminator removes exactly one trailing line terminator, an "\r\n"
// pair or a lone "\n", from a value piped in via --stdin. Stripping the pair as
// a unit keeps a value from a CRLF source ("secret\r\n") from storing a hidden
// trailing "\r"; an interior "\r" in a multiline value, or a deliberate bare
// trailing "\r", is left untouched.
func trimStdinTerminator(s string) string {
	switch {
	case strings.HasSuffix(s, "\r\n"):
		return s[:len(s)-2]
	case strings.HasSuffix(s, "\n"):
		return s[:len(s)-1]
	}
	return s
}

func init() {
	setCmd.Flags().BoolVar(&setStdin, "stdin", false, "read the value from stdin (for multiline or piped values)")
	setCmd.Flags().StringVar(&setDescription, "description", "", "what this secret is and how to use it, shown by `list` (omit to keep the current one; \"\" clears)")
}
