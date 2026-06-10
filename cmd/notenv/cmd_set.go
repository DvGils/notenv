package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/DvGils/notenv/internal/contract"
	"github.com/DvGils/notenv/internal/keyring"
	"github.com/DvGils/notenv/internal/ui"
)

var setStdin bool

var setCmd = &cobra.Command{
	Use:   "set KEY",
	Short: "Set a secret value (prompted hidden, encrypted, uploaded; never echoed, never on disk)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		key := args[0]
		a, err := loadApp()
		if err != nil {
			return err
		}

		// Master key first: on virgin storage this runs the header
		// ceremony (choose passphrase + escrow warning) before anything
		// else happens.
		ctx := cmd.Context()
		mk, err := a.master(ctx)
		if err != nil {
			return err
		}

		// Fetch fresh (bypass the read cache): a read-modify-write must see
		// current storage state, not a possibly-stale local copy.
		secrets := map[string]string{}
		ciphertext, found, err := a.getBlob(ctx, false, false)
		if err != nil {
			return err
		}
		if found {
			plaintext, err := mk.Decrypt(ciphertext)
			if err != nil {
				return err
			}
			if secrets, err = decodePayload(plaintext); err != nil {
				return err
			}
		}

		value, err := readValue(key)
		if err != nil {
			return err
		}
		secrets[a.contract.StorageKey(key)] = value

		plaintext, err := encodePayload(secrets)
		if err != nil {
			return err
		}
		sealed, err := mk.Encrypt(plaintext)
		if err != nil {
			return err
		}
		if err := ui.Spin("Uploading encrypted blob", func() error {
			return a.store.Put(ctx, a.namespace, sealed)
		}); err != nil {
			return err
		}
		// Refresh the local cache with the freshly written blob, so the next
		// `run` on this machine is instant and coherent.
		_ = a.blobs.Put(a.cacheScope, a.namespace, sealed)
		ui.Successf("%s set in namespace %q", key, a.namespace)

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
