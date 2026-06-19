package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "notenv",
	Short: "Encrypted secrets, no infrastructure, no plaintext on disk",
	Long: `notenv replaces .env files: secrets are encrypted on your machine with age,
stored on storage you already own (any rclone remote), and decrypted only
into the environment of the process you run. Plaintext never touches disk.`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

// exitCodeError carries a specific exit code up to main: a child's code
// passed through silently (err nil), or a classified failure whose message
// still must be printed. `run` follows docker's convention so scripts and
// agents can tell whose failure an exit is: 125 = notenv's own failure,
// 126 = the command was found but cannot run, 127 = the command was not
// found; anything else is the child's own exit code.
type exitCodeError struct {
	code int
	err  error
}

func (e *exitCodeError) Error() string {
	if e.err != nil {
		return e.err.Error()
	}
	return fmt.Sprintf("exit code %d", e.code)
}

// printJSON writes one indented JSON document to stdout: the machine-facing
// data surface (everything human-facing goes to stderr, so a --json stdout is
// always exactly one parseable document).
func printJSON(v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(os.Stdout, string(data))
	return err
}

// storageFlag selects which configured storage to use, overriding a project's
// local binding and the machine default. Persistent so every command honors it.
var storageFlag string

// namespaceFlag addresses a vault namespace directly, with no project
// checkout: the contract walk is skipped entirely, so it works from any
// directory (or none, e.g. a headless agent with no checkout).
var namespaceFlag string

func init() {
	rootCmd.Version = versionString()
	rootCmd.SetVersionTemplate("{{.Version}}\n")
	rootCmd.PersistentFlags().StringVar(&storageFlag, "storage", "", "named storage to use (overrides the project binding and default)")
	rootCmd.PersistentFlags().StringVar(&namespaceFlag, "namespace", "", "address a vault namespace directly, ignoring the project binding (works from any directory)")
	rootCmd.AddCommand(setupCmd, initCmd, importCmd, setCmd, unsetCmd, copyCmd, listCmd, inspectCmd, runCmd, handoffCmd, handoffBuildCmd, cacheCmd, credentialCmd, vaultCmd)
}
