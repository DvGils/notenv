package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "notenv",
	Short: "Your .env, encrypted and off your disk, without standing up any infrastructure",
	Long: `notenv replaces .env files: secrets are encrypted on your machine with age,
stored on storage you already own (any rclone remote), and decrypted only
into the environment of the process you run. Plaintext never touches disk.`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

// exitCodeError carries a child process's exit code up to main.
type exitCodeError struct{ code int }

func (e *exitCodeError) Error() string { return fmt.Sprintf("exit code %d", e.code) }

// storageFlag selects which configured storage to use, overriding a project's
// local binding and the machine default. Persistent so every command honors it.
var storageFlag string

func init() {
	rootCmd.Version = versionString()
	rootCmd.SetVersionTemplate("{{.Version}}\n")
	rootCmd.PersistentFlags().StringVar(&storageFlag, "storage", "", "named storage to use (overrides the project binding and default)")
	rootCmd.AddCommand(setupCmd, initCmd, setCmd, listCmd, runCmd, cacheCmd, keyCmd)
}
