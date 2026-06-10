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

func init() {
	rootCmd.Version = versionString()
	rootCmd.SetVersionTemplate("{{.Version}}\n")
	rootCmd.AddCommand(setupCmd, initCmd, setCmd, listCmd, runCmd, cacheCmd)
}
