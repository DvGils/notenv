package main

import "github.com/spf13/cobra"

var secretCmd = &cobra.Command{
	Use:   "secret",
	Short: "Set, inspect, and manage the secrets in a namespace",
	Long: `A secret is one encrypted key/value in the selected namespace (chosen by your
project's notenv.toml or --namespace). These commands operate on the secrets
inside that namespace.

To see what a namespace holds, use "notenv namespace inspect"; to run a command
with the secrets injected, use "notenv run".`,
}

func init() {
	secretCmd.AddCommand(secretSetCmd, secretUnsetCmd, secretUpdateCmd, secretCopyCmd)
	rootCmd.AddCommand(secretCmd)
}
