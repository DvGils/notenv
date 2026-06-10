package main

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/DvGils/notenv/internal/runner"
)

var runRefresh bool

var runCmd = &cobra.Command{
	Use:   "run -- command [args...]",
	Short: "Run a command with secrets injected as environment variables",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		a, err := loadApp()
		if err != nil {
			return err
		}
		secrets, err := a.fetchSecrets(cmd.Context(), runRefresh)
		if err != nil {
			return err
		}
		env, err := a.contract.BuildEnv(os.Environ(), secrets)
		if err != nil {
			return err
		}
		code, err := runner.Run(args, env)
		if err != nil {
			return err
		}
		if code != 0 {
			return &exitCodeError{code: code}
		}
		return nil
	},
}

func init() {
	// Stop flag parsing at the first non-flag arg so `notenv run cmd --flag`
	// passes --flag to cmd, not to notenv.
	runCmd.Flags().SetInterspersed(false)
	runCmd.Flags().BoolVar(&runRefresh, "refresh", false, "bypass the local cache and pull the latest secrets (e.g. after a change on another machine)")
}
