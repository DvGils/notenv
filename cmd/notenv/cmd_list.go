package main

import (
	"fmt"
	"sort"

	"github.com/spf13/cobra"
)

var listRefresh bool

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List stored secret names (never values)",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		a, err := loadApp(cmd.Context())
		if err != nil {
			return err
		}
		secrets, err := a.fetchSecrets(cmd.Context(), listRefresh)
		if err != nil {
			return err
		}
		names := make([]string, 0, len(secrets))
		for name := range secrets {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			fmt.Println(name)
		}
		return nil
	},
}

func init() {
	listCmd.Flags().BoolVar(&listRefresh, "refresh", false, "bypass the local cache and pull the latest secrets")
}
