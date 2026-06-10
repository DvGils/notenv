package main

import (
	"github.com/spf13/cobra"

	"github.com/DvGils/notenv/internal/blobcache"
	"github.com/DvGils/notenv/internal/ui"
)

var cacheCmd = &cobra.Command{
	Use:   "cache",
	Short: "Manage the local ciphertext cache",
}

// cacheClearCmd wipes all cached blobs on this machine. Deliberately needs
// no project/config; it works anywhere (e.g. before handing off a machine).
var cacheClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "Remove all locally cached ciphertext blobs on this machine",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		n, err := blobcache.Clear()
		if err != nil {
			return err
		}
		ui.Successf("cleared %d cached blob(s)", n)
		return nil
	},
}

func init() {
	cacheCmd.AddCommand(cacheClearCmd)
}
