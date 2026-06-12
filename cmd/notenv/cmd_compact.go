package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/DvGils/notenv/internal/crypto"
	"github.com/DvGils/notenv/internal/ui"
)

var compactCmd = &cobra.Command{
	Use:   "compact",
	Short: "Collapse a namespace's change log into a single snapshot",
	Long: `Fold a namespace's accumulated write segments into one snapshot and remove
them, so cold reads stay fast. Run it occasionally on a busy namespace.

Safe to run alongside other machines writing secrets; their writes are never
lost. Avoid running two compactions against the same namespace at once.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		a, err := loadApp(cmd.Context())
		if err != nil {
			return err
		}
		if err := a.requireWritable("compact the namespace (it rewrites and deletes objects)"); err != nil {
			return err
		}
		ctx := cmd.Context()
		if _, err := a.withMaster(ctx, func(mk *crypto.MasterKey) error {
			return ui.Spin(fmt.Sprintf("Compacting namespace %q", a.namespace), func() error {
				return a.compactNamespace(ctx, mk)
			})
		}); err != nil {
			return err
		}
		ui.Successf("namespace %q compacted", a.namespace)
		return nil
	},
}
