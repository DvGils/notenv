package main

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/DvGils/notenv/internal/contract"
	"github.com/DvGils/notenv/internal/dotenv"
	"github.com/DvGils/notenv/internal/secrets"
	"github.com/DvGils/notenv/internal/ui"
)

var importDryRun bool

// importItem is one validated assignment headed for the vault.
type importItem struct {
	key        string // the declared name (what the user sees)
	storageKey string // the namespaced storage key
	value      string
}

var importCmd = &cobra.Command{
	Use:   "import [file]",
	Short: "Import an existing .env file: every value encrypted, every key declared",
	Long: `Parse a dotenv file and store every value encrypted in the vault, declaring
each key in the project contract: one command instead of re-typing secrets.

The whole file is parsed and validated before anything is written, and all
values land in a single recorded write: an import either fully happens or
doesn't. The accepted syntax is the documented dotenv subset: comments,
'export' prefixes, unquoted/single-/double-quoted values (quoted values may
span lines), and never any variable expansion. The file itself is not touched;
once the import succeeds, deleting it is safe, and the point.`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		file := ".env"
		if len(args) == 1 {
			file = args[0]
		}
		f, err := os.Open(file)
		if err != nil {
			return err
		}
		defer f.Close()
		pairs, err := dotenv.Parse(f)
		if err != nil {
			return fmt.Errorf("%s: %w (nothing was imported)", file, err)
		}
		if len(pairs) == 0 {
			return fmt.Errorf("%s holds no assignments; nothing to import", file)
		}

		a, err := loadApp(cmd.Context())
		if err != nil {
			return err
		}
		items, skipped, err := vetImport(a, pairs)
		if err != nil {
			return err
		}
		if importDryRun {
			reportDryRun(file, items, skipped)
			return nil
		}
		return runImport(cmd, a, file, items, skipped)
	},
}

// vetImport validates every assignment up front (all offenders reported
// together, nothing written), applies last-wins to duplicate keys, and sets
// aside empty values: `set` refuses those, so import does too.
func vetImport(a *app, pairs []dotenv.Pair) (items []importItem, skipped []string, err error) {
	var invalid []string
	last := map[string]dotenv.Pair{}
	var order []string
	for _, p := range pairs {
		if !contract.ValidEnvName(p.Key) {
			invalid = append(invalid, fmt.Sprintf("%s (line %d)", p.Key, p.Line))
			continue
		}
		if _, seen := last[p.Key]; !seen {
			order = append(order, p.Key)
		}
		last[p.Key] = p
	}
	if len(invalid) > 0 {
		return nil, nil, fmt.Errorf("not valid environment variable names: %s (nothing was imported)", strings.Join(invalid, ", "))
	}
	for _, key := range order {
		p := last[key]
		if p.Value == "" {
			skipped = append(skipped, key)
			continue
		}
		items = append(items, importItem{key: key, storageKey: a.storageKey(key), value: p.Value})
	}
	sort.Strings(skipped)
	return items, skipped, nil
}

func reportDryRun(file string, items []importItem, skipped []string) {
	ui.Notef("dry run: %s parses cleanly; %d secrets would be imported", file, len(items))
	for _, it := range items {
		ui.Infof("  %s", it.key)
	}
	for _, key := range skipped {
		ui.Warnf("  %s would be skipped (empty value)", key)
	}
}

func runImport(cmd *cobra.Command, a *app, file string, items []importItem, skipped []string) error {
	// --dry-run never reaches here, so a read-only storage still vets a file.
	if err := a.requireWritable("import secrets"); err != nil {
		return err
	}
	if len(items) == 0 {
		return errors.New("every assignment was empty; nothing to import")
	}
	ctx := cmd.Context()
	state, view, err := a.foldState(ctx)
	if err != nil {
		return err
	}
	updatedKeys := 0
	for _, it := range items {
		if _, present := state.Secrets[it.storageKey]; present {
			updatedKeys++
		}
	}

	var updated *secrets.State
	if err := ui.Spin(fmt.Sprintf("Encrypting and recording %d secrets", len(items)), func() error {
		var aerr error
		updated, aerr = a.appendGuardedBatch(ctx, view, state, items)
		return aerr
	}); err != nil {
		return err
	}
	a.cacheFolded(view.mk, updated)
	reportConflicts(updated.Conflicts)
	a.maybeCompact(ctx, view.mk, state.SegmentCount()+len(items)-1)

	if a.contract != nil {
		for _, it := range items {
			if _, declared := a.contract.Secrets[it.key]; declared {
				continue
			}
			if err := contract.Declare(a.contractPath, it.key); err != nil {
				ui.Warnf("could not declare %s in %s: %v; add it by hand or `notenv run` won't inject it", it.key, contract.FileName, err)
			}
		}
	}
	for _, key := range skipped {
		ui.Warnf("skipped %s: empty value", key)
	}
	if a.contract != nil {
		ui.Successf("imported %d secrets into namespace %q (%d new, %d updated); keys declared in %s", len(items), a.namespace, len(items)-updatedKeys, updatedKeys, contract.FileName)
	} else {
		ui.Successf("imported %d secrets into namespace %q (%d new, %d updated)", len(items), a.namespace, len(items)-updatedKeys, updatedKeys)
	}
	ui.Notef("every value is now encrypted in your vault, so you can delete %s", file)
	return nil
}

func init() {
	importCmd.Flags().BoolVar(&importDryRun, "dry-run", false, "parse and validate only; show what would be imported (names, never values)")
}
