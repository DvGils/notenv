package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/DvGils/notenv/internal/backend"
	"github.com/DvGils/notenv/internal/config"
	"github.com/DvGils/notenv/internal/crypto"
	"github.com/DvGils/notenv/internal/secrets"
	"github.com/DvGils/notenv/internal/ui"
)

var (
	exportAll  bool
	exportJSON bool
)

var exportCmd = &cobra.Command{
	Use:   "export",
	Short: "Print secrets as .env to stdout, for leaving notenv (never writes a file)",
	Long: `Print a namespace's secrets (or, with --all, the whole vault) as .env to
standard output, so you can move to another tool or keep a copy. It is the
inverse of import: ` + "`notenv export | notenv import`" + ` round-trips a namespace.

notenv never writes the plaintext to a file itself; it only writes to stdout.
If you want a file, redirect it yourself (` + "`notenv export > .env`" + `), which is
your deliberate act. There is deliberately no --output flag: opening a plaintext
file is exactly what the rest of notenv exists to avoid.

Bulk plaintext egress is gated like ` + "`run --no-mask`" + `: it asks for the vault's
primary passphrase even when the session key is cached, and refuses without a
terminal. A machine identity cannot export.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if exportAll {
			return exportWholeVault(cmd.Context())
		}
		return exportOneNamespace(cmd.Context())
	},
}

// exportOneNamespace exports the project's namespace (or --namespace), gated by
// the primary passphrase, folded under the just-typed master.
func exportOneNamespace(ctx context.Context) error {
	a, err := loadApp(ctx)
	if err != nil {
		return err
	}
	v, err := a.vault()
	if err != nil {
		return err
	}
	mk, slot, header, err := humanUnlock(ctx, v, fmt.Sprintf("exporting the plaintext secrets in namespace %q", a.namespace))
	if err != nil {
		return err
	}
	if err := requirePrimarySlot(header, slot, "export"); err != nil {
		return err
	}
	state, err := foldNamespaceUnder(ctx, a.store, a.namespace, mk, a.machine, header)
	if err != nil {
		return err
	}
	warnExportScrollback()
	return writeExport(os.Stdout, map[string]*secrets.State{a.namespace: state}, exportJSON, false)
}

// exportWholeVault exports every namespace, gated by the primary passphrase. It
// works at the storage level (no project needed): the offboarding path.
func exportWholeVault(ctx context.Context) error {
	store, err := loadHeaderStore()
	if err != nil {
		return err
	}
	ui.Warnf("this prints EVERY secret in the vault as plaintext")
	mk, slot, header, err := humanUnlock(ctx, store, "exporting every secret in the vault")
	if err != nil {
		return err
	}
	if err := requirePrimarySlot(header, slot, "export --all"); err != nil {
		return err
	}
	machine, err := config.MachineID()
	if err != nil {
		return err
	}
	names, err := vaultNamespaces(ctx, store)
	if err != nil {
		return err
	}
	if len(names) == 0 {
		return errors.New("the vault holds no secrets to export")
	}
	out := map[string]*secrets.State{}
	for _, ns := range names {
		state, err := foldNamespaceUnder(ctx, store, ns, mk, machine, header)
		if err != nil {
			return fmt.Errorf("namespace %q: %w", ns, err)
		}
		out[ns] = state
	}
	warnExportScrollback()
	return writeExport(os.Stdout, out, exportJSON, true)
}

// requirePrimarySlot refuses an owner operation unlocked with a non-primary
// slot. Policy, not cryptography (any slot holds the master), but it fits the
// owner nature of bulk export and vault deletion.
func requirePrimarySlot(header *crypto.Header, slot int, action string) error {
	if slot != header.PrimarySlot() {
		return fmt.Errorf("%s requires the vault's primary passphrase; the slot you unlocked is not primary", action)
	}
	return nil
}

func foldNamespaceUnder(ctx context.Context, store backend.Backend, ns string, mk *crypto.MasterKey, machine string, header *crypto.Header) (*secrets.State, error) {
	return secrets.For(store, ns, mk, machine, header.Manifest).Fold(ctx)
}

// vaultNamespaces lists the namespaces a storage holds, from object names alone.
func vaultNamespaces(ctx context.Context, store backend.Backend) ([]string, error) {
	keys, err := store.List(ctx, "")
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var names []string
	for _, k := range keys {
		ns, _, found := strings.Cut(k, "/")
		if !found || seen[ns] {
			continue
		}
		seen[ns] = true
		names = append(names, ns)
	}
	sort.Strings(names)
	return names, nil
}

func warnExportScrollback() {
	if term.IsTerminal(int(os.Stdout.Fd())) {
		ui.Warnf("stdout is a terminal, so these values are now in your scroll-back; redirect to a file or pipe if that matters")
	}
}

func writeExport(w io.Writer, byNS map[string]*secrets.State, asJSON, all bool) error {
	if asJSON {
		return writeExportJSON(w, byNS, all)
	}
	names := make([]string, 0, len(byNS))
	for ns := range byNS {
		names = append(names, ns)
	}
	sort.Strings(names)
	for i, ns := range names {
		if all {
			if i > 0 {
				fmt.Fprintln(w)
			}
			fmt.Fprintf(w, "# namespace: %s\n", ns)
		}
		state := byNS[ns]
		keys := make([]string, 0, len(state.Secrets))
		for k := range state.Secrets {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if d := state.Meta[k].Description; d != "" {
				for line := range strings.SplitSeq(d, "\n") {
					fmt.Fprintf(w, "# %s\n", line)
				}
			}
			fmt.Fprintf(w, "%s=%s\n", k, formatEnvValue(state.Secrets[k]))
		}
	}
	return nil
}

func writeExportJSON(w io.Writer, byNS map[string]*secrets.State, all bool) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if all {
		out := map[string]map[string]string{}
		for ns, st := range byNS {
			out[ns] = st.Secrets
		}
		return enc.Encode(out)
	}
	for _, st := range byNS { // exactly one namespace in the non-all case
		return enc.Encode(st.Secrets)
	}
	return enc.Encode(map[string]string{})
}

// bareEnvValue matches values safe to write unquoted in a .env line: no
// whitespace, quotes, comment char, or backslash. Anything else is
// double-quoted with the escapes the dotenv parser understands.
var bareEnvValue = regexp.MustCompile(`^[A-Za-z0-9._/@:+=,~-]+$`)

func formatEnvValue(v string) string {
	if bareEnvValue.MatchString(v) {
		return v
	}
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\t", `\t`)
	return `"` + r.Replace(v) + `"`
}

func init() {
	exportCmd.Flags().BoolVar(&exportAll, "all", false, "export every namespace in the vault (the offboarding path)")
	exportCmd.Flags().BoolVar(&exportJSON, "json", false, "emit JSON instead of .env")
	rootCmd.AddCommand(exportCmd)
}
