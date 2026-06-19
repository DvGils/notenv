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
	Short: "Print secrets as .env to stdout for backup or offboarding (never writes a file)",
	Long: `Print a namespace's secrets (or, with --all, the whole vault) as .env to
standard output, so you can move to another tool or keep a copy. It is the
inverse of import: ` + "`notenv export | notenv import`" + ` round-trips a namespace.

notenv never writes the plaintext to a file itself; it only writes to stdout.
If you want a file, redirect it yourself (` + "`notenv export > .env`" + `), which is
your deliberate act. There is deliberately no --output flag: opening a plaintext
file is exactly what the rest of notenv exists to avoid.

The output is meant for ` + "`notenv import`" + `, not for ` + "`source`" + `: values are emitted
literally, so a value containing ` + "`$(...)`" + ` or backticks is just data here, but a
POSIX shell would execute it on ` + "`source`" + `. Feed it to ` + "`notenv import`" + ` (or load it
with a parser that does no expansion).

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
// the primary passphrase, read under the just-typed master.
func exportOneNamespace(ctx context.Context) error {
	a, err := loadApp(ctx)
	if err != nil {
		return err
	}
	v, err := a.vault()
	if err != nil {
		return err
	}
	mk, slot, header, err := humanUnlock(ctx, v, a.cacheScope, fmt.Sprintf("exporting the plaintext secrets in namespace %q", a.namespace))
	if err != nil {
		return err
	}
	if err := requirePrimarySlot(header, slot, "export"); err != nil {
		return err
	}
	state, err := readNamespaceUnder(ctx, a.store, a.namespace, mk, header)
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
	mk, slot, header, err := humanUnlock(ctx, store, store.scope, "exporting every secret in the vault")
	if err != nil {
		return err
	}
	if err := requirePrimarySlot(header, slot, "export --all"); err != nil {
		return err
	}
	names := vaultNamespaces(header)
	if len(names) == 0 {
		return errors.New("the vault holds no secrets to export")
	}
	out := map[string]*secrets.State{}
	for _, ns := range names {
		state, err := readNamespaceUnder(ctx, store, ns, mk, header)
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
		return fmt.Errorf("%s requires the vault's primary passphrase; you unlocked a non-primary slot, so re-run and unlock with the primary passphrase", action)
	}
	return nil
}

func readNamespaceUnder(ctx context.Context, store backend.Backend, ns string, mk *crypto.MasterKey, header *crypto.Header) (*secrets.State, error) {
	entry, _ := header.NamespaceEntry(ns)
	return secrets.For(store, ns, mk).Read(ctx, entry)
}

// vaultNamespaces lists the namespaces a vault holds, from the authenticated
// header manifest (not the raw object listing, which would include orphan blobs
// from interrupted writes), sorted.
func vaultNamespaces(header *crypto.Header) []string {
	names := make([]string, 0, len(header.Manifest))
	for ns := range header.Manifest {
		names = append(names, ns)
	}
	sort.Strings(names)
	return names
}

func warnExportScrollback() {
	if term.IsTerminal(int(os.Stdout.Fd())) {
		ui.Warnf("stdout is a terminal, so these values are now in your scrollback; redirect to a file or pipe if that matters")
	}
}

func writeExport(w io.Writer, byNS map[string]*secrets.State, asJSON, all bool) error {
	if asJSON {
		return writeExportJSON(w, byNS, all)
	}
	// A warning at the point a human would see the file: this is for
	// `notenv import`, not for `source`. Values are literal here, but a POSIX
	// shell would execute `$(...)`/backticks in a value on `source`. The dotenv
	// parser ignores these comment lines, so the import round-trip is unaffected.
	fmt.Fprintln(w, "# notenv export: import with `notenv import`. Do NOT `source` this in a shell;")
	fmt.Fprintln(w, "# values are literal and may contain characters a shell would execute.")
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
				// Descriptions are not gated like values, so escape any control byte
				// before it lands in the .env as a comment (the same line-/terminal-
				// injection concern values are escaped for). The \n that separates
				// comment lines is consumed by the split, so each line is single-line.
				for line := range strings.SplitSeq(d, "\n") {
					fmt.Fprintf(w, "# %s\n", sanitizeDisplay(line))
				}
			}
			fmt.Fprintf(w, "%s=%s\n", k, formatEnvValue(state.Secrets[k]))
		}
	}
	return nil
}

// exportSingleJSON is the frozen `export --json` shape for one namespace, and
// exportAllJSON the shape for `export --all --json`. Both carry a version so the
// envelope can grow without breaking consumers (the bare maps they replaced
// could not). secrets values are emitted literally, as in the .env form.
type exportSingleJSON struct {
	Version   int               `json:"version"`
	Namespace string            `json:"namespace"`
	Secrets   map[string]string `json:"secrets"`
}

type exportAllJSON struct {
	Version    int                          `json:"version"`
	Namespaces map[string]map[string]string `json:"namespaces"`
}

func writeExportJSON(w io.Writer, byNS map[string]*secrets.State, all bool) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if all {
		out := exportAllJSON{Version: 1, Namespaces: map[string]map[string]string{}}
		for ns, st := range byNS {
			out.Namespaces[ns] = nonNilSecrets(st.Secrets)
		}
		return enc.Encode(out)
	}
	for ns, st := range byNS { // exactly one namespace in the non-all case
		return enc.Encode(exportSingleJSON{Version: 1, Namespace: ns, Secrets: nonNilSecrets(st.Secrets)})
	}
	return enc.Encode(exportSingleJSON{Version: 1, Secrets: map[string]string{}})
}

// nonNilSecrets returns m, or an empty map when m is nil, so the JSON emits {}
// rather than null for an empty namespace.
func nonNilSecrets(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}

// bareEnvValue matches values safe to write unquoted in a .env line: no
// whitespace, quotes, comment char, or backslash. Anything else is
// double-quoted with the escapes the dotenv parser understands.
var bareEnvValue = regexp.MustCompile(`^[A-Za-z0-9._/@:+=,~-]+$`)

func formatEnvValue(v string) string {
	if bareEnvValue.MatchString(v) {
		return v
	}
	// Values are validated (internal/secrets) to hold no control bytes beyond the
	// newline family, so escaping \n \r \t (plus the quote and backslash) covers
	// everything: no raw control byte is ever written into the .env artifact.
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\r", `\r`, "\t", `\t`)
	return `"` + r.Replace(v) + `"`
}

func init() {
	exportCmd.Flags().BoolVar(&exportAll, "all", false, "export every namespace in the vault (the offboarding path)")
	exportCmd.Flags().BoolVar(&exportJSON, "json", false, "emit JSON instead of .env")
	rootCmd.AddCommand(exportCmd)
}
