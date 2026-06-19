package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"
	"unicode"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/DvGils/notenv/internal/secrets"
)

var (
	listRefresh bool
	listJSON    bool
	listSalvage bool
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List stored secret names with their descriptions (never values)",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		a, err := loadApp(cmd.Context())
		if err != nil {
			return err
		}
		a.salvage = listSalvage
		res, err := a.fetchSecrets(cmd.Context(), listRefresh, true)
		if err != nil {
			return err
		}
		names := make([]string, 0, len(res.secrets))
		for name := range res.secrets {
			names = append(names, name)
		}
		sort.Strings(names)
		if listJSON {
			return printJSON(listOutput{Version: 1, Namespace: a.namespace, Secrets: listedSecrets(names, res.meta)})
		}
		// Piped output is the stable scripting surface: one name per line,
		// nothing else. The table with descriptions is for human eyes only.
		if !term.IsTerminal(int(os.Stdout.Fd())) {
			for _, name := range names {
				fmt.Println(name)
			}
			return nil
		}
		printSecretsTable(names, res.meta)
		return nil
	},
}

// listOutput is the frozen shape of `list --json`. Values never appear; the
// metadata fields are omitted when absent so consumers need no sentinel
// handling. Extensions are additive fields only.
type listOutput struct {
	Version   int            `json:"version"`
	Namespace string         `json:"namespace"`
	Secrets   []listedSecret `json:"secrets"`
}

type listedSecret struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	// Modified is the winning write's advisory wall-clock time (RFC 3339,
	// UTC); absent when the write predates timestamps. Clocks lie: it is
	// informational, never an ordering claim.
	Modified string `json:"modified,omitempty"`
}

func listedSecrets(names []string, meta map[string]secrets.Meta) []listedSecret {
	out := make([]listedSecret, 0, len(names))
	for _, name := range names {
		m := meta[name]
		s := listedSecret{Name: name, Description: m.Description}
		if m.TS != 0 {
			s.Modified = time.Unix(m.TS, 0).UTC().Format(time.RFC3339)
		}
		out = append(out, s)
	}
	return out
}

func printSecretsTable(names []string, meta map[string]secrets.Meta) {
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tDESCRIPTION\tMODIFIED")
	for _, name := range names {
		m := meta[name]
		fmt.Fprintf(w, "%s\t%s\t%s\n", name, dashIfEmpty(sanitizeDisplay(m.Description)), modifiedLabel(m.TS))
	}
	_ = w.Flush()
}

// sanitizeDisplay renders user-authored text (a description) safe for a terminal
// and for the tab-separated list/inspect output. Descriptions are stored
// faithfully (see internal/secrets) and are not gated like values, so they may
// carry control bytes; rendering each as a visible escape stops a description
// from breaking the column layout or injecting a terminal escape sequence when
// printed (e.g. a teammate's booby-trapped description shown by `notenv list`).
// Structured (--json) output is left faithful: encoding/json escapes control
// bytes in its own text, and a machine consumer should receive the real value.
func sanitizeDisplay(s string) string {
	if !strings.ContainsFunc(s, unicode.IsControl) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if unicode.IsControl(r) {
				fmt.Fprintf(&b, `\x%02x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	return b.String()
}

// modifiedLabel renders a write's advisory wall-clock timestamp for humans; a
// zero TS is a write that predates timestamps.
func modifiedLabel(ts int64) string {
	if ts == 0 {
		return "-"
	}
	return time.Unix(ts, 0).Local().Format("2006-01-02 15:04")
}

func init() {
	listCmd.Flags().BoolVar(&listRefresh, "refresh", false, "bypass the local cache and pull the latest secrets")
	listCmd.Flags().BoolVar(&listJSON, "json", false, "machine-readable output: names, descriptions, modified times (never values)")
	listCmd.Flags().BoolVar(&listSalvage, "skip-corrupt", false, "use the previous backup when the current data is missing or corrupt, instead of stopping (the most recent change may be lost; notenv will tell you if so)")
}
