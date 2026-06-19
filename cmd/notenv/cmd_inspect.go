package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/DvGils/notenv/internal/backend"
	"github.com/DvGils/notenv/internal/config"
	"github.com/DvGils/notenv/internal/crypto"
	"github.com/DvGils/notenv/internal/secrets"
)

var (
	inspectAll  bool
	inspectJSON bool
)

var inspectCmd = &cobra.Command{
	Use:   "inspect [KEY]",
	Short: "Show metadata about a secret, a namespace, or the whole vault (never values)",
	Long: `Report on what a vault holds without revealing any secret value.

  notenv inspect KEY     one secret: whether it exists, its length, description,
                         and when it last changed (exit 1 if it does not exist).
  notenv inspect         the current namespace: its secrets with lengths, and a count.
  notenv inspect --all   the whole vault: its namespaces, id, revision, and storage.

The namespace and vault are selected the usual way (the project, or --namespace /
--storage). No value is ever printed. --all reads only the authenticated header, so
it needs no passphrase.`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if inspectAll {
			if len(args) > 0 {
				return errors.New("--all inspects the whole vault; do not also name a key")
			}
			return inspectVault(cmd.Context())
		}
		if len(args) == 1 {
			return inspectKey(cmd.Context(), args[0])
		}
		return inspectNamespace(cmd.Context())
	},
}

// keyInspect is the frozen `inspect KEY --json` shape; a value never appears.
// When the key is absent only namespace/name/exists are present.
type keyInspect struct {
	Namespace   string `json:"namespace"`
	Name        string `json:"name"`
	Exists      bool   `json:"exists"`
	Length      int    `json:"length,omitempty"`
	Description string `json:"description,omitempty"`
	By          string `json:"by,omitempty"`
	Modified    string `json:"modified,omitempty"`
}

// keyInspectOf builds a key's metadata from a resolved namespace state. storageKey
// is the key the secret is stored under (name, unless a contract renames it). It
// records only length and metadata, never the value.
func keyInspectOf(namespace, name, storageKey string, state *secrets.State) keyInspect {
	value, ok := state.Secrets[storageKey]
	info := keyInspect{Namespace: namespace, Name: name, Exists: ok}
	if ok {
		m := state.Meta[storageKey]
		info.Length = len(value)
		info.Description = m.Description
		info.By = m.By
		info.Modified = rfc3339(m.TS)
	}
	return info
}

func inspectKey(ctx context.Context, name string) error {
	a, err := loadApp(ctx)
	if err != nil {
		return err
	}
	state, _, err := a.readState(ctx)
	if err != nil {
		return err
	}
	info := keyInspectOf(a.namespace, name, a.storageKey(name), state)

	if inspectJSON {
		if err := printJSON(info); err != nil {
			return err
		}
	} else {
		w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
		fmt.Fprintf(w, "namespace:\t%s\n", info.Namespace)
		fmt.Fprintf(w, "secret:\t%s\n", info.Name)
		fmt.Fprintf(w, "exists:\t%s\n", yesNo(info.Exists))
		if info.Exists {
			m := state.Meta[a.storageKey(name)]
			fmt.Fprintf(w, "length:\t%d bytes\n", info.Length)
			fmt.Fprintf(w, "description:\t%s\n", dashIfEmpty(sanitizeDisplay(info.Description)))
			fmt.Fprintf(w, "last written:\t%s\n", stampLabel(m.TS, m.By))
		}
		_ = w.Flush()
	}

	// A missing secret exits non-zero, so scripts and agents can branch on it
	// without parsing output; the report above already explained it.
	if !info.Exists {
		return &exitCodeError{code: 1}
	}
	return nil
}

// namespaceInspect is the frozen `inspect --json` shape (no key argument). The
// namespace-level metadata fields are omitted when unset (a vault written before
// they existed, or never stamped).
type namespaceInspect struct {
	Namespace   string            `json:"namespace"`
	Description string            `json:"description,omitempty"`
	Created     string            `json:"created,omitempty"`
	CreatedBy   string            `json:"created_by,omitempty"`
	Updated     string            `json:"updated,omitempty"`
	UpdatedBy   string            `json:"updated_by,omitempty"`
	Count       int               `json:"secret_count"`
	Secrets     []inspectedSecret `json:"secrets"`
}

type inspectedSecret struct {
	Name        string `json:"name"`
	Length      int    `json:"length"`
	Description string `json:"description,omitempty"`
	By          string `json:"by,omitempty"`
	Modified    string `json:"modified,omitempty"`
}

// namespaceInspectOf builds a namespace summary from its resolved state: the
// namespace's own metadata plus each secret's name, length, and metadata (never a
// value), sorted by name.
func namespaceInspectOf(namespace string, state *secrets.State) namespaceInspect {
	names := make([]string, 0, len(state.Secrets))
	for name := range state.Secrets {
		names = append(names, name)
	}
	sort.Strings(names)
	nm := state.Namespace
	out := namespaceInspect{
		Namespace:   namespace,
		Description: nm.Description,
		Created:     rfc3339(nm.Created),
		CreatedBy:   nm.CreatedBy,
		Updated:     rfc3339(nm.Updated),
		UpdatedBy:   nm.UpdatedBy,
		Count:       len(names),
		Secrets:     make([]inspectedSecret, 0, len(names)),
	}
	for _, name := range names {
		m := state.Meta[name]
		out.Secrets = append(out.Secrets, inspectedSecret{
			Name:        name,
			Length:      len(state.Secrets[name]),
			Description: m.Description,
			By:          m.By,
			Modified:    rfc3339(m.TS),
		})
	}
	return out
}

// stampLabel renders a write's advisory time and actor for humans: "2006-01-02
// 15:04 by user@host", with the actor omitted when unknown and a dash when the
// whole stamp is absent (predates timestamps, or never stamped).
func stampLabel(ts int64, by string) string {
	if ts == 0 && by == "" {
		return "-"
	}
	label := modifiedLabel(ts)
	if by != "" {
		label += " by " + sanitizeDisplay(by)
	}
	return label
}

func inspectNamespace(ctx context.Context) error {
	a, err := loadApp(ctx)
	if err != nil {
		return err
	}
	state, _, err := a.readState(ctx)
	if err != nil {
		return err
	}
	out := namespaceInspectOf(a.namespace, state)

	if inspectJSON {
		return printJSON(out)
	}
	nm := state.Namespace
	hw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintf(hw, "namespace:\t%s\n", a.namespace)
	fmt.Fprintf(hw, "description:\t%s\n", dashIfEmpty(sanitizeDisplay(nm.Description)))
	fmt.Fprintf(hw, "created:\t%s\n", stampLabel(nm.Created, nm.CreatedBy))
	fmt.Fprintf(hw, "updated:\t%s\n", stampLabel(nm.Updated, nm.UpdatedBy))
	_ = hw.Flush()
	fmt.Println()
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tBYTES\tDESCRIPTION\tLAST WRITTEN")
	for _, s := range out.Secrets {
		m := state.Meta[s.Name]
		fmt.Fprintf(w, "%s\t%d\t%s\t%s\n", s.Name, s.Length, dashIfEmpty(sanitizeDisplay(s.Description)), stampLabel(m.TS, m.By))
	}
	_ = w.Flush()
	fmt.Printf("\n%d secret(s) in namespace %q\n", out.Count, a.namespace)
	return nil
}

// vaultInspect is the frozen `inspect --all --json` shape. It comes from the
// authenticated header alone, so no value is decrypted and no passphrase is asked.
type vaultInspect struct {
	Storage    string   `json:"storage"`
	VaultID    string   `json:"vault_id"`
	Revision   int      `json:"revision"`
	ReadOnly   bool     `json:"read_only"`
	Namespaces []string `json:"namespaces"`
}

func inspectVault(ctx context.Context) error {
	user, err := config.LoadUser()
	if err != nil {
		return err
	}
	eff, err := config.ResolveStorage(user, storageSelector(""))
	if err != nil {
		return err
	}
	store := openStorage(eff)
	raw, err := store.GetHeader(ctx)
	if errors.Is(err, backend.ErrNotFound) {
		return fmt.Errorf("no vault found at storage %q; create one with `notenv init`", eff.StorageName)
	}
	if err != nil {
		return err
	}
	header, err := crypto.ParseHeader(raw)
	if err != nil {
		return err
	}
	namespaces := vaultNamespaces(header)
	out := vaultInspect{
		Storage:    eff.StorageName,
		VaultID:    header.VaultID,
		Revision:   header.Revision,
		ReadOnly:   readOnlyReason(eff.StorageName, eff.ReadOnly) != "",
		Namespaces: namespaces,
	}

	if inspectJSON {
		return printJSON(out)
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintf(w, "storage:\t%s\n", out.Storage)
	fmt.Fprintf(w, "vault id:\t%s\n", dashIfEmpty(out.VaultID))
	fmt.Fprintf(w, "revision:\t%d\n", out.Revision)
	fmt.Fprintf(w, "read-only:\t%s\n", yesNo(out.ReadOnly))
	if len(namespaces) == 0 {
		fmt.Fprintf(w, "namespaces:\t-\n")
	} else {
		fmt.Fprintf(w, "namespaces (%d):\t%s\n", len(namespaces), strings.Join(namespaces, ", "))
	}
	_ = w.Flush()
	return nil
}

func rfc3339(ts int64) string {
	if ts == 0 {
		return ""
	}
	return time.Unix(ts, 0).UTC().Format(time.RFC3339)
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func init() {
	inspectCmd.Flags().BoolVar(&inspectAll, "all", false, "inspect the whole vault (its namespaces, id, revision, storage); no passphrase needed")
	inspectCmd.Flags().BoolVar(&inspectJSON, "json", false, "machine-readable output (never a secret value)")
}
