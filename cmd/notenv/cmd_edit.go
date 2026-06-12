package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/DvGils/notenv/internal/contract"
	"github.com/DvGils/notenv/internal/secrets"
	"github.com/DvGils/notenv/internal/ui"
)

// keepSentinel stands in for every existing value in the edit buffer: editing
// does not require reading, so no notenv command displays a stored value, and
// a leaked or forgotten buffer can disclose at most what was typed into it
// during this edit.
const keepSentinel = "<keep>"

var editCmd = &cobra.Command{
	Use:   "edit",
	Short: "Bulk-edit a namespace in $EDITOR without displaying any value",
	Long: `Open the namespace in $VISUAL/$EDITOR as a dotenv-shaped buffer in which
every existing value reads ` + keepSentinel + `: replace it to set a new value, delete
the line to unset the key, add KEY=value lines to create keys, and edit the
comment line above a key to change its description. Values are taken
literally (no quoting), and a value is never shown: the buffer can leak at
most what you type into it.

Saving applies the difference as one recorded write. A key that also changed
on another machine while the buffer was open is detected and stops the save
with the key named. An unchanged buffer writes nothing.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		a, err := loadApp(cmd.Context())
		if err != nil {
			return err
		}
		if err := a.requireWritable("edit secrets"); err != nil {
			return err
		}
		return runEdit(cmd, a)
	},
}

func runEdit(cmd *cobra.Command, a *app) error {
	ctx := cmd.Context()
	before, _, err := a.foldState(ctx)
	if err != nil {
		return err
	}

	path, cleanup, err := writeEditBuffer(a, before)
	if err != nil {
		return err
	}
	defer cleanup()
	if err := runEditor(path); err != nil {
		return fmt.Errorf("editor: %w (nothing was written)", err)
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	entries, err := parseEditBuffer(f)
	f.Close()
	if err != nil {
		return fmt.Errorf("%w (nothing was written; the buffer was discarded)", err)
	}
	cleanup()

	writes, err := diffEdit(before, entries)
	if err != nil {
		return err
	}
	if len(writes) == 0 {
		ui.Notef("nothing changed")
		return nil
	}

	// Re-fold before writing: the buffer may have been open for a while, and
	// a key this edit touches that also changed remotely must stop the save
	// rather than be clobbered. Untouched keys merge as usual.
	fresh, view, err := a.foldState(ctx)
	if err != nil {
		return err
	}
	if err := refuseConcurrentEdits(before, fresh, writes); err != nil {
		return err
	}

	var sets, unsets int
	for _, w := range writes {
		if w.Deleted {
			unsets++
		} else {
			sets++
		}
	}
	var updated *secrets.State
	if err := ui.Spin(fmt.Sprintf("Encrypting and recording %d change(s)", len(writes)), func() error {
		var aerr error
		updated, aerr = a.appendGuardedBatch(ctx, view, fresh, writes)
		return aerr
	}); err != nil {
		return err
	}
	a.cacheFolded(view.mk, updated)
	reportConflicts(updated.Conflicts)
	a.maybeCompact(ctx, view.mk, fresh.SegmentCount()+len(writes)-1)
	declareNewKeys(a, before, writes)
	ui.Successf("edited namespace %q: %d set, %d unset", a.namespace, sets, unsets)
	return nil
}

// writeEditBuffer renders the sentinel buffer into a private directory:
// the runtime dir when available (RAM-backed on Linux), 0700/0600, removed
// on exit and on a signal. TMPDIR points there for the editor child so its
// own temp files land in the same place.
func writeEditBuffer(a *app, state *secrets.State) (string, func(), error) {
	base := os.Getenv("XDG_RUNTIME_DIR")
	if base == "" {
		base = os.TempDir()
	}
	dir, err := os.MkdirTemp(base, "notenv-edit-*")
	if err != nil {
		return "", nil, err
	}
	remove := func() { _ = os.RemoveAll(dir) }
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		if _, ok := <-sig; ok {
			remove()
			os.Exit(1)
		}
	}()
	var once sync.Once
	cleanup := func() {
		once.Do(func() {
			signal.Stop(sig)
			close(sig)
			remove()
		})
	}

	path := filepath.Join(dir, "edit.env")
	if err := os.WriteFile(path, []byte(renderEditBuffer(a.namespace, state)), 0o600); err != nil {
		cleanup()
		return "", nil, err
	}
	return path, cleanup, nil
}

// renderEditBuffer produces the buffer text: the instructions, then every key
// sorted, its description as the comment line above it, its value the
// sentinel.
func renderEditBuffer(namespace string, state *secrets.State) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Editing namespace %q with %d secret(s).\n", namespace, len(state.Secrets))
	fmt.Fprintf(&b, "# %s leaves a value unchanged; replace it to set a new value.\n", keepSentinel)
	b.WriteString("# Delete a line to unset that key. Add KEY=value lines to create keys.\n")
	b.WriteString("# A comment line directly above a key is its description. Values are\n")
	b.WriteString("# taken literally; no quoting. Existing values are never shown.\n")
	keys := make([]string, 0, len(state.Secrets))
	for k := range state.Secrets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		b.WriteString("\n")
		if desc := state.Meta[k].Description; desc != "" {
			fmt.Fprintf(&b, "# %s\n", desc)
		}
		fmt.Fprintf(&b, "%s=%s\n", k, keepSentinel)
	}
	return b.String()
}

// runEditor opens path in $VISUAL, falling back to $EDITOR. The value is
// split on whitespace so editors invoked with flags ("code --wait") work.
func runEditor(path string) error {
	editor := os.Getenv("VISUAL")
	if editor == "" {
		editor = os.Getenv("EDITOR")
	}
	if editor == "" {
		return errors.New("$VISUAL and $EDITOR are both unset; set one to your editor")
	}
	parts := strings.Fields(editor)
	cmd := exec.Command(parts[0], append(parts[1:], path)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = append(os.Environ(), "TMPDIR="+filepath.Dir(path))
	return cmd.Run()
}

// editEntry is one parsed buffer line: a kept value (sentinel), a set value,
// and the description from the comment block directly above it.
type editEntry struct {
	value       string
	keep        bool
	description string
}

// parseEditBuffer reads the saved buffer back. The format is notenv's own
// (it rendered it), so parsing is strict: a non-comment line must be a
// KEY=VALUE assignment with a valid name, duplicates are ambiguous, and an
// empty value is an error (deleting the line is how a key is unset).
func parseEditBuffer(r io.Reader) (map[string]editEntry, error) {
	entries := map[string]editEntry{}
	var comments []string
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for line := 1; scanner.Scan(); line++ {
		text := strings.TrimSpace(scanner.Text())
		switch {
		case text == "":
			comments = nil
			continue
		case strings.HasPrefix(text, "#"):
			comments = append(comments, strings.TrimSpace(strings.TrimPrefix(text, "#")))
			continue
		}
		key, rest, found := strings.Cut(text, "=")
		key = strings.TrimSpace(key)
		if !found || !contract.ValidEnvName(key) {
			return nil, fmt.Errorf("line %d: not a KEY=value line", line)
		}
		if _, dup := entries[key]; dup {
			return nil, fmt.Errorf("line %d: %s appears twice; keep one line per key", line, key)
		}
		value := strings.TrimSpace(rest)
		if value == "" {
			return nil, fmt.Errorf("line %d: %s has an empty value; delete the line to unset the key, or give it a value", line, key)
		}
		entries[key] = editEntry{
			value:       value,
			keep:        value == keepSentinel,
			description: strings.Join(comments, " "),
		}
		comments = nil
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

// diffEdit turns the buffer into the write batch: kept values change only
// when their description does (the old value is carried), new and rewritten
// values are set, and keys whose lines were deleted are unset. The buffer is
// authoritative for descriptions: a removed comment clears one.
func diffEdit(before *secrets.State, entries map[string]editEntry) ([]secrets.Write, error) {
	var writes []secrets.Write
	for key, e := range entries {
		prev, exists := before.Secrets[key]
		prevDesc := before.Meta[key].Description
		if e.keep {
			if !exists {
				return nil, fmt.Errorf("%s is %s but holds no value yet; give it one (a literal %s value is not storable)", key, keepSentinel, keepSentinel)
			}
			if e.description != prevDesc {
				writes = append(writes, secrets.Write{Key: key, Value: prev, Description: e.description})
			}
			continue
		}
		if !exists || e.value != prev || e.description != prevDesc {
			writes = append(writes, secrets.Write{Key: key, Value: e.value, Description: e.description})
		}
	}
	for key := range before.Secrets {
		if _, present := entries[key]; !present {
			writes = append(writes, secrets.Write{Key: key, Deleted: true})
		}
	}
	sort.Slice(writes, func(i, j int) bool { return writes[i].Key < writes[j].Key })
	return writes, nil
}

// refuseConcurrentEdits stops the save when a key this edit touches also
// changed remotely while the buffer was open: silently overwriting a write
// the user never saw is the one wrong answer. Keys the edit does not touch
// merge as usual.
func refuseConcurrentEdits(before, fresh *secrets.State, writes []secrets.Write) error {
	var clashed []string
	for _, w := range writes {
		bv, bok := before.Secrets[w.Key]
		fv, fok := fresh.Secrets[w.Key]
		if bok != fok || bv != fv || before.Meta[w.Key] != fresh.Meta[w.Key] {
			clashed = append(clashed, w.Key)
		}
	}
	if len(clashed) > 0 {
		return fmt.Errorf("%s changed on another machine while you were editing; nothing was written. Re-run `notenv edit` to pick up the new state", strings.Join(clashed, ", "))
	}
	return nil
}

// declareNewKeys mirrors import's convenience: a key this edit created gets
// declared in the project contract so `notenv run` injects it.
func declareNewKeys(a *app, before *secrets.State, writes []secrets.Write) {
	if a.contract == nil {
		return
	}
	for _, w := range writes {
		if w.Deleted {
			continue
		}
		if _, existed := before.Secrets[w.Key]; existed {
			continue
		}
		if _, declared := a.contract.Secrets[w.Key]; declared {
			continue
		}
		if err := contract.Declare(a.contractPath, w.Key); err != nil {
			ui.Warnf("could not declare %s in %s: %v; add it by hand or `notenv run` won't inject it", w.Key, contract.FileName, err)
		}
	}
}

func init() {
	rootCmd.AddCommand(editCmd)
}
