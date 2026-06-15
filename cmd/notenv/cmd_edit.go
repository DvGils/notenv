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
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

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
comment line above a key to change its description. A value is single-line and
trimmed of surrounding whitespace; to store one with surrounding whitespace or
newlines, use "notenv set --stdin" (edit refuses a namespace whose values it cannot
represent that way, rather than corrupt them). A value is never shown: the buffer
can leak at most what you type into it.

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
	before, _, err := a.readState(ctx)
	if err != nil {
		return err
	}
	// The line-oriented, no-quoting buffer cannot round-trip a value with
	// surrounding whitespace or an embedded newline, so refuse rather than render
	// it and silently corrupt it on save. `set --stdin` handles such values.
	if bad := unrepresentableKeys(before); len(bad) > 0 {
		return fmt.Errorf("namespace %q has secret(s) %s whose value has surrounding whitespace or spans multiple lines, which edit cannot represent; change them with `notenv set <KEY> --stdin` (or `notenv unset <KEY>`), then edit the rest", a.namespace, strings.Join(bad, ", "))
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

	// Re-read before writing: the buffer may have been open for a while, and
	// a key this edit touches that also changed remotely must stop the save
	// rather than be clobbered. Untouched keys merge as usual (the write's
	// read-modify-write preserves them).
	fresh, view, err := a.readState(ctx)
	if err != nil {
		return err
	}
	if err := refuseConcurrentEdits(before, fresh, writes); err != nil {
		return err
	}

	var sets, unsets int
	now := time.Now().Unix()
	for i := range writes {
		writes[i].TS = now
		if writes[i].Deleted {
			unsets++
		} else {
			sets++
		}
	}
	// Deleting every secret with nothing added (a truncated or emptied buffer, an
	// editor that wrote 0 bytes, a stray select-all-delete) is the crontab -r
	// footgun: confirm before wiping a whole namespace.
	if err := confirmWipe(before, writes, a.namespace); err != nil {
		return err
	}
	var updated *secrets.State
	if err := ui.Spin(fmt.Sprintf("Encrypting and recording %d change(s)", len(writes)), func() error {
		var aerr error
		updated, aerr = a.writeNamespace(ctx, view, writes)
		return aerr
	}); err != nil {
		return err
	}
	a.cacheState(view.mk, updated)
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
		// No runtime dir: on Linux that falls to /tmp on persistent disk, where a
		// newly typed value (and the editor's own swap/undo files) can outlive the
		// edit if cleanup never runs (SIGKILL, power loss). macOS/Windows temp dirs
		// are per-user and acceptable, so the warning is Linux-only. Existing values
		// never reach the buffer (they render as <keep>), so the exposure is bounded
		// to values typed this session.
		if runtime.GOOS == "linux" {
			ui.Warnf("XDG_RUNTIME_DIR is unset, so the edit buffer uses %s (likely persistent disk); a value you type could linger there if the editor or notenv is killed. Point XDG_RUNTIME_DIR at a RAM-backed dir (e.g. /run/user/$UID) to avoid this", base)
		}
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
	b.WriteString("# A comment line directly above a key is its description; removing it keeps\n")
	b.WriteString("# the existing description (clear one with `notenv set KEY --description \"\"`).\n")
	b.WriteString("# Values are taken literally; no quoting. Existing values are never shown.\n")
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
	// The editor is a child like any other: notenv's own credential must not
	// ride into it.
	cmd.Env = append(stripCredentialEnv(os.Environ()), "TMPDIR="+filepath.Dir(path))
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

// diffEdit turns the buffer into the write batch: new and rewritten values are
// set, keys whose lines were deleted are unset, and a comment directly above a
// key sets that key's description. An ABSENT comment keeps the stored
// description rather than clearing it (via KeepDescription), so an editor reflow
// or a stray blank line between a comment and its key cannot silently wipe
// metadata; clearing a description is done with `notenv set KEY --description ""`.
func diffEdit(before *secrets.State, entries map[string]editEntry) ([]secrets.Write, error) {
	var writes []secrets.Write
	for key, e := range entries {
		prev, exists := before.Secrets[key]
		prevDesc := before.Meta[key].Description
		// A non-empty comment is an explicit description; treat it as a change only
		// when it actually differs from what is stored.
		setDesc := e.description != "" && e.description != prevDesc

		if e.keep {
			if !exists {
				return nil, fmt.Errorf("%s is %s but holds no value yet; give it one (a literal %s value is not storable)", key, keepSentinel, keepSentinel)
			}
			if setDesc {
				writes = append(writes, secrets.Write{Key: key, Value: prev, Description: e.description})
			}
			continue
		}
		switch {
		case setDesc:
			// New or changed description, carrying the (possibly new) value.
			writes = append(writes, secrets.Write{Key: key, Value: e.value, Description: e.description})
		case !exists || e.value != prev:
			// Value moved with no description change in the buffer: keep the stored
			// description rather than overwrite it with an absent comment.
			writes = append(writes, secrets.Write{Key: key, Value: e.value, KeepDescription: true})
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

// wouldWipeNamespace reports whether a write batch deletes every existing secret
// and adds none, i.e. empties the namespace. runEdit confirms before doing this, so
// a truncated or emptied buffer cannot silently delete everything.
func wouldWipeNamespace(before *secrets.State, writes []secrets.Write) bool {
	if len(before.Secrets) == 0 {
		return false
	}
	dels := 0
	for _, w := range writes {
		if !w.Deleted {
			return false
		}
		dels++
	}
	return dels == len(before.Secrets)
}

// unrepresentableKeys lists secrets whose value the line-oriented, no-quoting edit
// buffer cannot round-trip faithfully: surrounding whitespace (invisible in the
// buffer and trimmed on re-parse) or an embedded newline (which would break the
// one-line-per-key format). edit refuses such a namespace; `set --stdin` stores
// these values. Internal whitespace is fine.
func unrepresentableKeys(before *secrets.State) []string {
	var bad []string
	for k, v := range before.Secrets {
		if v != strings.TrimSpace(v) || strings.ContainsRune(v, '\n') {
			bad = append(bad, k)
		}
	}
	sort.Strings(bad)
	return bad
}

// confirmWipe asks before an edit that would empty the namespace; it returns an
// error when the user declines or there is no terminal to ask on.
func confirmWipe(before *secrets.State, writes []secrets.Write, namespace string) error {
	if !wouldWipeNamespace(before, writes) {
		return nil
	}
	ok, err := ui.Confirm(fmt.Sprintf("delete all %d secret(s) in namespace %q?", len(before.Secrets), namespace), false)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("aborted; nothing was written")
	}
	return nil
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
