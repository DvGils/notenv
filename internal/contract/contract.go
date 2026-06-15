// Package contract models notenv.toml, the committed contract declaring
// which env vars a project needs. It contains no values.
package contract

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

const FileName = "notenv.toml"

// ErrNotFound is returned by Find when no notenv.toml exists between the
// start directory and the filesystem root.
var ErrNotFound = errors.New("no " + FileName + " found (run `notenv init` in your project root)")

var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// ValidEnvName reports whether s is a usable environment variable name (and
// thus a valid secret key): a letter or underscore followed by letters,
// digits, or underscores. Entry points that store a key (e.g. `notenv set`)
// should check this before doing any work, so a name that could never be
// injected never reaches storage.
func ValidEnvName(s string) bool { return envName.MatchString(s) }

// NamespaceName constrains namespaces: they become remote object names.
// Must start with an alphanumeric or underscore, which excludes the
// path-significant names "." and ".." (and any leading "-"), while still
// allowing dots/dashes internally.
var NamespaceName = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]*$`)

// Spec describes one declared secret.
type Spec struct {
	// Name overrides the storage key (defaults to the env var name).
	Name string `toml:"name"`
	// Required defaults to true: declaring a secret means you need it.
	Required *bool `toml:"required"`
}

func (s Spec) IsRequired() bool { return s.Required == nil || *s.Required }

type File struct {
	Namespace string          `toml:"namespace"`
	Secrets   map[string]Spec `toml:"secrets"`
}

// Find walks up from start to the filesystem root looking for notenv.toml
// (like git does for .git) and parses the first one found. Returns the
// parsed file and the directory containing it.
func Find(start string) (*File, string, error) {
	dir, err := filepath.Abs(start)
	if err != nil {
		return nil, "", err
	}
	for {
		path := filepath.Join(dir, FileName)
		if _, err := os.Stat(path); err == nil {
			f, err := Parse(path)
			return f, dir, err
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return nil, "", ErrNotFound
		}
		dir = parent
	}
}

func Parse(path string) (*File, error) {
	var f File
	md, err := toml.DecodeFile(path, &f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	// The contract is committed and may come from a cloned repo. Storage
	// remote/base are per-machine settings, NOT per-project: a contract
	// must not be able to redirect where this machine reads/writes secrets.
	// Reject (don't silently ignore) a [storage] block so the author is told.
	for _, key := range md.Undecoded() {
		if len(key) > 0 && key[0] == "storage" {
			return nil, fmt.Errorf("%s: [storage] is not allowed in the committed contract. Storage remote/base are per-machine settings (run `notenv setup`), not per-project", path)
		}
	}
	for key := range f.Secrets {
		if !ValidEnvName(key) {
			return nil, fmt.Errorf("%s: %q is not a valid environment variable name", path, key)
		}
	}
	if f.Namespace != "" && !NamespaceName.MatchString(f.Namespace) {
		return nil, fmt.Errorf("%s: namespace %q must match %s", path, f.Namespace, NamespaceName)
	}
	return &f, nil
}

// Declare appends a secret declaration to the contract file's [secrets]
// section (creating the section if absent). Textual insert, not a TOML
// rewrite, so the user's comments and layout survive.
func Declare(path, key string) error {
	if !ValidEnvName(key) {
		return fmt.Errorf("%q is not a valid environment variable name", key)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	declaration := fmt.Sprintf("%s = { required = true }\n", key)

	lines := strings.SplitAfter(string(data), "\n")
	for i, line := range lines {
		if !isTableHeader(line, "secrets") {
			continue
		}
		// Already declared in this table? A textual append would duplicate the
		// key, which the next Parse rejects ("key already defined"). Callers also
		// guard in memory, but a hand-edited contract can disagree, so check here
		// too: scan from the header to the next table header.
		for _, l := range lines[i+1:] {
			if isTableHeader(l, "") {
				break
			}
			if declaresKey(l, key) {
				return nil
			}
		}
		// Insert directly under the header: TOML keys belong to the table whose
		// header precedes them, so this is safe no matter what follows.
		rest := strings.Join(lines[i+1:], "")
		updated := strings.Join(lines[:i+1], "") + declaration + rest
		return os.WriteFile(path, []byte(updated), 0o644)
	}

	updated := string(data)
	if !strings.HasSuffix(updated, "\n") {
		updated += "\n"
	}
	updated += "\n[secrets]\n" + declaration
	return os.WriteFile(path, []byte(updated), 0o644)
}

// isTableHeader reports whether a line is a TOML table header. With name set, it
// must be that table (tolerating surrounding and inner whitespace and a quoted
// name: `[secrets]`, `[ secrets ]`, `["secrets"]`); with name empty, it matches
// any table header (used to find where the current table ends). Array-of-tables
// (`[[x]]`) is treated as a header boundary but never as the named table.
func isTableHeader(line, name string) bool {
	t := strings.TrimSpace(line)
	if !strings.HasPrefix(t, "[") || !strings.HasSuffix(t, "]") {
		return false
	}
	if name == "" {
		return true
	}
	if strings.HasPrefix(t, "[[") {
		return false
	}
	inner := strings.TrimSpace(t[1 : len(t)-1])
	inner = strings.Trim(inner, `"'`)
	return inner == name
}

// declaresKey reports whether a contract line declares key (`key = ...` or
// `key=...`), ignoring leading whitespace and avoiding a prefix false match
// (`KEYS` for `KEY`).
func declaresKey(line, key string) bool {
	rest, ok := strings.CutPrefix(strings.TrimSpace(line), key)
	if !ok {
		return false
	}
	return strings.HasPrefix(strings.TrimLeft(rest, " \t"), "=")
}

// StorageKey maps an env var name to the key it is stored under.
func (f *File) StorageKey(envKey string) string {
	if spec, ok := f.Secrets[envKey]; ok && spec.Name != "" {
		return spec.Name
	}
	return envKey
}

// BuildEnv appends the contract's env vars (resolved from secrets) to base.
// Missing required secrets are an error; missing optional ones are skipped.
// os/exec deduplicates by key with last-wins, so appending overrides base.
func (f *File) BuildEnv(base []string, secrets map[string]string) ([]string, error) {
	keys := make([]string, 0, len(f.Secrets))
	for k := range f.Secrets {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	env := base
	var missing []string
	for _, key := range keys {
		value, ok := secrets[f.StorageKey(key)]
		switch {
		case ok:
			env = append(env, key+"="+value)
		case f.Secrets[key].IsRequired():
			missing = append(missing, key)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("missing required secrets: %s (use `notenv set KEY`)",
			strings.Join(missing, ", "))
	}
	return env, nil
}
