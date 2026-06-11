// Package config loads the user-global config (~/.config/notenv/config.toml,
// not committed) and merges it with the project contract into an effective
// configuration. A machine may define several named storages; the storage
// target is machine-only, and the contract contributes just the namespace.
package config

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/DvGils/notenv/internal/contract"
)

const (
	DefaultBase         = "notenv"
	DefaultStorage      = "default" // name of the storage setup creates first
	ModePass            = "passphrase"
	DefaultCacheTTL     = time.Hour // master-key keyring cache
	DefaultBlobCacheTTL = time.Hour // local ciphertext cache (matches key cache; --refresh forces fresh)
)

// User is the per-machine config. Storage targets are keyed by name so one
// machine can drive several vaults; Default names the one used when a project
// has no local binding.
type User struct {
	Default string                  `toml:"default"`
	Storage map[string]StorageEntry `toml:"storage"`
	Crypto  struct {
		Mode string `toml:"mode"`
		// CacheTTL is how long the master-key cache may hold the key
		// (Go duration string; "0" disables caching). Default: 1h.
		CacheTTL string `toml:"cache_ttl"`
	} `toml:"crypto"`
}

// storageNameRe constrains storage names: they become TOML table keys and CLI
// selectors, so no dots (which TOML reads as table nesting), spaces, or other
// punctuation.
var storageNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]*$`)

// ValidStorageName reports whether name is usable as a storage name.
func ValidStorageName(name string) bool { return storageNameRe.MatchString(name) }

// StorageEntry is one named storage target.
type StorageEntry struct {
	Remote string `toml:"remote"`
	Base   string `toml:"base"`
	// Versioned: the remote retains old object versions on overwrite
	// (B2 does natively), so skip the ~3s server-side .prev backup copy.
	Versioned bool `toml:"versioned"`
	// CacheTTL bounds local ciphertext-cache lifetime for this storage
	// (Go duration; "0" disables). Default 1h.
	CacheTTL string `toml:"cache_ttl"`
}

// Dir returns the user config directory, honoring XDG_CONFIG_HOME.
func Dir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "notenv"), nil
}

func Path() (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.toml"), nil
}

// IdentityPath returns the default age identity file location. It holds the
// private key a teammate unlocks their recipient slot with; the NOTENV_IDENTITY
// environment variable overrides it.
func IdentityPath() (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "identity"), nil
}

// LoadUser reads the user config. A missing file is not an error: it
// returns a zero-value config (callers surface the "no storage" error later).
func LoadUser() (*User, error) {
	path, err := Path()
	if err != nil {
		return nil, err
	}
	var u User
	if _, err := toml.DecodeFile(path, &u); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return &User{}, nil
		}
		return nil, fmt.Errorf("%s: %w (re-run `notenv setup` if this is an old-format config)", path, err)
	}
	return &u, nil
}

// StorageNames returns the configured storage names, sorted.
func (u *User) StorageNames() []string {
	names := make([]string, 0, len(u.Storage))
	for name := range u.Storage {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// SelectStorage picks the storage to use, in precedence order: an explicit name
// (from --storage or a project's local binding) → the configured default → the
// sole storage when only one exists. It returns the resolved name and entry, or
// an actionable error.
func (u *User) SelectStorage(explicit string) (string, StorageEntry, error) {
	path, _ := Path()
	if explicit != "" {
		entry, ok := u.Storage[explicit]
		if !ok {
			return "", StorageEntry{}, fmt.Errorf("no storage named %q configured; add it with `notenv setup --name %s`", explicit, explicit)
		}
		return explicit, entry, nil
	}
	if len(u.Storage) == 0 {
		return "", StorageEntry{}, fmt.Errorf("no storage configured; run `notenv setup` (config: %s)", path)
	}
	if u.Default != "" {
		entry, ok := u.Storage[u.Default]
		if !ok {
			return "", StorageEntry{}, fmt.Errorf("default storage %q is not defined; fix `default` in %s", u.Default, path)
		}
		return u.Default, entry, nil
	}
	if len(u.Storage) == 1 {
		name := u.StorageNames()[0]
		return name, u.Storage[name], nil
	}
	return "", StorageEntry{}, fmt.Errorf("multiple storages configured (%s) but none selected; run `notenv init` to bind this project, or pass --storage NAME", strings.Join(u.StorageNames(), ", "))
}

// UpsertStorage adds or replaces a named storage and writes the config. The
// storage becomes the default if it is the first one, if no default is set, or
// if makeDefault is true. Returns the config path.
func UpsertStorage(name string, entry StorageEntry, makeDefault bool) (string, error) {
	if !ValidStorageName(name) {
		return "", fmt.Errorf("invalid storage name %q: use letters, digits, '-' or '_' (no dots or spaces)", name)
	}
	u, err := LoadUser()
	if err != nil {
		return "", err
	}
	if u.Storage == nil {
		u.Storage = map[string]StorageEntry{}
	}
	u.Storage[name] = entry
	if makeDefault || u.Default == "" || len(u.Storage) == 1 {
		u.Default = name
	}
	return writeUserConfig(u)
}

// writeUserConfig renders the whole config from u. It is a generated machine
// file, so it is regenerated wholesale (deterministically, storages sorted).
func writeUserConfig(u *User) (string, error) {
	path, err := Path()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}

	var b strings.Builder
	b.WriteString("# notenv user config (NOT committed). Storage targets + crypto for this machine.\n\n")
	if u.Default != "" {
		fmt.Fprintf(&b, "default = %q   # storage used when a project has no local binding\n\n", u.Default)
	}
	for _, name := range u.StorageNames() {
		st := u.Storage[name]
		fmt.Fprintf(&b, "[storage.%q]\n", name) // quoted key: never let a name nest as TOML tables
		fmt.Fprintf(&b, "remote    = %q\n", st.Remote)
		fmt.Fprintf(&b, "base      = %q\n", st.Base)
		fmt.Fprintf(&b, "versioned = %t   # remote keeps old versions on overwrite (B2: yes), so skip backup copies\n", st.Versioned)
		if st.CacheTTL != "" {
			fmt.Fprintf(&b, "cache_ttl = %q\n", st.CacheTTL)
		} else {
			b.WriteString("# cache_ttl = \"1h\"   # local ciphertext cache lifetime (tmpfs, Linux only); \"0\" disables\n")
		}
		b.WriteString("\n")
	}
	mode := u.Crypto.Mode
	if mode == "" {
		mode = ModePass
	}
	b.WriteString("[crypto]\n")
	fmt.Fprintf(&b, "mode = %q\n", mode)
	if u.Crypto.CacheTTL != "" {
		fmt.Fprintf(&b, "cache_ttl = %q\n", u.Crypto.CacheTTL)
	} else {
		b.WriteString("# cache_ttl = \"1h\"   # master-key cache lifetime (Linux kernel keyring); \"0\" disables\n")
	}

	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		return "", err
	}
	return path, nil
}

// MasterCacheTTL is the master-key cache lifetime (crypto.cache_ttl; default 1h,
// "0" disables caching).
func (u *User) MasterCacheTTL() (time.Duration, error) {
	if u.Crypto.CacheTTL == "" {
		return DefaultCacheTTL, nil
	}
	return time.ParseDuration(u.Crypto.CacheTTL)
}

// SetDefault changes which storage is the default.
func SetDefault(name string) error {
	u, err := LoadUser()
	if err != nil {
		return err
	}
	if _, ok := u.Storage[name]; !ok {
		return fmt.Errorf("no storage named %q to set as default", name)
	}
	u.Default = name
	_, err = writeUserConfig(u)
	return err
}

// LocalBindingFile is the per-checkout, git-ignored file that binds a project
// to a named storage. It lives beside the contract and is never committed.
const LocalBindingFile = "notenv.local.toml"

type localBinding struct {
	Storage string `toml:"storage"`
}

// ReadLocalBinding returns the storage name bound to the project in dir, or ""
// when no binding file exists.
func ReadLocalBinding(dir string) (string, error) {
	path := filepath.Join(dir, LocalBindingFile)
	var b localBinding
	if _, err := toml.DecodeFile(path, &b); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", nil
		}
		return "", fmt.Errorf("%s: %w", path, err)
	}
	return b.Storage, nil
}

// WriteLocalBinding records the storage a project uses in dir and returns the
// file path. The caller is responsible for git-ignoring it.
func WriteLocalBinding(dir, storageName string) (string, error) {
	path := filepath.Join(dir, LocalBindingFile)
	content := fmt.Sprintf("# notenv project-local storage binding (NOT committed).\n"+
		"# Selects which configured storage this checkout uses; see `notenv setup`.\n"+
		"storage = %q\n", storageName)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return "", err
	}
	return path, nil
}

// Exists reports whether a user config file is present (the "is this
// machine set up" check).
func Exists() bool {
	path, err := Path()
	if err != nil {
		return false
	}
	_, err = os.Stat(path)
	return err == nil
}

// Effective is the merged result of the selected storage + contract.
type Effective struct {
	StorageName  string // the resolved storage name
	Remote       string // rclone remote name
	Base         string // path within the remote
	Versioned    bool   // remote retains versions on overwrite
	Namespace    string
	Mode         string        // crypto mode
	CacheTTL     time.Duration // master-key cache TTL; <= 0 disables caching
	BlobCacheTTL time.Duration // local ciphertext cache TTL; <= 0 disables
}

// Resolve selects a storage (storageName empty means auto: default or sole) and
// combines it with the contract's namespace. Storage target is machine config
// only; the contract contributes the namespace (it cannot redirect where this
// machine reads/writes; see contract.Parse).
func Resolve(u *User, f *contract.File, contractDir, storageName string) (Effective, error) {
	name, st, err := u.SelectStorage(storageName)
	if err != nil {
		return Effective{}, err
	}
	eff := Effective{
		StorageName: name,
		Remote:      st.Remote,
		Base:        firstOf(st.Base, DefaultBase),
		Versioned:   st.Versioned,
		Namespace:   firstOf(f.Namespace, filepath.Base(contractDir)),
		Mode:        firstOf(u.Crypto.Mode, ModePass),
	}
	if eff.Remote == "" {
		path, _ := Path()
		return eff, fmt.Errorf("storage %q has no remote configured; fix it in %s or re-run `notenv setup --name %s`", name, path, name)
	}
	if !contract.NamespaceName.MatchString(eff.Namespace) {
		return eff, fmt.Errorf("derived namespace %q is not a valid object name; set namespace explicitly in %s", eff.Namespace, contract.FileName)
	}
	if eff.Mode != ModePass {
		return eff, fmt.Errorf("unsupported crypto mode %q (MVP supports %q)", eff.Mode, ModePass)
	}
	ttl, err := u.MasterCacheTTL()
	if err != nil {
		return eff, fmt.Errorf("invalid crypto.cache_ttl %q: %w", u.Crypto.CacheTTL, err)
	}
	eff.CacheTTL = ttl
	eff.BlobCacheTTL = DefaultBlobCacheTTL
	if st.CacheTTL != "" {
		ttl, err := time.ParseDuration(st.CacheTTL)
		if err != nil {
			return eff, fmt.Errorf("invalid cache_ttl %q for storage %q: %w", st.CacheTTL, name, err)
		}
		eff.BlobCacheTTL = ttl
	}
	return eff, nil
}

// Pin is a per-vault rollback anchor: the highest header revision this machine
// has seen and the master public key it expects. It is not secret (the threat
// is storage write, not local read), so it lives in a plain local file.
type Pin struct {
	Revision  int    `json:"revision"`
	MasterPub string `json:"master_pub"`
}

func pinPath() (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "pins.json"), nil
}

func loadPins() (map[string]Pin, error) {
	path, err := pinPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return map[string]Pin{}, nil
		}
		return nil, err
	}
	pins := map[string]Pin{}
	if err := json.Unmarshal(data, &pins); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return pins, nil
}

// ReadPin returns the stored pin for a storage scope (have=false if none).
func ReadPin(scope string) (p Pin, have bool, err error) {
	pins, err := loadPins()
	if err != nil {
		return Pin{}, false, err
	}
	p, have = pins[scope]
	return p, have, nil
}

// WritePin records the pin for a storage scope.
func WritePin(scope string, p Pin) error {
	pins, err := loadPins()
	if err != nil {
		return err
	}
	pins[scope] = p
	path, err := pinPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(pins, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// CheckPin compares an observed header (revision, master public key) against the
// stored pin. It returns advance=true when the pin should move forward (or on
// first contact), or an actionable error on a rollback or unexpected
// master-change alarm.
func CheckPin(stored Pin, have bool, obsRevision int, obsMasterPub string) (advance bool, err error) {
	if !have {
		return true, nil // trust on first use
	}
	if obsMasterPub != stored.MasterPub {
		return false, errors.New("the vault's master key changed unexpectedly: a legitimate rotation on another machine, or a substitution attack. If you have confirmed it is legitimate, run `notenv key trust`; otherwise treat the storage as compromised")
	}
	if obsRevision < stored.Revision {
		return false, fmt.Errorf("the header is older than one this machine already trusted (revision %d < %d): possible rollback. If you have confirmed it is legitimate, run `notenv key trust`", obsRevision, stored.Revision)
	}
	return true, nil
}

// CacheScope is the keyring cache key for a storage base. Length-prefixed
// on the remote so (remote, base) pairs can't alias: a plain "remote:base"
// join makes ("r","a:b") and ("r:a","b") collide.
func CacheScope(remote, base string) string {
	return fmt.Sprintf("%d:%s:%s", len(remote), remote, base)
}

func firstOf(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// MachineID returns this machine's stable identifier, creating it on first use.
// It names and orders the segments this machine writes, so two machines never
// produce the same segment. It is random, not secret, and lives in local state.
func MachineID() (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, "machine")
	switch data, err := os.ReadFile(path); {
	case err == nil:
		if id := strings.TrimSpace(string(data)); id != "" {
			return id, nil
		}
	case !errors.Is(err, fs.ErrNotExist):
		return "", err
	}
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	id := hex.EncodeToString(buf)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(id+"\n"), 0o600); err != nil {
		return "", err
	}
	return id, nil
}

// NextSeq returns the next strictly-increasing sequence number for (scope,
// namespace) on this machine, persisting the counter. It orders this machine's
// segments even when a freshly listed remote is briefly stale, so two of its
// writes never share a sequence number.
func NextSeq(scope, namespace string) (int, error) {
	dir, err := Dir()
	if err != nil {
		return 0, err
	}
	path := filepath.Join(dir, "seq.json")
	seqs := map[string]int{}
	switch data, err := os.ReadFile(path); {
	case err == nil:
		if err := json.Unmarshal(data, &seqs); err != nil {
			return 0, fmt.Errorf("%s: %w", path, err)
		}
	case !errors.Is(err, fs.ErrNotExist):
		return 0, err
	}
	key := scope + "\x00" + namespace
	seqs[key]++
	next := seqs[key]
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return 0, err
	}
	data, err := json.MarshalIndent(seqs, "", "  ")
	if err != nil {
		return 0, err
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return 0, err
	}
	return next, nil
}
