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
	"runtime"
	"slices"
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

// StorageEntry is one named storage target: either a local vault directory
// (Path) or an rclone remote (Remote/Base/Versioned) — the populated field is
// the storage's type, and exactly one of the two must be set.
type StorageEntry struct {
	// Path is a local vault directory (pure-Go backend, no rclone).
	Path   string `toml:"path"`
	Remote string `toml:"remote"`
	Base   string `toml:"base"`
	// Versioned: the remote retains old object versions on overwrite
	// (B2 does natively), so skip the ~3s server-side .prev backup copy.
	Versioned bool `toml:"versioned"`
	// ReadOnly refuses every mutating command against this storage. It is
	// policy, not crypto: it constrains cooperating clients (an honest agent
	// doing something destructive by accident), it does not contain
	// adversaries — anyone who can decrypt can forge writes with their own
	// tooling. Enforced read-only comes from the storage credential itself
	// (e.g. a read-only B2 application key behind the rclone remote).
	ReadOnly bool `toml:"read_only"`
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
	if err := entry.check(name); err != nil {
		return "", err
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
		if st.Path != "" {
			fmt.Fprintf(&b, "path      = %q   # local vault directory (no rclone); attach a remote later with `notenv vault copy`\n", st.Path)
		} else {
			fmt.Fprintf(&b, "remote    = %q\n", st.Remote)
			fmt.Fprintf(&b, "base      = %q\n", st.Base)
			fmt.Fprintf(&b, "versioned = %t   # remote keeps old versions on overwrite (B2: yes), so skip backup copies\n", st.Versioned)
		}
		if st.ReadOnly {
			b.WriteString("read_only = true   # refuse mutating commands here (policy for cooperating clients, not enforcement)\n")
		}
		// The ciphertext cache is remote-only: a local vault is its own disk,
		// so its reads always verify the manifest and cache nothing.
		if st.Path == "" {
			if st.CacheTTL != "" {
				fmt.Fprintf(&b, "cache_ttl = %q\n", st.CacheTTL)
			} else {
				b.WriteString("# cache_ttl = \"1h\"   # local ciphertext cache lifetime (tmpfs, Linux only); \"0\" disables\n")
			}
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
// to a named storage and pins its namespace. It lives beside the contract and
// is never committed.
const LocalBindingFile = "notenv.local.toml"

// LocalBinding is what a checkout has locally agreed to: which configured
// storage it uses (empty means "resolve from the machine config") and which
// namespace it reads. The namespace pin is a security boundary, not a
// convenience: the committed contract chooses the namespace, so without a
// local pin a cloned repository could silently point a checkout at any other
// project's secrets in the bound vault.
type LocalBinding struct {
	Storage   string `toml:"storage"`
	Namespace string `toml:"namespace"`
}

// ReadLocalBinding returns the project's local binding in dir. A missing file
// is a zero binding, not an error.
func ReadLocalBinding(dir string) (LocalBinding, error) {
	path := filepath.Join(dir, LocalBindingFile)
	var b LocalBinding
	if _, err := toml.DecodeFile(path, &b); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return LocalBinding{}, nil
		}
		return LocalBinding{}, fmt.Errorf("%s: %w", path, err)
	}
	return b, nil
}

// WriteLocalBinding records the binding for the project in dir and returns the
// file path. The caller is responsible for git-ignoring it.
func WriteLocalBinding(dir string, b LocalBinding) (string, error) {
	path := filepath.Join(dir, LocalBindingFile)
	var content strings.Builder
	content.WriteString("# notenv project-local binding (NOT committed).\n")
	if b.Storage != "" {
		content.WriteString("# storage: which configured storage this checkout uses; see `notenv setup`.\n")
		fmt.Fprintf(&content, "storage = %q\n", b.Storage)
	}
	if b.Namespace != "" {
		content.WriteString("# namespace: pinned so the committed contract can't silently retarget\n")
		content.WriteString("# this checkout at another project's secrets. Re-run `notenv init` to change it.\n")
		fmt.Fprintf(&content, "namespace = %q\n", b.Namespace)
	}
	if err := os.WriteFile(path, []byte(content.String()), 0o644); err != nil {
		return "", err
	}
	return path, nil
}

// NamespaceDecision is CheckNamespacePin's verdict on using a contract's
// namespace in a checkout.
type NamespaceDecision int

const (
	// NamespaceOK: the checkout already pinned this namespace; proceed.
	NamespaceOK NamespaceDecision = iota
	// NamespacePin: first use and the namespace is just the directory's name
	// (the obvious default); pin it without ceremony.
	NamespacePin
	// NamespaceConfirm: first use of an explicitly chosen namespace; pinning it
	// is a decision the user should see (confirm interactively, warn in CI).
	NamespaceConfirm
)

// CheckNamespacePin decides whether a checkout may use the contract's resolved
// namespace. derived is the namespace the directory name would yield. A pinned
// checkout whose contract now names a different namespace is refused: the
// committed contract selects which secrets reach a child process, so changing
// it underneath an existing checkout is either an attack or a rename the user
// must explicitly re-accept (`notenv init` re-pins).
func CheckNamespacePin(b LocalBinding, resolved, derived string) (NamespaceDecision, error) {
	switch {
	case b.Namespace == resolved:
		return NamespaceOK, nil
	case b.Namespace != "":
		return 0, fmt.Errorf("the contract requests namespace %q but this checkout is pinned to %q; if the rename is intentional, re-run `notenv init` to re-pin, otherwise treat the contract change as suspect", resolved, b.Namespace)
	case resolved == derived:
		return NamespacePin, nil
	default:
		return NamespaceConfirm, nil
	}
}

// ReadOnlyEnv reports whether NOTENV_READONLY marks this whole process
// read-only — the env-shaped sibling of a storage entry's read_only, for
// wrapping an agent without touching the machine config. Any value but "" and
// "0" counts.
func ReadOnlyEnv() bool {
	v := os.Getenv("NOTENV_READONLY")
	return v != "" && v != "0"
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
	Path         string // local vault directory (absolute); empty for remote storages
	Remote       string // rclone remote name; empty for local storages
	Base         string // path within the remote
	Versioned    bool   // remote retains versions on overwrite
	ReadOnly     bool   // policy: refuse mutating commands against this storage
	Namespace    string
	Mode         string        // crypto mode
	CacheTTL     time.Duration // master-key cache TTL; <= 0 disables caching
	BlobCacheTTL time.Duration // local ciphertext cache TTL; <= 0 disables
}

// Local reports whether the storage is a local vault directory.
func (e Effective) Local() bool { return e.Path != "" }

// Scope returns the storage's local-state scope (key cache, pins, seq
// counters). Local storages scope on ":local" plus the absolute path — a
// ":" cannot appear in an rclone remote name, so a local scope can never
// collide with a remote's, however the remote is named.
func (e Effective) Scope() string {
	if e.Local() {
		return CacheScope(":local", e.Path)
	}
	return CacheScope(e.Remote, e.Base)
}

// check validates that an entry is exactly one kind: a local path or a
// remote. Run on write (so a contradictory entry can't be recorded) and on
// resolution (so a hand-edited config still fails closed).
func (st StorageEntry) check(name string) error {
	confPath, _ := Path()
	switch {
	case st.Path != "" && st.Remote != "":
		return fmt.Errorf("storage %q sets both path and remote; it must be exactly one (fix it in %s)", name, confPath)
	case st.Path == "" && st.Remote == "":
		return fmt.Errorf("storage %q has neither path nor remote configured; fix it in %s or re-run `notenv setup --name %s`", name, confPath, name)
	}
	return nil
}

// storageEffective fills the storage half of an Effective from a named entry,
// validating that the entry is exactly one kind and normalizing it (base
// default, path expansion).
func storageEffective(name string, st StorageEntry) (Effective, error) {
	eff := Effective{StorageName: name, Versioned: st.Versioned, ReadOnly: st.ReadOnly}
	if err := st.check(name); err != nil {
		return eff, err
	}
	if st.Path != "" {
		p, err := AbsPath(st.Path)
		if err != nil {
			return eff, fmt.Errorf("storage %q: %w", name, err)
		}
		eff.Path = p
		return eff, nil
	}
	eff.Remote = st.Remote
	eff.Base = firstOf(st.Base, DefaultBase)
	return eff, nil
}

// ResolveStorage selects and normalizes a storage without a project contract
// (storage-wide commands: the key family, vault copy).
func ResolveStorage(u *User, explicit string) (Effective, error) {
	name, st, err := u.SelectStorage(explicit)
	if err != nil {
		return Effective{}, err
	}
	return storageEffective(name, st)
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
	eff, err := storageEffective(name, st)
	if err != nil {
		return eff, err
	}
	eff.Namespace = firstOf(f.Namespace, filepath.Base(contractDir))
	if !contract.NamespaceName.MatchString(eff.Namespace) {
		return eff, fmt.Errorf("derived namespace %q is not a valid object name; set namespace explicitly in %s", eff.Namespace, contract.FileName)
	}
	return cryptoEffective(u, eff, st, name)
}

// ResolveNamespace is Resolve without a project: an explicitly named namespace
// (--namespace) combined with a selected storage. The vault is addressed
// directly — no contract, no checkout, no cwd.
func ResolveNamespace(u *User, storageName, namespace string) (Effective, error) {
	name, st, err := u.SelectStorage(storageName)
	if err != nil {
		return Effective{}, err
	}
	eff, err := storageEffective(name, st)
	if err != nil {
		return eff, err
	}
	eff.Namespace = namespace
	if !contract.NamespaceName.MatchString(namespace) {
		return eff, fmt.Errorf("namespace %q is not a valid object name (must match %s)", namespace, contract.NamespaceName)
	}
	return cryptoEffective(u, eff, st, name)
}

// cryptoEffective fills the crypto half of an Effective: mode and the two
// cache TTLs.
func cryptoEffective(u *User, eff Effective, st StorageEntry, name string) (Effective, error) {
	eff.Mode = firstOf(u.Crypto.Mode, ModePass)
	if eff.Mode != ModePass {
		return eff, fmt.Errorf("unsupported crypto mode %q (MVP supports %q)", eff.Mode, ModePass)
	}
	ttl, err := u.MasterCacheTTL()
	if err != nil {
		return eff, fmt.Errorf("invalid crypto.cache_ttl %q: %w", u.Crypto.CacheTTL, err)
	}
	eff.CacheTTL = ttl
	// Local vaults never blob-cache. The cache exists to skip a network
	// round-trip plus a fold, and its warm path skips header and manifest
	// verification entirely — a trade justified against a network, not
	// against the same disk. A local vault verifies the manifest on every
	// read and keeps no second ciphertext copy; cache_ttl is remote-only.
	// (The master-key cache is untouched: it avoids re-prompting the
	// passphrase, equally valuable locally.)
	if eff.Local() {
		eff.BlobCacheTTL = 0
		return eff, nil
	}
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
// has seen, plus the master's encryption and signing public keys it expects.
// It is not secret (the threat is storage write, not local read), so it lives
// in a plain local file.
//
// Pins are keyed by the vault's own ID, not by where the vault happens to be
// stored, so trust survives relocating a vault to another remote or base. A
// separate scope → vault-ID binding records which vault each storage location
// held: without it, substituting a header with a freshly minted vault ID would
// sidestep the pin entirely (no pin under the new ID, trust on first use).
// A bound scope whose header claims a different vault ID — or no header at
// all — is therefore an alarm, never a fresh start.
type Pin struct {
	Revision  int    `json:"revision"`
	MasterPub string `json:"master_pub"`
	SignPub   string `json:"sign_pub"`
}

// trustState is the on-disk shape of pins.json.
type trustState struct {
	// Vaults maps vault ID → pin.
	Vaults map[string]Pin `json:"vaults"`
	// Scopes maps storage scope (CacheScope) → the vault ID seen there.
	Scopes map[string]string `json:"scopes"`
	// Namespaces maps storage scope → the namespaces this user has accepted
	// addressing there explicitly (--namespace) — the dirless sibling of the
	// checkout's namespace pin, since without a checkout there is no
	// notenv.local.toml to record acceptance in.
	Namespaces map[string][]string `json:"namespaces,omitempty"`
}

func pinPath() (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "pins.json"), nil
}

func loadTrust() (*trustState, error) {
	state := &trustState{Vaults: map[string]Pin{}, Scopes: map[string]string{}, Namespaces: map[string][]string{}}
	path, err := pinPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return state, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(data, state); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if state.Vaults == nil {
		state.Vaults = map[string]Pin{}
	}
	if state.Scopes == nil {
		state.Scopes = map[string]string{}
	}
	if state.Namespaces == nil {
		state.Namespaces = map[string][]string{}
	}
	return state, nil
}

func saveTrust(state *trustState) error {
	path, err := pinPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// ReadPin returns the stored pin for a vault (have=false if none).
func ReadPin(vaultID string) (p Pin, have bool, err error) {
	state, err := loadTrust()
	if err != nil {
		return Pin{}, false, err
	}
	p, have = state.Vaults[vaultID]
	return p, have, nil
}

// WritePin records the pin for a vault and binds the scope it was seen at.
func WritePin(scope, vaultID string, p Pin) error {
	state, err := loadTrust()
	if err != nil {
		return err
	}
	state.Vaults[vaultID] = p
	state.Scopes[scope] = vaultID
	return saveTrust(state)
}

// ScopeVault returns the vault ID previously seen at a storage scope
// (bound=false if this machine has never pinned anything there).
func ScopeVault(scope string) (vaultID string, bound bool, err error) {
	state, err := loadTrust()
	if err != nil {
		return "", false, err
	}
	vaultID, bound = state.Scopes[scope]
	return vaultID, bound, nil
}

// NamespaceAccepted reports whether this user has explicitly accepted
// addressing a namespace at a storage scope before (--namespace first use).
func NamespaceAccepted(scope, namespace string) (bool, error) {
	state, err := loadTrust()
	if err != nil {
		return false, err
	}
	return slices.Contains(state.Namespaces[scope], namespace), nil
}

// AcceptNamespace records the acceptance of a namespace at a storage scope.
func AcceptNamespace(scope, namespace string) error {
	state, err := loadTrust()
	if err != nil {
		return err
	}
	if slices.Contains(state.Namespaces[scope], namespace) {
		return nil
	}
	state.Namespaces[scope] = append(state.Namespaces[scope], namespace)
	sort.Strings(state.Namespaces[scope])
	return saveTrust(state)
}

// ForgetScope removes a scope's binding, its vault's pin (`notenv key
// forget`, after a deliberate vault reset), and the namespaces accepted
// there. The pin survives if another scope still references the vault (the
// same vault reachable through two storage configurations). Forgetting an
// unbound scope still drops its namespace acceptances.
func ForgetScope(scope string) error {
	state, err := loadTrust()
	if err != nil {
		return err
	}
	_, hadNamespaces := state.Namespaces[scope]
	delete(state.Namespaces, scope)
	vaultID, bound := state.Scopes[scope]
	if !bound {
		if !hadNamespaces {
			return nil
		}
		return saveTrust(state)
	}
	delete(state.Scopes, scope)
	stillReferenced := false
	for _, id := range state.Scopes {
		if id == vaultID {
			stillReferenced = true
			break
		}
	}
	if !stillReferenced {
		delete(state.Vaults, vaultID)
	}
	return saveTrust(state)
}

// ErrMasterChanged reports that an observed header wraps a different master
// than the pinned one. The caller distinguishes it from other pin failures
// because it has a second chance: a chain of signed transitions from the
// pinned master can prove the change legitimate before the alarm stands.
var ErrMasterChanged = errors.New("the vault's master key changed unexpectedly: a legitimate rotation on another machine, or a substitution attack. If you have confirmed it is legitimate, run `notenv key trust`; otherwise treat the storage as compromised")

// CheckPin compares an observed header (revision, master public key) against the
// stored pin. It returns advance=true when the pin should move forward (or on
// first contact), or an actionable error: ErrMasterChanged for an unexpected
// master (the caller may try signed transitions before alarming), or a
// rollback error for an older revision.
func CheckPin(stored Pin, have bool, obsRevision int, obsMasterPub string) (advance bool, err error) {
	if !have {
		return true, nil // trust on first use
	}
	if obsMasterPub != stored.MasterPub {
		return false, ErrMasterChanged
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

// AbsPath expands a leading "~" and makes the path absolute.
func AbsPath(path string) (string, error) {
	if path == "~" || strings.HasPrefix(path, "~/") || strings.HasPrefix(path, `~\`) {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		path = filepath.Join(home, path[1:])
	}
	return filepath.Abs(path)
}

// DefaultVaultDir is where a named local vault lives by default: the
// platform's data directory, never a repository.
func DefaultVaultDir(name string) (string, error) {
	base, err := dataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "notenv", "vaults", name), nil
}

func dataDir() (string, error) {
	switch runtime.GOOS {
	case "windows":
		if dir := os.Getenv("LocalAppData"); dir != "" {
			return dir, nil
		}
		return os.UserConfigDir()
	case "darwin":
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, "Library", "Application Support"), nil
	default:
		if dir := os.Getenv("XDG_DATA_HOME"); dir != "" {
			return dir, nil
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, ".local", "share"), nil
	}
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
// writes never share a sequence number. The read-modify-write is locked, so two
// concurrent processes on the machine can't read the same counter and collide.
func NextSeq(scope, namespace string) (int, error) {
	dir, err := Dir()
	if err != nil {
		return 0, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return 0, err
	}
	path := filepath.Join(dir, "seq.json")

	unlock, err := lockFile(path + ".lock")
	if err != nil {
		return 0, err
	}
	defer unlock()

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
	data, err := json.MarshalIndent(seqs, "", "  ")
	if err != nil {
		return 0, err
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return 0, err
	}
	return next, nil
}

// lockFile takes an exclusive lock by atomically creating lock, spinning while
// another process holds it and reclaiming a lock left by a crash (one older than
// the stale window). It guards a local, low-contention counter, so a short spin
// is fine. The returned function releases the lock.
func lockFile(lock string) (func(), error) {
	const (
		spin  = 5 * time.Millisecond
		stale = 15 * time.Second
		wait  = 30 * time.Second
	)
	start := time.Now()
	for {
		f, err := os.OpenFile(lock, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			_ = f.Close()
			return func() { _ = os.Remove(lock) }, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return nil, err
		}
		if info, statErr := os.Stat(lock); statErr == nil && time.Since(info.ModTime()) > stale {
			_ = os.Remove(lock) // reclaim a lock left by a crashed process
			continue
		}
		if time.Since(start) > wait {
			return nil, fmt.Errorf("timed out acquiring %s; remove it if no notenv is running", lock)
		}
		time.Sleep(spin)
	}
}
