// Package config loads the user-global config (~/.config/notenv/config.toml,
// not committed) and merges it with the project contract into an effective
// configuration. Storage target is machine-only; the contract contributes
// just the namespace.
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/DvGils/notenv/internal/contract"
)

const (
	DefaultBase         = "notenv"
	ModePass            = "passphrase"
	DefaultCacheTTL     = time.Hour // master-key keyring cache
	DefaultBlobCacheTTL = time.Hour // local ciphertext cache (matches key cache; --refresh forces fresh)
)

type User struct {
	Storage struct {
		Remote string `toml:"remote"`
		Base   string `toml:"base"`
		// Versioned: the remote retains old object versions on overwrite
		// (B2 does natively), so skip the ~3s server-side .prev backup copy.
		Versioned bool `toml:"versioned"`
		// CacheTTL bounds local ciphertext-cache lifetime (Go duration;
		// "0" disables). Default 1h. Same-machine writes refresh the cache
		// instantly; for another machine's change, `run --refresh` or wait
		// out the TTL.
		CacheTTL string `toml:"cache_ttl"`
	} `toml:"storage"`
	Crypto struct {
		Mode string `toml:"mode"`
		// CacheTTL is how long the passphrase cache may hold a passphrase
		// (Go duration string; "0" disables caching). Default: 1h.
		CacheTTL string `toml:"cache_ttl"`
	} `toml:"crypto"`
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

// LoadUser reads the user config. A missing file is not an error: it
// returns a zero-value config (callers surface the "no remote" error later).
func LoadUser() (*User, error) {
	path, err := Path()
	if err != nil {
		return nil, err
	}
	var u User
	if _, err := toml.DecodeFile(path, &u); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return &u, nil
		}
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &u, nil
}

const userTemplate = `# notenv user config (NOT committed). Storage + crypto for this machine.

[storage]
remote    = %q   # rclone remote name (see ` + "`rclone listremotes`" + `)
base      = %q   # path within the remote
versioned = %t   # remote keeps old versions on overwrite (B2: yes), so skip backup copies
# cache_ttl = "1h"   # local ciphertext cache lifetime (tmpfs, Linux only); "0" disables. Use 'notenv run --refresh' to force-pull another machine's change

[crypto]
mode = "passphrase"
# cache_ttl = "1h"   # master-key cache lifetime (Linux kernel keyring); "0" disables
`

// WriteUser writes a fresh user config and returns its path.
func WriteUser(remote, base string, versioned bool) (string, error) {
	path, err := Path()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, fmt.Appendf(nil, userTemplate, remote, base, versioned), 0o600); err != nil {
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

// Effective is the merged result of user config + contract overrides.
type Effective struct {
	Remote       string // rclone remote name
	Base         string // path within the remote
	Versioned    bool   // remote retains versions on overwrite
	Namespace    string
	Mode         string        // crypto mode
	CacheTTL     time.Duration // master-key cache TTL; <= 0 disables caching
	BlobCacheTTL time.Duration // local ciphertext cache TTL; <= 0 disables
}

// Resolve combines the machine config with the contract's namespace and
// applies defaults: base path "notenv", namespace = contract directory name,
// mode "passphrase".
func Resolve(u *User, f *contract.File, contractDir string) (Effective, error) {
	// Storage target is machine config only; the contract contributes the
	// namespace (it cannot redirect where this machine reads/writes; see
	// contract.Parse).
	eff := Effective{
		Remote:    u.Storage.Remote,
		Base:      firstOf(u.Storage.Base, DefaultBase),
		Versioned: u.Storage.Versioned,
		Namespace: firstOf(f.Namespace, filepath.Base(contractDir)),
		Mode:      firstOf(u.Crypto.Mode, ModePass),
	}
	if eff.Remote == "" {
		path, _ := Path()
		return eff, fmt.Errorf("no storage remote configured; run `notenv init --remote NAME` or set storage.remote in %s", path)
	}
	if !contract.NamespaceName.MatchString(eff.Namespace) {
		return eff, fmt.Errorf("derived namespace %q is not a valid object name; set namespace explicitly in %s", eff.Namespace, contract.FileName)
	}
	if eff.Mode != ModePass {
		return eff, fmt.Errorf("unsupported crypto mode %q (MVP supports %q)", eff.Mode, ModePass)
	}
	eff.CacheTTL = DefaultCacheTTL
	if u.Crypto.CacheTTL != "" {
		ttl, err := time.ParseDuration(u.Crypto.CacheTTL)
		if err != nil {
			return eff, fmt.Errorf("invalid crypto.cache_ttl %q: %w", u.Crypto.CacheTTL, err)
		}
		eff.CacheTTL = ttl
	}
	eff.BlobCacheTTL = DefaultBlobCacheTTL
	if u.Storage.CacheTTL != "" {
		ttl, err := time.ParseDuration(u.Storage.CacheTTL)
		if err != nil {
			return eff, fmt.Errorf("invalid storage.cache_ttl %q: %w", u.Storage.CacheTTL, err)
		}
		eff.BlobCacheTTL = ttl
	}
	return eff, nil
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
