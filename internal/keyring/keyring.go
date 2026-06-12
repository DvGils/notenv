// Package keyring handles credential acquisition: hidden terminal prompts
// plus a platform-specific session cache for the unwrapped master key. On
// Linux the cache is the kernel keyring: the key lives in kernel memory,
// expires on TTL, and never touches disk, the same trust model as an
// ssh-agent. Elsewhere the cache is a no-op and every acquisition prompts
// (macOS Keychain and Windows Credential Manager are planned as their own
// cache_GOOS.go implementations).
package keyring

import (
	"errors"
	"fmt"
	"os"
	"time"

	"golang.org/x/term"
)

// Cache is a session-scoped cache for the unwrapped master key (its identity
// string: never the passphrase, which unlocks every future rewrap and is
// strictly more valuable). Keyed by an opaque scope string (notenv uses a
// length-prefixed remote+base, one entry per storage base, see
// config.CacheScope). Implementations must never persist the key to disk.
type Cache interface {
	// Get returns the cached master key for a scope, if present.
	Get(scope string) (string, bool)
	// Store caches the master key. A non-positive ttl is the caller's
	// signal not to call Store at all; implementations may also treat it
	// as "do not cache".
	Store(scope, masterKey string, ttl time.Duration) error
	// Drop invalidates a cached master key (e.g. after it failed to
	// decrypt because the vault was re-keyed under a new one).
	Drop(scope string)
}

// DefaultCache returns this platform's cache: kernel keyring on Linux,
// no-op elsewhere.
func DefaultCache() Cache { return newCache() }

// ReadSecret prompts on the controlling terminal with echo disabled.
// It prefers the console device (/dev/tty; CONIN$ on Windows) so prompts
// work even when stdin is a pipe (e.g. `notenv set --stdin`).
func ReadSecret(label string) (string, error) {
	tty, err := openConsole()
	if err != nil {
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			return "", errors.New("no terminal available for hidden prompt")
		}
		tty = os.Stdin
	} else {
		defer tty.Close()
	}

	fmt.Fprint(os.Stderr, label)
	value, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("read hidden input: %w", err)
	}
	return string(value), nil
}

// PromptPassphrase asks for an existing passphrase (non-empty).
func PromptPassphrase(label string) (string, error) {
	pass, err := ReadSecret(label)
	if err != nil {
		return "", err
	}
	if pass == "" {
		return "", errors.New("empty passphrase")
	}
	return pass, nil
}

// PromptNewPassphrase asks twice, used when creating the key header, where
// a typo would be unrecoverable.
func PromptNewPassphrase(label string) (string, error) {
	pass, err := PromptPassphrase(label)
	if err != nil {
		return "", err
	}
	again, err := ReadSecret("Confirm passphrase: ")
	if err != nil {
		return "", err
	}
	if pass != again {
		return "", errors.New("passphrases do not match")
	}
	return pass, nil
}
