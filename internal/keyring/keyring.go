// Package keyring handles credential acquisition: hidden terminal prompts
// plus a platform-specific session cache for the unwrapped master key. On
// Linux the cache is the kernel keyring: the key lives in kernel memory,
// expires on TTL, and never touches disk, the same trust model as an
// ssh-agent. On macOS it is the Keychain and on Windows DPAPI, each holding the
// key as ciphertext under the user's login credentials with a lazy TTL (see the
// cache_GOOS.go implementations). On any other platform the cache is a no-op and
// every acquisition prompts.
package keyring

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
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
// Keychain on macOS, DPAPI on Windows, no-op elsewhere.
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

// GeneratePassphrase returns a random diceware-style passphrase: six words
// drawn uniformly from the embedded wordlist, hyphen-joined. Used for the
// temporary onboarding credential, which must be high-entropy without asking
// its issuer to invent it (issuers pick weak ones) and easy to relay over a
// chat message.
func GeneratePassphrase() (string, error) {
	const count = 6
	words := make([]string, count)
	for i := range words {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(tempWords))))
		if err != nil {
			return "", fmt.Errorf("generate passphrase: %w", err)
		}
		words[i] = tempWords[n.Int64()]
	}
	return strings.Join(words, "-"), nil
}
