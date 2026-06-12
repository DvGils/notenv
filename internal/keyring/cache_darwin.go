//go:build darwin

package keyring

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// keychainCache stores master keys in the macOS Keychain via the security
// CLI (present on every Mac; no cgo). Entries are ciphertext at rest under
// the user's login credentials, the same custody class the platform secret
// store provides for machine identities. The TTL is lazy: the expiry rides
// inside the entry and a stale read deletes it and misses, so an expired key
// persists encrypted until its next touch rather than vanishing at the
// deadline the way the Linux kernel keyring enforces. caching.md states the
// difference.
type keychainCache struct{}

const cacheIsNull = false

func newCache() Cache { return keychainCache{} }

const keychainService = "notenv"

// keychainAccount digests the scope: scopes embed remote paths, and the
// digest keeps the account a fixed, argv-safe token.
func keychainAccount(scope string) string {
	sum := sha256.Sum256([]byte(scope))
	return "scope-" + hex.EncodeToString(sum[:16])
}

func (keychainCache) Get(scope string) (string, bool) {
	out, err := exec.Command("security", "find-generic-password",
		"-s", keychainService, "-a", keychainAccount(scope), "-w").Output()
	if err != nil {
		return "", false
	}
	expiry, key, found := strings.Cut(strings.TrimSpace(string(out)), ":")
	if !found {
		keychainCache{}.Drop(scope)
		return "", false
	}
	deadline, err := strconv.ParseInt(expiry, 10, 64)
	if err != nil || time.Now().Unix() >= deadline {
		keychainCache{}.Drop(scope)
		return "", false
	}
	return key, true
}

func (keychainCache) Store(scope, masterKey string, ttl time.Duration) error {
	if ttl <= 0 {
		return nil
	}
	payload := fmt.Sprintf("%d:%s", time.Now().Add(ttl).Unix(), masterKey)
	// -U updates an existing entry in place instead of failing on it.
	out, err := exec.Command("security", "add-generic-password",
		"-U", "-s", keychainService, "-a", keychainAccount(scope), "-w", payload).CombinedOutput()
	if err != nil {
		return fmt.Errorf("keychain store: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (keychainCache) Drop(scope string) {
	_ = exec.Command("security", "delete-generic-password",
		"-s", keychainService, "-a", keychainAccount(scope)).Run()
}
