//go:build darwin

package keyring

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
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
	if err != nil || time.Now().UnixNano() >= deadline {
		keychainCache{}.Drop(scope)
		return "", false
	}
	return key, true
}

func (keychainCache) Store(scope, masterKey string, ttl time.Duration) error {
	if ttl <= 0 {
		return nil
	}
	// Nanosecond resolution, not seconds: a second-truncated deadline rounds a
	// short TTL down to its sub-second remainder, so an entry stored just before
	// a second boundary can read back already expired (now.Unix() == deadline).
	payload := fmt.Sprintf("%d:%s", time.Now().Add(ttl).UnixNano(), masterKey)
	// Feed the command (and the master key) to `security` over stdin via its
	// interactive mode, never as a -w argv argument. The master key decrypts the
	// whole vault, and argv is readable by any same-user process (ps) and is
	// routinely captured by EDR/MDM agents on managed Macs, which would land the
	// crown-jewel key in logs off-box. Interactive mode reads commands from stdin
	// until EOF and tokenizes each line shell-style, so the fields are
	// single-quote escaped. -U updates an existing entry in place. (Same technique
	// as zalando/go-keyring; keeps notenv cgo-free, unlike the Keychain API.)
	cmd := exec.Command("security", "-i")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("keychain store: %v", err)
	}
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("keychain store: %v", err)
	}
	line := fmt.Sprintf("add-generic-password -U -s %s -a %s -w %s\n",
		shellQuote(keychainService), shellQuote(keychainAccount(scope)), shellQuote(payload))
	// Always close stdin and reap the process, even if the write fails: EOF is
	// what makes security run the command and exit, so skipping it would leak it.
	_, writeErr := io.WriteString(stdin, line)
	closeErr := stdin.Close()
	waitErr := cmd.Wait()
	switch {
	case writeErr != nil:
		return fmt.Errorf("keychain store: %v", writeErr)
	case closeErr != nil:
		return fmt.Errorf("keychain store: %v", closeErr)
	case waitErr != nil:
		return fmt.Errorf("keychain store: %v: %s", waitErr, strings.TrimSpace(out.String()))
	}
	return nil
}

// shellQuote single-quotes s for security's interactive line parser, which
// tokenizes shell-style; the '\” dance escapes an embedded single quote. The
// fields here (service, digested account, the key payload) carry no single
// quotes today, but quoting keeps the line robust if a format ever changes.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func (keychainCache) Drop(scope string) {
	_ = exec.Command("security", "delete-generic-password",
		"-s", keychainService, "-a", keychainAccount(scope)).Run()
}
