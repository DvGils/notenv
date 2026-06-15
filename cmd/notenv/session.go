package main

// A handoff session takes a no-cache lease on its source vault's scope: while
// the lease is live, no notenv process on the machine caches that vault's master
// (cacheMaster consults leaseActive). This closes the one honest edge of
// `handoff`, an accidental concurrent unlock in another terminal leaving the
// master in the shared per-uid cache where the agent could read it. The marker
// is not a secret (a scope digest plus the supervisor PID), so it lives in a
// per-user runtime dir on every platform; a marker whose owning process is gone
// is stale and ignored, so a SIGKILLed session cannot wedge caching forever.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

// sessionEnv marks a process as running inside a handoff session and carries the
// scope of the one ephemeral vault it may unlock. It is set on the agent's
// environment by `handoff` (never on the builder's), so the builder can still
// unlock the source vault.
const sessionEnv = "NOTENV_SESSION"

// sessionGuard fails closed when a process inside a handoff session tries to
// unlock any vault but the session's ephemeral one. The agent is pointed only at
// the ephemeral vault E (NOTENV_SESSION carries E's scope); E is identity-only
// and never prompts, so an attempt to unlock a different, passphrase-gated vault
// is a misconfiguration (a stray --storage, or a sub-tool pointed at your real
// vault), and we refuse it rather than prompt you and re-cache your master. This
// is accident-reduction and master protection, not agent containment: the marker
// is same-uid and strippable, and we deliberately do not chase a malicious agent
// (that is the OS's job, see design/ephemeral-scope.md).
func sessionGuard(scope string) error {
	want := os.Getenv(sessionEnv)
	if want == "" || want == scope {
		return nil
	}
	return fmt.Errorf("this is a notenv handoff session scoped to one ephemeral vault; refusing to unlock a different vault (point NOTENV_STORAGE at the handed-off vault, or run this outside the session)")
}

// sessionDir is the per-user directory holding session lease markers. It prefers
// XDG_RUNTIME_DIR (tmpfs, auto-cleaned on logout) on Linux and falls back to the
// user cache dir elsewhere; the marker holds no secret, and the PID check below
// handles staleness whether or not the directory self-cleans.
func sessionDir() (string, error) {
	if rt := os.Getenv("XDG_RUNTIME_DIR"); rt != "" {
		return filepath.Join(rt, "notenv", "sessions"), nil
	}
	base, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "notenv", "sessions"), nil
}

// leaseDir is the per-scope directory holding one marker file per live handoff
// supervisor (each filename is its PID). Refcounting via separate files lets
// concurrent handoffs of the same source vault coexist: the lease is active while
// ANY supervisor's marker is live, and each session removes only its own, so the
// first to finish cannot cancel the lease the others still rely on. The scope is
// hashed so the directory name is filesystem-safe and does not spell out the
// storage location.
func leaseDir(scope string) (string, error) {
	dir, err := sessionDir()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(scope))
	return filepath.Join(dir, hex.EncodeToString(sum[:16])+".lease.d"), nil
}

// takeLease registers this process as a no-cache-lease holder on scope and returns
// a release func that removes only this holder's marker (and the directory once it
// empties). A missing lease only means caching is not suppressed, never a loss of
// the master guarantee (the builder drops the cache and cannot refill it), so
// callers may proceed on error.
func takeLease(scope string) (func(), error) {
	dir, err := leaseDir(scope)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	marker := filepath.Join(dir, strconv.Itoa(os.Getpid()))
	if err := os.WriteFile(marker, nil, 0o600); err != nil {
		return nil, err
	}
	return func() {
		_ = os.Remove(marker)
		_ = os.Remove(dir) // succeeds only when this was the last holder
	}, nil
}

// leaseActive reports whether any live no-cache lease covers scope. A marker whose
// owning process is gone, or whose name is not a PID, is reaped, so a crashed
// session cannot suppress caching forever; an emptied directory is removed too.
func leaseActive(scope string) bool {
	dir, err := leaseDir(scope)
	if err != nil {
		return false
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	active := false
	for _, e := range entries {
		if pid, err := strconv.Atoi(e.Name()); err == nil && pid > 0 && pidAlive(pid) {
			active = true
			continue
		}
		_ = os.Remove(filepath.Join(dir, e.Name())) // dead PID or stray file
	}
	if !active {
		_ = os.Remove(dir)
	}
	return active
}
