package main

// A handoff session takes a global no-cache lease: while the lease is live, no
// notenv process on the machine caches ANY vault's master (cacheMaster consults
// noCacheLeaseActive). A handoff hands an agent your whole uid, and the master
// cache is the shared per-uid keyring, so a master left warm there, the handed-off
// vault's or any sibling vault's, is one the agent could read directly and decrypt
// outside its scope. Suppressing the entire cache for the session keeps the "the
// agent can't get your master" guarantee true for every vault, not just the one
// handed off. The marker is not a secret (just the supervisor PID), so it lives in
// a per-user runtime dir on every platform; a marker whose owning process is gone
// is stale and ignored, so a SIGKILLed session cannot wedge caching forever.

import (
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
	return fmt.Errorf("you're inside a notenv handoff session, which can only open the vault it was handed; refusing to unlock a different one (point NOTENV_STORAGE at the handed-off vault, or run this command outside the handoff)")
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

// noCacheLeaseDir is the single directory holding one marker file per live handoff
// supervisor (each filename is its PID). One directory, not one per scope: the
// lease suppresses caching for every vault, so there is nothing to key it by.
// Refcounting via separate files lets concurrent handoffs coexist: the lease is
// active while ANY supervisor's marker is live, and each session removes only its
// own, so the first to finish cannot cancel the lease the others still rely on.
func noCacheLeaseDir() (string, error) {
	dir, err := sessionDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "nocache.lease.d"), nil
}

// takeNoCacheLease registers this process as a no-cache-lease holder and returns a
// release func that removes only this holder's marker (and the directory once it
// empties). A missing lease only means caching is not suppressed, never a loss of
// the master guarantee (handoff drops the cache and the agent's reads cannot refill
// it past this), so callers may proceed on error.
func takeNoCacheLease() (func(), error) {
	dir, err := noCacheLeaseDir()
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

// noCacheLeaseActive reports whether any live handoff holds the no-cache lease. A
// marker whose owning process is gone, or whose name is not a PID, is reaped, so a
// crashed session cannot suppress caching forever; an emptied directory is removed.
func noCacheLeaseActive() bool {
	dir, err := noCacheLeaseDir()
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
