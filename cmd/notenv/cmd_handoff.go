package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"filippo.io/age"
	"github.com/spf13/cobra"

	"github.com/DvGils/notenv/internal/config"
	"github.com/DvGils/notenv/internal/keyring"
	"github.com/DvGils/notenv/internal/runner"
	"github.com/DvGils/notenv/internal/ui"
)

// handoffDirPrefix names every ephemeral vault directory; the supervisor PID
// follows it ("notenv-handoff-<pid>-<random>") so a sweep can check liveness.
const handoffDirPrefix = "notenv-handoff-"

var handoffCmd = &cobra.Command{
	Use:   "handoff -- command [args...]",
	Short: "Hand a coding agent a scoped, ephemeral copy of this project's secrets",
	Long: `Hand a local coding agent (Claude Code, Codex, ...) a scoped, ephemeral vault
and run it, so it can use your secrets and run real tests without ever holding
the key to the rest of your vault.

The namespace is resolved the way "run" resolves it: from the project in the
current directory, or with --namespace. handoff mints an ephemeral vault holding
only that namespace's secrets, under a fresh key, and points the agent at it, so
the agent's own "notenv run -- cmd" resolves the same namespace and gets the real
values. Your master key is never in the agent's reach, so a compromised or
prompt-injected agent can leak at most the namespace you scoped in, never the
rest of your vault. The ephemeral vault is destroyed when the agent exits.

This protects your master key; it is not a sandbox. The agent runs as you and
can use, store, or leak the secrets you scoped in, so hand off only to an agent
you trust, and contain what it can do with the OS (a sandbox, network egress
control) if you need that.

Exit codes follow the same convention as "run": the agent's own code passes
through; 125 means notenv itself failed.`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		err := runHandoff(cmd, args)
		var ec *exitCodeError
		if err != nil && !errors.As(err, &ec) {
			return &exitCodeError{code: 125, err: err}
		}
		return err
	},
}

func runHandoff(cmd *cobra.Command, agentArgv []string) error {
	ctx := cmd.Context()

	// Resolve the source storage and namespace exactly as `run` does: the project
	// contract auto-detected from the working directory, or --namespace. This is
	// what makes the agent's own `notenv run` resolve the same namespace it was
	// handed. loadApp also runs the namespace guard; it does not unlock anything,
	// so the parent never touches your master (the builder does, see R2).
	a, err := loadApp(ctx)
	if err != nil {
		return err
	}
	namespace, srcSpec, srcScope := a.namespace, a.sourceSpec, a.cacheScope

	// Clean up after any earlier handoff that died without running its teardown
	// (SIGKILL, power loss): remove its leftover ephemeral vault and forget its
	// trust pin. A session whose supervisor is still alive is left untouched.
	sweepStaleHandoffs()

	// Generate the fresh ephemeral identity Me. The parent keeps the private half
	// (it becomes the agent's credential) and passes only the public recipient to
	// the builder, so the builder never holds or returns your master (R2/R3).
	me, err := age.GenerateX25519Identity()
	if err != nil {
		return fmt.Errorf("generate ephemeral key: %w", err)
	}

	// Create the ephemeral vault directory, RAM-backed where available. Its name
	// carries this process's PID so a later sweep can tell a dead session's
	// leftovers from a concurrent live one.
	eDir, err := os.MkdirTemp(ephemeralBase(), fmt.Sprintf("%s%d-", handoffDirPrefix, os.Getpid()))
	if err != nil {
		return fmt.Errorf("create ephemeral vault directory: %w", err)
	}
	eScope := config.Effective{Path: eDir}.Scope()

	// Teardown for this session: release the source no-cache lease, drop E's
	// master from the cache, forget E's local trust pin, and remove E's vault. It
	// runs on every return path. Both the builder and the agent run through
	// runner.Run, which catches termination signals and returns rather than letting
	// the default handler kill us, so a Ctrl-C still unwinds through here; the
	// startup sweep is the backstop for an uncatchable kill (SIGKILL, power loss).
	var releaseLease func()
	defer func() {
		if releaseLease != nil {
			releaseLease()
		}
		keyring.DefaultCache().Drop(eScope)
		_ = config.ForgetScope(eScope)
		_ = os.RemoveAll(eDir)
	}()

	// Take the no-cache lease on the source for the session's lifetime: while the
	// agent runs, the source master stays out of the shared cache even if you
	// unlock the same vault in another terminal.
	if release, err := takeLease(srcScope); err != nil {
		ui.Warnf("could not take a no-cache lease on the source vault (%v); avoid unlocking it elsewhere during this session", err)
	} else {
		releaseLease = release
	}

	// Build E in a subprocess that unlocks the source and exits before the agent
	// runs, so no live process holds your master while the agent is alive (R2).
	if err := runBuilder(srcSpec, namespace, eDir, me.Recipient().String()); err != nil {
		return err
	}

	// Spawn the agent pointed only at E.
	env := handoffEnv(os.Environ(), eDir, eScope, me.String(), namespace)
	ui.Notef("handed off namespace %q to an ephemeral vault; your master is not in the agent's reach", namespace)
	code, err := runner.Run(agentArgv, env, os.Stdin, os.Stdout, os.Stderr)
	if err != nil {
		return classifyRunError(err)
	}
	if code != 0 {
		return &exitCodeError{code: code}
	}
	return nil
}

// runBuilder re-execs notenv as the hidden builder subprocess. The builder gets
// the user's environment (it needs the controlling terminal to prompt for the
// passphrase, and NOTENV_IDENTITY for the precondition check) but NOT
// NOTENV_SESSION, so it can still unlock the source. Its chatter goes to stderr,
// keeping the agent's stdout clean.
func runBuilder(srcSpec, namespace, eDir, recipient string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	// Run through runner.Run so the builder gets the same signal handling as the
	// agent: a Ctrl-C at its passphrase prompt is forwarded to it and we get its
	// exit code back, rather than the default handler killing us and skipping the
	// caller's teardown. Its output goes to stderr, keeping the agent's stdout
	// clean. stdin is wired, though the passphrase prompt reads /dev/tty directly.
	argv := []string{exe, "__handoff-build",
		"--source", srcSpec,
		"--namespaces", namespace,
		"--vault", eDir,
		"--recipient", recipient,
	}
	code, err := runner.Run(argv, os.Environ(), os.Stdin, os.Stderr, os.Stderr)
	if err != nil {
		return fmt.Errorf("could not run the ephemeral vault builder: %w", err)
	}
	if code != 0 {
		// The builder already printed why; do not double-report.
		return errors.New("could not build the ephemeral vault (see the error above)")
	}
	return nil
}

// handoffEnv builds the agent's environment: the user's, stripped of the real
// credential, then pointed only at the ephemeral vault. NOTENV_SESSION marks the
// agent as in-session and fails closed any attempt to unlock another vault;
// NOTENV_ACCEPT_NAMESPACE lets a projectless read of E skip the first-use prompt.
func handoffEnv(base []string, eDir, eScope, meIdentity, namespace string) []string {
	env := stripCredentialEnv(base) // remove the user's real NOTENV_IDENTITY
	env = upsertEnv(env, storageEnv, "local:"+eDir)
	env = upsertEnv(env, identityEnv, meIdentity)
	env = upsertEnv(env, sessionEnv, eScope)
	env = upsertEnv(env, acceptNamespaceEnv, namespace)
	return env
}

// upsertEnv replaces any existing KEY= entry and appends KEY=val, so the agent
// gets exactly our value regardless of what it inherited.
func upsertEnv(env []string, key, val string) []string {
	out := make([]string, 0, len(env)+1)
	for _, kv := range env {
		if name, _, ok := strings.Cut(kv, "="); ok && name == key {
			continue
		}
		out = append(out, kv)
	}
	return append(out, key+"="+val)
}

// storageSpec renders a resolved storage as a self-contained NOTENV_STORAGE spec.
func storageSpec(eff config.Effective) string {
	if eff.Local() {
		return "local:" + eff.Path
	}
	return "rclone:" + eff.Remote + ":" + eff.Base
}

// ephemeralBase is the directory the ephemeral vault is created under: a
// RAM-backed runtime dir where available (Linux tmpfs via XDG_RUNTIME_DIR), else
// the per-user temp dir. On macOS/Windows the temp dir is on disk; the ciphertext
// there is the scoped namespace only and decrypts solely with the ephemeral key,
// which is destroyed at teardown (the same caveat class as the `edit` buffer).
func ephemeralBase() string {
	if rt := os.Getenv("XDG_RUNTIME_DIR"); rt != "" {
		return rt
	}
	return os.TempDir()
}

// sweepStaleHandoffs removes the residue of handoff sessions that exited without
// running their teardown (an uncatchable SIGKILL or a power loss): leftover
// ephemeral vault directories and the trust pins they left in pins.json. A
// directory or pin whose supervisor PID is still alive belongs to a running
// session and is left alone, so concurrent handoffs are safe. Best-effort: any
// error just means the residue is swept on a later run.
func sweepStaleHandoffs() {
	base := ephemeralBase()
	// Leftover directories (clutter on non-tmpfs; also covers a kill before any
	// pin was written). Forget the matching pin here too, by recomputing its scope.
	if entries, err := os.ReadDir(base); err == nil {
		for _, e := range entries {
			name := e.Name()
			if !e.IsDir() || !strings.HasPrefix(name, handoffDirPrefix) {
				continue
			}
			if pid, ok := pidFromHandoffDir(name); ok && pidAlive(pid) {
				continue // a live session owns it
			}
			dir := filepath.Join(base, name)
			_ = config.ForgetScope(config.Effective{Path: dir}.Scope())
			_ = os.RemoveAll(dir)
		}
	}
	// Orphan pins whose ephemeral vault is already gone (the tmpfs case: the
	// directory vanished on logout/reboot, but pins.json persists).
	scopes, err := config.PinnedScopes()
	if err != nil {
		return
	}
	for _, scope := range scopes {
		path, ok := config.LocalScopePath(scope)
		if !ok || filepath.Dir(path) != base || !strings.HasPrefix(filepath.Base(path), handoffDirPrefix) {
			continue
		}
		if pid, ok := pidFromHandoffDir(filepath.Base(path)); ok && pidAlive(pid) {
			continue
		}
		if _, err := os.Stat(path); err == nil {
			continue // still on disk: handled by the directory pass above
		}
		_ = config.ForgetScope(scope)
	}
}

// pidFromHandoffDir extracts the supervisor PID from an ephemeral vault directory
// name ("notenv-handoff-<pid>-<random>").
func pidFromHandoffDir(name string) (int, bool) {
	rest := strings.TrimPrefix(name, handoffDirPrefix)
	dash := strings.IndexByte(rest, '-')
	if dash <= 0 {
		return 0, false
	}
	pid, err := strconv.Atoi(rest[:dash])
	if err != nil || pid <= 0 {
		return 0, false
	}
	return pid, true
}

func init() {
	// Stop flag parsing at the first non-flag arg so flags meant for the agent are
	// not consumed by notenv (mirrors `run`); the leading `--` still works too.
	handoffCmd.Flags().SetInterspersed(false)
}
