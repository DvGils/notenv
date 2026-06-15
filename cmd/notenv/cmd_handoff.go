package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"filippo.io/age"
	"github.com/spf13/cobra"

	"github.com/DvGils/notenv/internal/config"
	"github.com/DvGils/notenv/internal/keyring"
	"github.com/DvGils/notenv/internal/runner"
	"github.com/DvGils/notenv/internal/ui"
)

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

	// Generate the fresh ephemeral identity Me. The parent keeps the private half
	// (it becomes the agent's credential) and passes only the public recipient to
	// the builder, so the builder never holds or returns your master (R2/R3).
	me, err := age.GenerateX25519Identity()
	if err != nil {
		return fmt.Errorf("generate ephemeral key: %w", err)
	}

	// Create the ephemeral vault directory, RAM-backed where available.
	eDir, err := os.MkdirTemp(ephemeralBase(), "notenv-handoff-")
	if err != nil {
		return fmt.Errorf("create ephemeral vault directory: %w", err)
	}
	defer os.RemoveAll(eDir)
	eScope := config.Effective{Path: eDir}.Scope()
	defer config.ForgetScope(eScope)          // drop E's local trust pin
	defer keyring.DefaultCache().Drop(eScope) // drop E's master from the cache

	// Take the no-cache lease on the source for the session's lifetime: while the
	// agent runs, the source master stays out of the shared cache even if you
	// unlock the same vault in another terminal.
	if release, err := takeLease(srcScope); err != nil {
		ui.Warnf("could not take a no-cache lease on the source vault (%v); avoid unlocking it elsewhere during this session", err)
	} else {
		defer release()
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
	build := exec.Command(exe, "__handoff-build",
		"--source", srcSpec,
		"--namespaces", namespace,
		"--vault", eDir,
		"--recipient", recipient,
	)
	build.Env = os.Environ()
	build.Stdin = os.Stdin
	build.Stdout = os.Stderr
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			// The builder already printed why; do not double-report.
			return errors.New("could not build the ephemeral vault (see the error above)")
		}
		return fmt.Errorf("could not run the ephemeral vault builder: %w", err)
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

func init() {
	// Stop flag parsing at the first non-flag arg so flags meant for the agent are
	// not consumed by notenv (mirrors `run`); the leading `--` still works too.
	handoffCmd.Flags().SetInterspersed(false)
}
