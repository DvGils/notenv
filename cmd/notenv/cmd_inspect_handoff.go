package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/DvGils/notenv/internal/config"
)

var handoffInspectJSON bool

var handoffInspectCmd = &cobra.Command{
	Use:   "handoff",
	Short: "Report whether this process is inside a scoped notenv handoff session",
	Long: `Answer one question for a program notenv launched: am I running against a
scoped, ephemeral handoff vault, or not?

An agent started with "notenv handoff -- <agent>" holds only a scoped copy of one
namespace and can safely query it. An agent started with "notenv run -- <agent>"
(not recommended for agents) instead has the raw secret values injected into its
environment and no scoped vault. This command lets the agent tell the two apart at
startup and, when it is not in a handoff, tell the user they ran the unrecommended
mode and may want to restart under handoff.

It reads only its own environment and the ephemeral vault on disk: no vault is
unlocked, no passphrase is asked, and no secret value is ever printed. The answer is
also the exit code, so a script can branch without parsing:

  notenv inspect handoff   exit 0 = inside a handoff session, exit 1 = not.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		info := detectHandoff()
		if handoffInspectJSON {
			if err := printJSON(info); err != nil {
				return err
			}
		} else {
			w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
			fmt.Fprintf(w, "handoff:\t%s\n", yesNo(info.Handoff))
			if info.Handoff && info.Namespace != "" {
				fmt.Fprintf(w, "namespace:\t%s\n", info.Namespace)
			}
			_ = w.Flush()
		}
		// The answer is the exit code too, the way `inspect KEY` exits 1 when the
		// secret is absent, so an agent can gate on it without parsing output.
		if !info.Handoff {
			return &exitCodeError{code: 1}
		}
		return nil
	},
}

// handoffInspect is the frozen `inspect handoff --json` shape. Namespace is the
// single scope the agent was handed (what it already knows it holds), never an
// enumeration of the real vault's other namespaces; no secret value ever appears.
type handoffInspect struct {
	Version   int    `json:"version"`
	Handoff   bool   `json:"handoff"`
	Namespace string `json:"namespace,omitempty"`
}

// detectHandoff reports whether this process is the agent of a live `notenv
// handoff` (or a descendant of it, e.g. its own `notenv run`). It reads only the
// environment and the filesystem, so it never unlocks a vault or prompts.
func detectHandoff() handoffInspect {
	return evalHandoff(os.Getenv(sessionEnv), os.Getenv(storageEnv), os.Getenv(acceptNamespaceEnv), pidAlive)
}

// evalHandoff is the detection logic, pure given its inputs and an aliveness
// check so every branch is testable without the real process table. A bare
// NOTENV_SESSION is only a claim: an honest environment can carry a stale one (a
// process that detached and outlived its session) or lose it to an unrelated
// `export`. So the claim is confirmed against live ground truth, the ephemeral
// vault itself: it must be the local vault NOTENV_SESSION names, still present on
// disk, and named for a handoff supervisor that is still running. This fails in
// the safe direction. A lost or clobbered NOTENV_SESSION yields a false "no" (a
// harmless nag to restart), while a "yes" requires an actual live handoff behind
// the variables, so it cannot misfire into a false sense of being scoped.
func evalHandoff(session, storage, namespace string, alive func(int) bool) handoffInspect {
	out := handoffInspect{Version: 1}
	if session == "" {
		return out
	}
	path, ok := localSpecPath(storage)
	if !ok {
		return out
	}
	// The session marker must name this very vault; a scope that does not match is
	// a partial clobber of one variable but not the other, so we do not trust it.
	if (config.Effective{Path: path}).Scope() != session {
		return out
	}
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return out // the ephemeral vault is gone: the session is over
	}
	base := filepath.Base(path)
	if !strings.HasPrefix(base, handoffDirPrefix) {
		return out // a local vault, but not a handoff one
	}
	pid, ok := pidFromHandoffDir(base)
	if !ok || !alive(pid) {
		return out // its supervisor has exited: stale leftovers, not a live session
	}
	out.Handoff = true
	out.Namespace = firstNamespace(namespace)
	return out
}

// localSpecPath returns the absolute path of a "local:<path>" storage spec, the
// form `handoff` points the agent at. Anything else (a configured name, an rclone
// spec, a relative or empty path) is not a handoff vault.
func localSpecPath(storage string) (string, bool) {
	const scheme = "local:"
	if !strings.HasPrefix(storage, scheme) {
		return "", false
	}
	path := strings.TrimPrefix(storage, scheme)
	if !filepath.IsAbs(path) {
		return "", false
	}
	return filepath.Clean(path), true
}

// firstNamespace returns the first entry of a NOTENV_ACCEPT_NAMESPACE list, the
// single namespace handoff scoped the agent to.
func firstNamespace(list string) string {
	n, _, _ := strings.Cut(list, ",")
	return strings.TrimSpace(n)
}

func init() {
	handoffInspectCmd.Flags().BoolVar(&handoffInspectJSON, "json", false, "machine-readable output (handoff yes/no and the scoped namespace, never a secret value)")
	inspectCmd.AddCommand(handoffInspectCmd)
}
