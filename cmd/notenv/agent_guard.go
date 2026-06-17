package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// knownAgents are the terminal coding agents `run` nudges toward `handoff`,
// keyed by program basename to a display name. Running one through `run` injects
// this namespace's real secret values straight into its environment; `handoff`
// instead hands it a scoped ephemeral vault and keeps the master key out of
// reach, so it is the recommended path for an agent.
var knownAgents = map[string]string{
	"claude":    "Claude Code",
	"codex":     "OpenAI Codex CLI",
	"copilot":   "GitHub Copilot CLI",
	"gemini":    "Gemini CLI",
	"aider":     "Aider",
	"openhands": "OpenHands",
	"cn":        "Continue CLI",
	"opencode":  "OpenCode",
	"agent":     "Cursor CLI",
}

// agentName returns the display name of a known coding agent if argv invokes
// one, matched on the program's basename (with a Windows .exe stripped). It is a
// best-effort, name-only check: a wrapper invocation like `npx <agent>` is not
// matched, because the guard it feeds is accident-proofing, not enforcement.
func agentName(argv []string) (string, bool) {
	if len(argv) == 0 {
		return "", false
	}
	base := filepath.Base(argv[0])
	if runtime.GOOS == "windows" {
		base = strings.TrimSuffix(strings.ToLower(base), ".exe")
	}
	name, ok := knownAgents[base]
	return name, ok
}

// guardAgentRun nudges a human who ran a coding agent through `run` toward
// `handoff`, the recommended path that scopes the agent to an ephemeral vault.
// It only ever asks a human at a terminal: a non-interactive caller (CI, an
// agent harness, a script) proceeds untouched, since there is nobody to answer
// and it ran `run` on purpose, and a process already inside a handoff session is
// scoped, so it is left alone too. Declining (the default) stops before any
// vault is touched and points at the handoff command.
func guardAgentRun(argv []string) error {
	name, ok := agentName(argv)
	if !ok {
		return nil
	}
	if os.Getenv(sessionEnv) != "" {
		return nil // already inside a handoff: scoped, nothing to suggest
	}
	if !interactiveFn() {
		return nil // no human to ask, and the caller ran `run` deliberately
	}
	cmd := filepath.Base(argv[0])
	proceed, err := confirmFn(fmt.Sprintf("%s (%s) looks like a coding agent. `run` injects this namespace's real secret values into its environment with no scoped vault; `notenv handoff -- %s` hands it an ephemeral scoped copy and keeps your master key out of reach. Run it with `run` anyway?", cmd, name, cmd), false)
	if err != nil {
		return err
	}
	if !proceed {
		return fmt.Errorf("stopped before running %q; use `notenv handoff -- %s` to give the agent a scoped vault", cmd, strings.Join(argv, " "))
	}
	return nil
}
