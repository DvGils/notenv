package main

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/DvGils/notenv/internal/runner"
	"github.com/DvGils/notenv/internal/ui"
)

var (
	runRefresh bool
	runMask    bool
	runNoMask  bool
	runSalvage bool
	runOnly    []string
)

var runCmd = &cobra.Command{
	Use:   "run -- command [args...]",
	Short: "Run a command with secrets injected as environment variables",
	Long: `Run a command with this project's secrets injected as environment variables.

Captured output is masked: when stdout or stderr is not a terminal (a pipe, a
file, an agent or CI harness reading the output), any injected secret value
appearing in that stream is replaced with <notenv-masked:NAME> before it can
land in a log or an LLM context. A live terminal is wired through untouched,
so colors and interactive programs keep working.

--mask forces masking on a live terminal too; --no-mask disables it everywhere
(e.g. when a consumer needs the raw bytes). Because --no-mask sends raw values
to a captured stream, it asks for your passphrase even when the session key is
cached: plaintext egress needs a human present. Masking is accident-proofing
for output, not a security boundary: the value and its common encodings
(base64, hex, url) are masked, but values shorter than 6 bytes pass through,
and code that holds a secret can always move it some other way.

When the command is a known coding agent, run asks (default No) before
injecting your real secret values into its environment with no scoped vault,
and points you at "notenv handoff -- <agent>", which hands the agent an
ephemeral scoped copy and keeps your master key out of reach. The prompt only
fires for a human at a terminal, so automation is never blocked.

Exit codes (docker's convention): the child's own exit code passes through;
125 means notenv itself failed, 126 the command was found but cannot run,
127 the command was not found.`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// Exit codes follow docker's convention: the child's code passes
		// through; 125 is notenv's own failure, 126 the command was found
		// but cannot run, 127 the command was not found. Scripts and agents
		// can tell whose failure they are looking at.
		err := runChild(cmd, args)
		var ec *exitCodeError
		if err != nil && !errors.As(err, &ec) {
			return &exitCodeError{code: 125, err: err}
		}
		return err
	},
}

func runChild(cmd *cobra.Command, args []string) error {
	if runMask && runNoMask {
		return errors.New("--mask and --no-mask are mutually exclusive")
	}
	// Nudge a human who ran a coding agent through `run` toward `handoff` before
	// anything touches the vault. Argv-only and interactive-only, so automation
	// never hangs and the cost is nil when the command is not an agent.
	if err := guardAgentRun(args); err != nil {
		return err
	}
	a, err := loadApp(cmd.Context())
	if err != nil {
		return err
	}
	a.salvage = runSalvage
	a.only = runOnly
	if err := emptyOnlyError(cmd.Flags().Changed("only"), a.onlyKeys()); err != nil {
		return err
	}
	if runNoMask {
		if err := a.requireHumanPassphrase(cmd.Context(), "--no-mask sends raw secret values to a captured stream"); err != nil {
			return err
		}
	}
	res, err := a.fetchSecrets(cmd.Context(), runRefresh, false)
	if err != nil {
		return err
	}
	env, err := a.buildEnv(os.Environ(), res.secrets)
	if err != nil {
		return err
	}

	injected := a.injectedSecrets(res.secrets)
	stdout, outMask := maskedStream(os.Stdout, injected)
	stderr, errMask := maskedStream(os.Stderr, injected)

	code, err := runner.Run(args, env, os.Stdin, stdout, stderr)
	flushMasker(outMask)
	flushMasker(errMask)
	if err != nil {
		return classifyRunError(err)
	}
	if code != 0 {
		return &exitCodeError{code: code}
	}
	return nil
}

// emptyOnlyError fails closed when --only was given but, after dropping blanks
// and duplicates, names nothing (`--only ""`, `--only ,`, or a templated value
// that came out empty). A scoping flag must never let an empty selection fall
// through to injecting the whole namespace, the opposite of what --only is for.
func emptyOnlyError(given bool, keys []string) error {
	if given && len(keys) == 0 {
		return errors.New("--only was given but names no variables; name the keys to inject, or drop --only to inject the whole namespace")
	}
	return nil
}

// classifyRunError maps a runner failure to its exit code: a command that was
// never started exits 127 (not found) or 126 (found but cannot run); anything
// else is notenv's own failure and falls through to 125.
func classifyRunError(err error) error {
	var start *runner.StartError
	if !errors.As(err, &start) {
		return err
	}
	if errors.Is(err, exec.ErrNotFound) || errors.Is(err, fs.ErrNotExist) {
		return &exitCodeError{code: 127, err: err}
	}
	return &exitCodeError{code: 126, err: err}
}

// maskedStream decides per stream: captured output (not a terminal) is the
// surface that ends up in logs and agent context, so it gets the masker; a
// live terminal is wired through directly so TUI programs and colors keep
// working. --mask / --no-mask override in either direction.
func maskedStream(f *os.File, injected []runner.Secret) (io.Writer, *runner.Masker) {
	mask := runMask || (!runNoMask && !term.IsTerminal(int(f.Fd())))
	if !mask {
		return f, nil
	}
	m := runner.NewMasker(f, injected)
	return m, m
}

func flushMasker(m *runner.Masker) {
	if m == nil {
		return
	}
	if err := m.Flush(); err != nil {
		ui.Warnf("could not finish writing masked output: %v", err)
	}
}

func init() {
	// Stop flag parsing at the first non-flag arg so `notenv run cmd --flag`
	// passes --flag to cmd, not to notenv.
	runCmd.Flags().SetInterspersed(false)
	runCmd.Flags().BoolVar(&runRefresh, "refresh", false, "bypass the local cache and pull the latest secrets (e.g. after a change on another machine)")
	runCmd.Flags().BoolVar(&runMask, "mask", false, "mask secret values in output even on a live terminal")
	runCmd.Flags().BoolVar(&runNoMask, "no-mask", false, "never mask output (asks for your passphrase: raw values may reach a captured stream)")
	runCmd.Flags().BoolVar(&runSalvage, "skip-corrupt", false, "use the previous backup when the current data is missing or corrupt, instead of stopping (the most recent change may be lost; notenv will tell you if so)")
	runCmd.Flags().StringSliceVar(&runOnly, "only", nil, "inject only the named variables from the namespace (comma-separated or repeated), instead of all of them")
}
