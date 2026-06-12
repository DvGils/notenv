package main

import (
	"errors"
	"io"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/DvGils/notenv/internal/runner"
	"github.com/DvGils/notenv/internal/ui"
)

var (
	runRefresh bool
	runMask    bool
	runNoMask  bool
)

var runCmd = &cobra.Command{
	Use:   "run -- command [args...]",
	Short: "Run a command with secrets injected as environment variables",
	Long: `Run a command with the contract's secrets injected as environment variables.

Captured output is masked: when stdout or stderr is not a terminal (a pipe, a
file, an agent or CI harness reading the output), any injected secret value
appearing in that stream is replaced with <notenv-masked:NAME> before it can
land in a log or an LLM context. A live terminal is wired through untouched,
so colors and interactive programs keep working; --mask forces masking there
too, --no-mask disables it everywhere (e.g. when a consumer needs the raw
bytes). Masking is accident-proofing for output, not a security boundary:
values shorter than 6 bytes pass through, and code that holds a secret can
always move it some other way.`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if runMask && runNoMask {
			return errors.New("--mask and --no-mask are mutually exclusive")
		}
		a, err := loadApp(cmd.Context())
		if err != nil {
			return err
		}
		res, err := a.fetchSecrets(cmd.Context(), runRefresh)
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

		code, err := runner.Run(args, env, stdout, stderr)
		flushMasker(outMask)
		flushMasker(errMask)
		if err != nil {
			return err
		}
		if code != 0 {
			return &exitCodeError{code: code}
		}
		return nil
	},
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
		ui.Warnf("flush masked output: %v", err)
	}
}

func init() {
	// Stop flag parsing at the first non-flag arg so `notenv run cmd --flag`
	// passes --flag to cmd, not to notenv.
	runCmd.Flags().SetInterspersed(false)
	runCmd.Flags().BoolVar(&runRefresh, "refresh", false, "bypass the local cache and pull the latest secrets (e.g. after a change on another machine)")
	runCmd.Flags().BoolVar(&runMask, "mask", false, "mask secret values in output even on a live terminal")
	runCmd.Flags().BoolVar(&runNoMask, "no-mask", false, "never mask output (interactive/TUI programs needing a real pipe of raw bytes)")
}
