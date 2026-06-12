package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/spf13/cobra"

	"github.com/DvGils/notenv/internal/mcp"
	"github.com/DvGils/notenv/internal/runner"
)

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Serve this machine's vaults to MCP clients over stdio (experimental)",
	Long: `Run a Model Context Protocol server on stdin/stdout, giving an agent a
narrow window into your vaults: it can discover what secrets exist and what
they are for, and run commands with secrets injected. It can never read a
value. Tool output is masked the same way captured 'run' output is.

Tools: list_secrets (names, descriptions, modified times) and
run_with_secrets (inject and execute; returns exit code and masked output).
Both address a namespace explicitly, like --namespace: no checkout needed.

The vault must unlock without a prompt: set NOTENV_IDENTITY to an identity
that holds a slot, or rely on a session-cached master key. To make the whole
server read-only by policy, start it with NOTENV_READONLY=1 (the two tools
mutate nothing either way).

Experimental: this server exists to prove the machine-facing shapes before
they freeze; the tool surface may still change.

Wire it up with e.g.:  claude mcp add notenv -- notenv mcp`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		server := &mcp.Server{Name: "notenv", Version: versionString(), Tools: mcpTools()}
		return server.Serve(cmd.Context(), os.Stdin, os.Stdout)
	},
}

func mcpTools() []mcp.Tool {
	return []mcp.Tool{
		{
			Name: "list_secrets",
			Description: "List the secrets in a vault namespace: names, human descriptions of what " +
				"each secret is for, and last-modified times. Never returns secret values. " +
				"Use it to discover what is available before run_with_secrets.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"namespace": map[string]any{"type": "string", "description": "vault namespace to list"},
					"storage":   map[string]any{"type": "string", "description": "named storage (omit for the machine default)"},
					"refresh":   map[string]any{"type": "boolean", "description": "bypass the local cache and read storage"},
				},
				"required": []string{"namespace"},
			},
			Handler: mcpListSecrets,
		},
		{
			Name: "run_with_secrets",
			Description: "Run a command with a namespace's secrets injected as environment variables. " +
				"Returns the exit code and the command's output, with any injected secret value " +
				"replaced by <notenv-masked:NAME>. Secrets are never returned in plaintext; write " +
				"commands that use the variables by name.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"namespace": map[string]any{"type": "string", "description": "vault namespace to inject"},
					"storage":   map[string]any{"type": "string", "description": "named storage (omit for the machine default)"},
					"command":   map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "minItems": 1, "description": "argv to execute, e.g. [\"psql\", \"-c\", \"select 1\"]"},
					"refresh":   map[string]any{"type": "boolean", "description": "bypass the local cache and read storage"},
				},
				"required": []string{"namespace", "command"},
			},
			Handler: mcpRunWithSecrets,
		},
	}
}

// mcpVaultArgs is the addressing every tool shares, mirroring the global
// --storage/--namespace flags.
type mcpVaultArgs struct {
	Namespace string `json:"namespace"`
	Storage   string `json:"storage"`
	Refresh   bool   `json:"refresh"`
}

func mcpListSecrets(ctx context.Context, raw json.RawMessage) (string, error) {
	var args mcpVaultArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return "", err
	}
	a, err := projectlessApp(ctx, args.Storage, args.Namespace)
	if err != nil {
		return "", err
	}
	res, err := a.fetchSecrets(ctx, args.Refresh)
	if err != nil {
		return "", err
	}
	names := make([]string, 0, len(res.secrets))
	for name := range res.secrets {
		names = append(names, name)
	}
	sort.Strings(names)
	// The tool result is the same frozen shape as `list --json`.
	data, err := json.MarshalIndent(listOutput{Namespace: a.namespace, Secrets: listedSecrets(names, res.meta)}, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func mcpRunWithSecrets(ctx context.Context, raw json.RawMessage) (string, error) {
	var args struct {
		mcpVaultArgs
		Command []string `json:"command"`
	}
	if err := json.Unmarshal(raw, &args); err != nil {
		return "", err
	}
	if len(args.Command) == 0 {
		return "", errors.New("command must name at least the program to run")
	}
	a, err := projectlessApp(ctx, args.Storage, args.Namespace)
	if err != nil {
		return "", err
	}
	res, err := a.fetchSecrets(ctx, args.Refresh)
	if err != nil {
		return "", err
	}
	env, err := a.buildEnv(os.Environ(), res.secrets)
	if err != nil {
		return "", err
	}

	// Tool output is headed for a model's context: always mask, and clip so a
	// chatty child can't flood it. The child's stdin is empty; ours carries
	// the protocol.
	injected := a.injectedSecrets(res.secrets)
	var stdout, stderr bytes.Buffer
	outMask := runner.NewMasker(&stdout, injected)
	errMask := runner.NewMasker(&stderr, injected)
	start := time.Now()
	code, err := runner.Run(args.Command, env, nil, outMask, errMask)
	flushMasker(outMask)
	flushMasker(errMask)
	if err != nil {
		return "", err
	}

	result := map[string]any{
		"exit_code":  code,
		"duration_s": time.Since(start).Round(time.Millisecond).Seconds(),
		"stdout":     clipOutput(stdout.String()),
		"stderr":     clipOutput(stderr.String()),
	}
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// clipOutput bounds one captured stream for a model's context: past the
// limit, keep the head and the tail (failures usually report at the end) with
// an elision marker counting what was dropped.
func clipOutput(s string) string {
	const head, tail = 8 * 1024, 24 * 1024
	if len(s) <= head+tail {
		return s
	}
	return fmt.Sprintf("%s\n…[%d bytes elided]…\n%s", s[:head], len(s)-head-tail, s[len(s)-tail:])
}

func init() {
	rootCmd.AddCommand(mcpCmd)
}
