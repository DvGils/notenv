package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/DvGils/notenv/internal/mcp"
	"github.com/DvGils/notenv/internal/runner"
)

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Serve this machine's vaults to MCP clients over stdio",
	Long: `Run a Model Context Protocol server on stdin/stdout, giving an agent a
narrow window into your vaults: it can discover namespaces and secrets, run
commands with secrets injected, and check a storage's health. No tool accepts
or returns a secret value, and no tool writes to a vault. Command output is
masked the same way captured 'run' output is.

Tools: list_namespaces, list_secrets (names, descriptions, modified times),
run_with_secrets (inject and execute; returns exit code and masked output),
and doctor (read-only health findings). Namespaces are addressed explicitly,
like --namespace: no checkout needed.

The server is headless, so its environment carries the policy:
  - unlock: a session-cached master key (you unlocked earlier), or enroll
    the agent as a machine ('key add --machine') and present its identity
    via NOTENV_IDENTITY
  - NOTENV_ACCEPT_NAMESPACE=name,...  namespaces this server may join on
    first use (a namespace that already holds secrets is otherwise refused,
    since nobody is at a prompt to confirm)
  - NOTENV_READONLY=1  refuse every mutating operation, as a belt; the
    tools mutate nothing either way

Wire it up with e.g.:  claude mcp add notenv -- notenv mcp`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		server := &mcp.Server{Name: "notenv", Version: versionString(), Tools: mcpTools()}
		return server.Serve(cmd.Context(), os.Stdin, os.Stdout)
	},
}

func mcpTools() []mcp.Tool {
	storageProp := map[string]any{"type": "string", "description": "named storage (omit for the machine default)"}
	return []mcp.Tool{
		{
			Name: "list_namespaces",
			Description: "List the namespaces a storage holds, so you can discover what exists " +
				"before list_secrets. Needs no unlock: it reads object names only.",
			ReadOnly: true,
			InputSchema: map[string]any{
				"type":       "object",
				"properties": map[string]any{"storage": storageProp},
			},
			OutputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"namespaces": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
				},
				"required": []string{"namespaces"},
			},
			Handler: mcpListNamespaces,
		},
		{
			Name: "list_secrets",
			Description: "List the secrets in a vault namespace: names, human descriptions of what " +
				"each secret is for, and last-modified times. Never returns secret values. " +
				"Use it to discover what is available before run_with_secrets.",
			ReadOnly: true,
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"namespace": map[string]any{"type": "string", "description": "vault namespace to list"},
					"storage":   storageProp,
					"refresh":   map[string]any{"type": "boolean", "description": "bypass the local cache and read storage"},
				},
				"required": []string{"namespace"},
			},
			OutputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"namespace": map[string]any{"type": "string"},
					"secrets": map[string]any{
						"type": "array",
						"items": map[string]any{
							"type": "object",
							"properties": map[string]any{
								"name":        map[string]any{"type": "string"},
								"description": map[string]any{"type": "string"},
								"modified":    map[string]any{"type": "string"},
							},
							"required": []string{"name"},
						},
					},
				},
				"required": []string{"namespace", "secrets"},
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
					"storage":   storageProp,
					"command":   map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "minItems": 1, "description": "argv to execute, e.g. [\"psql\", \"-c\", \"select 1\"]"},
					"refresh":   map[string]any{"type": "boolean", "description": "bypass the local cache and read storage"},
				},
				"required": []string{"namespace", "command"},
			},
			OutputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"exit_code":  map[string]any{"type": "integer"},
					"duration_s": map[string]any{"type": "number"},
					"stdout":     map[string]any{"type": "string"},
					"stderr":     map[string]any{"type": "string"},
				},
				"required": []string{"exit_code", "duration_s", "stdout", "stderr"},
			},
			Handler: mcpRunWithSecrets,
		},
		{
			Name: "doctor",
			Description: "Check a storage read-only for known problem states (unreachable storage, " +
				"a vanished or unreadable header, a pending rollback, unfinished onboarding, " +
				"unrecorded or missing objects), with the way out for each. Fixes nothing.",
			ReadOnly: true,
			InputSchema: map[string]any{
				"type":       "object",
				"properties": map[string]any{"storage": storageProp},
			},
			OutputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"problems": map[string]any{"type": "integer"},
					"findings": map[string]any{
						"type": "array",
						"items": map[string]any{
							"type": "object",
							"properties": map[string]any{
								"level": map[string]any{"type": "string"},
								"text":  map[string]any{"type": "string"},
							},
							"required": []string{"level", "text"},
						},
					},
				},
				"required": []string{"problems", "findings"},
			},
			Handler: mcpDoctor,
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

func mcpListSecrets(ctx context.Context, raw json.RawMessage) (any, error) {
	var args mcpVaultArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, err
	}
	a, err := projectlessApp(ctx, args.Storage, args.Namespace)
	if err != nil {
		return nil, err
	}
	res, err := a.fetchSecrets(ctx, args.Refresh)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(res.secrets))
	for name := range res.secrets {
		names = append(names, name)
	}
	sort.Strings(names)
	// The tool result is the same frozen shape as `list --json`.
	return listOutput{Namespace: a.namespace, Secrets: listedSecrets(names, res.meta)}, nil
}

// mcpListNamespaces lists what namespaces a storage holds, from object names
// alone: no unlock, no plaintext, just the discovery hop the other tools
// assume has already happened.
func mcpListNamespaces(ctx context.Context, raw json.RawMessage) (any, error) {
	var args struct {
		Storage string `json:"storage"`
	}
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, err
	}
	store, err := headerTargetFor(args.Storage)
	if err != nil {
		return nil, err
	}
	keys, err := store.List(ctx, "")
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	namespaces := []string{}
	for _, k := range keys {
		ns, _, found := strings.Cut(k, "/")
		if !found || seen[ns] {
			continue
		}
		seen[ns] = true
		namespaces = append(namespaces, ns)
	}
	sort.Strings(namespaces)
	return map[string]any{"namespaces": namespaces}, nil
}

// mcpDoctor runs the same checkup the doctor command does, returning the
// findings as data instead of printing them.
func mcpDoctor(ctx context.Context, raw json.RawMessage) (any, error) {
	var args struct {
		Storage string `json:"storage"`
	}
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, err
	}
	store, err := headerTargetFor(args.Storage)
	if err != nil {
		return nil, err
	}
	c := &checkup{}
	cmd := &cobra.Command{}
	cmd.SetContext(ctx)
	runDoctor(cmd, store, c)
	if c.findings == nil {
		c.findings = []finding{}
	}
	return map[string]any{"problems": c.problems, "findings": c.findings}, nil
}

func mcpRunWithSecrets(ctx context.Context, raw json.RawMessage) (any, error) {
	var args struct {
		mcpVaultArgs
		Command []string `json:"command"`
	}
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, err
	}
	if len(args.Command) == 0 {
		return nil, errors.New("command must name at least the program to run")
	}
	a, err := projectlessApp(ctx, args.Storage, args.Namespace)
	if err != nil {
		return nil, err
	}
	res, err := a.fetchSecrets(ctx, args.Refresh)
	if err != nil {
		return nil, err
	}
	env, err := a.buildEnv(os.Environ(), res.secrets)
	if err != nil {
		return nil, err
	}

	// Tool output is headed for a model's context: always mask, and clip so a
	// chatty child can't flood it. Mask down to a single byte (unlike the CLI's
	// length floor): a short secret echoed into a model's context is worse than
	// the occasional shredded common string. The child's stdin is empty; ours
	// carries the protocol.
	injected := a.injectedSecrets(res.secrets)
	var stdout, stderr bytes.Buffer
	outMask := runner.NewMaskerFloor(&stdout, injected, 1)
	errMask := runner.NewMaskerFloor(&stderr, injected, 1)
	start := time.Now()
	code, err := runner.Run(args.Command, env, nil, outMask, errMask)
	flushMasker(outMask)
	flushMasker(errMask)
	if err != nil {
		return nil, err
	}

	return map[string]any{
		"exit_code":  code,
		"duration_s": time.Since(start).Round(time.Millisecond).Seconds(),
		"stdout":     clipOutput(stdout.String()),
		"stderr":     clipOutput(stderr.String()),
	}, nil
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
