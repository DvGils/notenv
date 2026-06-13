# AI agents

Coding agents read everything: files, tool output, logs. A `.env` file on disk *will* eventually
enter the model's context (`cat`-ed while debugging, swept up by a glob, or extracted by a
prompt-injected instruction), and anything that enters context persists in transcripts and whatever
the conversation touches next. notenv removes the file and gives the agent a verb that separates
*using* credentials from *knowing* them.

## What the agent can and cannot do

- **`notenv run -- cmd`** injects secrets into the child only. The value never appears in anything
  the model reads.
- **`notenv list`** tells the agent *which* credentials exist, and with per-secret descriptions
  (`set KEY --description "..."`), *what they are for*, so it can decide what is runnable without
  ever seeing a value. `notenv list --json` gives it a stable shape to parse.
- **Captured output is masked.** When stdout/stderr is not a terminal (which is exactly how agents
  and CI read output), any injected value a child prints (a server echoing its connection string on
  boot, a debug dump) is replaced with `<notenv-masked:NAME>` before the model sees it.
- **Exit codes say whose failure it was.** `run` follows docker's convention: the child's code
  passes through; `125` is notenv's own failure, `126` found-but-cannot-run, `127` not found. An
  agent retrying a flaky test never mistakes a vault problem for a code problem.
- **No checkout needed.** `--namespace` (with `--storage`) addresses a vault directly from anywhere.
  An agent wired to a database needs credentials, not a git repository.
- **Read-only by policy.** Start an agent with `NOTENV_READONLY=1` (or mark a storage
  `read_only = true`) and every mutating command is refused.
- **Unlock prompts reach the human, not the model.** Passphrase prompts read the terminal device
  directly, so when an agent's command needs an unlock, the question goes to whoever is at the
  keyboard.
- **Unmasked output needs a human.** `run --no-mask` asks for a freshly typed passphrase even when
  the session key is cached, so an agent cannot turn masking off by itself.
- **First use of an existing namespace needs a human too.** Headless, notenv refuses to expose a
  namespace that already holds secrets unless the harness's environment names it
  (`NOTENV_ACCEPT_NAMESPACE=name`), so neither a cloned repository's contract nor a misdirected
  `--namespace` can silently reach another project's secrets.

## Two ways to wire an agent up

**A skill for agents with a shell, MCP for agents without one. Same surface either way.**

### The skill

The notenv repository ships an [Agent Skill](https://github.com/DvGils/notenv/tree/main/skills/notenv)
at `skills/notenv/SKILL.md`: the rules above plus the full CLI surface (discovery, exit codes, the
environment knobs), in the installable form shell-first agents understand. Install it into your
agent's skill location (`~/.claude/skills/` for Claude Code, `.agents/skills/` for the
cross-agent convention, or via a skill installer pointed at the repo). For a lighter touch, this
block in your `AGENTS.md` / `CLAUDE.md` covers the essentials:

```markdown
This project manages secrets with notenv (https://github.com/DvGils/notenv).
- Run anything needing credentials via `notenv run -- <cmd>`; the env vars in
  notenv.toml are injected automatically.
- `notenv list` shows which secret names exist and what they're for. Never
  print, ask for, or store secret values; never create .env files.
- If a command prompts for a passphrase, stop and let the user answer it.
```

### The MCP server

`notenv mcp` serves the same surface over the Model Context Protocol, for agents that are not
shell-first (or machines with no checkout at all):

```sh
claude mcp add notenv -- notenv mcp        # or any MCP client, stdio transport
```

For a client configured by a JSON file rather than a CLI, the stdio entry is:

```json title="mcp.json"
--8<-- "examples/agents/mcp.json"
```

Four tools, none of which accepts or returns a secret value, none of which writes to a vault:
`list_namespaces` (discovery, no unlock needed), `list_secrets` (names, descriptions, modified
times), `run_with_secrets` (inject and execute; the agent gets the exit code and masked output),
and `doctor` (read-only health findings). Results are typed (`structuredContent` with declared
output schemas), and the three read tools carry `readOnlyHint` so clients can skip confirmations.

The server is headless, so its environment is the configuration:

- **Unlock:** rely on the session-cached key (unlock once with your passphrase; the platform key
  store carries the session on Linux, macOS, and Windows), or enroll a standalone agent as a
  machine (`notenv key add --machine`) with `NOTENV_IDENTITY` from the harness's secret store.
- **`NOTENV_ACCEPT_NAMESPACE=name,...`**: namespaces the server may join on first use; without it,
  a namespace that already holds secrets is refused, since nobody is at a prompt.
- **`NOTENV_READONLY=1`** as a belt, paired with a read-only storage credential where the agent
  only reads.

## Honest limits

!!! danger "This is accident-proofing, not a security boundary"

    An agent running as your user can still extract a value deliberately (any encoding defeats
    exact-byte masking: `notenv run -- sh -c 'printenv KEY | base64'`) or read the session key cache,
    and a child process that legitimately holds a secret can always send it somewhere. Masking
    catches accidents, not intent.

    The same goes for read-only mode: with a single master key, anyone who can decrypt could author
    writes with their own tooling, so the flag stops accidents while the storage credential is what
    stops adversaries.

A broker mode that keeps the unlocked key in a separate trust domain (so agents can *use* but
provably not *extract*) is on the [roadmap](../project/roadmap.md). See the
[threat model](../security/threat-model.md) for the full analysis.
