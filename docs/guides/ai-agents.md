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

## Drop this in your `AGENTS.md` / `CLAUDE.md`

```markdown
This project manages secrets with notenv (https://github.com/DvGils/notenv).
- Run anything needing credentials via `notenv run -- <cmd>`; the env vars in
  notenv.toml are injected automatically.
- `notenv list` shows which secret names exist and what they're for. Never
  print, ask for, or store secret values; never create .env files.
- If a command prompts for a passphrase, stop and let the user answer it.
```

## The MCP server (experimental)

`notenv mcp` serves the same surface over the Model Context Protocol, for agents that are not
shell-first (or machines with no checkout at all):

```sh
claude mcp add notenv -- notenv mcp        # or any MCP client, stdio transport
```

Two tools: `list_secrets` (names, descriptions, modified times, never values) and `run_with_secrets`
(inject and execute; the agent gets the exit code and masked output). The vault must unlock without
a prompt. On your own machine, rely on the session-cached key (unlock once with your passphrase,
then the kernel keyring carries the session); for a standalone or sandboxed agent, enroll it as a
machine (`notenv key add --machine`) and present the identity via `NOTENV_IDENTITY` from the
harness's secret store, paired with `NOTENV_READONLY=1` and a read-only storage credential where it
only reads. It is experimental: the tool surface may still change before it is frozen.

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
