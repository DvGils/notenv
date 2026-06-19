# AI agents

A coding agent reads everything it touches: files, command output, logs. A `.env` on
disk ends up in the model's context sooner or later. notenv hands the agent a scoped
session instead, so it can use your secrets without ever holding the key to the rest of
your vault.

## Hand off a session

```sh
notenv handoff -- claude        # or codex, or any agent command
```

Run that from your project and the agent gets an ephemeral vault holding only this
project's secrets. It works normally (`notenv run -- pytest` gets the real values), and
when it exits the ephemeral vault is gone. Hand off a different namespace with
`--namespace NAME`.

That is the whole setup. Two things worth knowing:

- **It scopes, it does not sandbox.** The agent cannot decrypt anything outside the
  namespace you hand it, so the worst a prompt-injected agent can leak is that one
  namespace. But it runs as you, so it can still use, store, or send onward the secrets
  you gave it. Contain what it *does* with the OS (a sandbox, egress rules). The full
  account is in [Agent handoff](../concepts/agent-handoff.md).
- **Another terminal on the same vault re-prompts** while a session is live, because
  notenv keeps your real key uncached for the duration.

## Tell the agent how to use notenv

Drop this into your project's `AGENTS.md` (or `CLAUDE.md`):

```markdown
This project manages secrets with notenv (https://github.com/DvGils/notenv).
- Run anything needing credentials via `notenv run -- <cmd>`; the variables in
  notenv.toml are injected automatically. Use `notenv --help` for anything else.
- `notenv list` shows which secret names exist and what they're for, and
  `notenv inspect KEY` whether one is set (without revealing it). Never print,
  ask for, or store a secret value; never create .env files.
```

For the full rules in installable form, use the
[notenv agent skill](https://github.com/DvGils/notenv/tree/main/skills/notenv).

Your agent's MCP servers can pull their own credentials from notenv too, so a token never
sits in plaintext in `.mcp.json` or your shell. See [MCP servers](mcp-servers.md).

## Without a project

An agent or job with no checkout points at a vault directly with `NOTENV_STORAGE` (or
`--namespace` with `--storage`), and runs headless with a few environment knobs:

- **`NOTENV_ACCEPT_NAMESPACE=name`** approves a namespace's first headless use (otherwise
  notenv refuses, since nobody is at a prompt).
- **`NOTENV_READONLY=1`** refuses every mutating command.
- **`NOTENV_IDENTITY`** unlocks promptlessly for an enrolled machine (`notenv key add --machine`).

See [Environment variables](../reference/environment.md) for the rest.

---

**Under the hood:** [Agent handoff](../concepts/agent-handoff.md) ·
[Threat model](../security/threat-model.md)
