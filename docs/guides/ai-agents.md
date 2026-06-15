# AI agents

Coding agents read everything they touch: files, command output, logs. A `.env` on
disk ends up in the model's context sooner or later, and from there in transcripts.
notenv keeps secrets off disk and lets an agent *use* them without *seeing* them,
scoped to just what you hand it.

## Hand a scoped session to an agent

```sh
notenv handoff -- claude        # or codex, or any agent command
```

Run that from your project and the agent gets an ephemeral vault holding only this
project's secrets. It works normally (`notenv run -- pytest` gets the real values); when
it exits, the ephemeral vault is gone. Use `--namespace NAME` to hand off a different
namespace.

!!! warning "This scopes what the agent can decrypt; it does not sandbox the agent"

    The agent **cannot reach any secret outside the namespace you hand it**, because your
    master key is never in its reach, so the worst a rogue or prompt-injected agent can
    leak is that one namespace. But it still runs as you: it can use, store, or leak the
    secrets it was given, and reach your files and the network. Hand off only to an agent
    you trust, and use the OS (a sandbox, egress rules) to contain what it *does*.

While a session is live, notenv keeps your real vault's key uncached, so another terminal
working that *same* vault will re-prompt for your passphrase until the session ends.

## Tell the agent how to use notenv

Drop this into your project's `AGENTS.md` (or `CLAUDE.md`):

```markdown
This project manages secrets with notenv (https://github.com/DvGils/notenv).
- Run anything needing credentials via `notenv run -- <cmd>`; the variables in
  notenv.toml are injected automatically. Use `notenv --help` for anything else.
- `notenv list` shows which secret names exist and what they're for. Never
  print, ask for, or store a secret value; never create .env files.
```

For the full rules in installable form, use the
[notenv agent skill](https://github.com/DvGils/notenv/tree/main/skills/notenv).

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
