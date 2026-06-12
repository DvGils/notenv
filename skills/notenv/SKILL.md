---
name: notenv
description: Use secrets managed by notenv without ever reading their values. Use when a project contains notenv.toml, when the user mentions notenv or asks to run something that needs credentials a vault holds, or when a .env file is absent and notenv is installed.
---

# notenv: use secrets, never know them

notenv injects encrypted secrets into the environment of a child process. The
values are not yours to see: your job is to run things that need them, by
name.

## The rules

- Never print, echo, ask for, or store a secret value. Never write a .env
  file. If you need to know whether a variable is set, test it
  (`test -n "$VAR"`), do not print it.
- Run anything that needs credentials through notenv:
  `notenv run -- <command...>`. Inside a project with `notenv.toml`, that is
  the whole invocation; the declared variables are injected automatically.
- If a command stops at a `Passphrase:` prompt, stop and hand control to the
  user. The prompt is for them, not you; it reads the terminal directly and
  you cannot answer it.
- Captured output is masked: an injected value appearing in output is
  replaced by `<notenv-masked:NAME>`. That is working as intended. Do not try
  to unmask it; `--no-mask` requires the user's passphrase by design.

## Discovering what exists

- `notenv list` shows the secret names in the current project, with
  descriptions of what each is for. `notenv list --json` is the stable shape.
- Without a checkout: `notenv list --namespace <ns> --storage <name>`, and
  the same flags work on `run`. Namespaces and storages come from the user;
  if a first use of an existing namespace is refused, the user must approve
  it (interactively, or via `NOTENV_ACCEPT_NAMESPACE=<ns>` in your
  environment).

## Changing secrets

- `notenv set KEY` reads the new value from stdin
  (`printf '%s' "$VALUE" | notenv set KEY --stdin`); add
  `--description "what this is"` so humans and agents know what it is for.
  Only do this when the user gives you a value to store; never invent or
  display one.
- `notenv unset KEY` deletes. `notenv edit` opens the user's editor and is
  for humans, not you.

## Reading machine output

- Exit codes from `notenv run` follow docker's convention: the child's code
  passes through; 125 is notenv's own failure, 126 found-but-cannot-run, 127
  command not found. A vault problem is never a code problem.
- `notenv doctor` (read-only, exit 1 on findings) explains weird vault
  states and names the fix; run it before assuming a bug.

## Environment knobs (set by the user or harness, not by you)

- `NOTENV_READONLY=1` makes every mutating command refuse; respect it.
- `NOTENV_IDENTITY` is a machine credential; if it is set, unlocks are
  promptless. Never print it.
- `NOTENV_ACCEPT_NAMESPACE` pre-approves namespaces for headless first use.

Full documentation: https://dvgils.github.io/notenv/
