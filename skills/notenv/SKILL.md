---
name: notenv
description: Use secrets managed by notenv without ever reading their values. Use when a project has a notenv.toml, when the user mentions notenv or asks to run something that needs credentials a vault holds, when NOTENV_STORAGE is set, or when a .env file is absent and notenv is installed.
---

# notenv: use secrets, never know them

notenv injects encrypted secrets into the environment of a child process. The
values are not yours to see; your job is to run things that need them, by name.

## The rules

- **Never print, echo, ask for, or store a secret value, and never write a .env
  file.** To check a variable is set, test it (`test -n "$VAR"`), do not print it.
- **Run anything that needs credentials through `notenv run -- <command...>`.**
  Inside a project with `notenv.toml` that is the whole invocation; the declared
  variables are injected automatically.
- **A `Passphrase:` prompt is for the human, not you.** It reads the terminal
  directly and you cannot answer it. Stop and hand control back.
- **Captured output is masked**: an injected value shows up as
  `<notenv-masked:NAME>`. That is correct. Do not try to unmask it; `--no-mask`
  needs the user's passphrase by design.

## Finding your way around

- `notenv list` shows the secret names available here and what each is for.
  `notenv list --json` is the stable shape.
- `notenv inspect KEY` reports whether a secret exists, its length, and what it is
  for, without revealing the value (exit 1 if it does not exist, so you can branch
  on it). `notenv inspect` summarizes the namespace and `notenv inspect --all` the
  vault; all take `--json`. Use this to check a secret is set before running.
- For anything else, ask the tool: `notenv --help`, and `notenv <command> --help`
  for a specific command (`run`, `list`, `set`, `doctor`, ...). Prefer reading
  `--help` over guessing flags.
- `notenv doctor` (read-only) explains a vault that is misbehaving and names the
  fix; run it before assuming a bug. Exit codes from `run` follow docker's
  convention: the child's code passes through, `125` is notenv's own failure,
  `126` found-but-cannot-run, `127` not found, so a vault problem is never a code
  problem.

## Inside a handoff session

If you were started with `notenv handoff`, you are pointed at an ephemeral vault
holding only the namespace you were handed. Work normally: `notenv run -- <cmd>`
and `notenv list` resolve against it and give you the real values. Do not try to
reach another vault or storage (a different `--storage`, the user's real vault);
it is refused on purpose, and is never needed for your task.

## Changing secrets (only when asked, with a value the user gave you)

- `notenv set KEY` reads the new value from stdin
  (`printf '%s' "$VALUE" | notenv set KEY --stdin`); add `--description "..."` so
  others know what it is for. Never invent or display a value.
- `notenv unset KEY` deletes one. `notenv edit` is for humans, not you.

## Environment knobs (set by the user or harness, never by you)

- `NOTENV_READONLY=1` makes every mutating command refuse; respect it.
- `NOTENV_IDENTITY` is a machine credential; never print it.
- `NOTENV_STORAGE` / `NOTENV_ACCEPT_NAMESPACE` point you at a vault and
  pre-approve namespaces for headless use.

Full documentation: https://dvgils.github.io/notenv/
