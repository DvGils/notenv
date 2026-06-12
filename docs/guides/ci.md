# Continuous integration

A CI job is a machine with no human at the keyboard and often no project checkout. notenv runs there
with two pieces: an **identity** that unlocks the vault without a prompt, and flags that pin the
vault from outside the repo.

## Unlock without a prompt

Set `NOTENV_IDENTITY` to an age identity that is a slot on the vault. notenv unlocks with it and
never prompts:

```sh
export NOTENV_IDENTITY=/secure/path/to/identity   # an age identity file you provision
notenv run -- npm test
```

Provision that identity through your CI provider's own secret store (the one credential CI needs).
Generate it with `notenv key gen-identity` and add its public recipient to the vault with
`notenv key add --recipient age1...`.

!!! note "Why an identity, not a passphrase"

    Passphrase prompts read the terminal device directly so they reach a human, not a script. In CI
    there is no human, so use an identity: an on-disk credential you place and control.

## Pin the vault from outside the repo

`--storage NAME` selects a configured storage regardless of any project binding, and `--namespace
NAME` addresses a namespace directly when there is no checkout:

```sh
notenv run --storage prod --namespace my-service -- ./deploy.sh
```

## Read exit codes

`notenv run` follows docker's convention, so a job can tell a vault failure from a test failure: the
child's exit code passes through untouched, while `125` is notenv's own failure, `126` is
found-but-cannot-execute, and `127` is not-found. A flaky-test retry never mistakes a vault problem
for a code problem. See [Commands](../reference/commands.md#exit-codes).

## Refuse writes

To make a job read-only, set `NOTENV_READONLY=1` (or mark the storage `read_only = true`). Every
mutating command is then refused. This is policy that stops a cooperating job from an accident; for
enforced read-only, use a read-only storage credential (for example a Backblaze B2 application key
without write). See [Environment variables](../reference/environment.md).
