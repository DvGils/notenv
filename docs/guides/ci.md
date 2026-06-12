# Continuous integration

A CI job is a machine with no human at the keyboard and often no project checkout. notenv runs there
with two pieces: an **identity** that unlocks the vault without a prompt, and flags that pin the
vault from outside the repo.

## Unlock without a prompt

Enroll the job as a **machine slot** and present its identity via `NOTENV_IDENTITY`:

```sh
notenv key add --machine ci      # on your machine: prints the identity exactly once
```

Paste the printed `AGE-SECRET-KEY...` into your CI provider's secret store (the one credential the
job needs) and expose it to the job:

```sh
export NOTENV_IDENTITY="$CI_SECRET_NOTENV_IDENTITY"   # inline value, or a path the runner wrote
notenv run -- npm test
```

`NOTENV_IDENTITY` accepts the identity inline or as a path to a file the runner materialized.
notenv itself never stores an identity on disk anywhere.

!!! note "Why an identity, not a passphrase"

    Passphrases are for people, identities are for machines. Passphrase prompts read the terminal
    device directly so they reach a human, not a script; in CI there is no human. The identity's
    at-rest protection is the platform secret store that already guards your deploy keys.

## Pin the vault from outside the repo

`--storage NAME` selects a configured storage regardless of any project binding, and `--namespace
NAME` addresses a namespace directly when there is no checkout:

```sh
export NOTENV_ACCEPT_NAMESPACE=my-service   # CI checkouts are fresh every run; name what this job may use
notenv run --storage prod --namespace my-service -- ./deploy.sh
```

The first use of a namespace that already holds secrets needs confirmation, and in CI nobody can
answer: notenv refuses unless `NOTENV_ACCEPT_NAMESPACE` names the namespace. The value is exact
names, never a blanket yes, so a malicious repository's committed `notenv.toml` cannot point a
shared runner at another project's secrets. See
[Environment variables](../reference/environment.md).

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
