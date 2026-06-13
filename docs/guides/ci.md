# Continuous integration

A CI job is a machine with no human at the keyboard and often no project checkout. notenv runs there
with three pieces: the **rclone remote credentials** for your storage, a machine **identity** that
unlocks the vault without a prompt, and the **targeting** that points at the right vault and namespace
from outside the repo. Here they are together, then each piece on its own.

## A complete workflow

=== "GitHub Actions"

    ```yaml title=".github/workflows/test.yml"
    --8<-- "examples/ci/github-actions.yml"
    ```

=== "GitLab CI"

    ```yaml title=".gitlab-ci.yml"
    --8<-- "examples/ci/gitlab-ci.yml"
    ```

The rest of this page explains each piece.

## Point notenv at the storage

A fresh runner has no machine config, so two things have to arrive from the job's environment.

The **rclone remote** is defined with rclone's own `RCLONE_CONFIG_<NAME>_*` variables. notenv shells
out to rclone and inherits the environment, so no `rclone.conf` file is needed; the remote's secret
(a B2 application key, an S3 secret, an SFTP password) is the one credential your CI secret store
holds for storage:

```sh
export RCLONE_CONFIG_NOTENV_TYPE=b2
export RCLONE_CONFIG_NOTENV_ACCOUNT="$B2_KEY_ID"
export RCLONE_CONFIG_NOTENV_KEY="$B2_APP_KEY"
```

The **notenv storage config** (which remote, which path) is written non-interactively with `notenv
init`. In a checkout, the committed `notenv.toml` then supplies the namespace, so `run` needs no
further flags:

```sh
notenv init --remote notenv --base my-bucket/notenv
notenv run -- npm test
```

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
