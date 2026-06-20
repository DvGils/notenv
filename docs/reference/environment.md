# Environment variables

notenv reads a small set of environment variables. They let you drive notenv on a machine with no
human and no interactive config: an agent, a CI job, a container.

## `NOTENV_IDENTITY`

An age identity that is a machine slot on the vault: the inline `AGE-SECRET-KEY...` value, or a
path to a file your platform materialized (a CI runner's tmpfs). When set, notenv unlocks with it
and never prompts for a passphrase. This is the machine path: CI, agents, any non-interactive run.

```sh
export NOTENV_IDENTITY="$CI_SECRET_NOTENV_IDENTITY"
notenv run -- ./deploy.sh
```

Enroll a machine with `notenv credential add --machine NAME`, which prints a new identity exactly once for
the platform's secret store, or `notenv credential add --machine NAME --recipient age1...` to enroll a key
the machine generated itself. On virgin storage, a supplied identity also creates the vault
promptless, with that identity's recipient as the only slot.

!!! warning

    The identity is key-equivalent for the whole vault, which is why notenv never stores one on
    disk: its at-rest protection is your platform's secret store, and humans use passphrases
    instead (see [Teams and keys](../guides/teams-and-keys.md)). A vault that unlocks only with an
    identity is unrecoverable if you lose it.

## `NOTENV_STORAGE`

Selects the vault to use: the env-shaped sibling of `--storage`. It is either a configured storage
name, or a self-contained spec, so a process can be pointed at a vault with no machine-config entry:

- `local:<absolute-path>` for a local vault directory,
- `rclone:<remote>:<base>` for a remote vault.

```sh
NOTENV_STORAGE=local:/srv/vaults/app notenv --namespace app run -- ./serve
NOTENV_STORAGE=rclone:b2:notenv     notenv --namespace app list
```

`--storage` on the command line wins over `NOTENV_STORAGE`, which wins over a project's local
binding. `notenv handoff` sets this (to the ephemeral vault) on the agent it launches.

## `NOTENV_READONLY`

When set to any value other than empty or `0`, notenv refuses every mutating command for the whole
process. It is the env-shaped sibling of a storage entry's `read_only`, for wrapping an agent or a CI
job without touching the machine config.

```sh
NOTENV_READONLY=1 notenv run -- ./run-tests.sh
```

!!! danger "Policy, not enforcement"

    `NOTENV_READONLY` is accident-proofing for a cooperating client, not a defense against an
    adversary. With a single master key, anyone who can decrypt can author valid writes with their own
    tooling. *Enforced* read-only comes from the storage credential itself (for example a read-only
    Backblaze B2 application key behind the remote, or read-only directory permissions on a local
    vault). See the [threat model](../security/threat-model.md).

## `NOTENV_ACCEPT_NAMESPACE`

A comma-separated list of namespaces this runner's operator accepts without a prompt. The first use
of a namespace that already holds secrets normally asks for interactive confirmation; where nobody
can answer (CI, agent harnesses), notenv **refuses** instead of proceeding, unless this variable
names the exact namespace being accepted.

```sh
NOTENV_ACCEPT_NAMESPACE=my-service notenv run --storage prod --namespace my-service -- ./deploy.sh
```

The value is deliberately a list of names, not a yes-flag: a committed `notenv.toml` cannot write
the runner's environment, so a match is the operator's own statement of intent, while a blanket
yes would be satisfied by whatever namespace a malicious contract names. Acceptance through the
variable is per-invocation: notenv does not record it, so a run without the variable confirms again.
See the [threat model](../security/threat-model.md).

## `NOTENV_SESSION`

Set by `notenv handoff` on the agent it launches; you do not set this yourself. It marks the process
as running inside a handoff session and carries the scope of the one ephemeral vault it may unlock, so
an attempt to unlock any other vault from inside the session fails closed instead of prompting for
your real passphrase. A launched program does not read this variable directly to learn whether it is
scoped: it runs `notenv handoff inspect` (exit 0 = inside a handoff, exit 1 = not), which confirms the
claim against the live ephemeral vault and so fails safe to "no" on a stale or clobbered value. See
[Agent handoff](../concepts/agent-handoff.md#telling-whether-you-are-in-a-handoff).

## `XDG_RUNTIME_DIR` (Linux)

On Linux, notenv caches the encrypted blob under `XDG_RUNTIME_DIR` (tmpfs), and the master key in the
kernel keyring. Both are RAM-backed and reclaimed on logout or reboot. notenv reads `XDG_RUNTIME_DIR`
to locate the blob cache; it does not set it. It also writes the `notenv edit` buffer there; without
`XDG_RUNTIME_DIR`, `edit` falls back to the OS temp dir (persistent disk on Linux) and warns. See
[Caching](../concepts/caching.md).
