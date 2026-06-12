# Environment variables

notenv reads a small set of environment variables. They let you drive notenv on a machine with no
human and no interactive config: an agent, a CI job, a container.

## `NOTENV_IDENTITY`

Path to an age identity file that is a slot on the vault. When set, notenv unlocks with it and never
prompts for a passphrase. This is the promptless path for CI, agents, and any non-interactive run.

```sh
export NOTENV_IDENTITY=/secure/path/to/identity
notenv run -- ./deploy.sh
```

Generate an identity with `notenv key gen-identity` and add its public recipient to the vault with
`notenv key add --recipient age1...`. On virgin storage, a supplied identity also creates the vault
promptless, with that identity's recipient as the only slot.

!!! warning

    The identity file is an on-disk credential you place and control. Protect it: a vault that unlocks
    only with an identity is unrecoverable if you lose it.

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

## `XDG_RUNTIME_DIR` (Linux)

On Linux, notenv caches the encrypted blob under `XDG_RUNTIME_DIR` (tmpfs), and the master key in the
kernel keyring. Both are RAM-backed and reclaimed on logout or reboot. notenv reads `XDG_RUNTIME_DIR`
to locate the blob cache; it does not set it. See [Caching and performance](../guides/caching.md).
