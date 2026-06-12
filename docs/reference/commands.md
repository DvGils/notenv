# Command reference

## Core commands

| Command | What it does |
|---|---|
| `notenv setup` | Configure this machine: a local vault by default, or pick/create a cloud remote; create or unlock your key. |
| `notenv init` | Set up the current project (writes `notenv.toml`). Runs setup first if needed. |
| `notenv import [file]` | Import a `.env` file: every value encrypted in one write, every key declared. `--dry-run` previews. |
| `notenv set KEY` | Set a secret. Prompted hidden, encrypted, uploaded, and declared in `notenv.toml`. |
| `notenv set KEY --stdin` | Read the value from stdin (for multiline or piped values). |
| `notenv set KEY --description "..."` | Also record what the secret is for. Omitted, the existing note is kept; `""` clears it. |
| `notenv unset KEY` | Remove a stored secret value. |
| `notenv list` | List stored secret names with descriptions and modified times (never values). `--json` for machines; piped output is bare names. |
| `notenv run -- cmd` | Run a command with secrets injected as environment variables. |
| `notenv run --refresh -- cmd` | Same, but bypass the local cache and pull the latest secrets first. |
| `notenv compact` | Force-fold a namespace's change segments into a single snapshot (also happens automatically). |
| `notenv cache clear` | Remove all locally cached ciphertext on this machine. |
| `notenv vault copy` | Replicate this vault to new storage (for example local to cloud) and register it. The source is untouched. |
| `notenv mcp` | Serve the vault to MCP clients over stdio (experimental). |
| `notenv --version` | Print the version, commit, and build date. |

## Targeting a vault

Add these to any command:

- `--storage NAME` targets a specific configured storage (vault). Use it in CI to pin the vault from
  outside the repo.
- `--namespace NAME` addresses a vault namespace directly from anywhere, with no project and no
  checkout. The contract (and its declarations) is bypassed entirely, so `run` injects every secret
  in the namespace.

## Key and slot management

A vault's master key is wrapped under one or more **key slots**. Passphrases are for people,
identities are for machines: a slot is a person's passphrase or a machine's age public key. These
commands manage them.

| Command | What it does |
|---|---|
| `notenv key list` | List the key slots (name, principal, primary, added, fingerprint). `--json` for machines. |
| `notenv key add <name>` | Onboard a teammate: prints a one-time onboarding passphrase; their first command replaces it with their own. |
| `notenv key add --machine <name>` | Enroll a machine (CI, an agent): prints a new identity exactly once, for the platform's secret store. `--recipient age1...` enrolls an existing public key instead. |
| `notenv key rm <name\|index>` | Remove a slot **and re-key the vault** (offboarding). |
| `notenv key rotate` | Change the passphrase on your slot (header only). |
| `notenv key rotate-master` | Mint a fresh master key and re-encrypt every secret; all slots kept. |
| `notenv key set-primary <name\|index>` | Transfer the primary (governance) slot. |
| `notenv key trust` | Re-pin after a confirmed master change that carries no signed proof (shows what changed, asks). |
| `notenv key forget` | Forget this machine's pin and cached key for a storage (after a deliberate vault reset). |
| `notenv key restore-backup` | Restore the header from its pre-write backup. |

## Exit codes

`notenv run` follows docker's convention, so a script or agent can tell a vault problem from a code
problem:

| Code | Meaning |
|---|---|
| (child's code) | The child ran; its exit code passes through untouched. |
| `125` | notenv's own failure (could not unlock, fetch, or decrypt). |
| `126` | The command was found but could not be executed. |
| `127` | The command was not found. |
| `128 + N` | The child was killed by signal N. |
