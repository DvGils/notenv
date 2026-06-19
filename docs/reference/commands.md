# Command reference

## Core commands

| Command | What it does |
|---|---|
| `notenv setup` | Configure this machine: a local vault by default, or pick/create a cloud remote; create or unlock your key. |
| `notenv init [NAMESPACE]` | Set up the current project (writes `notenv.toml`). Namespace defaults to the directory name; pass it as an optional argument to override. Runs setup first if needed. |
| `notenv edit` | Bulk-edit a namespace in `$EDITOR`; existing values are shown as `<keep>`, never displayed. |
| `notenv import [file]` | Import a `.env` file: every value encrypted in one write, every key declared. `--dry-run` previews. |
| `notenv set KEY` | Set a secret. Prompted hidden, encrypted, uploaded, and declared in `notenv.toml`. |
| `notenv set KEY --stdin` | Read the value from stdin (for multiline or piped values). |
| `notenv set KEY --description "..."` | Also record what the secret is for. Omitted, the existing note is kept; `""` clears it. |
| `notenv update KEY --description "..."` | Change an existing secret's description without touching its value (`""` clears it). The metadata-only counterpart to `set`; errors if the secret does not exist. |
| `notenv unset KEY` | Remove a stored secret value. |
| `notenv copy KEY --from NS1 --to NS2` | Copy one secret between two namespaces of the same vault without exposing its value (re-encrypted in place, never printed). Refuses an existing destination key unless `--force`. |
| `notenv list` | List stored secret names with descriptions and modified times (never values). `--json` for machines; piped output is bare names; `--refresh` bypasses the local cache. |
| `notenv inspect KEY` | Show a secret's metadata: whether it exists, its length, description, and modified time; exit 1 if absent. Never a value. `--json` for machines. |
| `notenv inspect` | Summarize the current namespace: each secret's name, length, description, and modified time. `--json` for machines. |
| `notenv inspect handoff` | For a program notenv launched: report whether it is inside a scoped handoff session. Reads only its own environment and the ephemeral vault (no unlock, no value). The answer is the exit code too: 0 = inside a handoff, 1 = not. `--json` for machines. |
| `notenv run -- cmd` | Run a command with secrets injected as environment variables. |
| `notenv run --refresh -- cmd` | Same, but bypass the local cache and pull the latest secrets first. |
| `notenv run --only VAR1,VAR2 -- cmd` | Inject only the named variables from the namespace (comma-separated or repeated), not the whole set. Lets you give one tool (an MCP server) just its own credential. |
| `notenv export` | Print a namespace (or `--all` the whole vault) as `.env` to stdout, never a file. The inverse of `import`. Gated by the primary passphrase; `--json` emits a structured form. |
| `notenv doctor` | Check a storage read-only for known problem states; exit 1 when there are findings. `--json` for machines. |
| `notenv cache clear` | Remove all locally cached ciphertext on this machine. |
| `notenv vault inspect` | Summarize the whole vault: its namespaces, id, revision, and storage. Reads only the header, so no passphrase is needed. `--json` for machines. |
| `notenv vault copy` | Replicate this vault to new storage (for example local to cloud) and register it. The source is untouched. |
| `notenv vault delete <name>` | Permanently delete a configured vault's objects, this machine's trust state for it, and its config entry. Behind the primary passphrase and a type-the-name confirmation. |
| `notenv handoff -- cmd` | Run an agent against a scoped, ephemeral vault (only the resolved namespace), with your master key out of its reach. |
| `notenv --version` | Print the version, commit, and build date. |

## Targeting a vault

Add these to any command:

- `--storage NAME` targets a specific configured storage (vault). Use it in CI to pin the vault from
  outside the repo.
- `--namespace NAME` addresses a vault namespace directly from anywhere, with no project and no
  checkout. The contract (and its declarations) is bypassed entirely, so `run` injects every secret
  in the namespace.

## Namespace management

A **namespace** is a named, independently encrypted group of secrets in a vault. The secrets inside one
are managed with the core commands above (`set`, `run`, ...); these commands manage namespaces as
containers. Pick the namespace with your project's `notenv.toml` or `--namespace`.

| Command | What it does |
|---|---|
| `notenv namespace list` | List the namespaces the vault holds (names only, no passphrase). `--json` for machines. |
| `notenv namespace create NAME` | Create an empty namespace deliberately (setting the first secret also creates one). `--description` records what it holds. |
| `notenv namespace update NAME --description "..."` | Update an existing namespace's metadata (today, its description; `""` clears it). |
| `notenv namespace delete NAME` | Permanently remove a namespace and all of its secrets. Behind the passphrase and a confirmation (`--yes` skips it). |
| `notenv namespace recover NAME` | Last resort for honest media loss: rebuild a namespace whose current blob is unreadable from its one-generation backup, dropping the corrupt blobs (the most recent write is lost). If nothing readable survives it refuses; remove it with `namespace delete`. `--yes` skips the confirmation. |

## Key and slot management

A vault's master key is wrapped under one or more **key slots**. Passphrases are for people,
identities are for machines: a slot is a person's passphrase or a machine's age public key. These
commands manage them.

| Command | What it does |
|---|---|
| `notenv credential list` | List the key slots (name, principal, primary, added, fingerprint). `--json` for machines. |
| `notenv credential add <name>` | Onboard a teammate: prints a one-time onboarding passphrase; their first command replaces it with their own. |
| `notenv credential add --machine <name>` | Enroll a machine (CI, an agent): prints a new identity exactly once, for the platform's secret store. `--recipient age1...` enrolls an existing public key instead. |
| `notenv credential delete <name\|index>` | Remove a slot **and re-key the vault** (offboarding). Asks for confirmation; `--yes` skips it (the unlock is still required). |
| `notenv credential rotate` | Change the passphrase on your slot (header only). |
| `notenv credential rotate-master` | Mint a fresh master key and re-encrypt every secret; all slots kept. |
| `notenv credential set-primary <name\|index>` | Transfer the primary (governance) slot. |
| `notenv credential trust` | Re-pin after a confirmed master change that carries no signed proof (shows what changed, asks). |
| `notenv credential forget` | Forget this machine's pin and cached key for a storage (after a deliberate vault reset). |
| `notenv credential restore-backup` | Restore the header from its pre-write backup. |

## Exit codes

`notenv run` and `notenv handoff` both follow docker's convention, so a script or agent can tell a
vault problem from a code problem (other commands just use 1 on failure):

| Code | Meaning |
|---|---|
| (child's code) | The child ran; its exit code passes through untouched. |
| `125` | notenv's own failure (could not unlock, fetch, or decrypt). |
| `126` | The command was found but could not be executed. |
| `127` | The command was not found. |
| `128 + N` | The child was killed by signal N. |
