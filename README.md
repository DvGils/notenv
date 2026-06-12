# notenv

[![CI](https://github.com/DvGils/notenv/actions/workflows/ci.yml/badge.svg)](https://github.com/DvGils/notenv/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/DvGils/notenv?sort=semver)](https://github.com/DvGils/notenv/releases/latest)
[![Go Reference](https://pkg.go.dev/badge/github.com/DvGils/notenv.svg)](https://pkg.go.dev/github.com/DvGils/notenv)
[![Go Report Card](https://goreportcard.com/badge/github.com/DvGils/notenv)](https://goreportcard.com/report/github.com/DvGils/notenv)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](./LICENSE)

> Your `.env`, encrypted and off your disk, with no infrastructure to run.

notenv replaces `.env` files. Your secrets are encrypted **on your machine** with
[age](https://github.com/FiloSottile/age), stored as ciphertext in a **local vault**
or on **storage you already own** (Backblaze B2, S3, Google Drive, SFTP, WebDAV, or
anything [rclone](https://rclone.org) speaks), and decrypted **only into the
environment of the process you run**. Plaintext never touches your disk.

```sh
notenv setup                   # a local vault: no accounts, no dependencies, one passphrase
notenv import .env             # your existing secrets, encrypted; delete the .env after
notenv run -- npm run dev      # secrets injected as env vars, gone when the process exits
```

There is no server to run, no SaaS to sign up for, and nothing to install beyond notenv
itself to get started. You hold the key; storage only ever sees ciphertext, and when
syncing across machines starts to matter, `notenv vault copy` moves the same vault to a
cloud remote in one command.

---

## Requirements

- Linux, macOS, or Windows. On Linux, notenv also caches your key and secrets in RAM for a
  faster, prompt-free workflow (see [Caching](#caching-and-performance)).
- For **cloud remotes only**: [rclone](https://rclone.org/install/) on your `PATH` and a
  storage remote you control (Backblaze B2, S3, and so on; notenv can create the remote
  for you during setup). A local vault needs neither.

## Install

With Go:

```sh
go install github.com/DvGils/notenv/cmd/notenv@latest
```

Or download a prebuilt binary for Linux, macOS, or Windows (amd64 / arm64) from the
[Releases](https://github.com/DvGils/notenv/releases) page, extract `notenv`, and put it on
your `PATH`. Releases are reproducible, signed with
[cosign](https://github.com/sigstore/cosign) (keyless), and carry SLSA build provenance. To
verify a download:

```sh
cosign verify-blob \
  --bundle checksums.txt.bundle \
  --certificate-identity-regexp '^https://github\.com/DvGils/notenv/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  checksums.txt
sha256sum -c checksums.txt --ignore-missing      # then check your archive's hash
```

Homebrew and AUR packages are planned (see [Status](#status)).

## Quick start

**1. Set up this machine once.** The default is a local vault: no accounts, no rclone,
nothing but a passphrase (picking a cloud remote instead is the second option in the same
prompt, and a local vault can move to one later):

```sh
notenv setup
```

You choose a passphrase and escrow it in your password manager. That passphrase is the only
key to your secrets, so keep it safe: lose it and the ciphertext is unrecoverable by design.

**2. Set up a project.** Declare that this project uses notenv:

```sh
cd my-project
notenv init          # writes notenv.toml, which you commit
```

**3. Add secrets.** Have a `.env` already? Import it whole (every value encrypted, every
key declared), then delete it:

```sh
notenv import .env && rm .env
```

Or add values one at a time, prompted hidden:

```sh
notenv set DATABASE_URL
notenv set STRIPE_KEY
notenv list          # shows key names only, never values
```

**4. Run anything** with the secrets injected as environment variables:

```sh
notenv run -- npm run dev
notenv run -- python main.py
notenv run -- go test ./...
```

That is the whole loop. notenv is a process wrapper, so it works with any language that
reads environment variables.

### On a new machine

```sh
git clone <your-project>
cd <your-project>
notenv setup         # enter your escrowed passphrase
notenv run -- ...    # ready
```

Nothing else to restore. The committed `notenv.toml` and your password manager are all you
need. Joining someone else's vault instead of restoring your own? See
[Teams and key management](#teams-and-key-management).

---

## Why notenv

The secrets-tooling space is good, but there is a specific gap:

- **[SOPS](https://getsops.io) + age** nail client-side encryption and process injection,
  but you hand-roll the storage and the onboarding.
- **[Teller](https://github.com/tellerops/teller)** brokers cloud secret managers (Vault,
  AWS / GCP Secret Manager), but it is per-provider code and the provider holds your secrets.

notenv is the middle ground: SOPS-style client-side encryption, the storage reach of
rclone, and dotenv ergonomics, with zero infrastructure.

| | notenv | teller | SOPS + age (DIY) |
|---|---|---|---|
| Plaintext on disk | never | never | never |
| You hold the key | yes | no (provider does) | yes |
| Storage backends | local vault or any rclone remote | per-provider code | you wire it up |
| Infrastructure to run | none | none (uses your cloud) | none |
| One-command onboarding | yes | partial | no |

## How it works

```
notenv run -- cmd
  |
  |-- fetch ciphertext   <- rclone <-  your B2 / S3 / Drive / ...
  |-- unlock the master key (from your passphrase; cached after first use)
  |-- decrypt secrets in memory
  |-- build the child environment from notenv.toml
  |-- exec cmd, stream its I/O, exit with its code
        nothing written to disk
```

Your secrets are encrypted with a random **master key**. The master key never exists in
plaintext at rest: a small header object next to your secrets holds it wrapped under one or
more **key slots**, the same approach LUKS and restic use. A slot is either a **passphrase**
(yours, escrowed) or a teammate's **age public key** (so you can grant access without sharing
a secret). Unlocking any slot yields the master key for the session.

The header is authenticated and carries a monotonic revision, so a party that can write your
storage but holds no key cannot tamper with it or roll it back undetected. Changing a
passphrase rewrites only the header; rotating the master key re-encrypts every secret under a
fresh key while keeping all slots; see [Teams and key management](#teams-and-key-management).

## Commands

| Command | What it does |
|---|---|
| `notenv setup` | Configure this machine: a local vault by default, or pick/create a cloud remote; create or unlock your key. |
| `notenv init` | Set up the current project (writes `notenv.toml`). Runs setup first if needed. |
| `notenv import [file]` | Import a `.env` file: every value encrypted in one write, every key declared. `--dry-run` previews. |
| `notenv set KEY` | Set a secret. Prompted hidden, encrypted, uploaded, and declared in `notenv.toml`. |
| `notenv set KEY --stdin` | Read the value from stdin (for multiline or piped values). |
| `notenv set KEY --description "…"` | Also record what the secret is for; omitted, the existing note is kept (`""` clears). |
| `notenv unset KEY` | Remove a stored secret value. |
| `notenv list` | List stored secret names with descriptions and modified times (never values). `--json` for machines; piped output is bare names. |
| `notenv run -- cmd` | Run a command with secrets injected as environment variables. |
| `notenv run --refresh -- cmd` | Same, but bypass the local cache and pull the latest secrets first. |
| `notenv compact` | Force-fold a namespace's change segments into a single snapshot (also happens automatically). |
| `notenv cache clear` | Remove all locally cached ciphertext on this machine. |
| `notenv vault copy` | Replicate this vault to new storage (e.g. local → cloud) and register it. The source is untouched. |
| `notenv mcp` | Serve the vault to MCP clients over stdio (experimental; see [AI agents](#using-notenv-with-ai-agents)). |
| `notenv --version` | Print the version, commit, and build date. |

Add `--storage NAME` to any command to target a specific [vault](#multiple-vaults). Add
`--namespace NAME` to address a vault namespace directly from anywhere: no project, no
checkout; the contract (and its declarations) is bypassed entirely, so `run` injects every
secret in the namespace.

### Key and slot management

| Command | What it does |
|---|---|
| `notenv key list` | List the key slots (name, type, primary, fingerprint). `--json` for machines. |
| `notenv key add --passphrase` | Add another passphrase slot (a backup or second device). |
| `notenv key add --recipient age1… [--name N]` | Add a teammate by their age public key. |
| `notenv key rm <name\|index>` | Remove a slot **and re-key the vault** (offboarding). |
| `notenv key rotate` | Change the passphrase on your slot (header only). |
| `notenv key rotate-master` | Mint a fresh master key and re-encrypt every secret; all slots kept. |
| `notenv key set-primary <name\|index>` | Transfer the primary (governance) slot. |
| `notenv key gen-identity` | Generate an age identity on this machine (to join a vault). |
| `notenv key trust` | Re-pin after a confirmed master change that carries no signed proof (shows what changed, asks). |
| `notenv key forget` | Forget this machine's pin + cached key for a storage (after a deliberate vault reset). |
| `notenv key restore-backup` | Restore the header from its pre-write backup. |

## Configuration

notenv splits configuration in two:

**`notenv.toml`** lives in your project and **is committed**. It declares which environment
variables the project needs. It contains no secret values:

```toml
namespace = "my-project"   # optional; defaults to the directory name

[secrets]
DATABASE_URL = { required = true }
SENTRY_DSN   = { required = false }
STRIPE_KEY   = { name = "stripe-secret-key" }   # use a different storage key name
```

**`~/.config/notenv/config.toml`** is per machine and **is not committed**. It defines one or
more named storages (vaults) and is written for you by `notenv setup`:

```toml
default = "personal"               # storage used when a project has no local binding

[storage.local]
path      = "~/.local/share/notenv/vaults/local"   # a local vault directory (no rclone)

[storage.personal]
remote    = "s3-notenv"            # an rclone remote name
base      = "my-bucket/notenv"     # path within the remote
versioned = true                   # remote keeps old versions on overwrite (B2 does)
# read_only = true                 # refuse mutating commands here (policy, not enforcement)
# cache_ttl = "1h"                 # ciphertext cache lifetime (remote storages only); "0" disables

[crypto]
mode = "passphrase"
# cache_ttl = "1h"                 # master-key cache lifetime; "0" disables
```

Storage settings are deliberately machine-only: a committed `notenv.toml` cannot redirect
where your machine reads and writes secrets. A third, git-ignored file (**`notenv.local.toml`**,
written by `notenv init`) records what this *checkout* has agreed to: which storage it uses
(when the machine has several) and which **namespace** it reads. The namespace pin matters: the
committed contract chooses the namespace, so without it a cloned repository could silently point
your machine at another project's secrets in the same vault. Using a namespace other than the
directory's name is confirmed once per checkout, and a contract that later changes its namespace
is refused until you re-accept it with `notenv init`. See [Multiple vaults](#multiple-vaults).

## Teams and key management

Several people (or machines) can share one vault with no server, using key slots. The
asymmetric path is the point: you add a teammate with only their **public** key, and they
never share a secret with you.

**Onboard a teammate:**

1. Teammate: `notenv key gen-identity`; saves an age identity on their machine and prints
   their public `age1…` recipient.
2. They send you that recipient (public; safe to share in the clear).
3. You: `notenv key add --recipient age1… --name alice`.
4. Teammate: `notenv setup` (pointing at the same storage), then `notenv run -- …`. Their
   identity unlocks the vault; no passphrase.

**Offboard** with `notenv key rm <name>`: it removes the slot **and re-keys the vault** (mints
a fresh master key and re-encrypts every secret), so the removed credential can no longer
decrypt. All surviving slots keep working.

> **notenv does not own your storage**, so it cannot revoke a former holder's storage *write*
> access. For complete offboarding, also rotate that storage's credential at your provider.
> Otherwise a holder who kept both the old master key and write access could roll the vault
> back to a state where their slot still exists. notenv **detects** such a rollback
> ([Security](#security)) but cannot prevent it; `key rm` reminds you to rotate the credential.

**Other operations:** `notenv key rotate-master` re-keys the vault while keeping every slot (a
precaution if a machine may be compromised). `notenv key rotate` changes your own passphrase.
`notenv key list` shows the slots; `notenv key set-primary` transfers the advisory governance
slot (the one `key rm` refuses to remove). Re-keys, including offboarding, propagate to the
other machines automatically: each rotation is signed by the key it replaces, so everyone else
verifies and follows without prompts or alarms.

## Multiple vaults

One machine can use several storages. `notenv setup` adds a named storage and can be re-run to
add more; the first becomes the default.

- A project chooses its storage at `notenv init` time, recorded (along with its
  [namespace pin](#configuration)) in a git-ignored `notenv.local.toml` beside `notenv.toml`.
  With a single storage there is nothing to pick.
- `--storage NAME` overrides the choice for any command; use it in CI to pin the vault from
  outside the repo.
- The committed `notenv.toml` never names a storage, and the namespace it names is pinned per
  checkout, so cloning an untrusted project can't point your machine at a different vault, or
  silently at a different project's secrets within your vault.

## Caching and performance

To keep the workflow snappy, notenv caches two things on Linux:

- **Your master key** in the kernel keyring, so you are prompted for your passphrase at most
  once per session (default 1 hour, configurable via `crypto.cache_ttl`).
- **The encrypted blob** in `XDG_RUNTIME_DIR` (tmpfs), so a warm `notenv run` needs no
  network at all (default 1 hour, configurable via `storage.cache_ttl`). **Remote vaults
  only**: a local vault is its own disk, so its reads skip the cache and verify the vault
  manifest every time: no second ciphertext copy, nothing to go stale.

Both caches are RAM-backed and cleared on logout or reboot. This is not only a speed-up but a
**security property**: when the process exits there is no persistent cache for someone to
discover later. Only ciphertext is ever cached, never plaintext.

Changes you make on this machine refresh the cache immediately. To pull a change made on
another machine before the cache expires, use `notenv run --refresh` (or `notenv cache
clear`). Set either `cache_ttl` to `"0"` to disable caching.

### Caching is Linux-only, by design

| Platform | Cache | Persistence |
|---|---|---|
| Linux | RAM-backed (kernel keyring + tmpfs) | removed automatically on logout/reboot |
| macOS | **none, by design** | n/a |
| Windows | **none, by design** | n/a |

The Linux cache relies on the kernel keyring and `tmpfs`: secret material lives in RAM that the
OS reclaims on logout, so "the process exits and nothing is left behind" is a real guarantee.
We investigated the platform-native stores (macOS Keychain, Windows Credential Manager / DPAPI)
and none give that cleanup guarantee: they persist to disk, and with no daemon there is nothing
to evict them. Rather than ship a weaker cache under the same name and quietly break the
"nothing left behind" property, notenv **does not cache on macOS or Windows**. Those platforms
prompt and fetch on each run; for a prompt-free workflow there, use a configured
[age identity](#teams-and-key-management) (`NOTENV_IDENTITY`), an on-disk credential you place
and control, with no lifecycle managed by us.

**Concurrent writes.** `notenv set` never overwrites a shared object. Each change is appended
as its own uniquely named, encrypted segment, and reads fold a namespace's segments together,
last write wins per key. So if two people (or two machines) `set` different keys at the same
time, both survive, no lost writes, no locking, on any remote. Setting the *same* key
concurrently is a genuine conflict: one value wins deterministically and the other is reported
and kept recoverable in its segment until the next compaction.

Segments accumulate as you write, so once enough pile up a `set` folds them back into a single
snapshot automatically; it's best-effort housekeeping that never fails your write, and reads
are never affected. `notenv compact` forces it on demand. Compaction is safe to run while
others are writing (their writes are never lost); just don't run two compactions of the same
namespace at once.

Writes are also safe against a **concurrent master rotation**: every write confirms afterwards
that the key it was sealed under is still the vault's master, rolling itself back (and telling
you to re-run) if a teammate re-keyed mid-flight, while the rotation re-keys anything written
under the old master during its run. No write ever ends up encrypted to a key nobody holds.

## Using notenv with AI agents

Coding agents read everything: files, tool output, logs. A `.env` file on disk *will*
eventually enter the model's context (`cat`-ed while debugging, swept up by a glob, or
extracted by a prompt-injected instruction), and anything that enters context persists in
transcripts and whatever the conversation touches next. notenv removes the file and gives the
agent a verb that separates *using* credentials from *knowing* them:

- **`notenv run -- cmd`** injects secrets into the child only; the value never appears in
  anything the model reads.
- **`notenv list`** tells the agent *which* credentials exist, and, with per-secret
  descriptions (`set KEY --description "…"`), *what they are for*, so it can decide what's
  runnable without ever seeing a value. `notenv list --json` gives it a stable shape to parse.
- **Captured output is masked.** When stdout/stderr is not a terminal (which is exactly how
  agents and CI read output), any injected value a child prints (a server echoing its
  connection string on boot, a debug dump) is replaced with `<notenv-masked:NAME>` before the
  model sees it.
- **Exit codes say whose failure it was.** `run` follows docker's convention: the child's
  code passes through; 125 is notenv's own failure, 126 found-but-can't-run, 127 not found.
  An agent retrying a flaky test never mistakes a vault problem for a code problem.
- **No checkout needed.** `--namespace` (with `--storage`) addresses a vault directly from
  anywhere: an agent wired to a database needs credentials, not a git repository.
- **Read-only by policy.** Start an agent with `NOTENV_READONLY=1` (or mark a storage
  `read_only = true`) and every mutating command is refused. This constrains a cooperating
  client from having an accident; for *enforced* read-only, use a read-only storage
  credential (e.g. a B2 application key without write) behind the remote.
- **Unlock prompts reach the human, not the model.** Passphrase prompts read the terminal
  device directly, so when an agent's command needs an unlock, the question goes to whoever is
  at the keyboard.

Drop this in your `AGENTS.md` / `CLAUDE.md`:

```markdown
This project manages secrets with notenv (https://github.com/DvGils/notenv).
- Run anything needing credentials via `notenv run -- <cmd>`; the env vars in
  notenv.toml are injected automatically.
- `notenv list` shows which secret names exist and what they're for. Never
  print, ask for, or store secret values; never create .env files.
- If a command prompts for a passphrase, stop and let the user answer it.
```

### The MCP server (experimental)

`notenv mcp` serves the same surface over the Model Context Protocol, for agents that
aren't shell-first (or machines with no checkout at all):

```sh
claude mcp add notenv -- notenv mcp        # or any MCP client, stdio transport
```

Two tools: `list_secrets` (names, descriptions, modified times, never values) and
`run_with_secrets` (inject and execute; the agent gets the exit code and masked output).
The vault must unlock without a prompt: set `NOTENV_IDENTITY`, or rely on a session-cached
key. It is experimental: the tool surface may still change before it is frozen.

**Honest limits:** this is accident-proofing, not a security boundary. An agent running as
your user can still extract a value deliberately (any encoding defeats exact-byte masking:
`notenv run -- sh -c 'printenv KEY | base64'`) or read the
session key cache, and a child process that legitimately holds a secret can always send it
somewhere; masking catches accidents, not intent. The same goes for read-only mode: with a
single master key, anyone who can decrypt could author writes with their own tooling, so the
flag stops accidents while the storage credential is what stops adversaries. A broker mode
that keeps the unlocked key in a separate trust domain (so agents can *use* but provably not
*extract*) is on the roadmap; see [Status](#status) and the [threat model](./THREAT_MODEL.md).

## Security

- **At rest, anywhere:** only age ciphertext exists (on your storage and in any local
  cache). It is useless without your key.
- **Storage provider compromise:** the provider sees ciphertext only and cannot decrypt it.
- **Stolen storage credential:** grants read of ciphertext, not plaintext (your key is a
  separate factor held in your password manager). Most credentials also allow writes, so
  the integrity caveat below applies too.
- **Write access to your storage (integrity):** the key header is authenticated (an HMAC
  keyed from the master key) and carries a monotonic revision that each machine pins locally,
  under the vault's own identity. A party who can *write* your storage but holds no key cannot
  forge or alter the header undetected; rolling it back, deleting it, or swapping in a
  different vault at the same location are all detected and refused (`notenv key forget` is
  the deliberate-reset escape hatch). **Legitimate master rotations need no ceremony on other
  machines**: each rotation is signed by the outgoing master, and a machine pinned at it
  verifies the chain and follows silently. `notenv key trust` (which shows what changed and
  asks) remains only for changes that carry no such proof. **Every stored secret object is
  bound to that authenticated header**: the header carries a manifest of the vault's objects
  (a keyed fingerprint of each), and every object names the key it was written under, so
  deleting a stored write, reverting it, resurrecting a compacted one, or copying a real
  object into another namespace alarms with the object named, instead of silently changing
  what `notenv run` injects. They still cannot forge plaintext: a substituted blob they don't
  hold the key for fails to decrypt. Two honest limits: on *first* contact with a vault a
  machine has no prior pin to compare against (trust on first use), and a *former key holder*
  who kept the master key and retains storage *write* can fork history (including signing
  transitions onto the fork) in a way only machines pinned past the fork detect; rotate the
  storage credential to cut them off (notenv advises this on `key rm` but, not owning the
  storage, can't enforce it). Deletion of blobs remains an availability concern: detection
  doesn't recover bytes; object versioning (the default on B2) does.
- **A cloned, untrusted project:** the committed `notenv.toml` can redirect neither your
  storage (machine-only) nor, silently, your namespace: the namespace is pinned per
  checkout, an unusual one is confirmed before first use, and a contract that changes its
  namespace later is refused (see [Configuration](#configuration)). Explicit `--namespace`
  use gets the same first-use confirmation, recorded per user instead of per checkout.
- **Read-only mode is policy, not crypto:** `read_only` / `NOTENV_READONLY` make notenv
  refuse writes: protection against a cooperating client's accident, never against an
  adversary (with a single master key, read capability is write capability: anyone who can
  decrypt can author valid writes with their own tooling). Enforced read-only is the
  storage credential's job; cryptographic read-only identities require a key split and are
  explicitly future (v2) work.
- **Running machine compromise:** an attacker with your live session and your key can
  decrypt. notenv shrinks the window (no `.env` lying around, plaintext only in the child
  process for its lifetime) but cannot defend a fully compromised host.
- **notenv itself:** a small, auditable, client-side-crypto core. The tool never needs to be
  trusted with anything at rest.

The only irreplaceable secret is your passphrase, which you store somewhere safe (e.g. a
password manager), not on the storage backend. A lost or dead machine loses nothing: retrieve the passphrase on
a new machine and notenv works again.

For the full analysis (assets, adversaries, the properties that hold against each, and the
explicit non-goals), see [THREAT_MODEL.md](./THREAT_MODEL.md). To report a vulnerability, see
[SECURITY.md](./SECURITY.md).

## Building from source

```sh
git clone https://github.com/DvGils/notenv
cd notenv
make build       # compile ./notenv
make test        # run the test suite
make install     # install into $(go env GOPATH)/bin
```

Releases are produced with [GoReleaser](https://goreleaser.com); `make snapshot` builds the
full set of release artifacts locally without publishing.

## Status

Actively developed and being tested.

**Working today:** `setup`, `init`, `import`, `set`, `unset`, `list`, `run`, `compact`,
`cache`, and `vault copy`; **local vaults** (zero-account default, true compare-and-swap
header writes, promptless creation for agents/CI via `NOTENV_IDENTITY`) with one-command
replication to a cloud remote; full
key and slot management (`notenv key …`); team access by age recipient, passphrase and
master-key rotation, offboarding by re-key, advisory primary governance, and authenticated +
version-pinned headers (vanished-header and vault-replacement detection included); **signed
rotation transitions**, so legitimate re-keys propagate to every machine without prompts; a
**header manifest binding every stored object** to the authenticated header, so storage-level
tamper with any single secret (revert, delete, replay, relocate) alarms naming the object;
append-only writes so concurrent `set`s never lose each other (including against a concurrent
master rotation) with automatic compaction keeping reads fast; per-checkout namespace pinning
with join confirmation; [masked captured output](#using-notenv-with-ai-agents); multiple
storages per machine; passphrase or identity unlock; Linux key/blob caching. Releases are
reproducible, cosign-signed, and carry SLSA build provenance.

**Planned:**
- An MCP server mode, so agents discover and use notenv through their native tooling.
- A broker mode: the unlocked key lives in a separate trust domain and execs children on
  behalf of agents, turning "agents shouldn't see credentials" from a convention into a
  boundary.
- `notenv edit` for bulk edits in `$EDITOR`.
- Homebrew / AUR / Scoop packages.

**Non-goals:** secret caching on macOS and Windows; see
[Caching is Linux-only, by design](#caching-is-linux-only-by-design).

## License

[Apache-2.0](./LICENSE).
