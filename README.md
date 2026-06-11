# notenv

[![CI](https://github.com/DvGils/notenv/actions/workflows/ci.yml/badge.svg)](https://github.com/DvGils/notenv/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/DvGils/notenv?sort=semver)](https://github.com/DvGils/notenv/releases/latest)
[![Go Reference](https://pkg.go.dev/badge/github.com/DvGils/notenv.svg)](https://pkg.go.dev/github.com/DvGils/notenv)
[![Go Report Card](https://goreportcard.com/badge/github.com/DvGils/notenv)](https://goreportcard.com/report/github.com/DvGils/notenv)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](./LICENSE)

> Your `.env`, encrypted and off your disk, with no infrastructure to run.

notenv replaces `.env` files. Your secrets are encrypted **on your machine** with
[age](https://github.com/FiloSottile/age), stored as ciphertext on
**storage you already own** (Backblaze B2, S3, Google Drive, SFTP, WebDAV, or anything
[rclone](https://rclone.org) speaks), and decrypted **only into the environment of the
process you run**. Plaintext never touches your disk.

```sh
notenv run -- npm run dev      # secrets injected as env vars, gone when the process exits
```

There is no server to run and no SaaS to sign up for. You hold the key; the storage
provider only ever sees ciphertext.

---

## Requirements

- [rclone](https://rclone.org/install/) on your `PATH`. notenv uses it to move ciphertext
  to and from your storage.
- A storage remote you control (Backblaze B2, S3, and so on). notenv can create one for you
  during setup.
- Linux, macOS, or Windows. On Linux, notenv also caches your key and secrets in RAM for a
  faster, prompt-free workflow (see [Caching](#caching-and-performance)).

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

**1. Set up this machine once.** notenv finds or creates an rclone remote, generates your
encryption key, and locks it with a passphrase:

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

**3. Add secrets.** Values are prompted hidden, encrypted, and uploaded. The key name is
recorded in `notenv.toml` for you:

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
| Storage backends | any rclone remote | per-provider code | you wire it up |
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
| `notenv setup` | Configure this machine: pick or create a storage remote, create or unlock your key. |
| `notenv init` | Set up the current project (writes `notenv.toml`). Runs setup first if needed. |
| `notenv set KEY` | Set a secret. Prompted hidden, encrypted, uploaded, and declared in `notenv.toml`. |
| `notenv set KEY --stdin` | Read the value from stdin (for multiline or piped values). |
| `notenv list` | List stored secret names (never values). |
| `notenv run -- cmd` | Run a command with secrets injected as environment variables. |
| `notenv run --refresh -- cmd` | Same, but bypass the local cache and pull the latest secrets first. |
| `notenv cache clear` | Remove all locally cached ciphertext on this machine. |
| `notenv --version` | Print the version, commit, and build date. |

Add `--storage NAME` to any command to target a specific [vault](#multiple-vaults).

### Key and slot management

| Command | What it does |
|---|---|
| `notenv key list` | List the key slots (name, type, primary, fingerprint). |
| `notenv key add --passphrase` | Add another passphrase slot (a backup or second device). |
| `notenv key add --recipient age1… [--name N]` | Add a teammate by their age public key. |
| `notenv key rm <name\|index>` | Remove a slot **and re-key the vault** (offboarding). |
| `notenv key rotate` | Change the passphrase on your slot (header only). |
| `notenv key rotate-master` | Mint a fresh master key and re-encrypt every secret; all slots kept. |
| `notenv key set-primary <name\|index>` | Transfer the primary (governance) slot. |
| `notenv key gen-identity` | Generate an age identity on this machine (to join a vault). |
| `notenv key trust` | Re-pin after a confirmed legitimate master change (clears a rollback alarm). |
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

[storage.personal]
remote    = "s3-notenv"            # an rclone remote name
base      = "my-bucket/notenv"     # path within the remote
versioned = true                   # remote keeps old versions on overwrite (B2 does)
# cache_ttl = "1h"                 # local ciphertext cache lifetime; "0" disables

[crypto]
mode = "passphrase"
# cache_ttl = "1h"                 # master-key cache lifetime; "0" disables
```

Storage settings are deliberately machine-only: a committed `notenv.toml` cannot redirect
where your machine reads and writes secrets. When a machine has more than one storage, a
project records which one it uses in a git-ignored **`notenv.local.toml`** (written by
`notenv init`); see [Multiple vaults](#multiple-vaults).

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
slot (the one `key rm` refuses to remove).

## Multiple vaults

One machine can use several storages. `notenv setup` adds a named storage and can be re-run to
add more; the first becomes the default.

- A project chooses its storage at `notenv init` time, recorded in a git-ignored
  `notenv.local.toml` beside `notenv.toml`. With a single storage there is nothing to pick.
- `--storage NAME` overrides the choice for any command; use it in CI to pin the vault from
  outside the repo.
- The committed `notenv.toml` never names a storage, so cloning an untrusted project can't
  point your machine at a different vault than you intend.

## Caching and performance

To keep the workflow snappy, notenv caches two things on Linux:

- **Your master key** in the kernel keyring, so you are prompted for your passphrase at most
  once per session (default 1 hour, configurable via `crypto.cache_ttl`).
- **The encrypted blob** in `XDG_RUNTIME_DIR` (tmpfs), so a warm `notenv run` needs no
  network at all (default 1 hour, configurable via `storage.cache_ttl`).

Both caches are RAM-backed and cleared on logout or reboot, so encrypted secrets never
linger on persistent disk. Only ciphertext is ever cached, never plaintext.

Changes you make on this machine refresh the cache immediately. To pull a change made on
another machine before the cache expires, use `notenv run --refresh` (or `notenv cache
clear`). Set either `cache_ttl` to `"0"` to disable caching.

On macOS and Windows the caches are not yet wired up, so those platforms prompt and fetch on
every run; the cache lands together with their native key stores (see [Status](#status)).

**Concurrent writes.** `notenv set` is a read-modify-write of the whole namespace blob, and
there is no locking across machines yet. If two people (or two machines) run `set` on the
same namespace at nearly the same time, the later upload wins and the earlier new key is
lost. Object versioning on the remote preserves the overwritten bytes, but notenv does not
reconcile them automatically. In practice this is a non-issue for a single user; compare-and-swap
on write is planned.

## Security

- **At rest, anywhere:** only age ciphertext exists (on your storage and in any local
  cache). It is useless without your key.
- **Storage provider compromise:** the provider sees ciphertext only and cannot decrypt it.
- **Stolen storage credential:** grants read of ciphertext, not plaintext (your key is a
  separate factor held in your password manager). Most credentials also allow writes, so
  the integrity caveat below applies too.
- **Write access to your storage (integrity):** the key header is authenticated (an HMAC
  keyed from the master key) and carries a monotonic revision that each machine pins locally.
  A party who can *write* your storage but holds no key cannot forge or alter the header
  undetected, and rolling it back to an older version is detected on any machine that has seen
  a newer one (it refuses and points you at `notenv key trust`). They still cannot forge
  plaintext: a substituted blob they don't hold the key for fails to decrypt. Two honest
  limits: on *first* contact with a vault a machine has no prior revision to compare against
  (trust on first use), and a *former key holder* who kept the master key and retains storage
  *write* can fork history in a way only the vault owner's machine detects; rotate the
  storage credential to cut them off (notenv advises this on `key rm` but, not owning the
  storage, can't enforce it). Deletion is an availability concern, not confidentiality;
  object versioning (the default on B2) recovers prior bytes. Per-blob value rollback and
  cross-machine key continuity are planned hardening.
- **Running machine compromise:** an attacker with your live session and your key can
  decrypt. notenv shrinks the window (no `.env` lying around, plaintext only in the child
  process for its lifetime) but cannot defend a fully compromised host.
- **notenv itself:** a small, auditable, client-side-crypto core. The tool never needs to be
  trusted with anything at rest.

The only irreplaceable secret is your passphrase, which you store somewhere safe (e.g. a
password manager), not on the storage backend. A lost or dead machine loses nothing: retrieve the passphrase on
a new machine and notenv works again.

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

**Working today:** `setup`, `init`, `set`, `list`, `run`, and `cache`; full key and slot
management (`notenv key …`); team access by age recipient, passphrase and master-key
rotation, offboarding by re-key, advisory primary governance, and authenticated +
version-pinned headers; multiple storages per machine; passphrase or identity unlock; Linux
key/blob caching. Releases are reproducible, cosign-signed, and carry SLSA build provenance.

**Planned:**
- Compare-and-swap on write (closes the concurrent-write race).
- Signed rotation transitions (multi-machine key continuity, so legitimate rotations don't
  need a manual `notenv key trust`).
- Per-blob manifest (detect rollback of an individual secret's value).
- `notenv edit` for bulk edits in `$EDITOR`.
- Homebrew / AUR / Scoop packages.
- Native key/blob caching on macOS (Keychain) and Windows (DPAPI).

## License

[Apache-2.0](./LICENSE).
